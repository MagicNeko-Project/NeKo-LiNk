package main

import (
	"context"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"io"
	"github.com/quic-go/quic-go"
	"golang.zx2c4.com/wireguard/tun"
	"golang.org/x/crypto/chacha20poly1305"

)

// --- 全局分发 ---
var debugMode bool

func logDebug(format string, v ...interface{}) {
	if debugMode {
		log.Printf("[DEBUG] "+format, v...)
	}
}

// --- 配置结构 (保持兼容) ---

type Config struct {
	InterfaceName string `json:"interface_name"`
	Mode          string `json:"mode"`
	LocalAddr     string `json:"local_addr"`
	Key           string `json:"key"`
	Protocol      string `json:"protocol"`
	MTU           int    `json:"mtu"`

	ServerBindAddr string `json:"server_addr"`
	BasePort       int    `json:"base_port"`

	RemoteIP   string `json:"server_ip"`
	RemotePort int    `json:"server_port"`

	IPProtocolNum int  `json:"ip_protocol_num"`
	Debug         bool `json:"debug"`
}

func (c *Config) ParseLegacy() {
	if c.Mode == "client" && c.RemoteIP == "" && c.ServerBindAddr != "" {
		c.RemoteIP = c.ServerBindAddr
	}
	if c.Mode == "client" && c.RemotePort == 0 && c.BasePort != 0 {
		c.RemotePort = c.BasePort
	}
	if c.Protocol == "" {
		c.Protocol = "udp"
	}
	if c.IPProtocolNum == 0 {
		c.IPProtocolNum = 233
	}
	if c.MTU == 0 {
		c.MTU = 1400
	}
	if c.InterfaceName == "" {
		c.InterfaceName = "neko0"
	}
}

// --- 常量 ---

const (
	NonceSize = chacha20poly1305.NonceSizeX
	Overhead  = chacha20poly1305.Overhead
	TunOffset = 16
	BufSize   = 65536
	BatchSize = 256
	QUICBatchSize = 32 // QUIC 模式使用更小的 Batch 以降低突发
)

// --- 内存池 ---

var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, BufSize)
		return &b
	},
}

// --- VPN 实例 ---

type VPNInstance struct {
	Cfg Config
	TunDev tun.Device

	// --- QUIC 模式 (v6.0) ---
	quicListener *quic.Listener   // Server Mode
	quicConn     *quic.Conn       // Client Mode
	activeStream *quic.Stream     // 当前活跃的加密 Stream
	// 互斥锁保护 quicConn 重连
	connMx       sync.RWMutex

	// --- Raw 模式 (Legacy / High Perf) ---
	// 保留原有逻辑不动
	ConnRaw        []*net.IPConn
	ClientRemoteIP *net.IPAddr
	ServerPeerIP   atomic.Pointer[net.IPAddr]
	rawSendIdx     uint32
	// Raw 模式仍需 AEAD
	AEAD           cipher.AEAD
	aeadPool       []cipher.AEAD // Raw 模式并发需要

	// 通用统计
	SessionID    uint32
	nonceCounter uint64 // 若 Raw 模式需要
	numWorkers   int
	IsIPv6       bool
}

func NewVPNInstance(cfg Config) *VPNInstance {
	cfg.ParseLegacy()
	v := &VPNInstance{Cfg: cfg}

	// 初始化并发数 (Raw 和 QUIC 处理可能都需要)
	v.numWorkers = runtime.NumCPU()
	if v.numWorkers > 8 {
		v.numWorkers = 8
	}

	// 初始化 AEAD (XChaCha20-Poly1305)
	// 无论是 Raw 还是 QUIC 模式，我们都使用这套加密
	keyHash := sha256.Sum256([]byte(cfg.Key))
	v.aeadPool = make([]cipher.AEAD, 16)
	for i := 0; i < 16; i++ {
		v.aeadPool[i], _ = chacha20poly1305.NewX(keyHash[:])
	}
	v.AEAD = v.aeadPool[0]
	v.SessionID = uint32(os.Getpid()) ^ uint32(keyHash[0])<<24

	return v
}

// --- QUIC Server Logic ---
// Server 端活跃 Session (简化版：仅支持单客户端或最后活跃客户端)
// 生产环境需要 IP->Session 路由表
var serverActiveConn *quic.Conn 
var serverConnMx sync.RWMutex

func (v *VPNInstance) startQuicServer() {
	tlsConf := GenerateTLSConfig(true)
	bindAddr := fmt.Sprintf("%s:%d", v.Cfg.ServerBindAddr, v.Cfg.BasePort)
	listener, err := quic.ListenAddr(bindAddr, tlsConf, &quic.Config{
		MaxIdleTimeout:      60 * time.Second,
		EnableDatagrams:     true,
		KeepAlivePeriod:     15 * time.Second,
		InitialStreamReceiveWindow:     8 * 1024 * 1024,
		InitialConnectionReceiveWindow: 16 * 1024 * 1024,
		Allow0RTT: true,
	})
	if err != nil {
		log.Fatalf("QUIC Listen 失败: %v", err)
	}
	v.quicListener = listener
	log.Printf("[QUIC] Server 监听于 %s (TLS 1.3)", bindAddr)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("Accept Error: %v", err)
			continue
		}
		
		go v.handleQuicSession(conn)
	}
}

func (v *VPNInstance) handleQuicSession(conn *quic.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	log.Printf("[QUIC] Session 开始: %s", remoteAddr)
	
	defer func() {
		log.Printf("[QUIC] Session 结束: %s", remoteAddr)
		conn.CloseWithError(0, "bye")
	}()

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		
		// 持久化当前活跃 Stream 用于发送
		serverConnMx.Lock()
		serverActiveConn = conn // 借用这个存放 Conn 引用 (虽然名字叫 Conn) 
		// 我们需要一个地方存活跃 Stream。为了简单，我们让 TUN 发送逻辑直接从 Conn 打开新 Stream 或者缓存它
		// 在 v6.1 中，我们采用：一个 Session 对应一个持久 Stream
		serverConnMx.Unlock()

		go v.handleQuicStream(stream)
	}
}

func (v *VPNInstance) handleQuicStream(os *quic.Stream) {
	defer (*os).Close()
	
	// 设置为全局发送 Stream (简化逻辑：后到者优先)
	v.connMx.Lock()
	v.activeStream = os
	v.connMx.Unlock()

	v.readStreamToTUN(os)
}

func (v *VPNInstance) readStreamToTUN(s *quic.Stream) {
	lenBuf := make([]byte, 2)
	for {
		// 1. 读长度
		_, err := io.ReadFull(s, lenBuf)
		if err != nil { return }
		length := binary.BigEndian.Uint16(lenBuf)
		
		// 2. 读密文
		cipherPkt := make([]byte, length)
		_, err = io.ReadFull(s, cipherPkt)
		if err != nil { return }
		
		// 3. 解密
		// 我们假设总是使用 v.AEAD (Server 端解密)
		if len(cipherPkt) < NonceSize+Overhead { continue }
		plain, err := v.AEAD.Open(nil, cipherPkt[:NonceSize], cipherPkt[NonceSize:], nil)
		if err != nil { continue }
		
		// 4. 入站 Batch 写优化 (由于 Stream 本身是按序的，我们可以直接写)
		v.writeTUN(plain)
	}
}

// --- TUN -> QUIC Forwarder ---
func (v *VPNInstance) TUNReaderLoopQUIC() {
	// 使用较小的 BatchSize 降低突发
	buffs := make([][]byte, QUICBatchSize)
	for i := range buffs {
		buffs[i] = make([]byte, BufSize)
	}
	sizes := make([]int, QUICBatchSize)

	for {
		n, err := v.TunDev.Read(buffs, sizes, TunOffset)
		if err != nil { continue }
		if n == 0 { continue }
		
		v.connMx.RLock()
		stream := v.activeStream
		v.connMx.RUnlock()
		
		if stream == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		
		for i := 0; i < n; i++ {
			if sizes[i] == 0 { continue }
			plain := buffs[i][TunOffset : TunOffset+sizes[i]]
			
			// 1. AEAD 加密
			// 生成 Nonce (前 24 字节)
			cipherPkt := make([]byte, NonceSize+len(plain)+Overhead)
			vVal := atomic.AddUint64(&v.nonceCounter, 1)
			binary.BigEndian.PutUint64(cipherPkt[0:8], vVal)
			binary.BigEndian.PutUint32(cipherPkt[8:12], v.SessionID)
			// 注意：这里我们简单使用 v.AEAD (pool 中的第一个)
			// 为了绝对并发安全，可以在此处根据协程 ID 选择不同的 AEAD
			v.AEAD.Seal(cipherPkt[NonceSize:NonceSize], cipherPkt[:NonceSize], plain, nil)
			
			// 2. 写入 Stream (长度 +密文)
			lenBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(lenBuf, uint16(len(cipherPkt)))
			
			stream.Write(lenBuf)
			stream.Write(cipherPkt)
		}
	}
}

func (v *VPNInstance) Start() {
	if v.Cfg.Debug {
		debugMode = true
	}

	log.Printf("[%s] NekoLink v6.0 (QUIC Revolution) 启动中 - 核心: %d, MTU: %d",
		v.Cfg.InterfaceName, v.numWorkers, v.Cfg.MTU)

	v.InitTUN()
	v.InitNetwork()
	
	// 根据协议选择模式
	// QUIC 接管 "udp" 和 "tcp" (config usually has protocol field)
	// Raw 模式通常是 protocol="raw"
	
	if v.Cfg.Protocol == "udp" || v.Cfg.Protocol == "tcp" || v.Cfg.Protocol == "quic" {
		// 1. 启动 TUN 读取 -> QUIC 发送
		// 优化：QUIC 模式仅使用 1 个 Reader 协程，避免并发导致的过度突发
		go v.TUNReaderLoopQUIC()

		// 2. 启动 QUIC 网络栈
		if v.Cfg.Mode == "server" {
			go v.startQuicServer()
		} else {
			go v.startQuicClient()
		}
	} else {
		// Legacy Raw 模式 (保留)
		log.Printf("[Init] 启动 Raw 模式 (High Performance IP)")
		for i := 0; i < v.numWorkers; i++ {
			go v.TUNReaderLoopRaw(i)
		}
		for i := 0; i < len(v.ConnRaw); i++ {
			go v.rawReaderLoop(i)
		}
	}
}

// --- Producer: UDP (Net) -> Pipeline ---


// --- QUIC Client Logic ---
func (v *VPNInstance) startQuicClient() {
	tlsConf := GenerateTLSConfig(false)
	
	for {
		log.Printf("[QUIC] 正在连接 %s:%d ...", v.Cfg.RemoteIP, v.Cfg.RemotePort)
		addr := fmt.Sprintf("%s:%d", v.Cfg.RemoteIP, v.Cfg.RemotePort)
		conn, err := quic.DialAddr(context.Background(), addr, tlsConf, &quic.Config{
			MaxIdleTimeout: 60 * time.Second,
			KeepAlivePeriod: 15 * time.Second,
			InitialStreamReceiveWindow: 8 * 1024 * 1024,
			InitialConnectionReceiveWindow: 16 * 1024 * 1024,
			Allow0RTT: true,
		})
		
		if err != nil {
			log.Printf("Connect Failed: %v, retry in 3s...", err)
			time.Sleep(3 * time.Second)
			continue
		}
		
		log.Printf("[QUIC] 连接成功！(TLS 1.3)")
		
		// 打开持久加密 Stream
		stream, err := conn.OpenStreamSync(context.Background())
		if err != nil {
			conn.CloseWithError(0, "stream open failed")
			continue
		}
		
		v.connMx.Lock()
		v.quicConn = conn
		v.activeStream = stream
		v.connMx.Unlock()
		
		v.readStreamToTUN(stream)
		
		v.connMx.Lock()
		v.quicConn = nil
		v.activeStream = nil
		v.connMx.Unlock()
		
		log.Printf("[QUIC] 连接断开，准备重连...")
		time.Sleep(1 * time.Second)
	}
}

func (v *VPNInstance) handleClientSession(conn *quic.Conn) {
	// 已经由 startQuicClient 的 readStreamToTUN 接管
}



// --- TUN 初始化 ---

func (v *VPNInstance) InitTUN() {
	dev, err := tun.CreateTUN(v.Cfg.InterfaceName, v.Cfg.MTU)
	if err != nil {
		log.Fatalf("TUN 创建失败: %v", err)
	}
	v.TunDev = dev

	realName, _ := dev.Name()

	runCmd("ip", "addr", "add", v.Cfg.LocalAddr, "dev", realName)
	runCmd("ip", "link", "set", realName, "mtu", fmt.Sprintf("%d", v.Cfg.MTU))
	runCmd("ip", "link", "set", realName, "up")

	// IPv4 转发优化
	runCmdQuiet("sysctl", "-w", "net.ipv4.conf.all.rp_filter=0")
	runCmdQuiet("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", realName))
	
	// IPv6 基础支持
	runCmdQuiet("sysctl", "-w", "net.ipv6.conf.all.forwarding=1")

	v.setupNFTables(realName)
}

func (v *VPNInstance) setupNFTables(iface string) {
	runCmd("nft", "add", "table", "inet", "nekolink")

	chainMSS := fmt.Sprintf("mss_%s", iface)
	runCmdQuiet("nft", "delete", "chain", "inet", "nekolink", chainMSS)
	runCmd("nft", "add", "chain", "inet", "nekolink", chainMSS,
		"{ type filter hook forward priority mangle; policy accept; }")
	runCmd("nft", "flush", "chain", "inet", "nekolink", chainMSS)

	// 同时钳制 v4 和 v6 的 TCP MSS
	runCmd("nft", "add", "rule", "inet", "nekolink", chainMSS,
		"iifname", iface, "tcp", "flags", "syn", "tcp", "option", "maxseg", "size", "set", "rt", "mtu")
	runCmd("nft", "add", "rule", "inet", "nekolink", chainMSS,
		"oifname", iface, "tcp", "flags", "syn", "tcp", "option", "maxseg", "size", "set", "rt", "mtu")

	if v.Cfg.Mode == "server" {
		v.setupSecurityRules(iface)
	}
}

func (v *VPNInstance) setupSecurityRules(iface string) {
	tableName := fmt.Sprintf("nekolink_sec_%s", iface)
	runCmd("nft", "add", "table", "inet", tableName)

	runCmd("nft", "add", "chain", "inet", tableName, "input",
		"{ type filter hook input priority filter; policy accept; }")
	runCmd("nft", "flush", "chain", "inet", tableName, "input")

	runCmd("nft", "add", "rule", "inet", tableName, "input", "ct", "state", "established,related", "accept")
	runCmd("nft", "add", "rule", "inet", tableName, "input", "iifname", "lo", "accept")
	runCmd("nft", "add", "rule", "inet", tableName, "input", "meta", "l4proto", "{ icmp, icmpv6 }", "accept")

	if v.Cfg.Protocol == "raw" {
		protoNum := v.Cfg.IPProtocolNum
		runCmd("nft", "add", "rule", "inet", tableName, "input", "meta", "l4proto", fmt.Sprintf("%d", protoNum), "accept")
	} else {
		port := v.Cfg.BasePort
		runCmd("nft", "add", "rule", "inet", tableName, "input", "udp", "dport", fmt.Sprintf("%d", port), "accept")
	}

	runCmd("nft", "add", "rule", "inet", tableName, "input", "ct", "state", "invalid", "drop")
}

// --- 网络初始化 ---

func (v *VPNInstance) InitNetwork() {
	if v.Cfg.Protocol != "udp" && v.Cfg.Protocol != "tcp" && v.Cfg.Protocol != "quic" {
		// Assume Raw
		v.initRaw()
	} else {
		// UDP/QUIC 模式下无需在此通过 net.ListenUDP 初始化
		// quic.Listen 将在 Start 中进行
		v.IsIPv6 = strings.Contains(v.Cfg.RemoteIP, ":") || strings.Contains(v.Cfg.ServerBindAddr, ":")
	}
}

// --- 遗留 Raw 逻辑 ---
// v6.0: Raw 模式完整保留 (Expert Mode)

func (v *VPNInstance) initRaw() {
	numConns := 4
	if runtime.NumCPU() < 4 {
		numConns = runtime.NumCPU()
	}

	// 检测 IP 类型
	testIP := v.Cfg.RemoteIP
	if v.Cfg.Mode == "server" {
		testIP = v.Cfg.ServerBindAddr
	}
	
	protoStr := fmt.Sprintf("ip4:%d", v.Cfg.IPProtocolNum)
	if strings.Contains(testIP, ":") {
		v.IsIPv6 = true
		protoStr = fmt.Sprintf("ip6:%d", v.Cfg.IPProtocolNum)
		log.Printf("[RAW] IPv6 自定义协议模式 (Proto: %d)", v.Cfg.IPProtocolNum)
	}

	v.ConnRaw = make([]*net.IPConn, numConns)
	for i := 0; i < numConns; i++ {
		var lAddr *net.IPAddr
		if v.Cfg.Mode == "server" && v.Cfg.ServerBindAddr != "0.0.0.0" && v.Cfg.ServerBindAddr != "[::]" {
			lAddr, _ = net.ResolveIPAddr("ip", v.Cfg.ServerBindAddr)
		}
		conn, err := net.ListenIP(protoStr, lAddr)
		if err != nil {
			log.Fatalf("Raw 监听失败: %v", err)
		}
		conn.SetReadBuffer(32 << 20)
		conn.SetWriteBuffer(32 << 20)
		v.ConnRaw[i] = conn
	}

	if v.Cfg.Mode == "client" {
		v.ClientRemoteIP, _ = net.ResolveIPAddr("ip", v.Cfg.RemoteIP)
	}
}


func (v *VPNInstance) rawReaderLoop(idx int) {
	conn := v.ConnRaw[idx]
	buf := make([]byte, BufSize)
	for {
		n, addr, err := conn.ReadFromIP(buf)
		if err != nil { continue }
		if n < NonceSize+Overhead { continue }
		if v.Cfg.Mode == "server" { v.ServerPeerIP.Store(addr) }
		v.handleIncomingPacket(buf[:n])
	}
}



// --- Raw 专用 TUN 读取与发送循环 (v5.17) ---
func (v *VPNInstance) TUNReaderLoopRaw(workerID int) {
	buffs := make([][]byte, BatchSize)
	for i := range buffs {
		buffs[i] = make([]byte, BufSize)
	}
	sizes := make([]int, BatchSize)
	aead := v.aeadPool[workerID]

	for {
		n, err := v.TunDev.Read(buffs, sizes, TunOffset)
		if err != nil {
			continue
		}
		for i := 0; i < n; i++ {
			if sizes[i] > 0 {
				v.sendRawOptimized(buffs[i][TunOffset:TunOffset+sizes[i]], aead)
			}
		}
	}
}

func (v *VPNInstance) encryptInto(plain []byte, aead cipher.AEAD, dst []byte) []byte {
	outSize := NonceSize + len(plain) + Overhead
	if len(dst) < outSize { return nil }
	nonce := dst[:NonceSize]
	vVal := atomic.AddUint64(&v.nonceCounter, 1)
	binary.BigEndian.PutUint64(nonce[0:8], vVal)
	binary.BigEndian.PutUint32(nonce[8:12], v.SessionID)
	for i := 12; i < NonceSize; i++ { nonce[i] = 0 }
	aead.Seal(dst[NonceSize:NonceSize], nonce, plain, nil)
	return dst[:outSize]
}

func (v *VPNInstance) sendRawOptimized(plain []byte, aead cipher.AEAD) {
	dstPtr := bufPool.Get().(*[]byte)
	encrypted := v.encryptInto(plain, aead, *dstPtr)
	if encrypted != nil {
		addr := v.ClientRemoteIP
		if v.Cfg.Mode == "server" { addr = v.ServerPeerIP.Load() }
		if addr != nil {
			idx := atomic.AddUint32(&v.rawSendIdx, 1) % uint32(len(v.ConnRaw))
			v.ConnRaw[idx].WriteToIP(encrypted, addr)
		}
	}
	bufPool.Put(dstPtr)
}

func (v *VPNInstance) handleIncomingPacket(enc []byte) {
	if len(enc) < NonceSize+Overhead { return }
	plain, err := v.AEAD.Open(enc[NonceSize:NonceSize], enc[:NonceSize], enc[NonceSize:], nil)
	if err == nil && len(plain) > 0 { v.writeTUN(plain) }
}

func (v *VPNInstance) writeTUN(data []byte) {
	bufPtr := bufPool.Get().(*[]byte)
	buf := (*bufPtr)[:TunOffset+len(data)]
	copy(buf[TunOffset:], data)
	v.TunDev.Write([][]byte{buf}, TunOffset)
	bufPool.Put(bufPtr)
}

func main() {
	cfgPath := flag.String("c", "config.json", "Config path")
	debug := flag.Bool("debug", false, "Debug mode")
	flag.Parse()
	debugMode = *debug

	data, _ := os.ReadFile(*cfgPath)
	var configs []Config
	if err := json.Unmarshal(data, &configs); err != nil {
		var single Config
		if err2 := json.Unmarshal(data, &single); err2 == nil { configs = append(configs, single) }
	}

	for _, cfg := range configs { NewVPNInstance(cfg).Start() }
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c
}

func runCmd(name string, args ...string) {
	exec.Command(name, args...).Run()
}
func runCmdQuiet(name string, args ...string) {
	exec.Command(name, args...).Run()
}
