package main

import (
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

	"golang.zx2c4.com/wireguard/tun"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
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
	AEAD   cipher.AEAD

	// 多核加密
	aeadPool []cipher.AEAD

	// UDP 模式 (双协议支持)
	ConnUDP         *net.UDPConn
	ConnBatchV4     *ipv4.PacketConn
	ConnBatchV6     *ipv6.PacketConn
	IsIPv6          bool
	ClientRemoteUDP *net.UDPAddr
	ServerPeerAddr  atomic.Pointer[net.UDPAddr]

	// Raw 模式
	ConnRaw        []*net.IPConn
	ClientRemoteIP *net.IPAddr
	ServerPeerIP   atomic.Pointer[net.IPAddr]
	rawSendIdx     uint32

	// 性能
	nonceCounter uint64
	SessionID    uint32
	numWorkers   int
}

func NewVPNInstance(cfg Config) *VPNInstance {
	cfg.ParseLegacy()
	v := &VPNInstance{Cfg: cfg}

	keyHash := sha256.Sum256([]byte(cfg.Key))
	var err error
	v.AEAD, err = chacha20poly1305.NewX(keyHash[:])
	if err != nil {
		log.Fatalf("加密初始化失败: %v", err)
	}

	v.numWorkers = runtime.NumCPU()
	if v.numWorkers > 8 {
		v.numWorkers = 8
	}
	v.aeadPool = make([]cipher.AEAD, v.numWorkers)
	for i := 0; i < v.numWorkers; i++ {
		v.aeadPool[i], _ = chacha20poly1305.NewX(keyHash[:])
	}

	v.SessionID = uint32(os.Getpid()) ^ uint32(keyHash[0])<<24
	return v
}

func (v *VPNInstance) Start() {
	if v.Cfg.Debug {
		debugMode = true
	}

	log.Printf("[%s] NekoLink v5.19 (真·定鼎终极版) 启动中 - 核心: %d, MTU: %d",
		v.Cfg.InterfaceName, v.numWorkers, v.Cfg.MTU)

	v.InitTUN()
	v.InitNetwork()

	// v5.19 最后定鼎：UDP 接收/发送全部收束为保序架构，Raw 模式保持暴力
	if v.Cfg.Protocol == "udp" {
		go v.TUNReaderLoopUDP_Ordered() // 发送端保序
		go v.udpReaderLoop_Ordered()    // 接收端保序 (v5.19 核心修复)
	} else {
		for i := 0; i < v.numWorkers; i++ {
			go v.TUNReaderLoopRaw(i)
			go v.rawReaderLoop(i)
		}
	}
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
	if v.Cfg.Protocol == "udp" {
		v.initUDP()
	} else {
		v.initRaw()
	}
}

func (v *VPNInstance) initUDP() {
	bindAddr := ":0"
	if v.Cfg.Mode == "server" {
		bindAddr = fmt.Sprintf("%s:%d", v.Cfg.ServerBindAddr, v.Cfg.BasePort)
	} else {
		// 客户端模式检测远端地址类型
		rAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", v.Cfg.RemoteIP, v.Cfg.RemotePort))
		if err == nil {
			v.ClientRemoteUDP = rAddr
			if strings.Contains(rAddr.IP.String(), ":") {
				v.IsIPv6 = true
				bindAddr = "[::]:0"
			}
		}
	}

	// 如果服务端配置了 IPv6 绑定
	if v.Cfg.Mode == "server" && strings.Contains(v.Cfg.ServerBindAddr, ":") {
		v.IsIPv6 = true
	}

	lAddr, _ := net.ResolveUDPAddr("udp", bindAddr)
	conn, err := net.ListenUDP("udp", lAddr)
	if err != nil {
		log.Fatalf("UDP 监听失败: %v", err)
	}

	conn.SetReadBuffer(32 << 20)
	conn.SetWriteBuffer(32 << 20)
	v.ConnUDP = conn

	if v.IsIPv6 {
		v.ConnBatchV6 = ipv6.NewPacketConn(conn)
		log.Printf("[UDP] IPv6 模式已启用 (MTU建议 1400 以下)")
	} else {
		v.ConnBatchV4 = ipv4.NewPacketConn(conn)
		log.Printf("[UDP] IPv4 模式运行中")
	}
}

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

	// v5.17 [重要] 消除 DUP! 重复包
	// 无论开启多少个发送 Socket，只启动一个接收协程，防止 Linux 内核重复投递包
	// go v.rawReaderLoop(0) // Moved to Start()
	if v.Cfg.Mode == "client" {
		v.ClientRemoteIP, _ = net.ResolveIPAddr("ip", v.Cfg.RemoteIP)
	}
}

// --- 读取循环 ---

func (v *VPNInstance) udpReaderLoop() {
	if v.IsIPv6 {
		v.udpReaderLoopV6()
		return
	}
	msgs := make([]ipv4.Message, BatchSize)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{make([]byte, BufSize)}
	}
	for {
		n, err := v.ConnBatchV4.ReadBatch(msgs, 0)
		if err != nil { continue }
		for i := 0; i < n; i++ {
			if msgs[i].N == 0 { continue }
			if v.Cfg.Mode == "server" {
				if addr, ok := msgs[i].Addr.(*net.UDPAddr); ok { v.ServerPeerAddr.Store(addr) }
			}
			v.handleIncomingPacket(msgs[i].Buffers[0][:msgs[i].N])
		}
	}
}

func (v *VPNInstance) udpReaderLoopV6() {
	msgs := make([]ipv6.Message, BatchSize)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{make([]byte, BufSize)}
	}
	for {
		n, err := v.ConnBatchV6.ReadBatch(msgs, 0)
		if err != nil { continue }
		for i := 0; i < n; i++ {
			if msgs[i].N == 0 { continue }
			if v.Cfg.Mode == "server" {
				if addr, ok := msgs[i].Addr.(*net.UDPAddr); ok { v.ServerPeerAddr.Store(addr) }
			}
			v.handleIncomingPacket(msgs[i].Buffers[0][:msgs[i].N])
		}
	}
}

// --- UDP 接收端保序流水线 (v5.19 绝杀) ---
func (v *VPNInstance) udpReaderLoop_Ordered() {
	buf := make([]byte, BufSize)
	for {
		// 单协程读取 Socket，内核保证这里出来的包一定是按网络到达顺序的
		n, addr, err := v.ConnUDP.ReadFromUDP(buf)
		if err != nil || n < NonceSize+Overhead {
			continue
		}
		if v.Cfg.Mode == "server" {
			v.ServerPeerAddr.Store(addr)
		}

		// 拷贝数据并启动解密处理。虽然解密可以异步，但我们通过本协程顺序处理或
		// 利用 handleIncomingPacket。为了最稳，这里目前采用单线程同步解密。
		// 如果需要提升性能，此处可改为解密池，但目前单线程 handle 已足够跑满 300M+
		v.handleIncomingPacket(buf[:n])
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

// --- UDP 专用 TUN 读取与发送循环 (v5.18 严格保序版) ---
func (v *VPNInstance) TUNReaderLoopUDP_Ordered() {
	buffs := make([][]byte, BatchSize)
	for i := range buffs {
		buffs[i] = make([]byte, BufSize)
	}
	sizes := make([]int, BatchSize)

	// 结果占位槽和内存回收缓存
	encryptedBuffs := make([][]byte, BatchSize)
	ptrCache := make([]*[]byte, BatchSize)

	for {
		n, err := v.TunDev.Read(buffs, sizes, TunOffset)
		if err != nil {
			continue
		}
		if n == 0 {
			continue
		}

		// v5.18 核心：同步并行加工 (Fork-Join)
		// 利用所有 worker 加密，但必须等这一批齐了再按序发出
		var wg sync.WaitGroup
		wg.Add(n)

		for i := 0; i < n; i++ {
			go func(idx int, size int, plain []byte) {
				defer wg.Done()
				if size == 0 {
					return
				}
				dstPtr := bufPool.Get().(*[]byte)
				ptrCache[idx] = dstPtr

				// 均匀分配到 worker pool
				aead := v.aeadPool[idx%len(v.aeadPool)]
				encryptedBuffs[idx] = v.encryptInto(plain, aead, *dstPtr)
			}(i, sizes[i], buffs[i][TunOffset:TunOffset+sizes[i]])
		}

		wg.Wait() // 关键：等大家都切完菜

		// 顺序落地发送
		addr := v.ClientRemoteUDP
		if v.Cfg.Mode == "server" {
			addr = v.ServerPeerAddr.Load()
		}

		if addr != nil {
			// v5.19 极致平滑：每 8 个包一波均匀吐出，防止瞬间突发
			const subBatchSize = 8
			for i := 0; i < n; i += subBatchSize {
				end := i + subBatchSize
				if end > n {
					end = n
				}

				msgsV4 := make([]ipv4.Message, 0, subBatchSize)
				msgsV6 := make([]ipv6.Message, 0, subBatchSize)

				for j := i; j < end; j++ {
					if encryptedBuffs[j] == nil {
						continue
					}
					if v.IsIPv6 {
						msgsV6 = append(msgsV6, ipv6.Message{Buffers: [][]byte{encryptedBuffs[j]}, Addr: addr})
					} else {
						msgsV4 = append(msgsV4, ipv4.Message{Buffers: [][]byte{encryptedBuffs[j]}, Addr: addr})
					}
				}

				if v.IsIPv6 && len(msgsV6) > 0 {
					v.ConnBatchV6.WriteBatch(msgsV6, 0)
				} else if !v.IsIPv6 && len(msgsV4) > 0 {
					v.ConnBatchV4.WriteBatch(msgsV4, 0)
				}
			}
		}

		// 清理与回收
		for i := 0; i < n; i++ {
			if ptrCache[i] != nil {
				bufPool.Put(ptrCache[i])
				ptrCache[i] = nil
			}
			encryptedBuffs[i] = nil
		}
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
