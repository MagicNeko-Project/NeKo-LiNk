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
	"sync"
	"sync/atomic"
	"syscall"

	"golang.zx2c4.com/wireguard/tun"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
)

// --- 全局调试开关 ---
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

// --- 内存池 (全局) ---

var bufPool = sync.Pool{
	New: func() interface{} {
		// 预留前缀空间给发送逻辑
		b := make([]byte, BufSize)
		return &b
	},
}

// --- VPN 实例 ---

type VPNInstance struct {
	Cfg Config

	TunDev tun.Device
	AEAD   cipher.AEAD

	// 多核加密 - 每个核一个 AEAD 实例
	aeadPool []cipher.AEAD

	// UDP 模式
	ConnUDP         *net.UDPConn
	ConnBatch       *ipv4.PacketConn
	ClientRemoteUDP *net.UDPAddr
	ServerPeerAddr  atomic.Pointer[net.UDPAddr]

	// Raw 模式
	ConnRaw        []*net.IPConn
	ClientRemoteIP *net.IPAddr
	ServerPeerIP   atomic.Pointer[net.IPAddr]
	rawSendIdx     uint32

	// 性能优化
	nonceCounter uint64
	SessionID    uint32
	numWorkers   int
}

func NewVPNInstance(cfg Config) *VPNInstance {
	cfg.ParseLegacy()
	v := &VPNInstance{Cfg: cfg}

	keyHash := sha256.Sum256([]byte(cfg.Key))

	// 主 AEAD (解密用)
	var err error
	v.AEAD, err = chacha20poly1305.NewX(keyHash[:])
	if err != nil {
		log.Fatalf("加密初始化失败: %v", err)
	}

	// 多核加密池
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

	log.Printf("[%s] NekoLink v5.6 (稳定性能版) 启动中 - 核心: %d, MTU: %d",
		v.Cfg.InterfaceName, v.numWorkers, v.Cfg.MTU)

	v.InitTUN()
	v.InitNetwork()

	for i := 0; i < v.numWorkers; i++ {
		go v.TUNReaderLoop(i)
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

	runCmd("sysctl", "-w", "net.ipv4.conf.all.rp_filter=0")
	runCmd("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", realName))

	v.setupNFTables(realName)

	log.Printf("[%s] TUN 接口准备就绪 (Nya~)", realName)
}

func (v *VPNInstance) setupNFTables(iface string) {
	// 1. 基础表 (幂等)
	runCmd("nft", "add", "table", "inet", "nekolink")

	// 2. MSS 钳制链 (处理多实例冲突)
	chainMSS := fmt.Sprintf("mss_%s", iface)
	// 先尝试删除可能存在的同名但定义不同的链
	runCmdQuiet("nft", "delete", "chain", "inet", "nekolink", chainMSS)
	runCmd("nft", "add", "chain", "inet", "nekolink", chainMSS,
		"{ type filter hook forward priority mangle; policy accept; }")
	runCmd("nft", "flush", "chain", "inet", "nekolink", chainMSS)

	runCmd("nft", "add", "rule", "inet", "nekolink", chainMSS,
		"iifname", iface, "tcp", "flags", "syn", "tcp", "option", "maxseg", "size", "set", "rt", "mtu")
	runCmd("nft", "add", "rule", "inet", "nekolink", chainMSS,
		"oifname", iface, "tcp", "flags", "syn", "tcp", "option", "maxseg", "size", "set", "rt", "mtu")

	log.Printf("[%s] MSS 钳制已启用", iface)

	if v.Cfg.Mode == "server" {
		v.setupSecurityRules(iface)
	}
}

func (v *VPNInstance) setupSecurityRules(iface string) {
	// 为多实例使用接口专有表，避免互相 flush 规则
	tableName := fmt.Sprintf("nekolink_sec_%s", iface)
	runCmd("nft", "add", "table", "inet", tableName)

	runCmd("nft", "add", "chain", "inet", tableName, "input",
		"{ type filter hook input priority filter; policy accept; }")
	runCmd("nft", "flush", "chain", "inet", tableName, "input")

	runCmd("nft", "add", "rule", "inet", tableName, "input",
		"ct", "state", "established,related", "accept")
	runCmd("nft", "add", "rule", "inet", tableName, "input",
		"iifname", "lo", "accept")
	runCmd("nft", "add", "rule", "inet", tableName, "input",
		"meta", "l4proto", "icmp", "accept")

	if v.Cfg.Protocol == "raw" {
		protoNum := fmt.Sprintf("%d", v.Cfg.IPProtocolNum)
		runCmd("nft", "add", "rule", "inet", tableName, "input", "meta", "l4proto", protoNum, "accept")
		log.Printf("[%s] 安全防护已开启 (Proto: %s)", iface, protoNum)
	} else {
		port := fmt.Sprintf("%d", v.Cfg.BasePort)
		runCmd("nft", "add", "rule", "inet", tableName, "input", "udp", "dport", port, "accept")
		log.Printf("[%s] 安全防护已开启 (Port: %s)", iface, port)
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
	}

	lAddr, _ := net.ResolveUDPAddr("udp", bindAddr)
	conn, err := net.ListenUDP("udp", lAddr)
	if err != nil {
		log.Fatalf("UDP 监听失败: %v", err)
	}

	conn.SetReadBuffer(32 << 20)
	conn.SetWriteBuffer(32 << 20)
	v.ConnUDP = conn
	v.ConnBatch = ipv4.NewPacketConn(conn)

	if v.Cfg.Mode == "client" {
		rAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", v.Cfg.RemoteIP, v.Cfg.RemotePort))
		v.ClientRemoteUDP = rAddr
	}

	go v.udpReaderLoop()
}

func (v *VPNInstance) initRaw() {
	protoStr := fmt.Sprintf("ip4:%d", v.Cfg.IPProtocolNum)
	numConns := 4
	if runtime.NumCPU() < 4 {
		numConns = runtime.NumCPU()
	}

	v.ConnRaw = make([]*net.IPConn, numConns)
	for i := 0; i < numConns; i++ {
		var lAddr *net.IPAddr
		if v.Cfg.Mode == "server" && v.Cfg.ServerBindAddr != "0.0.0.0" {
			lAddr, _ = net.ResolveIPAddr("ip", v.Cfg.ServerBindAddr)
		}
		conn, err := net.ListenIP(protoStr, lAddr)
		if err != nil {
			log.Fatalf("Raw 监听失败: %v", err)
		}
		conn.SetReadBuffer(32 << 20)
		conn.SetWriteBuffer(32 << 20)
		v.ConnRaw[i] = conn
		go v.rawReaderLoop(i)
	}

	if v.Cfg.Mode == "client" {
		v.ClientRemoteIP, _ = net.ResolveIPAddr("ip", v.Cfg.RemoteIP)
	}
}

// --- 读取循环 ---

func (v *VPNInstance) udpReaderLoop() {
	msgs := make([]ipv4.Message, BatchSize)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{make([]byte, BufSize)}
	}

	for {
		n, err := v.ConnBatch.ReadBatch(msgs, 0)
		if err != nil {
			continue
		}

		for i := 0; i < n; i++ {
			msg := &msgs[i]
			if msg.N == 0 {
				continue
			}
			if v.Cfg.Mode == "server" {
				if addr, ok := msg.Addr.(*net.UDPAddr); ok {
					v.ServerPeerAddr.Store(addr)
				}
			}
			v.handleIncomingPacket(msg.Buffers[0][:msg.N])
		}
	}
}

func (v *VPNInstance) rawReaderLoop(idx int) {
	conn := v.ConnRaw[idx]
	buf := make([]byte, BufSize)
	for {
		n, addr, err := conn.ReadFromIP(buf)
		if err != nil {
			continue
		}
		if n < NonceSize+Overhead {
			continue
		}
		if v.Cfg.Mode == "server" {
			v.ServerPeerIP.Store(addr)
		}
		v.handleIncomingPacket(buf[:n])
	}
}

// --- TUN 处理 (多核并行) ---

func (v *VPNInstance) TUNReaderLoop(workerID int) {
	buffs := make([][]byte, BatchSize)
	for i := range buffs {
		buffs[i] = make([]byte, BufSize)
	}
	sizes := make([]int, BatchSize)

	aead := v.aeadPool[workerID]
	sendMsgs := make([]ipv4.Message, 0, BatchSize)
	
	// 用于存放已加密数据的缓冲区指针
	usedPtrs := make([]*[]byte, 0, BatchSize)

	for {
		n, err := v.TunDev.Read(buffs, sizes, TunOffset)
		if err != nil {
			continue
		}

		if v.Cfg.Protocol == "udp" {
			addr := v.ClientRemoteUDP
			if v.Cfg.Mode == "server" {
				addr = v.ServerPeerAddr.Load()
			}
			if addr == nil {
				continue
			}

			sendMsgs = sendMsgs[:0]
			usedPtrs = usedPtrs[:0]

			for i := 0; i < n; i++ {
				if sizes[i] == 0 {
					continue
				}
				
				// 从池中获取缓冲区并加密
				dstPtr := bufPool.Get().(*[]byte)
				data := buffs[i][TunOffset : TunOffset+sizes[i]]
				
				encrypted := v.encryptInto(data, aead, *dstPtr)
				if encrypted != nil {
					sendMsgs = append(sendMsgs, ipv4.Message{
						Buffers: [][]byte{encrypted},
						Addr:    addr,
					})
					usedPtrs = append(usedPtrs, dstPtr)
				} else {
					bufPool.Put(dstPtr)
				}
			}

			if len(sendMsgs) > 0 {
				v.ConnBatch.WriteBatch(sendMsgs, 0)
				// 发送完成后归还缓冲区
				for _, ptr := range usedPtrs {
					bufPool.Put(ptr)
				}
			}
		} else {
			// Raw 模式
			for i := 0; i < n; i++ {
				if sizes[i] == 0 {
					continue
				}
				v.sendRawOptimized(buffs[i][TunOffset:TunOffset+sizes[i]], aead)
			}
		}
	}
}

func (v *VPNInstance) encryptInto(plain []byte, aead cipher.AEAD, dst []byte) []byte {
	outSize := NonceSize + len(plain) + Overhead
	if len(dst) < outSize {
		return nil
	}
	
	nonce := dst[:NonceSize]
	nonceVal := atomic.AddUint64(&v.nonceCounter, 1)
	binary.BigEndian.PutUint64(nonce[0:8], nonceVal)
	binary.BigEndian.PutUint32(nonce[8:12], v.SessionID)
	// 其余填充 0
	for i := 12; i < NonceSize; i++ {
		nonce[i] = 0
	}

	aead.Seal(dst[NonceSize:NonceSize], nonce, plain, nil)
	return dst[:outSize]
}

func (v *VPNInstance) sendRawOptimized(plain []byte, aead cipher.AEAD) {
	dstPtr := bufPool.Get().(*[]byte)
	encrypted := v.encryptInto(plain, aead, *dstPtr)
	
	if encrypted != nil {
		addr := v.ClientRemoteIP
		if v.Cfg.Mode == "server" {
			addr = v.ServerPeerIP.Load()
		}
		if addr != nil {
			idx := atomic.AddUint32(&v.rawSendIdx, 1) % uint32(len(v.ConnRaw))
			v.ConnRaw[idx].WriteToIP(encrypted, addr)
		}
	}
	bufPool.Put(dstPtr)
}

func (v *VPNInstance) handleIncomingPacket(enc []byte) {
	if len(enc) < NonceSize+Overhead {
		return
	}
	nonce := enc[:NonceSize]
	cipherText := enc[NonceSize:]

	plain, err := v.AEAD.Open(cipherText[:0], nonce, cipherText, nil)
	if err == nil && len(plain) > 0 {
		v.writeTUN(plain)
	}
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
	flag.Parse()

	data, err := os.ReadFile(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}

	var configs []Config
	if err := json.Unmarshal(data, &configs); err != nil {
		var single Config
		if err2 := json.Unmarshal(data, &single); err2 == nil {
			configs = append(configs, single)
		} else {
			log.Fatal(err)
		}
	}

	for _, cfg := range configs {
		NewVPNInstance(cfg).Start()
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c
	log.Println("Bye~")
}

func runCmd(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Printf("[Warn] Cmd fail: %s %v -> %v", name, args, err)
	}
}

func runCmdQuiet(name string, args ...string) {
	exec.Command(name, args...).Run()
}
