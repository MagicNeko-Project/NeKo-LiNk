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
	"io"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"net/netip"
	"crypto/rand"

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

	// --- Optimized Naming ---
	ListenAddr string `json:"listen_addr,omitempty"`
	ListenPort int    `json:"listen_port,omitempty"`
	PeerAddr   string `json:"peer_addr,omitempty"`
	PeerPort   int    `json:"peer_port,omitempty"`

	// --- Internal WG Control ---
	WGPort int `json:"wg_port,omitempty"`

	// --- Transport Options ---
	IPProtocolNum int  `json:"ip_protocol_num,omitempty"`
	UseNATT       bool `json:"use_nat_t,omitempty"`
	UseTCP        bool `json:"use_tcp,omitempty"`
	UseEBPF       bool `json:"use_ebpf,omitempty"`
	EBPFDevice    string `json:"ebpf_device,omitempty"`
	UDPPort       int  `json:"udp_port,omitempty"`
	Debug         bool `json:"debug,omitempty"`

	// --- Legacy Fields (Hidden but mapped) ---
	LegacyServerAddr string `json:"server_addr,omitempty"`
	LegacyBasePort   int    `json:"base_port,omitempty"`
	LegacyServerIP   string `json:"server_ip,omitempty"`
	LegacyServerPort int    `json:"server_port,omitempty"`
}

func (c *Config) ParseLegacy() (changed bool) {
	// 1. 命名字段搬迁 (旧 -> 新)
	if c.ListenAddr == "" && c.LegacyServerAddr != "" {
		c.ListenAddr = c.LegacyServerAddr
		changed = true
	}
	c.LegacyServerAddr = "" // Clear always to clean up JSON

	if c.ListenPort == 0 && c.LegacyBasePort != 0 {
		c.ListenPort = c.LegacyBasePort
		changed = true
	}
	c.LegacyBasePort = 0 // Clear always

	if c.PeerAddr == "" && c.LegacyServerIP != "" {
		c.PeerAddr = c.LegacyServerIP
		changed = true
	}
	c.LegacyServerIP = "" // Clear always

	if c.PeerPort == 0 && c.LegacyServerPort != 0 {
		c.PeerPort = c.LegacyServerPort
		changed = true
	}
	c.LegacyServerPort = 0 // Clear always

	// 2. 基本字段兼容 (兼容之前的老代码可能还在直接用 RemoteIP 等逻辑)
	// (如果有其它代码引用了旧字段，可以在这里同步，但建议全部改为引用新字段)
	
	// 2. 协议迁移 (UDP/TCP/QUIC -> wg-raw)
	// 注意：这里移除了 "raw"，因为主人希望保留原有的 legacy raw 模式。
	oldProto := strings.ToLower(c.Protocol)
	if oldProto == "udp" || oldProto == "tcp" || oldProto == "quic" || oldProto == "" {
		if oldProto == "tcp" {
			c.UseTCP = true
			c.IPProtocolNum = 6
		}
		c.Protocol = "wg-raw"
		log.Printf("[%s] 自动将旧版协议 %s 升级为 wg-raw (Fake TCP: %v, eBPF: %v)", c.InterfaceName, oldProto, c.UseTCP, c.UseEBPF)
		changed = true
	}

	// 2.1 EBPF 设备冲突解决
	// 如果开启了 EBPF 但还没指定 EBPFDevice，且 InterfaceName 看起来像个物理网卡名
	if c.UseEBPF && c.EBPFDevice == "" {
		isPhysical := strings.HasPrefix(c.InterfaceName, "eth") || 
					  strings.HasPrefix(c.InterfaceName, "en") || 
					  strings.HasPrefix(c.InterfaceName, "wl")
		
		if isPhysical {
			c.EBPFDevice = c.InterfaceName
			c.InterfaceName = "neko0" // 虚拟网卡换个名字
			log.Printf("[EBPF] 检测到接口冲突，已自动调整：物理网卡=%s, 虚拟网卡=%s", c.EBPFDevice, c.InterfaceName)
			changed = true
		}
	}
	
	// 3. 默认值设置
	if c.IPProtocolNum == 0 {
		c.IPProtocolNum = 233
		changed = true
	}
	
	// 4. MTU 优化 (避免分片)
	if c.MTU == 0 || c.MTU > 1420 {
		oldMTU := c.MTU
		c.MTU = 1400
		if oldMTU != 0 {
			log.Printf("[%s] 优化 MTU: %d -> 1400", c.InterfaceName, oldMTU)
			changed = true
		}
		if oldMTU == 0 {
			changed = true
		}
	}
	
	if c.ListenPort == 0 && c.UDPPort != 0 {
		c.ListenPort = c.UDPPort
		changed = true
	}
	c.UDPPort = 0 // Clear always
	if c.ListenPort == 0 {
		c.ListenPort = 23333
		changed = true
	}
	if c.WGPort == 0 {
		c.WGPort = 51820 // Default internal WG port
		changed = true
	}
	if c.InterfaceName == "" {
		c.InterfaceName = "neko0"
		changed = true
	}
	if c.UseEBPF && c.EBPFDevice == "" {
		c.EBPFDevice = "eth0" // 默认物理网卡
		changed = true
	}
	return
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
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

	// --- QUIC 模式 (v6.0) --- (REMOVED)
	// quicListener *quic.Listener   // Server Mode
	// quicConn     *quic.Conn       // Client Mode
	// activeStream *quic.Stream     // 当前活跃的加密 Stream
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
	
	// WG Device Ref
	wgDevice *device.Device
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
	// 初始化 AEAD (XChaCha20-Poly1305)
	// 无论是 Raw 还是 wg-raw (握手用)，我们都使用这套加密
	keyHash := sha256.Sum256([]byte(cfg.Key))
	v.aeadPool = make([]cipher.AEAD, 16)
	for i := 0; i < 16; i++ {
		v.aeadPool[i], _ = chacha20poly1305.NewX(keyHash[:])
	}
	v.AEAD = v.aeadPool[0]
	v.SessionID = uint32(os.Getpid()) ^ uint32(keyHash[0])<<24

	return v
}


// --- WireGuard Auto-Config Logic ---

func generateWGKey() ([]byte, []byte) {
	var priv [32]byte
	rand.Read(priv[:])
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)
	return priv[:], pub[:]
}

func (v *VPNInstance) startWireGuardRaw() {
	// 1. Create Bind
	bind := NewRawBind(v.Cfg.IPProtocolNum, v.Cfg.UseNATT, v.Cfg.UseTCP, v.Cfg.UseEBPF, v.Cfg.EBPFDevice, v.Cfg.ListenPort, v.Cfg.PeerPort)
	
	// 2. Client Mode: Set Remote
	if v.Cfg.Mode == "client" {
		addr, _ := netip.ParseAddr(v.Cfg.PeerAddr)
		bind.SetClientRemote(addr)
	}
	
	// 3. Create Ephemeral Keys
	priv, pub := generateWGKey()
	
	// 4. Create Device
	logLevel := device.LogLevelSilent
	if v.Cfg.Debug {
		logLevel = device.LogLevelVerbose
	}
	logger := device.NewLogger(logLevel, fmt.Sprintf("(%s) ", v.Cfg.InterfaceName))
	
	dev := device.NewDevice(v.TunDev, bind, logger)
	v.wgDevice = dev

	// 5. Register Handshake Handler
	// Packet: [0xFE] [Nonce(24)] [Cipher(Ver(1)+PubKey(32))]
	bind.SetHandshakeCallback(func(pkt []byte, remote netip.AddrPort) bool {
		// Safety check for initialized device
		if v.wgDevice == nil { return false }

		// Decrypt
		if len(pkt) < 1+NonceSize+Overhead+33 { return false }
		nonce := pkt[1 : 1+NonceSize]
		cipherText := pkt[1+NonceSize:]
		
		plain, err := v.AEAD.Open(nil, nonce, cipherText, nil)
		if err != nil {
			log.Printf("[Handshake] Decrypt failed from %s", remote)
			return false
		}
		
		if len(plain) != 33 || plain[0] != 1 { return false }
		remotePub := plain[1:]
		
		log.Printf("[Handshake] Received PubKey from %s", remote)
		
		// Configure Peer via UAPI
		// We use 127.0.0.1:0 as endpoint to utilize our Shadow Endpoint logic
		conf := fmt.Sprintf("public_key=%x\nendpoint=127.0.0.1:0\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=25\n", remotePub)
		if err := v.wgDevice.IpcSet(conf); err != nil {
			log.Printf("Failed to configure peer: %v", err)
		}
		
		// If Server, reply with our PubKey
		if v.Cfg.Mode == "server" {
			v.sendHandshake(bind, remote, pub)
		}
		
		return true
	})
	
	// 6. Init Device Config
	initConf := fmt.Sprintf("private_key=%x\nlisten_port=%d\nreplace_peers=true\n", priv, v.Cfg.WGPort)
	dev.IpcSet(initConf)
	dev.Up()
	log.Printf("[WG-RAW] Device %s up using IP Protocol %d", v.Cfg.InterfaceName, v.Cfg.IPProtocolNum)
	
	// 7. Start UAPI Listener
	go v.startUAPI()
	
	// 8. Client: Initiate Handshake
	if v.Cfg.Mode == "client" {
		addr, _ := netip.ParseAddr(v.Cfg.PeerAddr)
		addrPort := netip.AddrPortFrom(addr, uint16(v.Cfg.PeerPort))
		go func() {
			for {
				v.sendHandshake(bind, addrPort, pub)
				time.Sleep(5 * time.Second) // Retry every 5s until connected (WG usually quiets down)
			}
		}()
	}
	
	// Keep alive
	select {}
}

func (v *VPNInstance) sendHandshake(bind *RawBind, remote netip.AddrPort, myPub []byte) {
	// Construct [0xFE] [Nonce] [Cipher]
	pkt := make([]byte, 1+NonceSize+33+Overhead)
	pkt[0] = 0xFE
	
	// Nonce
	nonce := pkt[1 : 1+NonceSize]
	if _, err := rand.Read(nonce); err != nil { return }
	
	// Payload: [Ver(Verification Code/Ver)(1)][PubKey] 
	plain := make([]byte, 33)
	plain[0] = 1
	copy(plain[1:], myPub)
	
	// Encrypt
	v.AEAD.Seal(pkt[1+NonceSize:1+NonceSize], nonce, plain, nil) // dst is slice at end of nonce
	
	bind.SendRaw(pkt, remote)
	log.Printf("[Handshake] Sent to %s", remote)
}

func (v *VPNInstance) startUAPI() {
	fileUAPI, err := ipc.UAPIOpen(v.Cfg.InterfaceName)
	if err != nil {
		log.Printf("[WG-RAW] UAPI Listen failed: %v", err)
		return
	}
	listener, err := net.FileListener(fileUAPI)
	if err != nil { return }
	fileUAPI.Close()
	
	for {
		conn, err := listener.Accept()
		if err != nil { continue }
		go v.wgDevice.IpcHandle(conn)
	}
}

func (v *VPNInstance) Start() {
	if v.Cfg.Debug {
		debugMode = true
	}

	log.Printf("[%s] NekoLink (WireGuard Edition) 启动中 - 核心: %d, MTU: %d",
		v.Cfg.InterfaceName, v.numWorkers, v.Cfg.MTU)

	v.InitTUN()
	v.InitNetwork()
	
	if v.Cfg.Protocol == "wg-raw" {
		log.Printf("[Init] 启动 wg-raw 模式 (Embedded WireGuard over Raw Socket)")
		go v.startWireGuardRaw()
	} else {
		// Legacy Raw 模式 (保留)
		log.Printf("[Init] 启动 Raw 模式 (High Performance Encrypted IP)")
		for i := 0; i < v.numWorkers; i++ {
			go v.TUNReaderLoopRaw(i)
		}
		// 所有的 reader goroutine 现在共享同一个底层连接，以避免 DUP
		for i := 0; i < v.numWorkers; i++ {
			go v.rawReaderLoop(0)
		}
	}
}

// --- Producer: UDP (Net) -> Pipeline ---


// --- QUIC Client Logic ---
// --- QUIC Client Logic Removed ---



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

	if v.Cfg.Protocol == "raw" || v.Cfg.Protocol == "wg-raw" {
		if v.Cfg.Protocol == "wg-raw" && v.Cfg.UseNATT {
			runCmd("nft", "add", "rule", "inet", tableName, "input", "udp", "dport", fmt.Sprintf("%d", v.Cfg.ListenPort), "accept")
		} else {
			protoNum := v.Cfg.IPProtocolNum
			runCmd("nft", "add", "rule", "inet", tableName, "input", "meta", "l4proto", fmt.Sprintf("%d", protoNum), "accept")
		}
	} else {
		port := v.Cfg.ListenPort
		runCmd("nft", "add", "rule", "inet", tableName, "input", "udp", "dport", fmt.Sprintf("%d", port), "accept")
	}

	runCmd("nft", "add", "rule", "inet", tableName, "input", "ct", "state", "invalid", "drop")
}

// --- 网络初始化 ---

func (v *VPNInstance) InitNetwork() {
	if v.Cfg.Protocol == "wg-raw" {
		// wg-raw 模式不需要在此初始化 ConnRaw，由 WireGuard Device 自己管理 RawBind
	} else {
		// Assume Raw
		v.initRaw()
	}
}

// --- 遗留 Raw 逻辑 ---
// v6.0: Raw 模式完整保留 (Expert Mode)

func (v *VPNInstance) initRaw() {
	numConns := 1 // 核心：只打开一个 Raw 句柄以避免 DUP

	// 检测 IP 类型
	testIP := v.Cfg.PeerAddr
	if v.Cfg.Mode == "server" {
		testIP = v.Cfg.ListenAddr
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
		if v.Cfg.Mode == "server" && v.Cfg.ListenAddr != "0.0.0.0" && v.Cfg.ListenAddr != "[::]" {
			lAddr, _ = net.ResolveIPAddr("ip", v.Cfg.ListenAddr)
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
		v.ClientRemoteIP, _ = net.ResolveIPAddr("ip", v.Cfg.PeerAddr)
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
	migrate := flag.Bool("migrate", false, "Migrate legacy config to new format and exit")
	flag.Parse()
	debugMode = *debug

	data, err := os.ReadFile(*cfgPath)
	if err != nil {
		log.Fatalf("无法读取配置文件: %v", err)
	}

	var configs []Config
	var isArray bool
	if err := json.Unmarshal(data, &configs); err != nil {
		var single Config
		if err2 := json.Unmarshal(data, &single); err2 == nil {
			configs = append(configs, single)
			isArray = false
		} else {
			log.Fatalf("配置文件格式错误: %v", err)
		}
	} else {
		isArray = true
	}

	for i := range configs {
		configs[i].ParseLegacy()
	}

	if *migrate {
		log.Printf(">>> 正在优化并清理配置文件布局...")
		var outData []byte
		if isArray {
			outData, _ = json.MarshalIndent(configs, "", "  ")
		} else {
			outData, _ = json.MarshalIndent(configs[0], "", "  ")
		}
		if err := os.WriteFile(*cfgPath, outData, 0644); err != nil {
			log.Printf("保存失败: %v", err)
		} else {
			log.Printf("✅ 配置文件已精简并保存！")
		}
		os.Exit(0)
	}

	for _, cfg := range configs {
		NewVPNInstance(cfg).Start()
	}
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
