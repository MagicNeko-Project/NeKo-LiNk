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
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"github.com/cilium/ebpf/rlimit"
	"net/netip"
	"crypto/rand"

	"vpn/xdp"
)

// --- 全局分发 ---
var debugMode bool

func logDebug(format string, v ...interface{}) {
	if debugMode {
		log.Printf("[DEBUG] "+format, v...)
	}
}

// --- 配置结构 ---

type Config struct {
	InterfaceName string `json:"interface_name"`
	Mode          string `json:"mode"`
	LocalAddr     string `json:"local_addr"` // Legacy (Keep for compatibility)
	LocalAddrV4   string `json:"local_addr_v4,omitempty"`
	LocalAddrV6   string `json:"local_addr_v6,omitempty"`
	Key           string `json:"key"` // Shared Secret (Password)
	Protocol      string `json:"protocol"`
	MTU           int    `json:"mtu"`

	// --- Optimized Naming ---
	ListenAddr string `json:"listen_addr,omitempty"`
	PeerAddr   string `json:"peer_addr,omitempty"`

	// --- Transport Options ---
	IPProtocolNum int  `json:"ip_protocol_num,omitempty"`
	Debug         bool `json:"debug,omitempty"`
	Comment       string `json:"comment,omitempty"`

	// --- Custom Interface Names ---
	AppInterface  string `json:"app_interface,omitempty"` // For raw mode veth peer

	// --- Legacy Fields (Hidden but mapped) ---
	LegacyServerAddr string `json:"server_addr,omitempty"`
	LegacyServerIP   string `json:"server_ip,omitempty"`
}

func (c *Config) ParseLegacy() (changed bool) {
	// 1. Force Raw Protocol
	if c.Protocol != "raw" {
		c.Protocol = "raw"
		changed = true
	}
	if c.IPProtocolNum != 233 {
		c.IPProtocolNum = 233
		changed = true
	}

	// 2. 命名字段搬迁 (旧 -> 新)
	if c.ListenAddr == "" && c.LegacyServerAddr != "" {
		c.ListenAddr = c.LegacyServerAddr
		changed = true
	}
	c.LegacyServerAddr = ""

	// 3. IP Version Split
	if c.LocalAddr != "" {
		if c.LocalAddrV4 == "" && !strings.Contains(c.LocalAddr, ":") {
			c.LocalAddrV4 = c.LocalAddr
		} else if c.LocalAddrV6 == "" && strings.Contains(c.LocalAddr, ":") {
			c.LocalAddrV6 = c.LocalAddr
		}
	}
	if c.LocalAddr == "" {
		if c.LocalAddrV4 != "" {
			c.LocalAddr = c.LocalAddrV4
		} else if c.LocalAddrV6 != "" {
			c.LocalAddr = c.LocalAddrV6
		}
	}

	if c.PeerAddr == "" && c.LegacyServerIP != "" {
		c.PeerAddr = c.LegacyServerIP
		changed = true
	}
	c.LegacyServerIP = ""

	// 4. MTU 优化
	if c.MTU == 0 || c.MTU > 1400 {
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

	// Client Mode: 修正 ListenAddr 误用
	if c.Mode == "client" && c.PeerAddr == "" && c.ListenAddr != "" {
		c.PeerAddr = c.ListenAddr
		c.ListenAddr = "" // Client bind default
		log.Printf("[%s] 修正配置: 将 ListenAddr 移动至 PeerAddr (Client 模式)", c.InterfaceName)
		changed = true
	}

	if c.InterfaceName == "" {
		c.InterfaceName = "neko0"
		changed = true
	}

	if c.AppInterface == "" {
		prefix := c.InterfaceName
		if len(prefix) > 11 {
			prefix = prefix[:11]
		}
		c.AppInterface = prefix + "_app"
		log.Printf("[%s] 自动分配 AppInterface: %s", c.InterfaceName, c.AppInterface)
		changed = true
	}

	// Truncate names
	if len(c.InterfaceName) > 15 {
		c.InterfaceName = c.InterfaceName[:15]
		changed = true
	}
	if len(c.AppInterface) > 15 {
		c.AppInterface = c.AppInterface[:15]
		changed = true
	}

	return
}

// --- 常量 ---

const (
	NonceSize = chacha20poly1305.NonceSizeX
	Overhead  = chacha20poly1305.Overhead
	BufSize   = 65536
)

// --- 内存池 ---

var bufPool = sync.Pool{
	New: func() interface{} {
		// 4096 is enough for any Jumbo Frame or Tunnel Overhead
		b := make([]byte, 4096)
		return &b
	},
}

type txPacket struct {
	bufPtr *[]byte
	n      int
}

// --- VPN 实例 ---

type VPNInstance struct {
	Cfg Config

	// --- Raw 模式 ---
	ConnRaw        []*net.IPConn
	ClientRemoteIP *net.IPAddr
	ServerPeerIP   atomic.Pointer[net.IPAddr]
	rawSendIdx     uint32
	// AEAD
	AEAD           cipher.AEAD
	aeadPool       []cipher.AEAD

	// Reordering Pipeline
	reorderChan chan *DecryptedPacket
	rxDispatchChan chan rxPacket

	// 通用统计
	SessionID    uint32
	nonceCounter uint64
	numWorkers   int
	IsIPv6       bool
	
	// XDP Socket
	Xsk *xdp.Socket
	
	// Handshake State (for Raw Mode Roaming/Keepalive)
	remoteAddr   netip.AddrPort
	remoteAddrMx sync.RWMutex
}

type rxPacket struct {
	bufPtr *[]byte
	n      int
	addr   *net.IPAddr
}

type DecryptedPacket struct {
	Seq       uint64
	SessionID uint32
	Data      []byte
	BufReq    *[]byte
}

func NewVPNInstance(cfg Config) *VPNInstance {
	cfg.ParseLegacy()
	v := &VPNInstance{Cfg: cfg}

	// 初始化并发数
	v.numWorkers = runtime.NumCPU()
	if v.numWorkers > 8 {
		v.numWorkers = 8
	}

	// 初始化 AEAD (XChaCha20-Poly1305)
	keyHash := sha256.Sum256([]byte(cfg.Key))
	v.aeadPool = make([]cipher.AEAD, 16)
	for i := 0; i < 16; i++ {
		v.aeadPool[i], _ = chacha20poly1305.NewX(keyHash[:])
	}
	v.AEAD = v.aeadPool[0]
	v.SessionID = uint32(os.Getpid()) ^ uint32(keyHash[0])<<24
	
	// High throughput reorder buffer
	v.reorderChan = make(chan *DecryptedPacket, 8192)
	v.rxDispatchChan = make(chan rxPacket, 8192)

	return v
}

func (v *VPNInstance) handshakeLoop() {
	// Periodically send 0xFE to Remote to keep session alive
	
	// Prepare Local Keys (Use Key for identity too in this simplified version, or just send dummy)
	// In legacy raw mode, we just need to keep NAT open or update IP.
	// We send [0xFE] [Nonce] [Cipher(Magic)]
	
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	magic := []byte("NEKO_HEARTBEAT")

	for {
		select {
		case <-ticker.C:
			// Send Handshake Packet if we have a target
			var target *net.IPAddr
			if v.Cfg.Mode == "client" {
				target = v.ClientRemoteIP
			} else {
				target = v.ServerPeerIP.Load()
			}

			if target != nil {
				v.sendHandshakePacket(target, magic)
			}
		}
	}
}

// Callback for when we receive a valid 0xFE Handshake
func (v *VPNInstance) onHandshakeReceived(data []byte, remote netip.AddrPort) bool {
	// [0xFE] [Nonce] [Cipher]
	if len(data) < 1+NonceSize+Overhead+1 { return false }
	
	nonce := data[1:1+NonceSize]
	cipherText := data[1+NonceSize:]
	
	// Decrypt with Shared Password
	plain, err := v.AEAD.Open(nil, nonce, cipherText, nil)
	if err != nil {
		logDebug("[Handshake] Decrypt failed from %s", remote)
		return false
	}
	
	// Validate Magic
	if string(plain) != "NEKO_HEARTBEAT" { return false }
	
	// Update Peer IP
	v.remoteAddrMx.Lock()
	if v.remoteAddr != remote {
		v.remoteAddr = remote
		// log.Printf("[Handshake] Peer updated to %s", remote)
	}
	v.remoteAddrMx.Unlock()

	// Update ServerPeerIP for Raw Mode
	ipAddr, _ := net.ResolveIPAddr("ip", remote.Addr().String())
	v.ServerPeerIP.Store(ipAddr)
	
	return true
}

func (v *VPNInstance) sendHandshakePacket(remote *net.IPAddr, payload []byte) {
	// Construct [0xFE] [Nonce] [Cipher]
	pkt := make([]byte, 1+NonceSize+len(payload)+Overhead)
	pkt[0] = 0xFE
	
	// Nonce
	nonce := pkt[1 : 1+NonceSize]
	if _, err := rand.Read(nonce); err != nil { return }
	
	// Encrypt
	v.AEAD.Seal(pkt[1+NonceSize:1+NonceSize], nonce, payload, nil)
	
	if len(v.ConnRaw) > 0 {
		v.ConnRaw[0].WriteToIP(pkt, remote)
	}
}

func (v *VPNInstance) Start() {
	if v.Cfg.Debug {
		debugMode = true
	}

	log.Printf("[%s] NekoLink (Raw Tunnel Edition) 启动中 - 核心: %d, MTU: %d",
		v.Cfg.InterfaceName, v.numWorkers, v.Cfg.MTU)

	v.InitInterface()
	v.InitNetwork()
	
	log.Printf("[Init] 启动 Raw Mode (Veth + AF_XDP)")

	// Initialize AF_XDP
	appIf := v.Cfg.AppInterface

	xsk, err := xdp.NewSocket(xdp.Config{
		Interface: appIf,
		QueueID:   0,
		RingSize:  2048,
	})
	if err != nil {
		log.Fatalf("AF_XDP 初始化失败: %v", err)
	}
	v.Xsk = xsk

	// Update BPF Map (Self-Registration)
	if err := v.Xsk.AddToMap(v.Xsk.XsksMap); err != nil {
		log.Printf("Warning: Map Update Failed: %v", err)
	}

	// 启动写入循环 (AF_XDP -> Encrypt -> IPConn)
	log.Printf("[RAW] 启用高性能并行 TX 流水线: 1 Producer -> %d Encryption Workers", v.numWorkers)
	go v.XDPReaderLoop(0)

	// 启动 RX Workers
	log.Printf("[RAW] 启用高性能并行 RX 流水线: %d Decryption Workers", v.numWorkers)
	for i := 0; i < v.numWorkers; i++ {
		go v.rxWorkerLoop(i)
	}

	// 启动重排序写入器 (Consumer) (Decrypt -> Reorder -> AF_XDP)
	go v.packetOrderedWriter()

	// 启动单路读取器 (IPConn -> Decrypt -> Reorder)
	log.Printf("[RAW] 启用单路 RX 读取模式 (Sequential Reading Active)")
	go v.rawReaderLoop(0)

	// 启动心跳机制
	go v.handshakeLoop()
}

func (v *VPNInstance) Cleanup() {
	log.Printf("[%s] 正在清理网络资源...", v.Cfg.InterfaceName)
	// Raw Mode (Veth): Deleting host side automatically removes peer side
	if v.Cfg.InterfaceName != "" {
		runCmdQuiet("ip", "link", "del", v.Cfg.InterfaceName)
	}
}

// --- TUN 初始化 ---

func (v *VPNInstance) InitInterface() {
	// Raw Mode: Veth
	hostIf := v.Cfg.InterfaceName
	appIf := v.Cfg.AppInterface
	
	// Cleanup
	runCmdQuiet("ip", "link", "del", hostIf)
	
	// Create Veth pair
	log.Printf("[%s] 创建 Veth Pair: %s <-> %s", hostIf, hostIf, appIf)
	if err := runCmd("ip", "link", "add", hostIf, "type", "veth", "peer", "name", appIf); err != nil {
		log.Fatalf("Veth 创建失败: %v", err)
	}

	// Configure Host Side
	runCmd("ip", "addr", "add", v.Cfg.LocalAddr, "dev", hostIf)
	runCmd("ip", "link", "set", hostIf, "mtu", fmt.Sprintf("%d", v.Cfg.MTU))
	// Enable ARP for L2 tunneling
	runCmd("ip", "link", "set", hostIf, "arp", "on")
	
	// Disable Checksum Offloading
	runCmd("ethtool", "-K", hostIf, "tx", "off", "rx", "off", "tso", "off", "gso", "off", "ufo", "off")
	
	runCmd("ip", "link", "set", hostIf, "up")
	
	// Configure App Side (AF_XDP Target)
	runCmd("ip", "link", "set", appIf, "arp", "on")
	runCmd("ip", "link", "set", appIf, "promisc", "on")
	runCmd("ethtool", "-K", appIf, "tx", "off", "rx", "off", "tso", "off", "gso", "off", "ufo", "off")
	runCmd("ip", "link", "set", appIf, "mtu", fmt.Sprintf("%d", v.Cfg.MTU))
	runCmd("ip", "link", "set", appIf, "up")
	runCmdQuiet("sysctl", "-w", fmt.Sprintf("net.ipv6.conf.%s.disable_ipv6=1", appIf))

	// IPv4 转发优化
	runCmdQuiet("sysctl", "-w", "net.ipv4.conf.all.rp_filter=0")
	runCmdQuiet("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", hostIf))
	
	// IPv6 基础支持
	runCmdQuiet("sysctl", "-w", "net.ipv6.conf.all.forwarding=1")

	v.setupNFTables(hostIf)
}

func (v *VPNInstance) setupNFTables(iface string) {
	runCmd("nft", "add", "table", "inet", "nekolink")

	chainMSS := fmt.Sprintf("mss_%s", iface)
	runCmdQuiet("nft", "delete", "chain", "inet", "nekolink", chainMSS)
	runCmd("nft", "add", "chain", "inet", "nekolink", chainMSS,
		"{ type filter hook forward priority mangle; policy accept; }")
	runCmd("nft", "flush", "chain", "inet", "nekolink", chainMSS)

	// MSS Clamping
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

	// Allow Raw Protocol (233)
	protoNum := v.Cfg.IPProtocolNum
	runCmd("nft", "add", "rule", "inet", tableName, "input", "meta", "l4proto", fmt.Sprintf("%d", protoNum), "accept")

	// Explicitly allow ARP? No, inet table doesn't see ARP. But to be safe against side effects.
	// Actually, let's NOT touch ARP in inet table.
	// If rp_filter is 0, ARP should flow.

	runCmd("nft", "add", "rule", "inet", tableName, "input", "ct", "state", "invalid", "drop")
}

// --- 网络初始化 ---

func (v *VPNInstance) InitNetwork() {
	v.initRaw()
}

func (v *VPNInstance) initRaw() {
	numConns := 1

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
	bufPtr := bufPool.Get().(*[]byte)
	
	for {
		buf := *bufPtr
		n, addr, err := conn.ReadFromIP(buf)
		if err != nil || n < NonceSize+Overhead { 
			continue
		}

		if v.Cfg.Mode == "server" { v.ServerPeerIP.Store(addr) }
		
		// 0. Check for Handshake (0xFE)
		if buf[0] == 0xFE {
			aPort := netip.AddrPortFrom(netip.AddrFrom4([4]byte{addr.IP[0], addr.IP[1], addr.IP[2], addr.IP[3]}), 0)
			v.onHandshakeReceived(buf[:n], aPort)
			continue
		}

		// Dispatch to RX Workers
		select {
		case v.rxDispatchChan <- rxPacket{bufPtr: bufPtr, n: n, addr: addr}:
			bufPtr = bufPool.Get().(*[]byte)
		default:
		}
	}
}

func (v *VPNInstance) XDPReaderLoop(idx int) {
	txChan := make(chan txPacket, 8192)

	for i := 0; i < v.numWorkers; i++ {
		go func(wIdx int) {
			aead := v.aeadPool[wIdx%len(v.aeadPool)]
			nonce := make([]byte, NonceSize)
			clientRemote := v.ClientRemoteIP

			for txPkt := range txChan {
				pkt := (*txPkt.bufPtr)[:txPkt.n]
				
				var target *net.IPAddr
				if v.Cfg.Mode == "client" {
					target = clientRemote
				} else {
					target = v.ServerPeerIP.Load()
				}
				
				if target != nil && len(v.ConnRaw) > 0 {
					vVal := atomic.AddUint64(&v.nonceCounter, 1)
					binary.BigEndian.PutUint64(nonce[0:8], vVal)
					binary.BigEndian.PutUint32(nonce[8:12], v.SessionID)

					cipherText := aead.Seal(nil, nonce, pkt, nil)
					finalPayload := append(nonce, cipherText...)

					v.ConnRaw[0].WriteToIP(finalPayload, target)
				}
				
				bufPool.Put(txPkt.bufPtr)
			}
		}(i)
	}
	
	for {
		pkts, err := v.Xsk.Receive()
		if err != nil || len(pkts) == 0 {
			v.Xsk.Poll(2)
			continue
		}
		
		for _, pkt := range pkts {
			if len(pkt) < 14 { continue }
			
			bufPtr := bufPool.Get().(*[]byte)
			if cap(*bufPtr) < len(pkt) {
				bufPool.Put(bufPtr)
				newBuf := make([]byte, len(pkt))
				bufPtr = &newBuf
			}
			copy(*bufPtr, pkt)
			
			select {
			case txChan <- txPacket{bufPtr: bufPtr, n: len(pkt)}:
			default:
				bufPool.Put(bufPtr)
			}
		}
	}
}

func (v *VPNInstance) rxWorkerLoop(wIdx int) {
	aead := v.aeadPool[wIdx%len(v.aeadPool)]

	for pkt := range v.rxDispatchChan {
		buf := (*pkt.bufPtr)[:pkt.n]

		// Handshake already handled by Dispatcher
		if len(buf) < NonceSize+Overhead {
			bufPool.Put(pkt.bufPtr)
			continue
		}

		// 1. Extract Sequence and SessionID
		seq := binary.BigEndian.Uint64(buf[0:8])
		sess := binary.BigEndian.Uint32(buf[8:12])

		// 2. Decrypt
		nonce := buf[:NonceSize]
		cipherText := buf[NonceSize:]

		plain, err := aead.Open(buf[NonceSize:NonceSize], nonce, cipherText, nil)

		if err == nil {
			v.reorderChan <- &DecryptedPacket{
				Seq:       seq,
				SessionID: sess,
				Data:      plain,
				BufReq:    pkt.bufPtr,
			}
		} else {
			bufPool.Put(pkt.bufPtr)
		}
	}
}

func (v *VPNInstance) packetOrderedWriter() {
	var nextSeq uint64 = 0
	var currentSessionID uint32 = 0
	buffer := make(map[uint64]*DecryptedPacket)
	
	firstPacket := true

	const ReorderTimeout = 5 * time.Millisecond
	const HeadOfLineLimit = 50

	timer := time.NewTimer(ReorderTimeout)
	defer timer.Stop()

	for {
		select {
		case pkt, ok := <-v.reorderChan:
			if !ok { return }
			
			if pkt.SessionID != currentSessionID {
				if !firstPacket {
					log.Printf("[Reorderer] Session Change Detected: %x -> %x. Resetting Sequence.", currentSessionID, pkt.SessionID)
				}
				currentSessionID = pkt.SessionID
				for k, p := range buffer {
					bufPool.Put(p.BufReq)
					delete(buffer, k)
				}
				nextSeq = pkt.Seq
				firstPacket = false
			}

			if firstPacket {
				nextSeq = pkt.Seq
				firstPacket = false
				currentSessionID = pkt.SessionID
				log.Printf("[Reorderer] Init Sequence: %d (Session %x)", nextSeq, currentSessionID)
			}

			if pkt.Seq < nextSeq {
				bufPool.Put(pkt.BufReq)
				continue
			}
			
			buffer[pkt.Seq] = pkt
			
			if _, ok := buffer[nextSeq+HeadOfLineLimit]; ok {
				nextSeq++
			}

			moved := false
			for {
				p, ok := buffer[nextSeq]
				if !ok { break }
				delete(buffer, nextSeq)
				v.writeTUN(p.Data)
				bufPool.Put(p.BufReq)
				nextSeq++
				moved = true
			}

			if moved {
				if !timer.Stop() { select { case <-timer.C: default: } }
				timer.Reset(ReorderTimeout)
			}

		case <-timer.C:
			if len(buffer) > 0 {
				var minSeq uint64 = 0xFFFFFFFFFFFFFFFF
				for s := range buffer {
					if s < minSeq { minSeq = s }
				}
				if minSeq != 0xFFFFFFFFFFFFFFFF && minSeq > nextSeq {
					nextSeq = minSeq
					for {
						p, ok := buffer[nextSeq]
						if !ok { break }
						delete(buffer, nextSeq)
						v.writeTUN(p.Data)
						bufPool.Put(p.BufReq)
						nextSeq++
					}
				}
			}
			timer.Reset(ReorderTimeout)
		}

		if len(buffer) > 2048 {
			var minSeq uint64 = 0xFFFFFFFFFFFFFFFF
			for s := range buffer {
				if s < minSeq { minSeq = s }
			}
			if minSeq != 0xFFFFFFFFFFFFFFFF {
				nextSeq = minSeq
			}
		}
	}
}

func (v *VPNInstance) writeTUN(data []byte) {
	if v.Xsk != nil {
		v.Xsk.Transmit(data)
	}
}

func genExampleConfig(mode string) {
	baseConfig := Config{
		InterfaceName: "neko0",
		MTU:           1400,
		Debug:         true,
		Key:           "CHANGE_ME_PLEASE_NYA_QAQ",
		Protocol:      "raw",
		IPProtocolNum: 233,
	}

	if mode == "client" {
		baseConfig.Mode = "client"
		baseConfig.LocalAddrV4 = "192.168.100.2/24"
		baseConfig.PeerAddr = "SERVER_IP"
	} else {
		baseConfig.Mode = "server"
		baseConfig.LocalAddrV4 = "192.168.100.1/24"
		baseConfig.PeerAddr = "CLIENT_IP"
	}

	data, _ := json.MarshalIndent(baseConfig, "  ", "  ")
	jsonStr := string(data)
	
    start := strings.Index(jsonStr, "{")
    end := strings.LastIndex(jsonStr, "}")
    if start != -1 && end != -1 {
        jsonStr = jsonStr[start+1 : end]
    }

	content := fmt.Sprintf(`[
  {
    "_comment": "NekoLink Raw Tunnel Config (%s) 🐾",
    "_note": "Please set key and peer_addr.",
%s
  }
]`, mode, jsonStr)

	targetDir := "/etc/neko-link"
	targetFile := targetDir + "/config.json"

	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			targetFile = "config.json"
			fmt.Printf(">>> Cannot create %s (%v), using local.\n", targetDir, err)
		}
	} else if syscall.Access(targetDir, syscall.O_RDWR) != nil {
		targetFile = "config.json"
	}

	if _, err := os.Stat(targetFile); err == nil {
		fmt.Printf(">>> Config %s exists, skipping.\n", targetFile)
		return
	}

	err := os.WriteFile(targetFile, []byte(content), 0644)
	if err != nil {
		fmt.Printf(">>> Write failed: %v\n", err)
	} else {
		fmt.Printf(">>> Generated example config: %s (Mode: %s)\n", targetFile, mode)
	}
}

func main() {
	cfgPath := flag.String("c", "config.json", "Config path")
	debug := flag.Bool("debug", false, "Debug mode")
	initCfg := flag.Bool("init", false, "Generate example config")
	cfgType := flag.String("type", "server", "Config type: 'server' or 'client'")
	flag.Parse()
	debugMode = *debug

	if *initCfg {
		genExampleConfig(*cfgType)
		return
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("[Init] Warning: Failed to remove memlock limit: %v", err)
	}

	var configs []Config
	
	fi, err := os.Stat(*cfgPath)
	if err != nil {
		log.Fatalf("Cannot read config path: %v", err)
	}

	if fi.IsDir() {
		files, err := os.ReadDir(*cfgPath)
		if err != nil {
			log.Fatalf("Read dir failed: %v", err)
		}
		
		for _, f := range files {
			if !f.IsDir() && strings.HasSuffix(f.Name(), ".json") {
				fullPath := filepath.Join(*cfgPath, f.Name())
				data, err := os.ReadFile(fullPath)
				if err != nil {
					log.Printf("Warning: Skipping file %s: %v", f.Name(), err)
					continue
				}
				
				var fileConfigs []Config
				if err := json.Unmarshal(data, &fileConfigs); err != nil {
					var single Config
					if err2 := json.Unmarshal(data, &single); err2 == nil {
						fileConfigs = append(fileConfigs, single)
					} else {
						log.Printf("Warning: Invalid JSON in %s: %v", f.Name(), err)
						continue
					}
				}
				configs = append(configs, fileConfigs...)
				log.Printf("[Init] Loaded config from %s", f.Name())
			}
		}
		if len(configs) == 0 {
			log.Fatalf("No valid config found in %s", *cfgPath)
		}
	} else {
		data, err := os.ReadFile(*cfgPath)
		if err != nil {
			log.Fatalf("Cannot read config file: %v", err)
		}
		if err := json.Unmarshal(data, &configs); err != nil {
			var single Config
			if err2 := json.Unmarshal(data, &single); err2 == nil {
				configs = append(configs, single)
			} else {
				log.Fatalf("Config format error: %v", err)
			}
		}
	}

	for i := range configs {
		configs[i].ParseLegacy()
	}

	var instances []*VPNInstance
	for _, cfg := range configs {
		v := NewVPNInstance(cfg)
		instances = append(instances, v)
		v.Start()
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	sig := <-c
	log.Printf("Received signal %v, exiting...", sig)

	for _, v := range instances {
		v.Cleanup()
	}
	log.Printf("Bye!")
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
func runCmdQuiet(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}
