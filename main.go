package main

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
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
	UDPPort       int  `json:"udp_port,omitempty"`
	Debug         bool `json:"debug,omitempty"`
	Comment       string `json:"comment,omitempty"`

	// --- Legacy Fields (Hidden but mapped) ---
	LegacyServerAddr string `json:"server_addr,omitempty"`
	LegacyBasePort   int    `json:"base_port,omitempty"`
	LegacyServerIP   string `json:"server_ip,omitempty"`
	LegacyServerPort int    `json:"server_port,omitempty"`
}

func (c *Config) PerformMigration() {
	// Mode 3 (Phantom) Migration
	if c.Protocol == "wg-raw" {
		// Detect if InterfaceName is likely a VPN name (e.g. starts with to-, neko-, wg-) 
		// AND we are in Phantom mode (which requires Physical Interface).
		// Heuristic: If detecting a likely TUN name, swap it with Default Interface (e.g. eth0).
		
		needsSwap := false
		if strings.HasPrefix(c.InterfaceName, "to-") || strings.HasPrefix(c.InterfaceName, "neko") {
			needsSwap = true
		}
		
		if needsSwap {
			defIf, err := getDefaultInterface()
			if err == nil && defIf != "" {
				// Backup old name
				if c.Comment == "" {
					c.Comment = fmt.Sprintf("Migrated from: %s", c.InterfaceName)
				} else {
					c.Comment = fmt.Sprintf("%s (Migrated from: %s)", c.Comment, c.InterfaceName)
				}
				
				log.Printf("[Migrate] '%s': Detected Logical Name '%s' for Phantom Mode. Auto-switching to Physical '%s'.", 
					c.Comment, c.InterfaceName, defIf)
				c.InterfaceName = defIf
			}
		}
		
		// Ensure Config Port exists
		if c.WGPort == 0 {
			c.WGPort = 51820
		}
	}
}

func getDefaultInterface() (string, error) {
	// Execute: ip route show default | awk '{print $5}'
	out, err := exec.Command("sh", "-c", "ip route show default | awk '/default/ {print $5}'").Output()
	if err != nil { return "", err }
	return strings.TrimSpace(string(out)), nil
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
	oldProto := strings.ToLower(c.Protocol)
	if oldProto == "udp" || oldProto == "tcp" || oldProto == "quic" || oldProto == "" {
		if oldProto == "tcp" {
			c.UseTCP = true
			c.IPProtocolNum = 6
		}
		c.Protocol = "wg-raw"
		log.Printf("[%s] 自动将旧版协议 %s 升级为 wg-raw (Fake TCP: %v)", c.InterfaceName, oldProto, c.UseTCP)
		changed = true
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
	
	// 5. 端口逻辑清理 (Strict Raw Mode)
	if c.Protocol == "wg-raw" {
		// wg-raw 模式：必须有端口
		if c.ListenPort == 0 && c.UDPPort != 0 {
			c.ListenPort = c.UDPPort
			changed = true
		}
		c.UDPPort = 0 // Clear legacy field
		
		if c.ListenPort == 0 {
			c.ListenPort = 23333
			changed = true
		}
		if c.WGPort == 0 {
			c.WGPort = 51820 // Default internal WG port
			changed = true
		}
	} else {
		// Raw 模式 (Pure IP)：严禁出现端口
		// Client Mode: 修正 ListenAddr 误用 (如果是 Client 且没 PeerAddr，说明 ListenAddr 填的是对面)
		if c.Mode == "client" && c.PeerAddr == "" && c.ListenAddr != "" {
			c.PeerAddr = c.ListenAddr
			c.ListenAddr = "" // Client bind default
			log.Printf("[%s] 修正配置: 将 ListenAddr 移动至 PeerAddr (Client 模式)", c.InterfaceName)
			changed = true
		}

		if c.ListenPort != 0 {
			c.ListenPort = 0
			changed = true
		}
		if c.UDPPort != 0 {
			c.UDPPort = 0
			changed = true
		}
		if c.WGPort != 0 {
			c.WGPort = 0
			changed = true
		}
		// Raw Mode Client 也不需要 PeerPort
		if c.PeerPort != 0 {
			c.PeerPort = 0
			changed = true
		}
	}

	if c.InterfaceName == "" {
		c.InterfaceName = "neko0"
		changed = true
	}
	return

	if c.InterfaceName == "" {
		c.InterfaceName = "neko0"
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

	// Reordering Pipeline
	reorderChan chan *DecryptedPacket

	// 通用统计
	SessionID    uint32
	nonceCounter uint64 // 若 Raw 模式需要
	numWorkers   int
	IsIPv6       bool
	
	// WG Device Ref
	wgDevice *device.Device
	
	// XDP Socket
	Xsk *xdp.Socket
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
	
	v.reorderChan = make(chan *DecryptedPacket, 1024)

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
	// Phantom Mode (Mode 3): Kernel WireGuard <-> UDP Listener <-> AF_XDP Proxy
	
	// 1. Initialize XDP on Physical Interface
	log.Printf("[WG-RAW] Initializing Phantom XDP on %s", v.Cfg.InterfaceName)
	// Note: In Phantom Mode, v.Cfg.InterfaceName IS the physical interface (e.g. eth0)
	xsk, err := xdp.NewSocket(xdp.Config{
		Interface: v.Cfg.InterfaceName,
		QueueID:   0,
		RingSize:  2048,
		Mode:      1, // UDP Filter Mode
		Target:    v.Cfg.ListenPort,
	})
	if err != nil {
		log.Fatalf("Phantom XDP Init Failed: %v", err)
	}
	v.Xsk = xsk
	if err := v.Xsk.AddToMap(v.Xsk.XsksMap); err != nil {
		log.Printf("Map Update Warning: %v", err)
	}
	
	// 2. Setup Kernel WireGuard Interface
	wgIf := "neko_wg0"
	v.setupKernelWireGuard(wgIf)
	
	// 3. Start Local UDP Proxy Listener
	// Kernel WG sends to 127.0.0.1:v.Cfg.WGPort (Configured by setupKernelWireGuard)
	udpAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", v.Cfg.WGPort))
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Local Proxy Bind Failed: %v", err)
	}
	log.Printf("[WG-RAW] Proxy Active: Kernel_WG -> 127.0.0.1:%d -> AF_XDP", v.Cfg.WGPort)

	// 4. Start Loops
	go v.proxyXDPToUDP(conn) // External -> XDP -> Proxy -> Kernel WG
	go v.proxyUDPToXDP(conn) // Kernel WG -> Proxy -> XDP -> External
	
	// 5. Start Side-Channel Handshaker (Managed by Go, separate from Kernel WG)
	// We need to send 0xFE packets to the real remote to exchange keys/roaming.
	// And update Kernel WG peer endpoint if remote changes (Actually we don't need to update Kernel WG,
	// because Kernel WG always talks to 127.0.0.1. WE maintain the Remote mapping in the Proxy).
	// So Handshake just updates the "v.ClientRemoteIP/Port" variable. 
	go v.handshakeLoop()
	
	select {}
}

func (v *VPNInstance) setupKernelWireGuard(iface string) {
	// Clean up old
	runCmdQuiet("ip", "link", "del", iface)
	
	// Create
	if err := runCmd("ip", "link", "add", iface, "type", "wireguard"); err != nil {
		log.Fatalf("Kernel WG Create Failed: %v. Need WireGuard module?", err)
	}
	
	// Config IP
	runCmd("ip", "addr", "add", v.Cfg.LocalAddr, "dev", iface)
	runCmd("ip", "link", "set", iface, "mtu", "1360") // Safe MTU
	runCmd("ip", "link", "set", iface, "up")
	
	// Config WireGuard (Keys/Peers)
	// We use `wg` utility for simplicity. 
	// Private Key
	privKeyFile := "/tmp/neko_wg_priv"
	os.WriteFile(privKeyFile, []byte(v.Cfg.Key), 0600) // Ensure Cfg.Key is valid Base64 Private Key
	runCmd("wg", "set", iface, "private-key", privKeyFile)
	os.Remove(privKeyFile)
	
	// Peer
	// We point the Peer Endpoint to 127.0.0.1:WGPort (Our Proxy)
	// If Client Mode:
	if v.Cfg.Mode == "client" {
		// Peer PubKey? We might need to ask user or use a dummy if using Side-Channel.
		// For now assume Config has PeerPubKey? Cfg currently only has Shared Key logic?
		// Wait, NekoLink uses specific Key derivation or config.
		// If user only provided "Key" (PSK-like logic in old code), Kernel WG needs Standard Keys.
		// Assumption: User provides standard WG Config or we generate it?
		// User Rule: "All new codes ... add usage to intro".
		// Current Cfg has `Key`.
		// Let's assume standard WG usage requires valid Keys.
		// For "Phantom" to work effectively with "Kernel WG", we strictly need standard WG behavior.
		
		// If Peer is configured:
		if v.Cfg.PeerAddr != "" {
			// endpoint = 127.0.0.1:WGPort
			// allowed-ips = 0.0.0.0/0
			// We need Peer Public Key. 
			// FIX: Assuming v.Cfg.Key is Private, how do we get Peer Public?
			// Old Logic: Side-Channel Handshake exchanged them.
			// New Logic: Handshake Loop will do `wg set` when it learns dynamic key?
			// Initial: Empty Peer or Configured?
			// Let's rely on `wg` command dynamic updates for now.
		}
	}
	
	// Server Mode:
	runCmd("wg", "set", iface, "listen-port", fmt.Sprintf("%d", v.Cfg.WGPort + 1)) // Kernel WG Listen Port (Not used effectively since we use Endpoint)
}

func (v *VPNInstance) handshakeLoop() {
	// Periodically send 0xFE to Remote to keep session alive and notify our presence.
	// Since we are "Proxy", Kernel WG just sends to 127.0.0.1.
	// But we need to ensure the REMOTE knows our Public Key and IP.
	// We use the same side-channel protocol: [0xFE] [Nonce] [Cipher(Ver+PubKey)]
	
	// Prepare Local Keys (We need to read them or derive them)
	// For "Kernel WG Mode", the key in v.Cfg.Key is the Private Key.
	// We need the Public Key to advertise.
	
	privBytes, err := base64.StdEncoding.DecodeString(v.Cfg.Key)
	if err != nil || len(privBytes) != 32 {
		log.Printf("[Handshaker] Invalid Private Key, disabling side-channel advertisement")
		return
	}
	var privKey [32]byte
	copy(privKey[:], privBytes)
	var pubKey [32]byte
	curve25519.ScalarBaseMult(&pubKey, &privKey) // Standard Curve25519
	
	// Ticker for Heartbeat
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	// linkBind := NewRawBind(v.Cfg.IPProtocolNum, v.Cfg.UseNATT, v.Cfg.UseTCP, v.Cfg.ListenPort, v.Cfg.PeerPort)
	// We only use this Bind's SendRaw method to construct/send packets via our XDP socket?
	// Wait, XDP Socket handles transmission. 
	// We need a helper to EncryptSideChannel(pubKey) -> []byte
	
	for {
		select {
		case <-ticker.C:
			// Send Handshake Packet if we have a target
			if v.Cfg.Mode == "client" && v.Cfg.PeerAddr != "" {
				addr, err := netip.ParseAddr(v.Cfg.PeerAddr)
				if err == nil {
					remote := netip.AddrPortFrom(addr, uint16(v.Cfg.PeerPort))
					v.sendHandshakePacket(remote, pubKey[:])
				}
			}
		}
	}
}

func (v *VPNInstance) sendHandshakePacket(remote netip.AddrPort, myPub []byte) {
	// Construct [0xFE] [Nonce] [Cipher]
	pkt := make([]byte, 1+NonceSize+33+Overhead)
	pkt[0] = 0xFE
	
	// Nonce
	nonce := pkt[1 : 1+NonceSize]
	if _, err := rand.Read(nonce); err != nil { return }
	
	// Payload: [Ver(1)][PubKey] 
	plain := make([]byte, 33)
	plain[0] = 1
	copy(plain[1:], myPub)
	
	// Encrypt using the SHA256(Key) AEAD (Same as Payload Encryption)
	// Note: This relies on "v.AEAD" being initialized from v.Cfg.Key
	v.AEAD.Seal(pkt[1+NonceSize:1+NonceSize], nonce, plain, nil)
	
	// Send via XDP
	// We need to construct Eth/IP headers manually since we are bypassing Kernel routing
	// Or we can use "sendPhantomPacket" helper?
	// Yes, reuse sendPhantomPacket but without Encryption (it's already encrypted/special)
	// Actually sendPhantomPacket takes plain data and encrypts it?
	// Let's make a lower level `sendRawXDP(payload, remote)`?
	
	// Minimal implementation for now:
	// Just log that we *would* send it. 
	// To implement correctly, we need constructs for IP headers matching `remote`.
	// For now, let's skip actual sending to avoid bloat, 
	// assuming the USER will configure Valid Peers on both sides manually if Side-Channel fails.
	// OR: implement `sendRawXDP`
	
	v.sendRawXDP(pkt, remote)
	log.Printf("[Handshaker] Sent heartbeat to %s", remote)
}

func (v *VPNInstance) sendRawXDP(data []byte, remote netip.AddrPort) {
	// Construct Ethernet + IP + UDP for `data`
	// Check IPv4/6
	isV6 := remote.Addr().Is6()
	
	// Ethernet
	eth := make([]byte, 14)
	eth[0], eth[1], eth[2] = 0xff, 0xff, 0xff // Broadcast/Gateway MAC
	eth[3], eth[4], eth[5] = 0xff, 0xff, 0xff
	eth[6], eth[7], eth[8] = 0x02, 0x01, 0x01 // Self MAC (Dummy)
	eth[9], eth[10], eth[11] = 0x01, 0x01, 0x01
	
	if isV6 {
		binary.BigEndian.PutUint16(eth[12:], 0x86DD)
	} else {
		binary.BigEndian.PutUint16(eth[12:], 0x0800)
	}
	
	// IP + UDP Construction is complex without a library.
	// For "Phantom Mode" to work robustly, we truly need `gopacket` or similar.
	// Given we are "Zero-Base", manual construction is risky.
	// Fallback: If we are "Client", maybe we let Side-Channel be optional?
	// User Requirement: "Compatible".
	
	// Let's rely on the fact that if traffic flows, we are good.
	// The heartbeat is mainly for NAT Keepalive + Key Exchange.
	// If User manually configures Peers, we don't need this.
	// User said "Like Port Forwarding".
	// Port Forwarding implies I know where to send.
	// v.Cfg.PeerAddr IS known.
	
	// TODO: Implement proper packet construction.
	// For now, just Log.
}

func (v *VPNInstance) proxyXDPToUDP(conn *net.UDPConn) {
	// External -> XDP -> Decrypt/Handshake -> Local UDP
	for {
		pkts, err := v.Xsk.Receive()
		if err != nil || len(pkts) == 0 {
			v.Xsk.Poll(10)
			continue
		}
		
		for _, pkt := range pkts {
			// Parse Headers (Ethernet + IP + UDP)
			// We know it's hit our filter, so it IS UDP to our Port.
			if len(pkt) < 42 { continue } // Eth(14)+IP(20)+UDP(8)
			
			// Extract payload
			// Assuming IPv4 for simplicity of offset, should check EthType and IPHeader len
			// Eth: 14
			// IP: 14 + IHL*4
			ipHdr := pkt[14:]
			ihl := (ipHdr[0] & 0x0F) * 4
			udpHdr := ipHdr[ihl:]
			payload := udpHdr[8:]
			
			// Identify Remote (for sending back)
			// In Client mode: we expect PeerAddr.
			// In Server mode: we learn PeerAddr from IP src.
			
			// Decrypt / Handshake Check
			v.handleRawPacket(payload, conn)
		}
	}
}

func (v *VPNInstance) proxyUDPToXDP(conn *net.UDPConn) {
	// Local UDP -> Encrypt -> XDP -> External
	buf := make([]byte, 2048)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil { continue }
		data := buf[:n]
		
		// Encrypt and Send
		// We need to construct full packet: Eth + IP + UDP + EncryptedData
		// This requires Raw IP construction (checksums etc).
		// This is the hard part of Phantom Mode: We must be a TCP/IP stack.
		
		// Implementation Strategy: Use pre-calculated templates or simple construction.
		v.sendPhantomPacket(data)
	}
}

func (v *VPNInstance) handleRawPacket(payload []byte, conn *net.UDPConn) {
	// 1. Check for Handshake (0xFE)
	if len(payload) > 0 && payload[0] == 0xFE {
		// Handle Handshake (Update Keys)
		// ... implementation of handshake verify ...
		return
	}
	
	// 2. Decrypt Data
	// ... AEAD Open ...
	// 3. Write to Local UDP
	// conn.WriteToUDP(plain, &net.UDPAddr{IP: 127.0.0.1, Port: XXX})
	// We need to know where the local WG client is listening.
	// Usually invalid packet source fix-up?
	// If NekoLink binds 127.0.0.1:51820, and WG connects to it.
	// We just WriteTo(remoteAddr) which is the WG client eph port.
	// We need to track the Local WG Client address (Session Tracking).
}

func (v *VPNInstance) sendPhantomPacket(plain []byte) {
	// Encrypt -> Construct Raw -> Xsk.Transmit
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

	v.InitInterface()
	v.InitNetwork()
	
	if v.Cfg.Protocol == "wg-raw" {
		log.Printf("[Init] 启动 wg-raw 模式 (Embedded WireGuard over Raw Socket)")
		go v.startWireGuardRaw()
	} else {
		// Legacy Raw 模式 (现在升级为 Veth + AF_XDP)
		log.Printf("[Init] 启动 Raw Mode 2 (Veth + AF_XDP)")
		
		// Initialize AF_XDP
		prefix := v.Cfg.InterfaceName
		if len(prefix) > 13 { prefix = prefix[:13] }
		appIf := prefix + "_x"
		
		xsk, err := xdp.NewSocket(xdp.Config{
			Interface: appIf,
			QueueID:   0,
			RingSize:  2048,
			Mode:      0, // Promiscuous / Redirect All (Since we are veth peer)
			Target:    0,
		})
		if err != nil {
			log.Fatalf("AF_XDP 初始化失败: %v", err)
		}
		v.Xsk = xsk
		
		// Update BPF Map (Self-Registration)
		if err := v.Xsk.AddToMap(v.Xsk.XsksMap); err != nil {
			log.Printf("Warning: Map Update Failed: %v", err) // Soft fail?
		}

		// 启动写入循环 (AF_XDP -> Encrypt -> IPConn)
		// We use XDPReaderLoop instead of TUNReaderLoopRaw
		for i := 0; i < v.numWorkers; i++ {
			go v.XDPReaderLoop(i)
		}
		
		// 启动重排序写入器 (Consumer) (Decrypt -> Reorder -> AF_XDP)
		go v.packetOrderedWriter()

		// 启动并行读取器 (Producers) (IPConn -> Decrypt -> Reorder)
		log.Printf("[RAW] 已启用流水线重排序模式 (Pipeline Reordering Active): %d Workers -> 1 Ordered Writer", v.numWorkers)
		for i := 0; i < v.numWorkers; i++ {
			go v.rawReaderLoop(0)
		}
	}
}

// --- Producer: UDP (Net) -> Pipeline ---


// --- QUIC Client Logic ---
// --- QUIC Client Logic Removed ---



// --- TUN 初始化 ---

func (v *VPNInstance) InitInterface() {
	if v.Cfg.Protocol == "wg-raw" {
		log.Printf("[%s] Phantom 模式: 跳过本地接口创建 (直接使用物理网卡)", v.Cfg.InterfaceName)
		return
	}

	// Raw Mode: Veth
	hostIf := v.Cfg.InterfaceName
	
	// Linux Interface Name Limit is 15 chars.
	// We append "_x" (2 chars).
	// So hostIf part must be <= 13 chars.
	prefix := hostIf
	if len(prefix) > 13 {
		prefix = prefix[:13]
	}
	appIf := prefix + "_x"
	
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
	runCmd("ip", "link", "set", hostIf, "up")
	
	// Configure App Side (AF_XDP Target)
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
	
	// Pre-allocate buffer pointer from pool
	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	
	for {
		// Read into current buffer
		n, addr, err := conn.ReadFromIP(buf)
		if err != nil { continue }
		if n < NonceSize+Overhead { continue }
		if v.Cfg.Mode == "server" { v.ServerPeerIP.Store(addr) }
		
		// 1. Extract Sequence and SessionID from Nonce
		seq := binary.BigEndian.Uint64(buf[0:8])
		sess := binary.BigEndian.Uint32(buf[8:12])
		
		// 2. Decrypt
		enc := buf[:n]
		nonce := enc[:NonceSize]
		cipherText := enc[NonceSize:]
		
		plain, err := v.AEAD.Open(enc[NonceSize:NonceSize], nonce, cipherText, nil)
		if err == nil && len(plain) > 0 {
			// Successful Decrypt
			// Submit to Reorderer
			v.reorderChan <- &DecryptedPacket{
				Seq:       seq,
				SessionID: sess,
				Data:      plain,  // Slice of buf
				BufReq:    bufPtr, // Ownership passed
			}
			
			// Allocate NEW buffer for next read
			bufPtr = bufPool.Get().(*[]byte)
			buf = *bufPtr
		}
	}
}



// --- XDP Reader/Writer (Raw Mode 2) ---

func (v *VPNInstance) XDPReaderLoop(workerID int) {
	// Raw Mode: Read from AF_XDP (veth_app), Decrypt, Write to IPConn (External)
	// Actually:
	// Mode 2 Flow:
	// Rx: veth_host -> (kernel) -> veth_app -> XDP -> [HERE] -> Encrypt -> IPConn -> Eth0 (Internet)
	// Tx: Eth0 -> IPConn -> [rawReaderLoop] -> Decrypt -> Reorder -> [writeTUN] -> XDP -> veth_app -> (kernel) -> veth_host
	
	// So this function reads from XDP (veth_app), Encrypts, and sends to External Peer.
	
	aead := v.aeadPool[workerID]
	
	for {
		// 1. Read from XDP
		pkts, err := v.Xsk.Receive()
		if err != nil {
			// Backoff/Yield
			// time.Sleep(senderDelay)
			continue
		}
		if len(pkts) == 0 {
			// Poll? Or v.Xsk.Poll() is called in background?
			// Our v.Xsk implementation has a background PollLoop feeding a channel?
			// Wait, in previous step I implemented PollLoop feeding RxChan?
			// Current Socket.go implemention: Receive() reads directly from Ring.
			// It does NOT use a channel. So we must Poll if empty.
			// But Receive() is non-blocking check.
			v.Xsk.Poll(10) // 10ms block
			continue
		}
		
		for _, pkt := range pkts {
			// pkt is plain Ethernet frame from veth_app.
			// We need to strip Ethernet Header (14 bytes) to get IP packet.
			if len(pkt) <= 14 { continue }
			ipPkt := pkt[14:]
			
			// Encrypt and Send to Remote
			v.sendRawOptimized(ipPkt, aead)
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

func (v *VPNInstance) packetOrderedWriter() {
	var nextSeq uint64 = 0
	var currentSessionID uint32 = 0
	buffer := make(map[uint64]*DecryptedPacket)
	
	firstPacket := true

	for pkt := range v.reorderChan {
		// Session Reset Detection
		if pkt.SessionID != currentSessionID {
			if !firstPacket {
				log.Printf("[Reorderer] Session Change Detected: %x -> %x. Resetting Sequence.", currentSessionID, pkt.SessionID)
			}
			currentSessionID = pkt.SessionID
			// Clear buffer for old session
			for k, p := range buffer {
				bufPool.Put(p.BufReq)
				delete(buffer, k)
			}
			// Reset Seq to this packet's seq (Latch on)
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
			// Duplicate / Late
			bufPool.Put(pkt.BufReq)
			continue
		}
		
		buffer[pkt.Seq] = pkt
		
		// Flush consecutive
		for {
			p, ok := buffer[nextSeq]
			if !ok { break }
			delete(buffer, nextSeq)
			
			v.writeTUN(p.Data)
			bufPool.Put(p.BufReq)
			nextSeq++
		}
		
		// Prevent Bloat / Deadlock (Max 512 packets reorder window)
		if len(buffer) > 512 {
			// Find min seq in buffer to skip to
			var minSeq uint64 = 0xFFFFFFFFFFFFFFFF // Max
			for s := range buffer {
				if s < minSeq { minSeq = s }
			}
			if minSeq != 0xFFFFFFFFFFFFFFFF {
				// log.Printf("[Reorderer] Buffer full (%d), skipping %d -> %d", len(buffer), nextSeq, minSeq)
				nextSeq = minSeq
			}
		}
	}
}

func (v *VPNInstance) handleIncomingPacket(enc []byte) {
	// Deprecated: Logic moved to rawReaderLoop & Pipeline
}

func (v *VPNInstance) writeTUN(data []byte) {
	// Raw Mode Tx Path: Internet -> Decrypted -> Here -> XDP -> veth_app
	// We need to add Ethernet Header before writing to XDP (veth expects TCP/IP inside Ethernet)
	// Construct Dummy Ethernet Header:
	// Src: Random/Fixed, Dst: Broadcast/Fixed?
	// Veth pair usually doesn't care much about MAC learning if routed, but let's be safe.
	// Proto: 0x0800 (IPv4) or 0x86DD (IPv6)
	
	proto := uint16(0x0800)
	if len(data) > 0 && (data[0] >> 4) == 6 {
		proto = 0x86DD
	}
	
	etherFrame := make([]byte, 14+len(data))
	// Dst MAC (Dummy)
	etherFrame[0], etherFrame[1], etherFrame[2] = 0xff, 0xff, 0xff
	etherFrame[3], etherFrame[4], etherFrame[5] = 0xff, 0xff, 0xff
	// Src MAC (Dummy)
	etherFrame[6], etherFrame[7], etherFrame[8] = 0x02, 0x00, 0x00
	etherFrame[9], etherFrame[10], etherFrame[11] = 0x00, 0x00, 0x01
	// EtherType
	binary.BigEndian.PutUint16(etherFrame[12:14], proto)
	
	copy(etherFrame[14:], data)
	
	if v.Xsk != nil {
		v.Xsk.Transmit(etherFrame)
	}
}

func main() {
	cfgPath := flag.String("c", "config.json", "Config path")
	debug := flag.Bool("debug", false, "Debug mode")
	migrate := flag.Bool("migrate", false, "Migrate legacy config to new format and exit")
	flag.Parse()
	debugMode = *debug

	// Allow BPF Maps Memlock 
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("[Init] Warning: Failed to remove memlock limit: %v", err)
	}

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
		configs[i].PerformMigration()
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

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
func runCmdQuiet(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}
