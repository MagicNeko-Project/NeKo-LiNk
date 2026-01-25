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
	Key           string `json:"key"` // Shared Secret (Password)
	PrivateKey    string `json:"private_key,omitempty"` // WireGuard Private Key
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
	
	// Key Generation (Auto-Provisioning)
	if c.PrivateKey == "" {
		out, err := exec.Command("wg", "genkey").Output()
		if err == nil {
			c.PrivateKey = strings.TrimSpace(string(out))
			log.Printf("[Config] Assigned new WireGuard Private Key.")
		} else {
			log.Printf("Warning: 'wg' tool not found. Cannot auto-generate keys: %v", err)
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
	
	// Phantom Mode State
	GatewayMAC   [6]byte
	PhyMAC       [6]byte
	remoteAddr   netip.AddrPort
	remoteAddrMx sync.RWMutex
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

	// Initialize Phantom Remote if Client
	if cfg.Mode == "client" && cfg.PeerAddr != "" {
		if addr, err := netip.ParseAddr(cfg.PeerAddr); err == nil {
			v.remoteAddr = netip.AddrPortFrom(addr, uint16(cfg.PeerPort))
		}
	}

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
	
	// Determine BPF Mode
	bpfMode := 2 // Default Raw
	bpfTarget := v.Cfg.IPProtocolNum

	// Check for UDP Mode
	if v.Cfg.UseNATT || v.Cfg.IPProtocolNum == 17 {
		bpfMode = 1
		bpfTarget = v.Cfg.ListenPort
	}

	// 1. Get Physical MAC
	iface, err := net.InterfaceByName(v.Cfg.InterfaceName)
	if err == nil && len(iface.HardwareAddr) >= 6 {
		copy(v.PhyMAC[:], iface.HardwareAddr)
		log.Printf("[WG-RAW] Physical MAC: %x", v.PhyMAC)
	}

	// 2. Initialize XDP on Physical Interface
	log.Printf("[WG-RAW] Initializing Phantom XDP on %s (Mode: %d, Target: %d)", v.Cfg.InterfaceName, bpfMode, bpfTarget)
	// Note: In Phantom Mode, v.Cfg.InterfaceName IS the physical interface (e.g. eth0)
	xsk, err := xdp.NewSocket(xdp.Config{
		Interface: v.Cfg.InterfaceName,
		QueueID:   0,
		RingSize:  2048,
		Mode:      bpfMode,
		Target:    bpfTarget,
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
	if v.Cfg.PrivateKey == "" {
		log.Fatal("[Wg-Raw] Error: No Private Key generated. Please use -migrate or check config.")
	}
	os.WriteFile(privKeyFile, []byte(v.Cfg.PrivateKey), 0600)
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
	
	// 1. Prepare Keys
	// We use the PRIVATE KEY for our Identity (Standard WG)
	// We use the KEY (Password) for the Shared Secret (AEAD Side-Channel)
	
	privateKeyHex := v.Cfg.PrivateKey
	var myPrivKey [32]byte
	if slice, err := base64.StdEncoding.DecodeString(privateKeyHex); err == nil && len(slice) == 32 {
		copy(myPrivKey[:], slice)
	}
	
	var myPubKey [32]byte
	curve25519.ScalarBaseMult(&myPubKey, &myPrivKey)

	// Ticker for Heartbeat
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Send Handshake Packet if we have a target
			// We send OUR Public Key so remote can add us.
			if v.Cfg.Mode == "client" && v.Cfg.PeerAddr != "" {
				addr, err := netip.ParseAddr(v.Cfg.PeerAddr)
				if err == nil {
					remote := netip.AddrPortFrom(addr, uint16(v.Cfg.PeerPort))
					v.sendHandshakePacket(remote, myPubKey[:])
				}
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
	
	if len(plain) < 33 { return false }
	// ver := plain[0]
	// Previous code: plain[0] = 1, plain[1:] = PubKey
	
	peerPubKey := plain[1:33]
	info := base64.StdEncoding.EncodeToString(peerPubKey)
	
	logDebug("[Handshake] Recv validated packet from %s. PeerPub: %s", remote, info)
	
	// Update Kernel WireGuard with this Peer
	// wg set <iface> peer <Pub> allowed-ips 0.0.0.0/0 endpoint 127.0.0.1:WGPort
	// Note: Endpoint for Kernel is always Local Proxy.
	// But Proxy needs to know where to send (v.remoteAddr).
	
	v.remoteAddrMx.Lock()
	if v.remoteAddr != remote {
		v.remoteAddr = remote
		log.Printf("[Handshake] Roaming: Peer moved to %s", remote)
	}
	v.remoteAddrMx.Unlock()
	
	// Update WG Peer
	// We need to know the Interface Name. "neko_wg0"?
	// We should probably store it.
	go func() {
		pubKey64 := base64.StdEncoding.EncodeToString(peerPubKey)
		// We trust this peer because they knew the Shared Password.
		// Add/Update Peer. 
		// Note: PersistentKeepalive is handled by NekoLink heartbeat? Or allow WG to do it?
		// Since we have Side-Channel, we don't strictly need WG Keepalive, but it helps.
		runCmdQuiet("wg", "set", "neko_wg0", "peer", pubKey64, "allowed-ips", "0.0.0.0/0,::/0", "endpoint", fmt.Sprintf("127.0.0.1:%d", v.Cfg.WGPort))
	}()
	
	return true
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
	isRaw := !v.Cfg.UseNATT && v.Cfg.IPProtocolNum != 17

	pktLen := 14 + 20 + 8 + len(data)
	if isRaw {
		pktLen = 14 + 20 + len(data)
	}

	pkt := make([]byte, pktLen)
	
	// 1. Ethernet
	// Dst: Gateway MAC (or Broadcast if unknown)
	// Src: My Dummy MAC (02:00:00:00:00:01) ?? No, must match physical if possible?
	// Actually, if we send out physical, we should probably use real MAC if we want reply.
	// But usually Gateway accepts if IP matches.
	// Let's use v.GatewayMAC which we learned.
	v.remoteAddrMx.RLock()
	gwMac := v.GatewayMAC
	v.remoteAddrMx.RUnlock()

	if gwMac == [6]byte{0,0,0,0,0,0} {
		// Fallback to Broadcast
		copy(pkt[0:6], []byte{0xff,0xff,0xff,0xff,0xff,0xff})
	} else {
		copy(pkt[0:6], gwMac[:])
	}
	// Src: Physical MAC
	if v.PhyMAC != [6]byte{0,0,0,0,0,0} {
		copy(pkt[6:12], v.PhyMAC[:])
	} else {
		// Fallback
		copy(pkt[6:12], []byte{0x02,0x00,0x00,0x00,0x00,0x01})
	}
	
	// EtherType IPv4
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800)
	
	// 2. IPv4 Header
	// IP Off: 14
	ipOff := 14
	pkt[ipOff] = 0x45 // Ver=4, IHL=5
	pkt[ipOff+1] = 0x00 // TOS

	totalLen := uint16(20 + 8 + len(data))
	if isRaw {
		totalLen = uint16(20 + len(data))
	}
	binary.BigEndian.PutUint16(pkt[ipOff+2:ipOff+4], totalLen) // Total Len

	pkt[ipOff+4], pkt[ipOff+5] = 0x00, 0x01 // ID
	pkt[ipOff+6], pkt[ipOff+7] = 0x00, 0x00 // Flags/Frag
	pkt[ipOff+8] = 64 // TTL

	if isRaw {
		pkt[ipOff+9] = uint8(v.Cfg.IPProtocolNum)
	} else {
		pkt[ipOff+9] = 17 // UDP
	}
	// Checksum (Zero for now, fill later)
	
	// Src IP (My IP)
	myIP := net.ParseIP(v.Cfg.LocalAddr).To4()
	if myIP == nil { myIP = net.IP{0,0,0,0} }
	copy(pkt[ipOff+12:ipOff+16], myIP)
	
	// Dst IP (Remote)
	copy(pkt[ipOff+16:ipOff+20], remote.Addr().AsSlice())
	
	// IP Checksum
	cs := checksum(pkt[ipOff:ipOff+20])
	binary.BigEndian.PutUint16(pkt[ipOff+10:ipOff+12], cs)
	
	if isRaw {
		// 3. Raw Payload
		copy(pkt[ipOff+20:], data)
	} else {
		// 3. UDP Header
		udpOff := ipOff + 20
		// Src Port (My Listen Port)
		binary.BigEndian.PutUint16(pkt[udpOff:udpOff+2], uint16(v.Cfg.ListenPort))
		// Dst Port
		binary.BigEndian.PutUint16(pkt[udpOff+2:udpOff+4], remote.Port())
		// Length
		binary.BigEndian.PutUint16(pkt[udpOff+4:udpOff+6], uint16(8 + len(data)))
		// Checksum (Pseudo Header)
		// Calculate UDP Checksum
		udpCs := checksumUDP(pkt[ipOff+12:ipOff+16], pkt[ipOff+16:ipOff+20], pkt[udpOff:udpOff+8+len(data)])
		binary.BigEndian.PutUint16(pkt[udpOff+6:udpOff+8], udpCs)

		// 4. Payload
		copy(pkt[udpOff+8:], data)
	}
	
	// Transmit
	if v.Xsk != nil {
		v.Xsk.Transmit(pkt)
	}
}

// Helpers
func checksum(data []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func checksumUDP(src, dst, udpPkt []byte) uint16 {
	sum := uint32(0)
	// Pseudo Header
	for i := 0; i < 4; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(src[i : i+2]))
		sum += uint32(binary.BigEndian.Uint16(dst[i : i+2]))
	}
	sum += 17 // Proto
	sum += uint32(len(udpPkt))
	
	// UDP Packet
	for i := 0; i < len(udpPkt)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udpPkt[i : i+2]))
	}
	if len(udpPkt)%2 == 1 {
		sum += uint32(udpPkt[len(udpPkt)-1]) << 8
	}
	
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	if sum == 0xffff { return 0xffff } // UDP zero checksum means "no checksum", but calculated zero is 0xffff
	return ^uint16(sum)
}

func (v *VPNInstance) proxyXDPToUDP(conn *net.UDPConn) {
	// External -> XDP -> Decrypt -> Local UDP (KernelWG)
	// We need to route traffic to KernelWG which is listening on 127.0.0.1:(WGPort+1)
	kernelAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", v.Cfg.WGPort+1))

	isRaw := !v.Cfg.UseNATT && v.Cfg.IPProtocolNum != 17

	for {
		pkts, err := v.Xsk.Receive()
		if err != nil || len(pkts) == 0 {
			v.Xsk.Poll(10)
			continue
		}
		
		for _, pkt := range pkts {
			if len(pkt) < 34 { continue }
			
			// 1. Learn Gateway MAC (Src MAC of incoming frame)
			// SrcMAC is at [6:12]
			// Moved to lock block below
			
			// 2. Parse IP/UDP
			ethType := binary.BigEndian.Uint16(pkt[12:14])
			var ipHdrLen int
			var srcIP net.IP
			var srcPort int
			var payload []byte

			if ethType == 0x0800 { // IPv4
				ipHdrLen = int((pkt[14] & 0x0F) * 4)
				srcIP = net.IP(pkt[14+12 : 14+16])

				if isRaw {
					proto := pkt[14+9]
					if int(proto) != v.Cfg.IPProtocolNum { continue }

					payloadStart := 14 + ipHdrLen
					if len(pkt) <= payloadStart { continue }
					payload = pkt[payloadStart:]
					srcPort = 0 // No port in Raw mode
				} else {
					// UDP Header at 14+ipHdrLen
					udpStart := 14 + ipHdrLen
					if len(pkt) < udpStart+8 { continue }
					srcPort = int(binary.BigEndian.Uint16(pkt[udpStart : udpStart+2]))
					// Payload
					payload = pkt[udpStart+8:]
				}
				
				// Update Remote State
				newRemote := netip.AddrPortFrom(netip.AddrFrom4([4]byte{srcIP[0], srcIP[1], srcIP[2], srcIP[3]}), uint16(srcPort))
				
				v.remoteAddrMx.Lock()
				if v.remoteAddr != newRemote {
					v.remoteAddr = newRemote
					// Optional: Log new connection
				}
				// Always update GatewayMAC (Learned from Switch/Gateway)
				copy(v.GatewayMAC[:], pkt[6:12])
				v.remoteAddrMx.Unlock()
				
				// Decrypt & Forward
				v.handleRawPacket(payload, conn, kernelAddr)
			}
			// TODO: IPv6 Support (similar logic)
		}
	}
}

func (v *VPNInstance) proxyUDPToXDP(conn *net.UDPConn) {
	// Local UDP (KernelWG) -> Encrypt -> XDP -> External
	buf := make([]byte, 2048)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil { continue }
		data := buf[:n]
		
		// If we don't have a remote yet (Server mode waiting for handshake), drop.
		// If Client mode, properly initialized.
		v.remoteAddrMx.RLock()
		remote := v.remoteAddr
		v.remoteAddrMx.RUnlock()
		
		if !remote.IsValid() { continue }

		v.sendPhantomPacket(data, remote)
	}
}

func (v *VPNInstance) handleRawPacket(payload []byte, conn *net.UDPConn, target *net.UDPAddr) {
	if len(payload) == 0 { return }

	// 1. Check for Handshake (0xFE)
	if payload[0] == 0xFE {
		// Side-Channel Handshake Processing
		ip := target.IP
		port := target.Port
		addrPort := netip.AddrPortFrom(netip.AddrFrom4([4]byte{ip[0],ip[1],ip[2],ip[3]}), uint16(port))
		
		v.onHandshakeReceived(payload, addrPort)
		return
	}

	// 2. Decrypt
	nonce := payload[:NonceSize]
	cipherText := payload[NonceSize:]
	
	plain, err := v.AEAD.Open(nil, nonce, cipherText, nil)
	if err != nil {
		// Decrypt failed (maybe not ours?), drop
		return
	}

	// 3. Forward to Kernel WireGuard
	conn.WriteToUDP(plain, target)
}

func (v *VPNInstance) sendPhantomPacket(plain []byte, remote netip.AddrPort) {
	// Encrypt -> Construct Raw -> Xsk.Transmit
	
	// Encrypt
	nonce := make([]byte, NonceSize)

	// Structure Nonce: [Seq (8)] + [SessionID (4)] + [Padding (12)]
	// This matches the expectation of the Reordering Logic on the receiver side.
	vVal := atomic.AddUint64(&v.nonceCounter, 1)
	binary.BigEndian.PutUint64(nonce[0:8], vVal)
	binary.BigEndian.PutUint32(nonce[8:12], v.SessionID)
	// Remaining bytes are 0 (make initializes to 0)
	
	// Cipher = Nonce + AEAD(plain)
	cipherText := v.AEAD.Seal(nil, nonce, plain, nil)
	finalPayload := append(nonce, cipherText...)
	
	v.sendRawXDP(finalPayload, remote)
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
	// Disable ARP to simulate Point-to-Point (TUN-like) behavior
	runCmd("ip", "link", "set", hostIf, "arp", "off")
	runCmd("ip", "link", "set", hostIf, "up")
	
	// Configure App Side (AF_XDP Target)
	// Also disable ARP on App side to prevent Kernel noise
	runCmd("ip", "link", "set", appIf, "arp", "off")
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

func (v *VPNInstance) XDPReaderLoop(idx int) {
	// XDP Reader
	// RAW MODE: veth_app RX = Host TX (Plain IP + ARP)
	// WG-RAW MODE: eth0 RX = Encrypted Packets
	
	for {
		pkts, err := v.Xsk.Receive()
		if err != nil || len(pkts) == 0 {
			v.Xsk.Poll(10)
			continue
		}
		
		for _, pkt := range pkts {
			// Parse Ethernet
			if len(pkt) < 14 { continue }
		
			// 2. Encrypt and Send (L2 Tunnel Mode - Ethernet over IP)
			// We tunnel the FULL Ethernet Frame (including Header)
			// No more ARP Responder needed - ARP is tunneled too!
			payload := pkt
			
			// Encrypt
			nonce := make([]byte, NonceSize)

			// Structure Nonce: [Seq (8)] + [SessionID (4)] + [Padding (12)]
			vVal := atomic.AddUint64(&v.nonceCounter, 1)
			binary.BigEndian.PutUint64(nonce[0:8], vVal)
			binary.BigEndian.PutUint32(nonce[8:12], v.SessionID)
			// Remaining bytes are 0

			cipherText := v.AEAD.Seal(nil, nonce, payload, nil)
			finalPayload := append(nonce, cipherText...)
			
			// Send via ConnRaw
			var remoteAddr *net.IPAddr
			if v.Cfg.Mode == "client" {
				remoteAddr = v.ClientRemoteIP
			} else {
				p := v.ServerPeerIP.Load()
				if p != nil { remoteAddr = p }
			}
			
			if remoteAddr != nil && len(v.ConnRaw) > 0 && v.ConnRaw[0] != nil {
				v.ConnRaw[0].WriteToIP(finalPayload, remoteAddr)
			}
		}
	}
}



// --- XDP Reader/Writer (Raw Mode 2) ---
// Note: XDPReaderLoop implemented above to resolve scope issues.

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
	// L2 Tunnel Mode: "data" is ALREADY a full Ethernet Frame.
	// We just transmit it directly.
	
	if v.Xsk != nil {
		v.Xsk.Transmit(data)
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
