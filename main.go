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
	"regexp"

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

// --- Global ---
var debugMode bool

func logDebug(format string, v ...interface{}) {
	if debugMode {
		log.Printf("[DEBUG] "+format, v...)
	}
}

// --- Config Structure ---

type Config struct {
	// --- Common ---
	Mode     string `json:"mode"`     // "server" | "client"
	Protocol string `json:"protocol"` // "raw" | "wg-raw"
	Debug    bool   `json:"debug"`
	MTU      int    `json:"mtu"`

	// --- Interfaces ---
	// Physical Interface (Required for wg-raw, optional for raw binding)
	PhyInterface string `json:"phy_interface"`
	// VPN Interface (The interface created by NekoLink: neko0 or wg0)
	VPNInterface string `json:"vpn_interface"`
	// VPN IP Address (CIDR, e.g. 10.0.0.1/24)
	VPNAddr      string `json:"vpn_addr"`

	// --- Server Binding ---
	// Port to listen on (Raw) or intercept (WG-Raw) on the Physical Interface
	ServerBindPort int `json:"server_bind_port"`

	// --- Client Remote ---
	ClientRemoteIP   string `json:"client_remote_ip"`
	ClientRemotePort int    `json:"client_remote_port"`

	// --- Auth ---
	Password   string `json:"password"`    // Shared Secret
	PrivateKey string `json:"private_key"` // WireGuard Private Key (wg-raw)

	// Runtime Key (Auto-generated if PrivateKey is empty)
	RuntimePrivateKey string `json:"-"`

	// --- Tuning / Transport ---
	CustomProtocol int  `json:"custom_protocol"` // IP Protocol Number (e.g. 253). If 17, implies UDP.
	TCPMode        bool `json:"tcp_mode"`        // Use Fake TCP Headers
	
	// --- Internal ---
	WGInternalPort int `json:"wg_internal_port"` // Port for internal Kernel WG (default 51820)
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

// --- Constants ---

const (
	NonceSize = chacha20poly1305.NonceSizeX
	Overhead  = chacha20poly1305.Overhead
	BufSize   = 65536
	BatchSize = 256
)

// --- Memory Pool ---

var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 4096)
		return &b
	},
}

type txPacket struct {
	bufPtr *[]byte
	n      int
}

// --- VPN Instance ---

type VPNInstance struct {
	Cfg Config
	TunDev tun.Device

	// --- Raw Mode State ---
	ConnRaw        []*net.IPConn
	ClientRemoteIP *net.IPAddr
	ServerPeerIP   atomic.Pointer[net.IPAddr]
	rawSendIdx     uint32

	AEAD           cipher.AEAD
	aeadPool       []cipher.AEAD

	// Reordering Pipeline
	reorderChan chan *DecryptedPacket
	rxDispatchChan chan rxPacket

	// Stats / Session
	SessionID    uint32
	nonceCounter uint64
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
	// Set Defaults
	if cfg.MTU == 0 { cfg.MTU = 1400 }
	if cfg.WGInternalPort == 0 { cfg.WGInternalPort = 51820 }
	if cfg.CustomProtocol == 0 { cfg.CustomProtocol = 233 }
	if cfg.VPNInterface == "" { cfg.VPNInterface = "neko0" }

	v := &VPNInstance{Cfg: cfg}

	v.numWorkers = runtime.NumCPU()
	if v.numWorkers > 8 {
		v.numWorkers = 8
	}

	// Initialize AEAD (XChaCha20-Poly1305) using Password
	keyHash := sha256.Sum256([]byte(cfg.Password))
	v.aeadPool = make([]cipher.AEAD, 16)
	for i := 0; i < 16; i++ {
		v.aeadPool[i], _ = chacha20poly1305.NewX(keyHash[:])
	}
	v.AEAD = v.aeadPool[0]
	v.SessionID = uint32(os.Getpid()) ^ uint32(keyHash[0])<<24

	// Auto-Generate WireGuard Keys if missing
	if cfg.PrivateKey == "" {
		log.Printf("[Init] ZeroConfig: No Private Key found. Auto-generating via 'wg genkey'...")
		out, err := exec.Command("wg", "genkey").Output()
		if err == nil {
			v.Cfg.RuntimePrivateKey = strings.TrimSpace(string(out))
			log.Printf("[Init] ZeroConfig: Ephemeral Key Generated.")
		} else {
			log.Printf("[Init] Warning: Failed to generate key: %v. Please install wireguard-tools.", err)
		}
	} else {
		v.Cfg.RuntimePrivateKey = cfg.PrivateKey
	}
	
	v.reorderChan = make(chan *DecryptedPacket, 8192)
	v.rxDispatchChan = make(chan rxPacket, 8192)

	// Initialize Remote Address (Client Mode)
	if cfg.Mode == "client" && cfg.ClientRemoteIP != "" {
		if addr, err := netip.ParseAddr(cfg.ClientRemoteIP); err == nil {
			v.remoteAddr = netip.AddrPortFrom(addr, uint16(cfg.ClientRemotePort))
		}
		// Also resolve for Raw mode usage
		v.ClientRemoteIP, _ = net.ResolveIPAddr("ip", cfg.ClientRemoteIP)
	}

	return v
}


// --- WireGuard Auto-Config Logic ---

func (v *VPNInstance) startWireGuardRaw() {
	// Phantom Mode (Mode 3): Kernel WireGuard <-> UDP Listener <-> AF_XDP Proxy
	
	// Determine BPF Mode
	bpfMode := 2 // Default Raw
	bpfTarget := v.Cfg.CustomProtocol

	// Check for UDP Mode
	if v.Cfg.CustomProtocol == 17 {
		bpfMode = 1
		bpfTarget = v.Cfg.ServerBindPort
	}

	// 1. Get Physical MAC
	iface, err := net.InterfaceByName(v.Cfg.PhyInterface)
	if err == nil && len(iface.HardwareAddr) >= 6 {
		copy(v.PhyMAC[:], iface.HardwareAddr)
		log.Printf("[WG-RAW] Physical MAC: %x", v.PhyMAC)
	} else {
		log.Printf("[WG-RAW] Warning: Could not find Physical Interface '%s'", v.Cfg.PhyInterface)
	}

	// 2. Initialize XDP on Parent Interface
	log.Printf("[WG-RAW] Initializing Phantom XDP on %s (Mode: %d, Target: %d)", v.Cfg.PhyInterface, bpfMode, bpfTarget)
	xsk, err := xdp.NewSocket(xdp.Config{
		Interface: v.Cfg.PhyInterface,
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
	v.setupKernelWireGuard(v.Cfg.VPNInterface)
	
	// 3. Start Local UDP Proxy Listener
	// Kernel WG sends to 127.0.0.1:v.Cfg.WGInternalPort
	udpAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", v.Cfg.WGInternalPort))
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Local Proxy Bind Failed: %v", err)
	}
	log.Printf("[WG-RAW] Proxy Active: Kernel_WG -> 127.0.0.1:%d -> AF_XDP", v.Cfg.WGInternalPort)

	// 4. Start Loops
	go v.proxyXDPToUDP(conn) // External -> XDP -> Proxy -> Kernel WG
	go v.proxyUDPToXDP(conn) // Kernel WG -> Proxy -> XDP -> External
	
	// 5. Start Side-Channel Handshaker
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
	if v.Cfg.VPNAddr != "" {
		runCmd("ip", "addr", "add", v.Cfg.VPNAddr, "dev", iface)
	}

	// Generate Random IPv6 Link-Local
	// WireGuard interfaces don't auto-generate IPv6 LL, so we add one.
	llBuf := make([]byte, 8)
	rand.Read(llBuf)
	llIP := fmt.Sprintf("fe80::%x%x:%x%x/64", llBuf[0:2], llBuf[2:4], llBuf[4:6], llBuf[6:8])
	runCmd("ip", "addr", "add", llIP, "dev", iface)
	
	// Safe MTU for tunneled traffic
	mtu := v.Cfg.MTU
	if mtu == 0 { mtu = 1380 }
	runCmd("ip", "link", "set", iface, "mtu", fmt.Sprintf("%d", mtu))
	runCmd("ip", "link", "set", iface, "up")
	
	// Config WireGuard (Keys/Peers)
	privKeyFile := "/tmp/neko_wg_priv"
	if v.Cfg.RuntimePrivateKey == "" {
		log.Fatal("[Wg-Raw] Error: No Private Key provided.")
	}
	os.WriteFile(privKeyFile, []byte(v.Cfg.RuntimePrivateKey), 0600)
	runCmd("wg", "set", iface, "private-key", privKeyFile)
	os.Remove(privKeyFile)
	
	// Server Mode:
	runCmd("wg", "set", iface, "listen-port", fmt.Sprintf("%d", v.Cfg.WGInternalPort + 1))
}

func (v *VPNInstance) handshakeLoop() {
	// Prepare Keys
	privateKeyHex := v.Cfg.RuntimePrivateKey
	var myPrivKey [32]byte
	if slice, err := base64.StdEncoding.DecodeString(privateKeyHex); err == nil && len(slice) == 32 {
		copy(myPrivKey[:], slice)
	}
	
	var myPubKey [32]byte
	curve25519.ScalarBaseMult(&myPubKey, &myPrivKey)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if v.Cfg.Mode == "client" && v.Cfg.ClientRemoteIP != "" {
				// Client sends heartbeat to server
				addr, err := netip.ParseAddr(v.Cfg.ClientRemoteIP)
				if err == nil {
					remote := netip.AddrPortFrom(addr, uint16(v.Cfg.ClientRemotePort))
					v.sendHandshakePacket(remote, myPubKey[:])
				}
			} else if v.Cfg.Mode == "server" {
				// Server sends heartbeat if it knows the peer
				var remote netip.AddrPort
				if v.Cfg.Protocol == "wg-raw" {
					v.remoteAddrMx.RLock()
					remote = v.remoteAddr
					v.remoteAddrMx.RUnlock()
				} else {
					p := v.ServerPeerIP.Load()
					if p != nil {
						addr, _ := netip.ParseAddr(p.String())
						remote = netip.AddrPortFrom(addr, 0)
					}
				}
				if remote.IsValid() {
					v.sendHandshakePacket(remote, myPubKey[:])
				}
			}
		}
	}
}

func (v *VPNInstance) onHandshakeReceived(data []byte, remote netip.AddrPort) bool {
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
	peerPubKey := plain[1:33]
	info := base64.StdEncoding.EncodeToString(peerPubKey)
	
	if v.Cfg.Protocol == "wg-raw" {
		logDebug("[Handshake] Recv validated packet from %s. PeerPub: %s", remote, info)
	}
	
	v.remoteAddrMx.Lock()
	if v.remoteAddr != remote {
		v.remoteAddr = remote
		if v.Cfg.Protocol == "wg-raw" {
			log.Printf("[Handshake] Roaming: Peer moved to %s", remote)
		}
	}
	v.remoteAddrMx.Unlock()

	// If legacy Raw Mode, update ServerPeerIP
	if v.Cfg.Protocol != "wg-raw" {
		ipAddr, _ := net.ResolveIPAddr("ip", remote.Addr().String())
		v.ServerPeerIP.Store(ipAddr)
		return true // Done for Raw mode
	}
	
	// Update WG Peer (only for wg-raw mode)
	if v.Cfg.Protocol == "wg-raw" {
		go func() {
			pubKey64 := base64.StdEncoding.EncodeToString(peerPubKey)
			runCmdQuiet("wg", "set", v.Cfg.VPNInterface, "peer", pubKey64, "allowed-ips", "0.0.0.0/0,::/0", "endpoint", fmt.Sprintf("127.0.0.1:%d", v.Cfg.WGInternalPort))
		}()
	}
	
	return true
}

func (v *VPNInstance) sendHandshakePacket(remote netip.AddrPort, myPub []byte) {
	pkt := make([]byte, 1+NonceSize+33+Overhead)
	pkt[0] = 0xFE
	
	nonce := pkt[1 : 1+NonceSize]
	if _, err := rand.Read(nonce); err != nil { return }
	
	plain := make([]byte, 33)
	plain[0] = 1
	copy(plain[1:], myPub)
	
	v.AEAD.Seal(pkt[1+NonceSize:1+NonceSize], nonce, plain, nil)
	
	if v.Cfg.Protocol == "wg-raw" {
		v.sendRawXDP(pkt, remote)
	} else if len(v.ConnRaw) > 0 {
		ipAddr, _ := net.ResolveIPAddr("ip", remote.Addr().String())
		v.ConnRaw[0].WriteToIP(pkt, ipAddr)
	}
	log.Printf("[Handshaker] Sent heartbeat to %s", remote)
}

func (v *VPNInstance) sendRawXDP(data []byte, remote netip.AddrPort) {
	isRaw := v.Cfg.CustomProtocol != 17
	useTCP := v.Cfg.TCPMode && isRaw

	pktLen := 14 + 20 + 8 + len(data)
	if isRaw {
		pktLen = 14 + 20 + len(data)
		if useTCP {
			pktLen += 20 // TCP Header
		}
	}

	pkt := make([]byte, pktLen)
	
	// 1. Ethernet
	v.remoteAddrMx.RLock()
	gwMac := v.GatewayMAC
	v.remoteAddrMx.RUnlock()

	if gwMac == [6]byte{0,0,0,0,0,0} {
		copy(pkt[0:6], []byte{0xff,0xff,0xff,0xff,0xff,0xff})
	} else {
		copy(pkt[0:6], gwMac[:])
	}
	// Src: Physical MAC
	if v.PhyMAC != [6]byte{0,0,0,0,0,0} {
		copy(pkt[6:12], v.PhyMAC[:])
	} else {
		copy(pkt[6:12], []byte{0x02,0x00,0x00,0x00,0x00,0x01})
	}
	
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800)
	
	// 2. IPv4
	ipOff := 14
	pkt[ipOff] = 0x45
	pkt[ipOff+1] = 0x00

	totalLen := uint16(20 + 8 + len(data))
	if isRaw {
		totalLen = uint16(20 + len(data))
		if useTCP {
			totalLen += 20
		}
	}
	binary.BigEndian.PutUint16(pkt[ipOff+2:ipOff+4], totalLen)

	pkt[ipOff+4], pkt[ipOff+5] = 0x00, 0x01
	pkt[ipOff+6], pkt[ipOff+7] = 0x00, 0x00
	pkt[ipOff+8] = 64

	if isRaw {
		pkt[ipOff+9] = uint8(v.Cfg.CustomProtocol)
	} else {
		pkt[ipOff+9] = 17
	}
	
	// Src IP
	myIP, _, _ := net.ParseCIDR(v.Cfg.VPNAddr)
	if myIP == nil {
		myIP = net.ParseIP(v.Cfg.VPNAddr) // Fallback if just IP
	}
	if myIP == nil { myIP = net.IP{0,0,0,0} }
	
	copy(pkt[ipOff+12:ipOff+16], myIP.To4())
	copy(pkt[ipOff+16:ipOff+20], remote.Addr().AsSlice())
	
	cs := checksum(pkt[ipOff:ipOff+20])
	binary.BigEndian.PutUint16(pkt[ipOff+10:ipOff+12], cs)
	
	if isRaw {
		payloadOff := ipOff + 20
		if useTCP {
			tcpOff := ipOff + 20
			payloadOff = tcpOff + 20
			
			binary.BigEndian.PutUint16(pkt[tcpOff:tcpOff+2], uint16(v.Cfg.ServerBindPort)) // Src Port
			binary.BigEndian.PutUint16(pkt[tcpOff+2:tcpOff+4], remote.Port())          // Dst Port
			binary.BigEndian.PutUint32(pkt[tcpOff+4:tcpOff+8], 0xDEADBEEF)
			binary.BigEndian.PutUint32(pkt[tcpOff+8:tcpOff+12], 0xCAFEBABE)
			pkt[tcpOff+12] = 0x50
			pkt[tcpOff+13] = 0x18
			binary.BigEndian.PutUint16(pkt[tcpOff+14:tcpOff+16], 0x4000)
			binary.BigEndian.PutUint16(pkt[tcpOff+16:tcpOff+18], 0x0000)
			binary.BigEndian.PutUint16(pkt[tcpOff+18:tcpOff+20], 0x0000)

			tcpPseudoHeader := make([]byte, 12)
			copy(tcpPseudoHeader[0:4], myIP.To4())
			copy(tcpPseudoHeader[4:8], remote.Addr().AsSlice())
			tcpPseudoHeader[9] = 6
			binary.BigEndian.PutUint16(tcpPseudoHeader[10:12], uint16(20+len(data)))

			tcpChecksum := v.calculateTCPChecksum(pkt[tcpOff:tcpOff+20], data, myIP.To4(), remote.Addr().AsSlice())
			binary.BigEndian.PutUint16(pkt[tcpOff+16:tcpOff+18], tcpChecksum)
		}
		copy(pkt[payloadOff:], data)
	} else {
		udpOff := ipOff + 20
		binary.BigEndian.PutUint16(pkt[udpOff:udpOff+2], uint16(v.Cfg.ServerBindPort))
		binary.BigEndian.PutUint16(pkt[udpOff+2:udpOff+4], remote.Port())
		binary.BigEndian.PutUint16(pkt[udpOff+4:udpOff+6], uint16(8+len(data)))
		binary.BigEndian.PutUint16(pkt[udpOff+6:udpOff+8], 0x0000)

		udpPkt := pkt[udpOff : udpOff+8+len(data)]
		copy(udpPkt[8:], data)
		udpChecksum := checksumUDP(myIP.To4(), remote.Addr().AsSlice(), udpPkt)
		binary.BigEndian.PutUint16(pkt[udpOff+6:udpOff+8], udpChecksum)

		copy(pkt[udpOff+8:], data)
	}
	
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
	for i := 0; i < 4; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(src[i : i+2]))
		sum += uint32(binary.BigEndian.Uint16(dst[i : i+2]))
	}
	sum += 17
	sum += uint32(len(udpPkt))
	
	for i := 0; i < len(udpPkt)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udpPkt[i : i+2]))
	}
	if len(udpPkt)%2 == 1 {
		sum += uint32(udpPkt[len(udpPkt)-1]) << 8
	}
	
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	if sum == 0xffff { return 0xffff }
	return ^uint16(sum)
}

func (v *VPNInstance) calculateTCPChecksum(header []byte, payload []byte, srcIP, dstIP net.IP) uint16 {
	sum := uint32(0)
	payloadLen := len(payload)
	headerLen := len(header)
	totalLen := uint32(headerLen + payloadLen)

	sum += uint32(binary.BigEndian.Uint16(srcIP[0:2])) + uint32(binary.BigEndian.Uint16(srcIP[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[0:2])) + uint32(binary.BigEndian.Uint16(dstIP[2:4]))
	sum += uint32(6)
	sum += totalLen

	for i := 0; i < headerLen; i += 2 {
		if i == 16 { continue }
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}

	for i := 0; i < payloadLen; i += 2 {
		if i+1 < payloadLen {
			sum += uint32(binary.BigEndian.Uint16(payload[i : i+2]))
		} else {
			sum += uint32(payload[i]) << 8
		}
	}

	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (v *VPNInstance) proxyXDPToUDP(conn *net.UDPConn) {
	// External -> XDP -> Decrypt -> Local UDP (KernelWG)
	kernelAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", v.Cfg.WGInternalPort+1))

	isRaw := v.Cfg.CustomProtocol != 17
	useTCP := v.Cfg.TCPMode && isRaw

	for {
		pkts, err := v.Xsk.Receive()
		if err != nil || len(pkts) == 0 {
			v.Xsk.Poll(2)
			continue
		}
		
		for _, pkt := range pkts {
			if len(pkt) < 34 { continue }
			
			ethType := binary.BigEndian.Uint16(pkt[12:14])
			var ipHdrLen int
			var srcIP net.IP
			var srcPort int
			var payload []byte

			if ethType == 0x0800 {
				ipHdrLen = int((pkt[14] & 0x0F) * 4)
				srcIP = net.IP(pkt[14+12 : 14+16])

				if isRaw {
					proto := pkt[14+9]
					if int(proto) != v.Cfg.CustomProtocol { continue }

					payloadStart := 14 + ipHdrLen
					if len(pkt) <= payloadStart { continue }
					
					if useTCP {
						if len(pkt) < payloadStart+20 { continue }
						srcPort = int(binary.BigEndian.Uint16(pkt[payloadStart : payloadStart+2]))
						payload = pkt[payloadStart+20:]
					} else {
						payload = pkt[payloadStart:]
						srcPort = 0
					}
				} else {
					udpStart := 14 + ipHdrLen
					if len(pkt) < udpStart+8 { continue }
					srcPort = int(binary.BigEndian.Uint16(pkt[udpStart : udpStart+2]))
					payload = pkt[udpStart+8:]
				}
				
				newRemote := netip.AddrPortFrom(netip.AddrFrom4([4]byte{srcIP[0], srcIP[1], srcIP[2], srcIP[3]}), uint16(srcPort))
				
				v.remoteAddrMx.Lock()
				if v.remoteAddr != newRemote {
					v.remoteAddr = newRemote
				}
				copy(v.GatewayMAC[:], pkt[6:12])
				v.remoteAddrMx.Unlock()
				
				v.handleRawPacket(payload, conn, kernelAddr)
			}
		}
	}
}

func (v *VPNInstance) proxyUDPToXDP(conn *net.UDPConn) {
	buf := make([]byte, 2048)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil { continue }
		data := buf[:n]
		
		v.remoteAddrMx.RLock()
		remote := v.remoteAddr
		v.remoteAddrMx.RUnlock()
		
		if !remote.IsValid() { continue }

		v.sendPhantomPacket(data, remote)
	}
}

func (v *VPNInstance) handleRawPacket(payload []byte, conn *net.UDPConn, target *net.UDPAddr) {
	if len(payload) == 0 { return }

	if payload[0] == 0xFE {
		ip := target.IP
		port := target.Port
		addrPort := netip.AddrPortFrom(netip.AddrFrom4([4]byte{ip[0],ip[1],ip[2],ip[3]}), uint16(port))
		
		v.onHandshakeReceived(payload, addrPort)
		return
	}

	nonce := payload[:NonceSize]
	cipherText := payload[NonceSize:]
	
	plain, err := v.AEAD.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return
	}

	conn.WriteToUDP(plain, target)
}

func (v *VPNInstance) sendPhantomPacket(plain []byte, remote netip.AddrPort) {
	nonce := make([]byte, NonceSize)

	vVal := atomic.AddUint64(&v.nonceCounter, 1)
	binary.BigEndian.PutUint64(nonce[0:8], vVal)
	binary.BigEndian.PutUint32(nonce[8:12], v.SessionID)
	
	cipherText := v.AEAD.Seal(nil, nonce, plain, nil)
	finalPayload := append(nonce, cipherText...)
	
	v.sendRawXDP(finalPayload, remote)
}

func (v *VPNInstance) startUAPI() {
	fileUAPI, err := ipc.UAPIOpen(v.Cfg.VPNInterface)
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

	log.Printf("[%s] NekoLink (WireGuard Edition) Starting - Workers: %d, MTU: %d",
		v.Cfg.VPNInterface, v.numWorkers, v.Cfg.MTU)

	v.InitInterface()
	v.InitNetwork()
	
	if v.Cfg.Protocol == "wg-raw" {
		log.Printf("[Init] Starting wg-raw mode (Phantom)")
		go v.startWireGuardRaw()
	} else {
		log.Printf("[Init] Starting Raw Mode 2 (Veth + AF_XDP)")
		
		appIf := v.Cfg.VPNInterface + "_app"
		
		xsk, err := xdp.NewSocket(xdp.Config{
			Interface: appIf,
			QueueID:   0,
			RingSize:  2048,
			Mode:      0,
			Target:    0,
		})
		if err != nil {
			log.Fatalf("AF_XDP Init Failed: %v", err)
		}
		v.Xsk = xsk
		
		if err := v.Xsk.AddToMap(v.Xsk.XsksMap); err != nil {
			log.Printf("Warning: Map Update Failed: %v", err)
		}

		log.Printf("[RAW] Starting Pipeline")
		go v.XDPReaderLoop(0)
		
		for i := 0; i < v.numWorkers; i++ {
			go v.rxWorkerLoop(i)
		}

		go v.packetOrderedWriter()
		go v.rawReaderLoop(0)
		go v.handshakeLoop()
	}
}

func (v *VPNInstance) Cleanup() {
	log.Printf("[%s] Cleaning up...", v.Cfg.VPNInterface)
	if v.Cfg.Protocol == "wg-raw" {
		if v.Cfg.VPNInterface != "" {
			runCmdQuiet("ip", "link", "del", v.Cfg.VPNInterface)
		}
	} else {
		if v.Cfg.VPNInterface != "" {
			runCmdQuiet("ip", "link", "del", v.Cfg.VPNInterface)
		}
	}
}

func (v *VPNInstance) InitInterface() {
	if v.Cfg.Protocol == "wg-raw" {
		log.Printf("[%s] Phantom Mode: Skipping local interface creation (Using Physical)", v.Cfg.VPNInterface)
		return
	}

	// Raw Mode: Veth
	hostIf := v.Cfg.VPNInterface
	appIf := v.Cfg.VPNInterface + "_app"
	
	runCmdQuiet("ip", "link", "del", hostIf)
	
	log.Printf("[%s] Creating Veth Pair: %s <-> %s", hostIf, hostIf, appIf)
	if err := runCmd("ip", "link", "add", hostIf, "type", "veth", "peer", "name", appIf); err != nil {
		log.Fatalf("Veth Create Failed: %v", err)
	}

	runCmd("ip", "addr", "add", v.Cfg.VPNAddr, "dev", hostIf)
	runCmd("ip", "link", "set", hostIf, "mtu", fmt.Sprintf("%d", v.Cfg.MTU))
	runCmd("ip", "link", "set", hostIf, "arp", "on")
	
	runCmd("ethtool", "-K", hostIf, "tx", "off", "rx", "off", "tso", "off", "gso", "off", "ufo", "off")
	
	runCmd("ip", "link", "set", hostIf, "up")
	
	runCmd("ip", "link", "set", appIf, "arp", "on")
	runCmd("ip", "link", "set", appIf, "promisc", "on")
	runCmd("ethtool", "-K", appIf, "tx", "off", "rx", "off", "tso", "off", "gso", "off", "ufo", "off")
	runCmd("ip", "link", "set", appIf, "mtu", fmt.Sprintf("%d", v.Cfg.MTU))
	runCmd("ip", "link", "set", appIf, "up")
	runCmdQuiet("sysctl", "-w", fmt.Sprintf("net.ipv6.conf.%s.disable_ipv6=1", appIf))

	runCmdQuiet("sysctl", "-w", "net.ipv4.conf.all.rp_filter=0")
	runCmdQuiet("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", hostIf))
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
		if v.Cfg.Protocol == "wg-raw" && v.Cfg.CustomProtocol == 17 {
			runCmd("nft", "add", "rule", "inet", tableName, "input", "udp", "dport", fmt.Sprintf("%d", v.Cfg.ServerBindPort), "accept")
		} else {
			protoNum := v.Cfg.CustomProtocol
			runCmd("nft", "add", "rule", "inet", tableName, "input", "meta", "l4proto", fmt.Sprintf("%d", protoNum), "accept")
		}
	} else {
		// Fallback (though protocol must be one of above)
		port := v.Cfg.ServerBindPort
		runCmd("nft", "add", "rule", "inet", tableName, "input", "udp", "dport", fmt.Sprintf("%d", port), "accept")
	}

	runCmd("nft", "add", "rule", "inet", tableName, "input", "ct", "state", "invalid", "drop")
}

func (v *VPNInstance) InitNetwork() {
	if v.Cfg.Protocol == "wg-raw" {
		// Managed by WG
	} else {
		v.initRaw()
	}
}

func (v *VPNInstance) initRaw() {
	numConns := 1

	// Bind to 0.0.0.0 by default or BindPort?
	// Old code listened on Custom Proto.

	protoStr := fmt.Sprintf("ip4:%d", v.Cfg.CustomProtocol)
	// Check for IPv6 based on VPNAddr? No, based on bind addr.
	// We don't have bind addr for Raw, only Port.
	// Assume IPv4 for now unless I parse something else.
	
	v.ConnRaw = make([]*net.IPConn, numConns)
	for i := 0; i < numConns; i++ {
		conn, err := net.ListenIP(protoStr, nil) // Listen on all interfaces
		if err != nil {
			log.Fatalf("Raw Listen Failed: %v", err)
		}
		conn.SetReadBuffer(32 << 20)
		conn.SetWriteBuffer(32 << 20)
		v.ConnRaw[i] = conn
	}

	if v.Cfg.Mode == "client" {
		v.ClientRemoteIP, _ = net.ResolveIPAddr("ip", v.Cfg.ClientRemoteIP)
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
		
		if buf[0] == 0xFE {
			aPort := netip.AddrPortFrom(netip.AddrFrom4([4]byte{addr.IP[0], addr.IP[1], addr.IP[2], addr.IP[3]}), 0)
			v.onHandshakeReceived(buf[:n], aPort)
			continue
		}

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

		if len(buf) < NonceSize+Overhead {
			bufPool.Put(pkt.bufPtr)
			continue
		}

		seq := binary.BigEndian.Uint64(buf[0:8])
		sess := binary.BigEndian.Uint32(buf[8:12])

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
					log.Printf("[Reorderer] Session Change: %x -> %x", currentSessionID, pkt.SessionID)
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
				log.Printf("[Reorderer] Init Sequence: %d", nextSeq)
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

// tryRepairJSON 尝试修复损坏的 JSON 语法 (针对遗忘引号和逗号的超级强力修复)
func tryRepairJSON(input string) string {
	// 1. 自动补全未加引号的键 (针对 mode: "server" 或 mode: server)
	// 匹配：单词后面跟着冒号，且前面是空格、换行、左大括号或逗号
	reKey := regexp.MustCompile(`(?m)([\{\,\s])([a-zA-Z0-9_]+)(\s*:)`)
	// 进行多次替换，确保所有嵌套/连续的键都能被处理
	for i := 0; i < 3; i++ {
		input = reKey.ReplaceAllString(input, `$1"$2"$3`)
	}

	// 2. 补全缺失的引号 (针对 "mode": server 且 server 是字符串的情况)
	reVal := regexp.MustCompile(`(?m)(:\s*)([a-zA-Z0-9_][a-zA-Z0-9_./@-]*)`)
	input = reVal.ReplaceAllStringFunc(input, func(s string) string {
		idx := strings.Index(s, ":")
		prefix := s[:idx+1]
		val := strings.TrimSpace(s[idx+1:])
		
		if val == "true" || val == "false" || val == "null" || val == "" || strings.HasPrefix(val, "\"") {
			return s
		}
		return prefix + " \"" + val + "\""
	})

	// 3. 补全缺失的逗号 (针对 "a":1 "b":2 这种情况)
	reComma := regexp.MustCompile(`([}\]"0-9a-zA-Z])(\s+)(["\[{a-zA-Z])`)
	for i := 0; i < 3; i++ {
		input = reComma.ReplaceAllString(input, `$1,$2$3`)
	}

	// 4. 处理并清理尾部多余的逗号
	reTailComma := regexp.MustCompile(`,\s*([}\]])`)
	input = reTailComma.ReplaceAllString(input, `$1`)

	// 5. 自动补全未闭合的括号
	objBrackets := 0
	arrBrackets := 0
	// 简单统计，不计算字符串内部的
	for _, char := range input {
		if char == '{' { objBrackets++ }
		if char == '}' { objBrackets-- }
		if char == '[' { arrBrackets++ }
		if char == ']' { arrBrackets-- }
	}
	for objBrackets > 0 { input += "}"; objBrackets-- }
	for arrBrackets > 0 { input += "]"; arrBrackets-- }
	// 多删掉的也补回来 (如果由于正则替换导致不匹配)
	for objBrackets < 0 { input = "{" + input; objBrackets++ }

	return input
}

func main() {
	cfgPath := flag.String("c", "config.json", "Config path")
	debug := flag.Bool("debug", false, "Debug mode")
	flag.Parse()
	debugMode = *debug

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("[Init] Warning: Failed to remove memlock limit: %v", err)
	}
	
	data, err := os.ReadFile(*cfgPath)
	if err != nil {
		log.Fatalf("Cannot read config file (%s): %v", *cfgPath, err)
	}

	var configs []Config
	if err := json.Unmarshal(data, &configs); err != nil {
		var single Config
		if err2 := json.Unmarshal(data, &single); err2 == nil {
			configs = append(configs, single)
		} else {
			// 尝试修复 JSON
			log.Printf("[Config] 检测到语法错误，正在尝试自动修复喵...")
			repaired := tryRepairJSON(string(data))
			
			if err3 := json.Unmarshal([]byte(repaired), &configs); err3 == nil {
				log.Printf("[Config] 修复成功！猫咪超厉害的对吧喵~")
			} else if err4 := json.Unmarshal([]byte(repaired), &single); err4 == nil {
				configs = append(configs, single)
				log.Printf("[Config] 修复成功！(单实例模式)")
			} else {
				log.Fatalf("Config Format Error even after repair: %v\nRepaired String: %s", err4, repaired)
			}
		}
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
	log.Printf("Received Signal %v, Exiting...", sig)

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
