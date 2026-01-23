package main

import (
	"container/heap"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/tap"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"vpn/xdp"
)

// --- Configuration ---

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

	IPProtocolNum int `json:"ip_protocol_num"`
	PortCount     int `json:"port_count"`
	UseXDP        bool   `json:"use_xdp"`
	XDPDevice     string `json:"xdp_device"` // Physical Interface for XDP binding

	SocksBind string `json:"socks_bind"`
}

func (c *Config) ParseLegacy() {
	if c.Mode == "client" && c.RemoteIP == "" && c.ServerBindAddr != "" {
		c.RemoteIP = c.ServerBindAddr
	}
	if c.Mode == "client" && c.RemotePort == 0 && c.BasePort != 0 {
		c.RemotePort = c.BasePort
	}
	if c.Protocol == "" { c.Protocol = "udp" }
	if c.IPProtocolNum == 0 { c.IPProtocolNum = 233 }
	if c.PortCount == 0 { c.PortCount = 1 }
	if c.MTU == 0 { c.MTU = 1400 }
	if c.InterfaceName == "" { c.InterfaceName = "neko0" }
}

const (
	NonceSize = chacha20poly1305.NonceSizeX
	Overhead  = chacha20poly1305.Overhead
	SeqSize   = 4
	MaxReorderBuffer = 8192 // Increased to 8192 (16MB) to safely buffer high-speed jitter
	TunOffset = 0 // TAP does not use PI/VirtioNet headers in water
)

// --- Helper Functions ---

// 检测是否为组播或广播包
func isMulticastOrBroadcast(ethFrame []byte) bool {
	if len(ethFrame) < 14 { return false }
	
	// 组播/广播判断：目标 MAC 最低位为 1
	// 组播: 01:xx:xx:xx:xx:xx
	// 广播: ff:ff:ff:ff:ff:ff
	return ethFrame[0]&0x01 != 0
}

var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 2048)
		return &b
	},
}

// --- VPN Instance ---

type VPNInstance struct {
	Cfg Config
	
	TunDev tap.Device
	AEAD  cipher.AEAD
	
	ConnUDP   []*net.UDPConn
	ConnTCP   net.Conn
	ConnRaw   *net.IPConn
	TCPMutex  sync.Mutex
	
	PeerMap sync.Map 
	
	ClientRemoteUDP []*net.UDPAddr
	ClientRemoteIP  *net.IPAddr
	
	XDP *xdp.XDPSocket
	
	SessionID uint32
	TxSeq     uint32
	
	Reorderer *PacketReorderer
}

func NewVPNInstance(cfg Config) *VPNInstance {
	cfg.ParseLegacy()
	v := &VPNInstance{ Cfg: cfg }
	
	keyHash := sha256.Sum256([]byte(cfg.Key))
	var err error
	v.AEAD, err = chacha20poly1305.NewX(keyHash[:])
	if err != nil { log.Fatalf("Crypto Fail: %v", err) }

	b := make([]byte, 4)
	rand.Read(b)
	v.SessionID = binary.BigEndian.Uint32(b)

	v.Reorderer = NewReorderer()
	v.Reorderer.WriteFunc = v.IfaceWrite
	
	return v
}

func (v *VPNInstance) InitTUN() {
	// EtherGuard-VPN TAP
	conf := mtypes.InterfaceConf{
		Name:          v.Cfg.InterfaceName,
		MTU:           uint16(v.Cfg.MTU),
		MacAddrPrefix: "02:00", // Default prefix
		IPv4CIDR:      "",      // Disable internal IP logic (We set manually)
	}

	// Use SessionID as NodeID (truncated to uint16)
	nodeID := mtypes.Vertex(v.SessionID)

	dev, err := tap.CreateTAP(conf, nodeID)
	if err != nil {
		log.Fatalf("TAP Init Fail: %v", err)
	}

	v.TunDev = dev
	v.Cfg.InterfaceName, _ = dev.Name()
	
	// Start Event consumer to prevent blocking
	go func() {
		// Manual Configuration Reuse
		time.Sleep(500 * time.Millisecond)
		runCmd("ip", "addr", "add", v.Cfg.LocalAddr, "dev", v.Cfg.InterfaceName)
		
		// Force Static MAC for Debugging (02:00:00:00:00:01)
		// This avoids random MAC mismatch if client expects something specific.
		runCmd("ip", "link", "set", "dev", v.Cfg.InterfaceName, "address", "02:00:00:00:00:01")
		
		runCmd("ip", "link", "set", v.Cfg.InterfaceName, "up") // Ensure UP
		
		// Log MAC Address
		ifif, err := net.InterfaceByName(v.Cfg.InterfaceName)
		if err == nil {
			log.Printf("TAP MAC: %s", ifif.HardwareAddr.String())
		} else {
			log.Printf("TAP MAC Query Fail: %v", err)
		}
		
		for event := range dev.Events() {
			log.Printf("TAP Event: %v", event)
		}
	}()

	log.Printf("TAP Device %s initialized (IP: %s)", v.Cfg.InterfaceName, v.Cfg.LocalAddr)
}




func (v *VPNInstance) IfaceWrite(data []byte) {
	// TAP Write (L2 Frame)
	_, err := v.TunDev.Write(data, 0)
	if err != nil {
		log.Printf("TAP Write Error: %v", err)
	}
}

// --- Network ---

func (v *VPNInstance) InitNetwork() {
	if v.Cfg.Protocol == "tcp" {
		addr := fmt.Sprintf("%s:%d", v.Cfg.ServerBindAddr, v.Cfg.BasePort)
		if v.Cfg.Mode == "client" { addr = fmt.Sprintf("%s:%d", v.Cfg.RemoteIP, v.Cfg.RemotePort) }
		
		if v.Cfg.Mode == "server" {
			ln, err := net.Listen("tcp", addr)
			if err != nil { log.Fatal(err) }
			log.Printf("[%s] TCP Listen %s", v.Cfg.InterfaceName, addr)
			go v.TCPAcceptLoop(ln)
		} else {
			go v.TCPClientDial(addr)
		}
		return
	}

	if v.Cfg.Protocol == "udp" {
		v.ConnUDP = make([]*net.UDPConn, v.Cfg.PortCount)
		v.ClientRemoteUDP = make([]*net.UDPAddr, v.Cfg.PortCount)
		for i := 0; i < v.Cfg.PortCount; i++ {
			var bindAddrStr string
			if v.Cfg.Mode == "server" { bindAddrStr = fmt.Sprintf("%s:%d", v.Cfg.ServerBindAddr, v.Cfg.BasePort+i) } else { bindAddrStr = ":0" }
			lAddr, _ := net.ResolveUDPAddr("udp", bindAddrStr)
			c, err := net.ListenUDP("udp", lAddr)
			if err != nil { log.Fatal(err) }
			
			// Increase Buffer to 16MB to match tuned system limits
			c.SetReadBuffer(16<<20)
			c.SetWriteBuffer(16<<20)
			
			v.ConnUDP[i] = c
			
			if v.Cfg.Mode == "client" {
				rAddrStr := fmt.Sprintf("%s:%d", v.Cfg.RemoteIP, v.Cfg.RemotePort+i)
				rAddr, _ := net.ResolveUDPAddr("udp", rAddrStr)
				v.ClientRemoteUDP[i] = rAddr
			}
			go v.UDPListenerLoop(i, c)
		}
		return
	}
	
	if v.Cfg.Protocol == "raw" {
		protoStr := fmt.Sprintf("ip4:%d", v.Cfg.IPProtocolNum)
		var lAddr *net.IPAddr
		if v.Cfg.Mode == "server" && v.Cfg.ServerBindAddr != "0.0.0.0" { lAddr, _ = net.ResolveIPAddr("ip", v.Cfg.ServerBindAddr) }
		c, err := net.ListenIP(protoStr, lAddr)
		if err != nil { log.Fatal(err) }
		// Increase Buffer to 16MB to match tuned system limits
		c.SetReadBuffer(16<<20); c.SetWriteBuffer(16<<20)
		v.ConnRaw = c
		if v.Cfg.Mode == "client" {
			v.ClientRemoteIP, _ = net.ResolveIPAddr("ip", v.Cfg.RemoteIP)
		}
		go v.RawListenerLoop(c)
	}
}

func (v *VPNInstance) UDPListenerLoop(idx int, c *net.UDPConn) {
	// GSO/GRO Optimization: Use ReadBatch (recvmmsg)
	pc := ipv4.NewPacketConn(c)
	const batchSize = 64 // Linux limit for recvmmsg is typically high, 64 is standard for offload
	
	msgs := make([]ipv4.Message, batchSize)
	bufPtrs := make([]*[]byte, batchSize) // Keep track of pointers to return/pass ownership
	
	// Pre-fill buffers
	for i := range msgs {
		bufPtrs[i] = bufPool.Get().(*[]byte)
		msgs[i].Buffers = [][]byte{ *bufPtrs[i] }
	}

	for {
		nMsgs, err := pc.ReadBatch(msgs, 0)
		if err != nil {
			log.Printf("ReadBatch error: %v", err)
			// Wait a bit before retry to avoid busy loop on error
			time.Sleep(100 * time.Millisecond)
			continue
		}

		for i := 0; i < nMsgs; i++ {
			msg := &msgs[i]
			bufPtr := bufPtrs[i]
			
			// ProcessPacket takes ownership of bufPtr and will Put it back to pool
			v.ProcessPacket(bufPtr, msg.N, msg.Addr, idx)
			
			// Refill the slot with a NEW buffer for next read
			newPtr := bufPool.Get().(*[]byte)
			bufPtrs[i] = newPtr
			msg.Buffers[0] = *newPtr
		}
	}
}

func (v *VPNInstance) RawListenerLoop(c *net.IPConn) {
	for {
		bufPtr := bufPool.Get().(*[]byte)
		buf := *bufPtr
		n, src, err := c.ReadFromIP(buf)
		if err != nil { bufPool.Put(bufPtr); return }
		if n < 4 { bufPool.Put(bufPtr); continue }
		
		// Zero-Copy for Raw:
		// We need to strip 4 bytes header. 
		// Instead of copy, we can just slice the buffer?
		// But ProcessPacket expects *bufPtr to point to the start of encryption data.
		// If we slice (*bufPtr)[4:], that's fine for data, but when we Put(bufPtr) back, we put the original slice header?
		// bufPool New() returns 2048 byte slice.
		// If we modify *bufPtr to be a sub-slice, Put() might be confused if it relies on cap? 
		// Go's sync.Pool doesn't care about cap/len resets unless we do it manually.
		// Our New() does not reset.
		// Ideally we should copy if we want to align payload?
		// Or we pass an offset? ProcessPacket takes *bufPtr.
		// Let's slide data to front? overlap copy.
		// copy(buf, buf[4:n]) -> data is now at 0.
		// n = n - 4
		copy(buf, buf[4:n])
		v.ProcessPacket(bufPtr, n-4, src, 0)
	}
}

func (v *VPNInstance) TCPAcceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil { continue }
		go v.TCPHandler(c)
	}
}
func (v *VPNInstance) TCPClientDial(addr string) {
	for {
		c, err := net.Dial("tcp", addr)
		if err != nil { time.Sleep(2 * time.Second); continue }
		v.TCPMutex.Lock(); v.ConnTCP = c; v.TCPMutex.Unlock()
		v.TCPHandler(c)
		v.TCPMutex.Lock(); v.ConnTCP = nil; v.TCPMutex.Unlock()
		time.Sleep(1 * time.Second)
	}
}
func (v *VPNInstance) TCPHandler(c net.Conn) {
	defer c.Close()
	header := make([]byte, 2)
	for {
		if _, err := io.ReadFull(c, header); err != nil { return }
		l := binary.BigEndian.Uint16(header)
		bufPtr := bufPool.Get().(*[]byte)
		buf := *bufPtr
		if cap(buf) < int(l) { newB := make([]byte, l); buf = newB }
		body := buf[:l]
		if _, err := io.ReadFull(c, body); err != nil { bufPool.Put(bufPtr); return }
		// TCP Framing: Body is the packet.
		// Zero-Copy: Pass bufPtr directly.
		v.ProcessPacket(bufPtr, int(l), c.RemoteAddr(), 0)
	}
}

// ProcessPacket takes ownership of bufPtr (which contains data at *bufPtr)
func (v *VPNInstance) ProcessPacket(bufPtr *[]byte, n int, srcAddr net.Addr, idx int) {
	encrypted := (*bufPtr)[:n]
	log.Printf("RX %d bytes from %v", n, srcAddr)
	
	if len(encrypted) < NonceSize+Overhead { 
		log.Printf("Drop: Too short for crypto (expected %d, got %d)", NonceSize+Overhead, len(encrypted))
		bufPool.Put(bufPtr)
		return 
	}
	nonce := encrypted[:NonceSize]
	ciphertext := encrypted[NonceSize:]
	
	// Zero-Copy Decrypt: Reuse 'encrypted' buffer for plaintext
	// Open appends to dst. If we pass nil as dst, it allocates.
	// We want to decrypt in-place or reuse buffer. 
	// AEAD.Open can decrypt in-place if dst and src overlap/are same.
	// But we need to be careful about Nonce preservation if needed? No, nonce is outside ciphertext.
	
	// Open(dst, nonce, ciphertext, additionalData)
	// We use the capacity of bufPtr.
	// Let's perform in-place decryption. 'ciphertext' is part of 'encrypted' underlying array.
	// We can reuse the start of 'encrypted' (which holds nonce) to store plaintext.
	
	// Careful: AEAD.Open clears/overwrites.
	// dst = ciphertext[:0] -> Strict in-place decryption (dst start == src start).
	// using encrypted[:0] caused partial overlap (dst=0, src=24) which Panics.
	plaintext, err := v.AEAD.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil { 
		log.Printf("Decrypt Fail: %v", err)
		bufPool.Put(bufPtr)
		return 
	}
	// log.Printf("Decrypt OK: len %d", len(plaintext))
	
	// [Sess 4][Seq 4][Ethernet Frame...]
	if len(plaintext) < 8+14 { 
		bufPool.Put(bufPtr)
		return 
	}
	
	// Parse Header
	sessionID := binary.BigEndian.Uint32(plaintext[0:4])
	seq := binary.BigEndian.Uint32(plaintext[4:8])
	
	// Debug Log for Header Analysis
	if v.Cfg.Mode == "server" && len(plaintext) > 16 {
		// Log first packet or occasional packets
		if seq % 100 == 0 || seq < 100 {
			// Analyze EtherType (Bytes 12-13 of ethFrame)
			// ethFrame starts at plaintext[8]
			// So plaintext[20], plaintext[21]
			var etherType uint16
			if len(plaintext) >= 22 {
				etherType = binary.BigEndian.Uint16(plaintext[20:22])
			}
			log.Printf("RX Debug: Sess=%d Seq=%d HeaderHex=%x EtherType=%04x", sessionID, seq, plaintext[:22], etherType)
		}
	}

	ethFrame := plaintext[8:]
	// ethFrame[0:6] Dst, [6:12] Src
	
	if v.Cfg.Mode == "server" {
		srcMac := ethFrame[6:12]
		// Determine MAC Key
		key := uint64(srcMac[5]) | uint64(srcMac[4])<<8 | uint64(srcMac[3])<<16 | uint64(srcMac[2])<<24 | uint64(srcMac[1])<<32 | uint64(srcMac[0])<<40
		
		isMcastSrc := (srcMac[0] & 1) == 1
		if !isMcastSrc {
			v.PeerMap.Store(key, srcAddr)
		}
	}
	
	sessionID = binary.BigEndian.Uint32(plaintext[0:4])
	seq = binary.BigEndian.Uint32(plaintext[4:8])
	// L2: Payload is the whole EthFrame
	ethPayload := ethFrame
	
	// Reorderer Push (Deep Copy Mode - Safe)
	// We do NOT pass bufPtr. We pass a copy of ethPayload.
	// But to avoid double copy (one here, one in Push), we can just let Reorderer handle it?
	// Reorderer needs to store specific packet data.
	// Let's alloc a new slice for data here if needed, or let Reorderer do it.
	// Reorderer.Push(..., data []byte) -> it will append/store.
	
	// CRITICAL: We MUST perform a deep copy because bufPtr is about to be recycled!
	// Reorderer.Push will store 'ethPayload'. 
	// If 'ethPayload' is a slice of 'bufPtr', we must copy it.
	// FIX: Add Headroom for TUN Write (TunOffset) - REMOVED FOR TAP
	
	payloadCopy := make([]byte, len(ethPayload))
	copy(payloadCopy, ethPayload)
	
	v.Reorderer.Push(sessionID, seq, payloadCopy)
	
	// Safe to recycle bufPtr now
	bufPool.Put(bufPtr)
}

func (v *VPNInstance) TUNReaderLoop() {
	buf := make([]byte, 2048)
	for {
		n, err := v.TunDev.Read(buf, 0)
		if err != nil { 
			log.Printf("TAP Read Error: %v", err)
			break 
		}
		
		data := buf[:n]
		if n < 14 { continue } // Min Eth Header

		// Parse Ethernet Header
		// Dst: 0-6, Src: 6-12, Type: 12-14
		// broadcast := isBroadcast(data[0:6])
		
		// Unicast Learning (L2 Learning Bridge)
		// We shouldn't learn from TAP Read? TAP Read = From Kernel/Local.
		// We learn where Local sends to? No.
		// We learn that 'SrcMAC' is Local.
		// But for Routing OUTBOUND:
		// We look at 'DstMAC' (data[0:6]).
		// If DstMAC is in PeerMap, send there.
		// If DstMAC is FF:FF... (Broadcast), Flood.
		// If DstMAC is Unknown, Flood.
		
		dstMac := data[0:6]
		// srcMac := data[6:12] // Local MAC
		
		isMcast := (dstMac[0] & 1) == 1
		
		var destAddr net.Addr
		if v.Cfg.Mode == "server" && !isMcast {
			// L2 Routing: Look up DstMAC
			// To store MAC in PeerMap (which expects uint64 key):
			// MAC is 6 bytes. Fits in uint64.
			key := uint64(dstMac[5]) | uint64(dstMac[4])<<8 | uint64(dstMac[3])<<16 | uint64(dstMac[2])<<24 | uint64(dstMac[1])<<32 | uint64(dstMac[0])<<40
			
			// Try to find which channel/peer owns this MAC
			// Note: We need to modify ProcessPacket to Learn MACs first!
			// For now, if we don't find it, we broadcast.
			
			if val, ok := v.PeerMap.Load(key); ok {
				destAddr = val.(net.Addr)
			}
		}
		
		seq := atomic.AddUint32(&v.TxSeq, 1) - 1
		idx := int(uint64(seq) % uint64(v.Cfg.PortCount))
		
		if destAddr != nil {
			v.SendPacket(data, idx, seq, destAddr)
		} else {
			// Broadcast / Flood / Unknown Unicast
			v.BroadcastToAllPeers(data, idx, seq)
		}
	}
}



func (v *VPNInstance) XDPListenerLoop() {
	for {
		pkt, err := v.XDP.ReadPacket()
		if err != nil { continue }
		if pkt == nil { continue }
		
		// Parse IP Payload (XDP returns Eth+IP+Payload)
		// UDP Header = 42 bytes (14 Eth + 20 IP + 8 UDP)
		// Raw Header = 38 bytes (14 Eth + 20 IP + 4 IDX)
		// But RawListenerLoop strips IDX (4). XDPListenerLoop receives full frame.
		// If we use Raw, sender sends [IDX][Nonce][Ciphertext].
		// So Raw Header on wire is 14+20+4 = 38.
		// Payload starts at 38.
		
		headerLen := 42
		if v.Cfg.Protocol == "raw" { headerLen = 38 }
		
		if len(pkt) < headerLen { continue }
		data := pkt[headerLen:]
		
		// Sender Addr? 
		// We can extract SrcIP/Port from packet headers.
		// For ZeroCopy speed, we might skip full net.UDPAddr alloc
		// But ProcessPacket needs addr to update PeerMap.
 
		// Or ProcessPacket handles copy? ProcessPacket copies 'ethPayload' to Reorderer?
		// Reorderer copies? No, Reorderer stores slice.
		// If slice in UMEM, we MUST copy before returning frame to kernel!
		dataCopy := make([]byte, len(data))
		copy(dataCopy, data)
		
		
		// XDP Zero-Copy Adaptor:
		// XDP ReadPacket returns a slice from UMEM (or copy depending on implementation).
		// We need to move it to bufPool to satisfy ProcessPacket ownership contract.
		// (Ideally XDP should integrate with bufPool directly, but step-by-step).
		bufPtr := bufPool.Get().(*[]byte)
		buf := *bufPtr
		n := len(data)
		if n > cap(buf) {
			bufPool.Put(bufPtr)
			continue // Too large
		}
		copy(buf, data)
		
		v.ProcessPacket(bufPtr, n, nil, 0)
	}
}

func (v *VPNInstance) SendPacket(ipPacket []byte, idx int, seq uint32, destAddr net.Addr) {
	// XDP Acceleration:
	// RX is handled via eBPF + AF_XDP (Zero Copy)
	// TX is handled via Standard Syscall (Mixed Mode) because implementing 
	// a full driver-like TX path in userspace is complex and prone to errors.
	if v.Cfg.Protocol == "tcp" {
		// TCP Encryption logic not fully implemented in this migration step (TCP was minimal)
		// But basic framing:
		v.TCPMutex.Lock(); c := v.ConnTCP; v.TCPMutex.Unlock()
		if c == nil { return }
		
		// For TCP we should also Encrypt? 
		// Previous TCP logic was raw write?
		// Actually NekoLink TCP should be encrypted too.
		// Assuming we stick to UDP focus for now.
		// If using TCP, we need framing.
		// Let's focus on UDP optimization.
		l := len(ipPacket); h := make([]byte, 2); binary.BigEndian.PutUint16(h, uint16(l))
		c.Write(h); c.Write(ipPacket)
		return
	}
	if v.Cfg.Protocol == "udp" {
		// Encryption Logic (Moved from ReaderLoop)
		// 1. Prepare Buffer (Sess+Seq+IP)
		// We need a temp buffer for plaintext.
		ptLen := 8 + len(ipPacket)
		
		// Get buffer for Result (Encrypted Frame)
		// Frame: [Nonce 24][Ciphertext (ptLen + 16)]
		
		dstPtr := bufPool.Get().(*[]byte)
		dst := *dstPtr; dst = dst[:0]
		
		// Nonce
		nonce := make([]byte, NonceSize)
		io.ReadFull(rand.Reader, nonce)
		dst = append(dst, nonce...)
		
		// Plaintext Construction
		// To avoid alloc, we could reuse `data` if we had headroom.
		// For now, alloc or use another pool buffer?
		// Using another pool buffer for plaintext is safest.
		ptBufPtr := bufPool.Get().(*[]byte)
		ptBuf := *ptBufPtr
		if cap(ptBuf) < ptLen { ptBuf = make([]byte, ptLen) } // Should fit in 2048 usually
		ptBuf = ptBuf[:ptLen]
		
		binary.BigEndian.PutUint32(ptBuf[0:4], v.SessionID)
		binary.BigEndian.PutUint32(ptBuf[4:8], seq)
		copy(ptBuf[8:], ipPacket)
		
		// Encrypt
		dst = v.AEAD.Seal(dst, nonce, ptBuf, nil)
		bufPool.Put(ptBufPtr)
		
		// Send
		c := v.ConnUDP[idx]
		var addr *net.UDPAddr
		if v.Cfg.Mode == "client" { addr = v.ClientRemoteUDP[idx] } else {
			if destAddr == nil { 
				bufPool.Put(dstPtr) // Don't leak
				return 
			}
			addr = destAddr.(*net.UDPAddr)
		}
		c.WriteToUDP(dst, addr)
		bufPool.Put(dstPtr)
		return
	}
	if v.Cfg.Protocol == "raw" {
		// Raw Mode: [IDX 4][Nonce 24][Ciphertext]
		
		dstPtr := bufPool.Get().(*[]byte)
		dst := *dstPtr; dst = dst[:0]
		
		// 1. IDX Header (4 bytes)
		var idxBytes [4]byte
		binary.BigEndian.PutUint32(idxBytes[:], uint32(idx))
		dst = append(dst, idxBytes[:]...)
		
		// 2. Nonce
		nonce := make([]byte, NonceSize)
		io.ReadFull(rand.Reader, nonce)
		dst = append(dst, nonce...)
		
		// 3. Plaintext
		ptLen := 8 + len(ipPacket)
		ptBufPtr := bufPool.Get().(*[]byte)
		ptBuf := *ptBufPtr
		if cap(ptBuf) < ptLen { ptBuf = make([]byte, ptLen) }
		ptBuf = ptBuf[:ptLen]
		
		binary.BigEndian.PutUint32(ptBuf[0:4], v.SessionID)
		binary.BigEndian.PutUint32(ptBuf[4:8], seq)
		copy(ptBuf[8:], ipPacket)
		
		// 4. Encrypt
		dst = v.AEAD.Seal(dst, nonce, ptBuf, nil)
		bufPool.Put(ptBufPtr)
		
		// 5. Send
		var addr *net.IPAddr
		if v.Cfg.Mode == "client" { 
			addr = v.ClientRemoteIP 
		} else {
			if destAddr == nil { 
				bufPool.Put(dstPtr)
				return 
			}
			addr = destAddr.(*net.IPAddr)
		}
		
		if _, err := v.ConnRaw.WriteToIP(dst, addr); err != nil {
			// Rate limit logs? For debug, print all.
			log.Printf("Raw Write Fail: %v", err)
		}
		bufPool.Put(dstPtr)
		return 
	}
}


// BroadcastToAllPeers 广播数据包给所有已知的 peer
func (v *VPNInstance) BroadcastToAllPeers(data []byte, channelIdx int, seq uint32) {
	var peers []net.Addr
	
	// 收集同一通道的所有 peer
	v.PeerMap.Range(func(key, value interface{}) bool {
		k := key.(uint64)
		// 检查通道索引匹配 (低 32 位存储通道索引)
		if uint32(k&0xFFFFFFFF) == uint32(channelIdx) {
			peers = append(peers, value.(net.Addr))
		}
		return true
	})
	
	// 向所有 peer 发送
	for _, addr := range peers {
		v.SendPacket(data, channelIdx, seq, addr)
	}
}

// --- SOCKS5 ---

func (v *VPNInstance) StartSocks5() {
	l, err := net.Listen("tcp", v.Cfg.SocksBind)
	if err != nil { log.Printf("SOCKS5 Fail: %v", err); return }
	log.Printf("[%s] SOCKS5 Listening %s", v.Cfg.InterfaceName, v.Cfg.SocksBind)
	for {
		c, err := l.Accept(); if err == nil { go v.HandleSocks5(c) }
	}
}

func (v *VPNInstance) HandleSocks5(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 260)
	if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 0x05 { return }
	n := int(buf[1]); io.ReadFull(c, buf[:n]); c.Write([]byte{0x05, 0x00})
	
	if _, err := io.ReadFull(c, buf[:4]); err != nil || buf[1] != 0x01 { return }
	
	var addr string
	switch buf[3] {
	case 1: // IPv4
		io.ReadFull(c, buf[:4])
		addr = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
	case 3: // Domain
		io.ReadFull(c, buf[:1])
		l := int(buf[0]); io.ReadFull(c, buf[:l])
		addr = string(buf[:l])
	default: return
	}
	io.ReadFull(c, buf[:2])
	port := binary.BigEndian.Uint16(buf[:2])
	target := fmt.Sprintf("%s:%d", addr, port)
	
	c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0}) 
	
	d := net.Dialer{
		Control: func(network, address string, rc syscall.RawConn) error {
			return rc.Control(func(fd uintptr) {
				syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, v.Cfg.InterfaceName)
			})
		},
		Timeout: 10 * time.Second,
	}
	rc, err := d.Dial("tcp", target)
	if err != nil { return }
	defer rc.Close()
	
	go io.Copy(c, rc)
	io.Copy(rc, c)
}

func (v *VPNInstance) KeepaliveLoop() {
	tick := time.NewTicker(15 * time.Second)
	
	// Parse Local IP from CIDR
	ip, _, err := net.ParseCIDR(v.Cfg.LocalAddr)
	if err != nil { return }
	ip4 := ip.To4()
	if ip4 == nil { return }

	// Construct IPv4 Header (20 bytes) + Eth (14 bytes)
	// Eth
	pkt := make([]byte, 34)
	// Dst MAC (Random/Broadcast)
	copy(pkt[0:6], []byte{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF})
	// Src MAC (Random)
	rand.Read(pkt[6:12])
	// EthType 0800
	pkt[12] = 0x08; pkt[13] = 0x00
	
	// IP Header
	pkt[14] = 0x45 // Ver 4, IHL 5
	pkt[22] = 0x80 // TTL (Offset 8)
	pkt[23] = 253  // Proto (Offset 9)
	
	// Src IP (Offset 12 -> 14+12=26)
	copy(pkt[26:30], ip4)
	
	// Dst IP (Offset 16 -> 14+16=30)
	copy(pkt[30:34], []byte{255,255,255,255})
	
	for range tick.C {

		
		// Keepalive: Send random payload using SendPacket
		// SendPacket will add Header(8) + Encrypt + Send
		bufPtr := bufPool.Get().(*[]byte); buf := *bufPtr
		if cap(buf) < 34 { buf = make([]byte, 34) }
		payload := buf[:34]
		if _, err := io.ReadFull(rand.Reader, payload); err != nil { bufPool.Put(bufPtr); continue }
		
		seq := atomic.AddUint32(&v.TxSeq, 1) - 1
		
		// Send to ALL ports to maintain NAT mappings for multi-channel mode
		for i := 0; i < v.Cfg.PortCount; i++ {
			v.SendPacket(payload, i, seq, nil)
		}
		bufPool.Put(bufPtr)
	}
}

// --- Reorderer ---

type SeqPacket struct {
	Seq  uint32
	Data []byte
	T    time.Time 
}
type PacketHeap []SeqPacket
func (h PacketHeap) Len() int           { return len(h) }
func (h PacketHeap) Less(i, j int) bool { return h[i].Seq < h[j].Seq }
func (h PacketHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *PacketHeap) Push(x interface{}) { *h = append(*h, x.(SeqPacket)) }
func (h *PacketHeap) Pop() interface{} {
	old := *h; n := len(old); x := old[n-1]; *h = old[0 : n-1]; return x
}

type PacketReorderer struct {
	mu          sync.Mutex
	nextSeq     uint32
	buffer      PacketHeap
	lastSession uint32
	WriteFunc   func([]byte)
}

func NewReorderer() *PacketReorderer {
	r := &PacketReorderer{ buffer: make(PacketHeap, 0) }
	heap.Init(&r.buffer)
	go r.watchdog()
	return r
}

// Push now accepts pre-copied data (ownership transferred to Reorderer/GC)
func (pr *PacketReorderer) Push(sess uint32, seq uint32, data []byte) {
	var toSend [][]byte
	
	pr.mu.Lock()
	
	if sess != pr.lastSession {
		pr.lastSession = sess; pr.nextSeq = seq
		pr.buffer = make(PacketHeap, 0)
	}
	// Handle sequence wrapping and duplicates
	diff := int32(seq - pr.nextSeq)
	// log.Printf("Reorderer Push: Sess %d Seq %d (Expected %d) Diff %d", sess, seq, pr.nextSeq, diff)
	
	if diff < 0 { 
		// log.Printf("Reorderer Drop Old: Seq %d < Next %d", seq, pr.nextSeq)
		pr.mu.Unlock(); return 
	} // Old packet
	
	if seq == pr.nextSeq {
		toSend = append(toSend, data)
		pr.nextSeq++
	} else {
		// Gap Detected
		// log.Printf("Reorderer Gap: Seq %d > Next %d", seq, pr.nextSeq)
		
		// FAST PATH FIX: If gap is large or simple reordering, just process it.
		// For L2 TAP, tight strict ordering isn't always critical (TCP handles it).
		// Preventing STALL is more important.
		
		if pr.buffer.Len() > MaxReorderBuffer || diff > 20 { 
			// If gap is too big, skip ahead!
			log.Printf("Reorderer Skip/Force: Seq %d > Next %d (Diff %d)", seq, pr.nextSeq, diff)
			pr.nextSeq = seq
			toSend = append(toSend, data)
			pr.nextSeq++
			// Clear buffer? No, maybe old packets arrive later.
			// But since we advanced nextSeq, old packets (processed by diff<0 check) will be dropped.
			// This effectively Resets the stream to new Seq.
		} else {
			// Small gap, buffer it
			heap.Push(&pr.buffer, SeqPacket{Seq: seq, Data: data, T: time.Now()})
		}
	}
	
	// Drain buffer if matches new nextSeq
	for pr.buffer.Len() > 0 {
		min := pr.buffer[0]
		if min.Seq == pr.nextSeq {
			heap.Pop(&pr.buffer)
			toSend = append(toSend, min.Data)
			pr.nextSeq++
		} else if min.Seq < pr.nextSeq {
			// Clean up old
			heap.Pop(&pr.buffer)
		} else {
			break
		}
	}
	pr.mu.Unlock()
	
	// IO out of lock
	if len(toSend) > 0 {
		// log.Printf("Reorderer Emit %d packets", len(toSend))
		if pr.WriteFunc != nil {
			for _, p := range toSend {
				pr.WriteFunc(p)
			}
		}
	}
}

// drain is removed, integrated into Push/Watchdog to manage ownership


func (pr *PacketReorderer) watchdog() {
	tick := time.NewTicker(20 * time.Millisecond) // Faster tick
	for range tick.C {
		var toSend [][]byte
		
		pr.mu.Lock()
		if pr.buffer.Len() > 0 {
			head := pr.buffer[0]
			// Strict timeout for head of line blocking
			// Tuned to 200ms: Safer for high-latency/jitter links to prevent TCP collapse
			if time.Since(head.T) > 200*time.Millisecond {
				pr.nextSeq = head.Seq
				heap.Pop(&pr.buffer)
				toSend = append(toSend, head.Data)
				pr.nextSeq++
				
				// Drain consecutive
				for pr.buffer.Len() > 0 {
					min := pr.buffer[0]
					if min.Seq == pr.nextSeq {
						heap.Pop(&pr.buffer)
						toSend = append(toSend, min.Data)
						pr.nextSeq++
					} else { break }
				}
			}
		}
		pr.mu.Unlock()
		
		// IO out of lock
		if pr.WriteFunc != nil {
			for _, p := range toSend {
				pr.WriteFunc(p)
			}
		}
	}
}

func main() {
	cfgPath := flag.String("c", "config.json", "")
	flag.Parse()
	data, _ := os.ReadFile(*cfgPath)
	
	var configs []Config
	if err := json.Unmarshal(data, &configs); err != nil {
		var single Config
		json.Unmarshal(data, &single)
		configs = append(configs, single)
	}

	// Check for duplicate interface names
	seen := make(map[string]bool)
	for _, c := range configs {
		if seen[c.InterfaceName] {
			log.Fatalf("Duplicate Interface Name detected: %s. Each instance must have a unique interface_name.", c.InterfaceName)
		}
		seen[c.InterfaceName] = true
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	
	for _, cfg := range configs {
		instance := NewVPNInstance(cfg)
		instance.Start()
	}
	
	<-c
	log.Println("Shutting down...")
}
func (v *VPNInstance) Start() {
	v.InitTUN()
	v.InitNetwork()
	
	// Start TUN Reader (L3 -> Network)
	go v.TUNReaderLoop()
	
	if v.Cfg.Mode == "client" {
		go v.KeepaliveLoop()
		if v.Cfg.SocksBind != "" {
			go v.StartSocks5()
		}
	} else {
		// Server Mode Log
		log.Printf("[%s] Server Ready (UDP/Raw)", v.Cfg.InterfaceName)
	}

	// Handle signals (Per instance blocking - acceptable for 1 instance)
	// If multiple instances, main() loop will block here and 2nd instance won't start.
	// FIX: Don't block here. Let main() handle signal.
	// Remove signal handling from Start().
	// main.go main() handles signal and waits.
}

func runCmd(name string, args ...string) {
	p, _ := os.StartProcess("/usr/bin/env", append([]string{"env", name}, args...), &os.ProcAttr{Files: []*os.File{nil, nil, nil}})
	p.Wait()
}
