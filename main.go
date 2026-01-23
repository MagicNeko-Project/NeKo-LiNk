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

	"github.com/songgao/water"
	"golang.org/x/crypto/chacha20poly1305"
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
	
	Iface *water.Interface
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
	
	return v
}

func (v *VPNInstance) Start() {
	log.Printf("[%s] Starting %s mode on %s...", v.Cfg.InterfaceName, v.Cfg.Mode, v.Cfg.LocalAddr)
	v.InitTAP()
	// Reorderer callback needs Instance method, but struct function pointer is easy
	v.Reorderer.WriteFunc = v.IfaceWrite
	
	v.InitNetwork()

	if v.Cfg.Mode == "client" && v.Cfg.SocksBind != "" {
		go v.StartSocks5()
	}
	if v.Cfg.Mode == "client" {
		go v.KeepaliveLoop()
	}
	go v.TAPReaderLoop()
}

// --- TAP ---

func (v *VPNInstance) InitTAP() {
	configIface := water.Config{ DeviceType: water.TAP }
	configIface.Name = v.Cfg.InterfaceName
	var err error
	v.Iface, err = water.New(configIface)
	if err != nil { log.Fatalf("TAP Init Fail: %v", err) }
	
	go func() {
		time.Sleep(500 * time.Millisecond)
		runCmd("ip", "addr", "add", v.Cfg.LocalAddr, "dev", v.Iface.Name())
		runCmd("ip", "link", "set", v.Iface.Name(), "mtu", fmt.Sprintf("%d", v.Cfg.MTU))
		runCmd("ip", "link", "set", v.Iface.Name(), "up")
		log.Printf("[%s] Interface Up", v.Cfg.InterfaceName)
	}()
}

func (v *VPNInstance) IfaceWrite(data []byte) {
	v.Iface.Write(data)
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
	for {
		bufPtr := bufPool.Get().(*[]byte)
		buf := *bufPtr
		n, src, err := c.ReadFromUDP(buf)
		if err != nil { bufPool.Put(bufPtr); return }
		// Zero-Copy Optimization:
		// Pass bufPtr ownership to ProcessPacket -> Reorderer -> Put back to pool
		// DO NOT Put back here.
		v.ProcessPacket(bufPtr, n, src, idx)
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
	
	if len(encrypted) < NonceSize+Overhead { 
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
	// dst = encrypted[:0] -> Reuses same backing array
	plaintext, err := v.AEAD.Open(encrypted[:0], nonce, ciphertext, nil)
	if err != nil { 
		bufPool.Put(bufPtr)
		return 
	}
	
	// [Sess 4][Seq 4][Ethernet[IP...]]
	// Eth=14. IP Start=22. SrcIP=22+12=34.
	// Min len = 38.
	// Min len = 38.
	if len(plaintext) < 38 { 
		bufPool.Put(bufPtr)
		return 
	}
	
	ethType := binary.BigEndian.Uint16(plaintext[8+12 : 8+14])
	
	// Learn IPv4 unicast source addresses
	if ethType == 0x0800 {
		srcIP := binary.BigEndian.Uint32(plaintext[8+14+12 : 8+14+16])
		if v.Cfg.Mode == "server" {
			// NAT-Aware: Store per-channel address using composite key
			key := (uint64(srcIP) << 32) | uint64(idx)
			v.PeerMap.Store(key, srcAddr)
		}
	}
	
	// Learn IPv6 unicast source addresses
	if ethType == 0x86dd && len(plaintext) >= 8+14+40 {
		// IPv6 源地址在偏移 8+14+8 (16 字节)
		// 使用前 8 字节作为简化实现
		srcIPv6High := binary.BigEndian.Uint64(plaintext[8+14+8 : 8+14+16])
		if v.Cfg.Mode == "server" && srcIPv6High != 0 {
			// XOR with channel index to create unique key
			key := srcIPv6High ^ (uint64(idx) << 56)
			v.PeerMap.Store(key, srcAddr)
		}
	}

	sessionID := binary.BigEndian.Uint32(plaintext[0:4])
	seq := binary.BigEndian.Uint32(plaintext[4:8])
	ethPayload := plaintext[8:]
	
	// Reorderer Push (Deep Copy Mode - Safe)
	// We do NOT pass bufPtr. We pass a copy of ethPayload.
	// But to avoid double copy (one here, one in Push), we can just let Reorderer handle it?
	// Reorderer needs to store specific packet data.
	// Let's alloc a new slice for data here if needed, or let Reorderer do it.
	// Reorderer.Push(..., data []byte) -> it will append/store.
	
	// CRITICAL: We MUST perform a deep copy because bufPtr is about to be recycled!
	// Reorderer.Push will store 'ethPayload'. 
	// If 'ethPayload' is a slice of 'bufPtr', we must copy it.
	
	payloadCopy := make([]byte, len(ethPayload))
	copy(payloadCopy, ethPayload)
	
	v.Reorderer.Push(sessionID, seq, payloadCopy)
	
	// Safe to recycle bufPtr now
	bufPool.Put(bufPtr)
}

func (v *VPNInstance) TAPReaderLoop() {
	for {
		bufPtr := bufPool.Get().(*[]byte)
		buf := *bufPtr
		n, err := v.Iface.Read(buf[8:])
		if err != nil { break }
		
		var destAddr net.Addr
		seq := atomic.AddUint32(&v.TxSeq, 1) - 1
		idx := int(uint64(seq) % uint64(v.Cfg.PortCount))

		if v.Cfg.Mode == "client" {
			// Client sends to Server (handled in SendPacket logic)
		} else {
			// Server Routing
			// Offset 12: EthType
			ethType := binary.BigEndian.Uint16(buf[8+12 : 8+14])
			var dstIP uint32
			
			if ethType == 0x0800 { // IPv4
				// DstIP at 30
				dstIP = binary.BigEndian.Uint32(buf[8+14+16 : 8+14+20])
			} else if ethType == 0x0806 { // ARP
				// Target IP at 14+24 = 38
				dstIP = binary.BigEndian.Uint32(buf[8+14+24 : 8+14+28])
			}

			if dstIP != 0 {
				// Fix: In Raw mode, we only listen/learn on idx 0 (ConnRaw), so we must lookup on idx 0.
				// For UDP, we learn on specific channels.
				lookupIdx := idx
				if v.Cfg.Protocol == "raw" { lookupIdx = 0 }
				
				key := (uint64(dstIP) << 32) | uint64(lookupIdx)
				if val, ok := v.PeerMap.Load(key); ok {
					destAddr = val.(net.Addr)
				}
			}
			
			// 🆕 Check for multicast/broadcast if no unicast route found
			if destAddr == nil && v.Cfg.Mode == "server" {
				if !isMulticastOrBroadcast(buf[8:8+14]) {
					// Unicast but no route found, drop
					bufPool.Put(bufPtr)
					continue
				}
				// Will broadcast after encryption
			}
		}

		binary.BigEndian.PutUint32(buf[0:4], v.SessionID)
		binary.BigEndian.PutUint32(buf[4:8], seq)
		packet := buf[:n+8]
		
		dstPtr := bufPool.Get().(*[]byte)
		dst := *dstPtr; dst = dst[:0]
		nonce := make([]byte, NonceSize)
		io.ReadFull(rand.Reader, nonce)
		dst = append(dst, nonce...)
		dst = v.AEAD.Seal(dst, nonce, packet, nil)
		bufPool.Put(bufPtr)

		v.SendPacket(dst, idx, destAddr)
		bufPool.Put(dstPtr)
	}
}

func (v *VPNInstance) XDPListenerLoop() {
	for {
		pkt, err := v.XDP.ReadPacket()
		if err != nil { continue }
		if pkt == nil { continue }
		
		// Parse UDP Payload
		// Eth(14) + IP(20) + UDP(8) = 42 bytes header
		if len(pkt) < 42 { continue }
		data := pkt[42:]
		
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

func (v *VPNInstance) SendPacket(data []byte, idx int, destAddr net.Addr) {
	// XDP Acceleration:
	// RX is handled via eBPF + AF_XDP (Zero Copy)
	// TX is handled via Standard Syscall (Mixed Mode) because implementing 
	// a full driver-like TX path in userspace is complex and prone to errors.
	if v.Cfg.Protocol == "tcp" {
		v.TCPMutex.Lock(); c := v.ConnTCP; v.TCPMutex.Unlock()
		if c == nil { return }
		l := len(data); h := make([]byte, 2); binary.BigEndian.PutUint16(h, uint16(l))
		c.Write(h); c.Write(data)
		return
	}
	if v.Cfg.Protocol == "udp" {
		c := v.ConnUDP[idx]
		var addr *net.UDPAddr
		if v.Cfg.Mode == "client" { addr = v.ClientRemoteUDP[idx] } else {
			if destAddr == nil { return }
			addr = destAddr.(*net.UDPAddr)
		}
		c.WriteToUDP(data, addr)
		return
	}
	if v.Cfg.Protocol == "raw" {
		payload := make([]byte, 4 + len(data))
		binary.BigEndian.PutUint32(payload[0:4], uint32(idx))
		copy(payload[4:], data)
		var addr *net.IPAddr
		if v.Cfg.Mode == "client" { addr = v.ClientRemoteIP } else {
			if destAddr == nil { return }
			addr = destAddr.(*net.IPAddr)
		}
		v.ConnRaw.WriteToIP(payload, addr)
	}
}

// BroadcastToAllPeers 广播数据包给所有已知的 peer
func (v *VPNInstance) BroadcastToAllPeers(data []byte, channelIdx int) {
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
		v.SendPacket(data, channelIdx, addr)
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
		bufPtr := bufPool.Get().(*[]byte); buf := *bufPtr
		
		binary.BigEndian.PutUint32(buf[0:4], v.SessionID)
		seq := atomic.AddUint32(&v.TxSeq, 1) - 1
		binary.BigEndian.PutUint32(buf[4:8], seq)
		
		copy(buf[8:], pkt)
		packetWithHeader := buf[:8+34]
		
		dstPtr := bufPool.Get().(*[]byte); dst := *dstPtr; dst = dst[:0]
		nonce := make([]byte, NonceSize); rand.Read(nonce)
		dst = append(dst, nonce...)
		dst = v.AEAD.Seal(dst, nonce, packetWithHeader, nil)
		bufPool.Put(bufPtr)
		
		// Send to ALL ports to maintain NAT mappings for multi-channel mode
		for i := 0; i < v.Cfg.PortCount; i++ {
			v.SendPacket(dst, i, nil)
		}
		bufPool.Put(dstPtr)
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
	if diff < 0 { pr.mu.Unlock(); return } // Old packet
	
	if seq == pr.nextSeq {
		toSend = append(toSend, data)
		pr.nextSeq++
		
		// Drain consecutive packets
		for pr.buffer.Len() > 0 {
			min := pr.buffer[0]
			if min.Seq == pr.nextSeq {
				heap.Pop(&pr.buffer)
				toSend = append(toSend, min.Data)
				pr.nextSeq++
			} else { break }
		}
	} else {
		if pr.buffer.Len() > MaxReorderBuffer {
			// Buffer overflow - force pop the oldest
			min := heap.Pop(&pr.buffer).(SeqPacket)
			pr.nextSeq = min.Seq
			toSend = append(toSend, min.Data)
			pr.nextSeq++
			// Drain
			for pr.buffer.Len() > 0 {
				m := pr.buffer[0]
				if m.Seq == pr.nextSeq {
					heap.Pop(&pr.buffer)
					toSend = append(toSend, m.Data)
					pr.nextSeq++
				} else { break }
			}
		}
		heap.Push(&pr.buffer, SeqPacket{Seq: seq, Data: data, T: time.Now()})
	}
	pr.mu.Unlock()

	// IO out of lock
	if pr.WriteFunc != nil {
		for _, p := range toSend {
			pr.WriteFunc(p)
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

func runCmd(name string, args ...string) {
	p, _ := os.StartProcess("/usr/bin/env", append([]string{"env", name}, args...), &os.ProcAttr{Files: []*os.File{nil, nil, nil}})
	p.Wait()
}
