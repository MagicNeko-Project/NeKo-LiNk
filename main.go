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
	"os/exec"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// --- Global Flags ---
var debugMode bool

func logDebug(format string, v ...interface{}) {
	if debugMode {
		log.Printf("[DEBUG] "+format, v...)
	}
}

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

	IPProtocolNum int  `json:"ip_protocol_num"`
	PortCount     int  `json:"port_count"`
	UseXDP        bool `json:"use_xdp"`
	Debug         bool `json:"debug"`

	TargetAddr string `json:"target_addr"` // For wg-raw mode (Server forward target)
	SocksBind string `json:"socks_bind"`
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
	if c.PortCount == 0 {
		c.PortCount = 1
	}
	if c.MTU == 0 {
		c.MTU = 1400
	}
	if c.InterfaceName == "" {
		c.InterfaceName = "neko0"
	}
}

const (
	NonceSize = chacha20poly1305.NonceSizeX
	Overhead  = chacha20poly1305.Overhead
	SeqSize   = 4
	MaxReorderBuffer = 1024
	TunOffset = 16
)

// --- Memory Pool ---
var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 65536+256)
		return &b
	},
}

// --- VPN Instance ---

type VPNInstance struct {
	Cfg Config

	TunDev tun.Device
	AEAD   cipher.AEAD

	Conn     *ipv4.PacketConn
	ConnTCP     net.Conn
	ConnRaw     *net.IPConn
	TCPMutex    sync.Mutex

	PeerMap sync.Map // Stores IP(uint32) -> PeerRoute

	ClientRemoteUDP []*net.UDPAddr
	ClientRemoteIP  *net.IPAddr

	SessionID uint32
	TxSeq     uint32

	WGNat sync.Map // Map[string]*net.UDPConn (NAT for wg-raw server)

	Reorderer *PacketReorderer
}

type PeerRoute struct {
	Addr     net.Addr
	Conn     net.Conn // TCP connection for this peer (if TCP mode)
}

func (v *VPNInstance) logDebug(format string, args ...interface{}) {
	if debugMode {
		prefix := fmt.Sprintf("[%s] ", v.Cfg.InterfaceName)
		log.Printf("[DEBUG] "+prefix+format, args...)
	}
}

func NewVPNInstance(cfg Config) *VPNInstance {
	cfg.ParseLegacy()
	v := &VPNInstance{Cfg: cfg}

	keyHash := sha256.Sum256([]byte(cfg.Key))
	var err error
	v.AEAD, err = chacha20poly1305.NewX(keyHash[:])
	if err != nil {
		log.Fatalf("Crypto Fail: %v", err)
	}

	b := make([]byte, 4)
	rand.Read(b)
	v.SessionID = binary.BigEndian.Uint32(b)

	v.Reorderer = NewReorderer()
	v.Reorderer.LogFunc = v.logDebug

	return v
}

func (v *VPNInstance) Start() {
	if v.Cfg.Debug {
		debugMode = true
	}
	log.Printf("[%s] Starting L3 Engine v4.2 in %s mode on %s...", v.Cfg.InterfaceName, v.Cfg.Mode, v.Cfg.LocalAddr)

	if v.Cfg.Protocol == "wg-raw" {
		log.Printf("[%s] Running in WireGuard-Raw Forwarding Mode", v.Cfg.InterfaceName)
		v.InitNetwork() // Setup Raw/UDP sockets
		return
	}

	v.InitTUN()
	v.Reorderer.WriteFunc = v.IfaceWrite

	v.InitNetwork()

	if v.Cfg.Mode == "client" && v.Cfg.SocksBind != "" {
		go v.StartSocks5()
	}
	if v.Cfg.Mode == "client" {
		go v.KeepaliveLoop()
	}
	go v.TUNReaderLoop()
}

// --- TUN ---

func (v *VPNInstance) InitTUN() {
	dev, err := tun.CreateTUN(v.Cfg.InterfaceName, v.Cfg.MTU)
	if err != nil {
		log.Fatalf("TUN Init Fail: %v", err)
	}
	v.TunDev = dev

	realName, _ := dev.Name()

	// Configure interface (Synchronous)
	runCmd("ip", "addr", "add", v.Cfg.LocalAddr, "dev", realName)
	runCmd("ip", "link", "set", realName, "mtu", fmt.Sprintf("%d", v.Cfg.MTU))
	runCmd("ip", "link", "set", realName, "up")

	// Optimize Routing
	runCmd("sysctl", "-w", "net.ipv4.conf.all.rp_filter=0")
	runCmd("sysctl", "-w", "net.ipv4.conf.default.rp_filter=0")
	runCmd("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", realName))

	// Setup MSS Clamping (NFTables)
	v.setupNFTables(realName)

	log.Printf("[%s] Interface Up & L3 Optimized (Nya~)", realName)
}

func (v *VPNInstance) setupNFTables(iface string) {
	// Ensure table exists
	runCmd("nft", "add", "table", "inet", "nekolink")
	
	// Create dedicated chain for this interface (hook forward)
	chainName := fmt.Sprintf("mss_%s", iface)
	runCmd("nft", "add", "chain", "inet", "nekolink", chainName, "{ type filter hook forward priority 0; policy accept; }")
	
	// Flush old rules in this chain
	runCmd("nft", "flush", "chain", "inet", "nekolink", chainName)
	
	// Add Clamping Rules
	// Inbound
	runCmd("nft", "add", "rule", "inet", "nekolink", chainName, "iifname", iface, "tcp", "flags", "syn", "tcp", "option", "maxseg", "size", "set", "rt", "mtu")
	// Outbound
	runCmd("nft", "add", "rule", "inet", "nekolink", chainName, "oifname", iface, "tcp", "flags", "syn", "tcp", "option", "maxseg", "size", "set", "rt", "mtu")
	
	log.Printf("[%s] NFTables MSS Clamping Applied", iface)
}

func (v *VPNInstance) IfaceWrite(data []byte) {
	if debugMode {
		v.tracePacket("TUN-WRITE", data)
	}

	// Helper for TUN Write with offset
	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	
	totalLen := TunOffset + len(data)
	if cap(buf) < totalLen {
		buf = make([]byte, totalLen)
	}
	
	copy(buf[TunOffset:], data)
	toWrite := buf[:totalLen]
	
	_, err := v.TunDev.Write([][]byte{toWrite}, TunOffset)
	if err != nil {
		v.logDebug("TUN-WRITE Error: %v", err)
	}
	
	// Only put back if it's the original large buffer
	if cap(buf) >= 65536 {
		bufPool.Put(bufPtr)
	}
}

func (v *VPNInstance) tracePacket(prefix string, data []byte) {
	if len(data) < 20 {
		return
	}
	version := data[0] >> 4
	if version == 4 {
		src := net.IPv4(data[12], data[13], data[14], data[15])
		dst := net.IPv4(data[16], data[17], data[18], data[19])
		proto := data[9]
		summary := fmt.Sprintf("[%s] IPv4: %s -> %s (Proto:%d, Len:%d)", prefix, src, dst, proto, len(data))
		if proto == 1 && len(data) >= 28 {
			icmpType := data[20]
			icmpCode := data[21]
			icmpID := binary.BigEndian.Uint16(data[24:26])
			summary += fmt.Sprintf(" [ICMP Type:%d, Code:%d, ID:%d]", icmpType, icmpCode, icmpID)
		}
		v.logDebug(summary)
	} else if version == 6 && len(data) >= 40 {
		src := net.IP(data[8:24])
		dst := net.IP(data[24:40])
		v.logDebug("[%s] IPv6: %s -> %s (Len:%d)", prefix, src, dst, len(data))
	}
}

// --- Network ---

func (v *VPNInstance) InitNetwork() {
	if v.Cfg.Protocol == "tcp" {
		addr := fmt.Sprintf("%s:%d", v.Cfg.ServerBindAddr, v.Cfg.BasePort)
		if v.Cfg.Mode == "client" {
			addr = fmt.Sprintf("%s:%d", v.Cfg.RemoteIP, v.Cfg.RemotePort)
		}

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
		var bindAddrStr string
		if v.Cfg.Mode == "server" {
			bindAddrStr = fmt.Sprintf("%s:%d", v.Cfg.ServerBindAddr, v.Cfg.BasePort)
		} else {
			bindAddrStr = ":0"
		}
		lAddr, _ := net.ResolveUDPAddr("udp", bindAddrStr)
		c, err := net.ListenUDP("udp", lAddr)
		if err != nil { log.Fatal(err) }
		
		c.SetReadBuffer(32 << 20) // Large buffer for single socket
		c.SetWriteBuffer(32 << 20)
		
		v.Conn = ipv4.NewPacketConn(c)

		// Optimize IPv6 Priority (DSCP: EF / 46 -> 0xB8)
		p6 := ipv6.NewPacketConn(c)
		if err := p6.SetTrafficClass(0xB8); err != nil {
			v.logDebug("IPv6 TrafficClass Warn: %v", err)
		}

		if v.Cfg.Mode == "client" {
			rAddrStr := fmt.Sprintf("%s:%d", v.Cfg.RemoteIP, v.Cfg.RemotePort)
			v.ClientRemoteUDP = make([]*net.UDPAddr, 1)
			v.ClientRemoteUDP[0], _ = net.ResolveUDPAddr("udp", rAddrStr)
		}
		
		go v.UDPListenerLoop(v.Conn)
		return
	}

	if v.Cfg.Protocol == "raw" || v.Cfg.Protocol == "wg-raw" {
		protoStr := fmt.Sprintf("ip4:%d", v.Cfg.IPProtocolNum)
		var lAddr *net.IPAddr

		// Fix: Only bind to specific address if Server Mode and not 0.0.0.0
		// Clients usually are behind NAT or have dynamic IP, so binding to nil (0.0.0.0) is safer.
		if v.Cfg.Mode == "server" && v.Cfg.ServerBindAddr != "" && v.Cfg.ServerBindAddr != "0.0.0.0" {
			lAddr, _ = net.ResolveIPAddr("ip", v.Cfg.ServerBindAddr)
		}
		c, err := net.ListenIP(protoStr, lAddr)
		if err != nil { log.Fatal(err) }
		c.SetReadBuffer(16 << 20)
		c.SetWriteBuffer(16 << 20)
		v.ConnRaw = c
		if v.Cfg.Mode == "client" {
			v.ClientRemoteIP, _ = net.ResolveIPAddr("ip", v.Cfg.RemoteIP)
			// Start UDP Listener for Local WG ONLY if protocol is wg-raw
			if v.Cfg.Protocol == "wg-raw" {
				go v.WGRawClientStart()
			}
		}
		go v.RawListenerLoop(c)
	}
}

func (v *VPNInstance) WGRawClientStart() {
    lAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", v.Cfg.BasePort))
    c, err := net.ListenUDP("udp", lAddr)
    if err != nil { log.Fatalf("WG-Raw Client UDP Bind Fail: %v", err) }
    log.Printf("[%s] WG-Raw Client Listening UDP %s", v.Cfg.InterfaceName, lAddr)

    // Store Conn for RawListenerLoop to use for Replies
    v.Conn = ipv4.NewPacketConn(c)
    
    buf := make([]byte, 2000)
    for {
        n, addr, err := c.ReadFromUDP(buf)
        if err != nil { continue }
        // Store the local WG addr to reply to later
        v.WGNat.Store("local_wg", addr)
        
        // Wrap & Send Raw
        // No headers, just payload
        v.ConnRaw.WriteToIP(buf[:n], v.ClientRemoteIP)
    }
}

func (v *VPNInstance) UDPListenerLoop(pc *ipv4.PacketConn) {
	const batchSize = 64 // Increased batch size for single thread efficiency
	msgs := make([]ipv4.Message, batchSize)
	bufPtrs := make([]*[]byte, batchSize)

	for i := range msgs {
		bufPtrs[i] = bufPool.Get().(*[]byte)
		msgs[i].Buffers = [][]byte{*bufPtrs[i]}
	}

	for {
		nMsgs, err := pc.ReadBatch(msgs, 0)
		if err != nil {
			log.Printf("ReadBatch error: %v", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}

		for i := 0; i < nMsgs; i++ {
			msg := &msgs[i]
			srcAddr := v.copyAddr(msg.Addr)
			v.ProcessPacket((*bufPtrs[i])[:msg.N], srcAddr, nil)
		}
	}
}

func (v *VPNInstance) copyAddr(addr net.Addr) net.Addr {
	if addr == nil { return nil }
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		return &net.UDPAddr{
			IP:   append(net.IP(nil), udpAddr.IP...),
			Port: udpAddr.Port,
			Zone: udpAddr.Zone,
		}
	}
	return addr
}

func (v *VPNInstance) RawListenerLoop(c *net.IPConn) {
    // WG-Raw Handling
    if v.Cfg.Protocol == "wg-raw" {
        buf := make([]byte, 65536) // Dedicated buffer for this loop
        for {
            n, src, err := c.ReadFromIP(buf)
            if err != nil { return }
            if n < 1 { continue }
            payload := buf[:n] // In wg-raw, payload starts at 0 (IP header stripped by kernel)

            if v.Cfg.Mode == "client" {
                // Received Raw from Server -> Forward to Local WG UDP
                if val, ok := v.WGNat.Load("local_wg"); ok {
                    addr := val.(*net.UDPAddr)
                    // We need the UDP conn. It's not stored globally?
                    // Issue: WGRawClientStart created the conn but didn't save it.
                    // Fix: Save it in v.ConnUDP[0] or similar.
                    // Let's use v.ConnUDP for convenience (it makes slice).
                    if v.Conn != nil {
                         v.Conn.WriteTo(payload, nil, addr)
                    } else {
                        // Re-find logic.
                        // Better: InitNetwork should save the UDP conn.
                    }
                }
            } else {
                // Server Mode: Received Raw from Client -> Forward to Target WG
                // Check Session
                srcIP := src.String()
                var udpConn *net.UDPConn
                if val, ok := v.WGNat.Load(srcIP); ok {
                    udpConn = val.(*net.UDPConn)
                } else {
                    // Create new Session
                    rAddr, _ := net.ResolveUDPAddr("udp", v.Cfg.TargetAddr)
                    u, err := net.DialUDP("udp", nil, rAddr)
                    if err != nil {
                        v.logDebug("WG-Raw Dial Target Fail: %v", err)
                        continue
                    }
                    udpConn = u
                    v.WGNat.Store(srcIP, udpConn)
                    log.Printf("WG-Raw: New Session %s -> %s", srcIP, v.Cfg.TargetAddr)

                    // Start Return Loop
                    go func(uc *net.UDPConn, targetSrc *net.IPAddr) {
                        b := make([]byte, 2000)
                        defer uc.Close()
                        for {
                            rn, _, err := uc.ReadFromUDP(b)
                            if err != nil { 
                                v.WGNat.Delete(srcIP)
                                return 
                            }
                            v.ConnRaw.WriteToIP(b[:rn], targetSrc)
                        }
                    }(u, src)
                }
                udpConn.Write(payload)
            }
        }
        return
    }

    // Standard Raw Mode
	for {
		bufPtr := bufPool.Get().(*[]byte)
		buf := *bufPtr
		n, src, err := c.ReadFromIP(buf)
		if err != nil {
			bufPool.Put(bufPtr)
			return
		}
		if n < 4 {
			bufPool.Put(bufPtr)
			continue
		}
		v.ProcessPacket(buf[4:n], src, nil)
		bufPool.Put(bufPtr)
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
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		v.TCPMutex.Lock()
		v.ConnTCP = c
		v.TCPMutex.Unlock()
		v.TCPHandler(c)
		v.TCPMutex.Lock()
		v.ConnTCP = nil
		v.TCPMutex.Unlock()
		time.Sleep(1 * time.Second)
	}
}
func (v *VPNInstance) TCPHandler(c net.Conn) {
	defer c.Close()

	if tcpConn, ok := c.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true) // Disable Nagle's Algo (Crucial for VPN!)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetReadBuffer(4 * 1024 * 1024)
		tcpConn.SetWriteBuffer(4 * 1024 * 1024)
	}

	header := make([]byte, 2)
	for {
		if _, err := io.ReadFull(c, header); err != nil { return }
		l := binary.BigEndian.Uint16(header)
		bufPtr := bufPool.Get().(*[]byte)
		buf := *bufPtr
		if cap(buf) < int(l) {
			newB := make([]byte, l)
			buf = newB
		}
		body := buf[:l]
		if _, err := io.ReadFull(c, body); err != nil {
			bufPool.Put(bufPtr)
			return
		}
		v.ProcessPacket(body, v.copyAddr(c.RemoteAddr()), c)
		bufPool.Put(bufPtr)
	}
}

func (v *VPNInstance) ProcessPacket(encrypted []byte, srcAddr net.Addr, conn net.Conn) {
	if len(encrypted) < NonceSize+Overhead { return }
	nonce := encrypted[:NonceSize]
	ciphertext := encrypted[NonceSize:]

	plaintext, err := v.AEAD.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		v.logDebug("Crypto: Decrypt failed from %v", srcAddr)
		return
	}

	if len(plaintext) < 8 { return }

	sessionID := binary.BigEndian.Uint32(plaintext[0:4])
	seq := binary.BigEndian.Uint32(plaintext[4:8])
	ipPacket := plaintext[8:]

	if debugMode {
		v.tracePacket("NET-RX", ipPacket)
	}

	if v.Cfg.Mode == "server" && len(ipPacket) >= 20 {
		version := ipPacket[0] >> 4
		if version == 4 {
			srcIP := binary.BigEndian.Uint32(ipPacket[12:16])
			if srcIP != 0 {
				v.PeerMap.Store(srcIP, PeerRoute{Addr: srcAddr, Conn: conn})
			}
		}
	}

	dataCopy := make([]byte, len(ipPacket))
	copy(dataCopy, ipPacket)
	v.Reorderer.Push(sessionID, seq, dataCopy)
}

func (v *VPNInstance) TUNReaderLoop() {
	const batchSize = 16
	buffs := make([][]byte, batchSize)
	for i := range buffs {
		buffs[i] = make([]byte, 65536)
	}
	sizes := make([]int, batchSize)

	for {
		n, err := v.TunDev.Read(buffs, sizes, TunOffset)
		if err != nil {
			log.Printf("TUN Read Error: %v", err)
			break
		}

		for i := 0; i < n; i++ {
			data := buffs[i][TunOffset : TunOffset+sizes[i]]
			// Move logging to handleOutgoingPacket to filtering takes effect
			v.handleOutgoingPacket(data)
		}
	}
}

func (v *VPNInstance) handleOutgoingPacket(ipPacket []byte) {
	if debugMode {
		v.tracePacket("TUN-READ", ipPacket)
	}

	var destAddr net.Addr
	var destConn net.Conn
	var isBroadcast bool
	seq := atomic.AddUint32(&v.TxSeq, 1) - 1
	// idx := int(uint64(seq) % uint64(v.Cfg.PortCount)) // Removed

	// Determine Routing
	if v.Cfg.Mode == "server" {
		if len(ipPacket) >= 20 {
			version := ipPacket[0] >> 4
			// IPv4
			if version == 4 {
				dstIP := binary.BigEndian.Uint32(ipPacket[16:20])
				// Multicast (224.0.0.0/4) or Broadcast
				if (dstIP & 0xF0000000) == 0xE0000000 || dstIP == 0xFFFFFFFF {
					isBroadcast = true
				} else {
					// Unicast Lookup
					if val, ok := v.PeerMap.Load(dstIP); ok {
						route := val.(PeerRoute)
						destAddr = route.Addr
						destConn = route.Conn
					} else if debugMode {
						v.logDebug("ROUTING: No peer for target, dropping...")
					}
				}
			} else if version == 6 {
				// IPv6
				// Multicast (FF00::/8)
				if ipPacket[24] == 0xff {
					isBroadcast = true
				} else {
					// TODO: IPv6 Unicast Lookup support if needed later
				}
			}
		}
		
		// If Unicast and no route found, return (Drop)
		if !isBroadcast && destAddr == nil { return }
	}

	ptLen := 8 + len(ipPacket)
	ptPtr := bufPool.Get().(*[]byte)
	pt := (*ptPtr)[:ptLen]
	binary.BigEndian.PutUint32(pt[0:4], v.SessionID)
	binary.BigEndian.PutUint32(pt[4:8], seq)
	copy(pt[8:], ipPacket)

	dstPtr := bufPool.Get().(*[]byte)
	dst := (*dstPtr)[:0]
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)
	dst = append(dst, nonce...)
	dst = v.AEAD.Seal(dst, nonce, pt, nil)

	if debugMode && v.Cfg.Mode == "client" {
		v.logDebug("NET-TX: Out %d bytes (Seq:%d) to Server", len(dst), seq)
	} else if debugMode {
		v.logDebug("NET-TX: Out %d bytes (Seq:%d) to %v (Bcast:%v)", len(dst), seq, destAddr, isBroadcast)
	}

	if isBroadcast && v.Cfg.Mode == "server" {
		// Broadcast to all active peers
		// Broadcast to all active peers (Simple)
		v.PeerMap.Range(func(key, value interface{}) bool {
			route := value.(PeerRoute)
			v.SendPacket(dst, route.Addr, route.Conn)
			return true
		})
	} else {
		// Unicast / Client Send
		v.SendPacket(dst, destAddr, destConn)
	}

	bufPool.Put(ptPtr)
	bufPool.Put(dstPtr)
}

func (v *VPNInstance) SendPacket(data []byte, destAddr net.Addr, conn net.Conn) {
	if v.Cfg.Protocol == "tcp" {
		var c net.Conn
		if conn != nil {
			c = conn
		} else {
			v.TCPMutex.Lock()
			c = v.ConnTCP
			v.TCPMutex.Unlock()
		}
		if c == nil { return }
		l := len(data)
		h := make([]byte, 2)
		binary.BigEndian.PutUint16(h, uint16(l))
		c.Write(h)
		c.Write(data)
		return
	}

	if v.Cfg.Protocol == "udp" {
		var addr net.Addr
		if v.Cfg.Mode == "client" {
			addr = v.ClientRemoteUDP[0]
		} else {
			if destAddr == nil { return }
			addr = destAddr
		}
		v.Conn.WriteTo(data, nil, addr)
		return
	}

	if v.Cfg.Protocol == "raw" {
		payload := make([]byte, 4+len(data))
		binary.BigEndian.PutUint32(payload[0:4], 0) // idx is always 0 now
		copy(payload[4:], data)
		var addr *net.IPAddr
		if v.Cfg.Mode == "client" {
			addr = v.ClientRemoteIP
		} else {
			if destAddr == nil { return }
			addr = destAddr.(*net.IPAddr)
		}
		v.ConnRaw.WriteToIP(payload, addr)
	}
}

func (v *VPNInstance) StartSocks5() {
	l, err := net.Listen("tcp", v.Cfg.SocksBind)
	if err != nil {
		log.Printf("SOCKS5 Fail: %v", err)
		return
	}
	log.Printf("[%s] SOCKS5 Listening %s", v.Cfg.InterfaceName, v.Cfg.SocksBind)
	for {
		c, err := l.Accept()
		if err == nil { go v.HandleSocks5(c) }
	}
}

func (v *VPNInstance) HandleSocks5(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 260)
	if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 0x05 { return }
	n := int(buf[1])
	io.ReadFull(c, buf[:n])
	c.Write([]byte{0x05, 0x00})
	if _, err := io.ReadFull(c, buf[:4]); err != nil || buf[1] != 0x01 { return }
	var addr string
	switch buf[3] {
	case 1: // IPv4
		io.ReadFull(c, buf[:4])
		addr = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
	case 3: // Domain
		io.ReadFull(c, buf[:1])
		l := int(buf[0])
		io.ReadFull(c, buf[:l])
		addr = string(buf[:l])
	default: return
	}
	io.ReadFull(c, buf[:2])
	port := binary.BigEndian.Uint16(buf[:2])
	target := fmt.Sprintf("%s:%d", addr, port)
	c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
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
	tick := time.NewTicker(10 * time.Second)
	ip, _, err := net.ParseCIDR(v.Cfg.LocalAddr)
	if err != nil { return }
	ip4 := ip.To4()
	if ip4 == nil { return }

	pkt := make([]byte, 20)
	pkt[0] = 0x45      
	binary.BigEndian.PutUint16(pkt[2:4], 20) // 设置正确的 IP 总长度
	pkt[9] = 253       
	copy(pkt[12:16], ip4)
	copy(pkt[16:20], []byte{255, 255, 255, 255})

	for range tick.C {
		v.logDebug("KEEPALIVE: Sending probe...")
		v.handleOutgoingPacket(pkt)
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
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

type PacketReorderer struct {
	mu          sync.Mutex
	nextSeq     uint32
	buffer      PacketHeap
	lastSession uint32
	WriteFunc   func([]byte)
	LogFunc     func(string, ...interface{})
}

func NewReorderer() *PacketReorderer {
	r := &PacketReorderer{buffer: make(PacketHeap, 0)}
	heap.Init(&r.buffer)
	go r.watchdog()
	return r
}

func (pr *PacketReorderer) log(format string, v ...interface{}) {
	if pr.LogFunc != nil {
		pr.LogFunc(format, v...)
	}
}

func (pr *PacketReorderer) Push(sess uint32, seq uint32, data []byte) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	if sess != pr.lastSession {
		pr.log("Reorderer: Session reset %v -> %v", pr.lastSession, sess)
		pr.lastSession = sess
		pr.nextSeq = seq
		pr.buffer = pr.buffer[:0]
	}
	diff := int32(seq - pr.nextSeq)
	if diff < 0 { return }
	if seq == pr.nextSeq {
		if pr.WriteFunc != nil { pr.WriteFunc(data) }
		pr.nextSeq++
		pr.drain()
		return
	}
	if pr.buffer.Len() > MaxReorderBuffer {
		min := heap.Pop(&pr.buffer).(SeqPacket)
		pr.nextSeq = min.Seq
		if pr.WriteFunc != nil { pr.WriteFunc(min.Data) }
		pr.nextSeq++
		pr.drain()
	}
	heap.Push(&pr.buffer, SeqPacket{Seq: seq, Data: data, T: time.Now()})
}

func (pr *PacketReorderer) drain() {
	for pr.buffer.Len() > 0 {
		min := pr.buffer[0]
		if min.Seq == pr.nextSeq {
			heap.Pop(&pr.buffer)
			if pr.WriteFunc != nil { pr.WriteFunc(min.Data) }
			pr.nextSeq++
		} else { break }
	}
}

func (pr *PacketReorderer) watchdog() {
	tick := time.NewTicker(20 * time.Millisecond)
	for range tick.C {
		pr.mu.Lock()
		if pr.buffer.Len() > 0 {
			head := pr.buffer[0]
			if time.Since(head.T) > 10*time.Millisecond {
				if debugMode {
					pr.log("Reorderer: Force jump Seq %v -> %v (Timeout > 10ms)", pr.nextSeq, head.Seq)
				}
				pr.nextSeq = head.Seq
				heap.Pop(&pr.buffer)
				if pr.WriteFunc != nil { pr.WriteFunc(head.Data) }
				pr.nextSeq++
				pr.drain()
			}
		}
		pr.mu.Unlock()
	}
}

func main() {
	cfgPath := flag.String("c", "config.json", "")
	flag.BoolVar(&debugMode, "debug", false, "debug logs")
	flag.Parse()
	data, err := os.ReadFile(*cfgPath)
	if err != nil { log.Fatalf("Fail config: %v", err) }
	var configs []Config
	if err := json.Unmarshal(data, &configs); err != nil {
		var single Config
		if err2 := json.Unmarshal(data, &single); err2 == nil {
			configs = append(configs, single)
		} else { log.Fatalf("Config: %v", err) }
	}
	seen := make(map[string]bool)
	for _, c := range configs {
		if seen[c.InterfaceName] { log.Fatalf("Dup: %s", c.InterfaceName) }
		seen[c.InterfaceName] = true
	}
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	for _, cfg := range configs {
		instance := NewVPNInstance(cfg)
		instance.Start()
	}
	<-c
	log.Println("Exit...")
}

func runCmd(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}
