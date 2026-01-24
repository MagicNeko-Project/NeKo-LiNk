package main

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// --- Raw Endpoint (Shadowing) ---

type RawEndpoint struct {
	RealAddr netip.AddrPort // The actual remote IP + Port (for sending)
}

func (e *RawEndpoint) ClearSrc() {}
func (e *RawEndpoint) SrcToString() string { return "" }
func (e *RawEndpoint) DstToString() string {
	// Fake Endpoint for external tools (Masking)
	// Derive a fake port from the RealAddr to distinguish peers in "wg show"
	// but keep IP as 127.0.0.1
	hash := crc32.ChecksumIEEE(e.RealAddr.Addr().AsSlice())
	port := 10000 + (hash % 50000)
	return fmt.Sprintf("127.0.0.1:%d", port)
}
func (e *RawEndpoint) DstToBytes() []byte  { return e.RealAddr.Addr().AsSlice() }
func (e *RawEndpoint) DstIP() netip.Addr   { return e.RealAddr.Addr() }
func (e *RawEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

// --- Raw Bind ---

type RawBind struct {
	mu           sync.RWMutex
	ipv4         *net.IPConn
	ipv6         *net.IPConn
	udpConn      *net.UDPConn
	protoNum     int
	useNATT       bool
	useTCP        bool
	nattLocalPort int
	nattRemotePort int
	handshakeCb  func(data []byte, remote netip.AddrPort) bool
	
	// For Client mode fix: optionally force a remote address if set
	clientRemote netip.Addr
}

func NewRawBind(proto int, useNATT bool, useTCP bool, localPort, remotePort int) *RawBind {
	return &RawBind{
		protoNum:       proto,
		useNATT:        useNATT,
		useTCP:         useTCP,
		nattLocalPort:  localPort,
		nattRemotePort: remotePort,
	}
}

func (b *RawBind) SetHandshakeCallback(cb func([]byte, netip.AddrPort) bool) {
	b.handshakeCb = cb
}

func (b *RawBind) SetClientRemote(addr netip.Addr) {
	b.clientRemote = addr
}

func (b *RawBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	if b.useNATT {
		// Use UDP for NAT-T
		addr := &net.UDPAddr{IP: net.IPv4zero, Port: b.nattLocalPort}
		c, err := net.ListenUDP("udp", addr)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to open UDP for NAT-T: %w", err)
		}
		c.SetReadBuffer(10 * 1024 * 1024)
		c.SetWriteBuffer(10 * 1024 * 1024)
		b.udpConn = c
		return []conn.ReceiveFunc{b.receiveUDP}, uint16(b.nattLocalPort), nil
	}

	// Open Raw Sockets based on Configured Protocol Number
	// IPv4
	protoStr4 := fmt.Sprintf("ip4:%d", b.protoNum)
	v4Addr, _ := net.ResolveIPAddr("ip4", "0.0.0.0")
	v4Conn, err := net.ListenIP(protoStr4, v4Addr)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to open raw ipv4 (proto %d): %w", b.protoNum, err)
	}
	v4Conn.SetReadBuffer(25 * 1024 * 1024)
	v4Conn.SetWriteBuffer(25 * 1024 * 1024)
	b.ipv4 = v4Conn

	// IPv6
	protoStr6 := fmt.Sprintf("ip6:%d", b.protoNum)
	v6Addr, _ := net.ResolveIPAddr("ip6", "::")
	v6Conn, err := net.ListenIP(protoStr6, v6Addr)
	if err == nil {
		v6Conn.SetReadBuffer(25 * 1024 * 1024)
		v6Conn.SetWriteBuffer(25 * 1024 * 1024)
		b.ipv6 = v6Conn
	}

	return []conn.ReceiveFunc{b.receiveIPv4, b.receiveIPv6}, port, nil
}

func (b *RawBind) receiveUDP(packets [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
	if b.udpConn == nil { return 0, net.ErrClosed }
	if len(packets) == 0 { return 0, nil }
	
	buf := packets[0]
	nRead, addr, err := b.udpConn.ReadFromUDP(buf)
	if err != nil { return 0, err }
	
	addrPort, err := netip.ParseAddrPort(addr.String())
	if err != nil { return 0, nil }
	
	ip := addrPort.Addr().Unmap()
	addrPort = netip.AddrPortFrom(ip, addrPort.Port())

	if nRead > 0 && buf[0] == 0xFE {
		if b.handshakeCb != nil {
			packetCopy := make([]byte, nRead)
			copy(packetCopy, buf[:nRead])
			go b.handshakeCb(packetCopy, addrPort)
		}
		return 0, nil
	}
	
	sizes[0] = nRead
	eps[0] = &RawEndpoint{RealAddr: addrPort}
	return 1, nil
}

func (b *RawBind) receiveIPv4(packets [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
	if b.ipv4 == nil { return 0, net.ErrClosed }
	if len(packets) == 0 { return 0, nil }
	
	buf := packets[0]
	nRead, addr, err := b.ipv4.ReadFromIP(buf) // Reads Payload (excluding IP header)
	if err != nil { return 0, err }
	
	payload := buf[:nRead]
	remotePort := 0
	if b.useTCP {
		if len(payload) < 20 { return 0, nil }
		// Strip TCP header: SrcPort(2), DstPort(2), Seq(4), Ack(4), Off(1), Flags(1), Win(2), Sum(2), Urg(2)
		remotePort = int(uint16(payload[0])<<8 | uint16(payload[1]))
		payload = payload[20:]
		nRead -= 20
		copy(buf, payload) // Move payload back
	}

	ip, ok := netip.AddrFromSlice(addr.IP)
	if !ok { return 0, nil }
	ip = ip.Unmap()

	// Check for Handshake/Control Packet (0xFE)
	if nRead > 0 && buf[0] == 0xFE {
		if b.handshakeCb != nil {
			// Copy buffer because we might overwrite it or it's reused
			packetCopy := make([]byte, nRead)
			copy(packetCopy, buf[:nRead])
			go b.handshakeCb(packetCopy, netip.AddrPortFrom(ip, uint16(remotePort)))
		}
		// Consume packet, don't pass to WireGuard
		return 0, nil
	}
	
	sizes[0] = nRead
	eps[0] = &RawEndpoint{RealAddr: netip.AddrPortFrom(ip, uint16(remotePort))}
	return 1, nil
}

func (b *RawBind) receiveIPv6(packets [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
	if b.ipv6 == nil { return 0, net.ErrClosed }
	if len(packets) == 0 { return 0, nil }
	
	buf := packets[0]
	nRead, addr, err := b.ipv6.ReadFromIP(buf)
	if err != nil { return 0, err }
	
	payload := buf[:nRead]
	remotePort := 0
	if b.useTCP {
		if len(payload) < 20 { return 0, nil }
		remotePort = int(uint16(payload[0])<<8 | uint16(payload[1]))
		payload = payload[20:]
		nRead -= 20
		copy(buf, payload)
	}

	ip, ok := netip.AddrFromSlice(addr.IP)
	if !ok { return 0, nil }

	if nRead > 0 && buf[0] == 0xFE {
		if b.handshakeCb != nil {
			packetCopy := make([]byte, nRead)
			copy(packetCopy, buf[:nRead])
			go b.handshakeCb(packetCopy, netip.AddrPortFrom(ip, uint16(remotePort)))
		}
		return 0, nil
	}

	sizes[0] = nRead
	eps[0] = &RawEndpoint{RealAddr: netip.AddrPortFrom(ip, uint16(remotePort))}
	return 1, nil
}

func (b *RawBind) calculateTCPChecksum(header []byte, payload []byte, srcIP, dstIP netip.Addr) uint16 {
	sum := uint32(0)
	payloadLen := len(payload)
	headerLen := len(header)
	totalLen := uint32(headerLen + payloadLen)

	// Pseudo-header
	if srcIP.Is4() {
		src := srcIP.AsSlice()
		dst := dstIP.AsSlice()
		sum += uint32(binary.BigEndian.Uint16(src[0:2])) + uint32(binary.BigEndian.Uint16(src[2:4]))
		sum += uint32(binary.BigEndian.Uint16(dst[0:2])) + uint32(binary.BigEndian.Uint16(dst[2:4]))
		sum += uint32(6) // Proto TCP
		sum += totalLen
	} else {
		src := srcIP.AsSlice()
		dst := dstIP.AsSlice()
		for i := 0; i < 16; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(src[i:i+2]))
			sum += uint32(binary.BigEndian.Uint16(dst[i:i+2]))
		}
		sum += totalLen
		sum += uint32(6)
	}

	// TCP Header
	for i := 0; i < headerLen; i += 2 {
		if i == 16 { continue } // Skip checksum field
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}

	// TCP Payload
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

func (b *RawBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	var target netip.AddrPort
	
	if b.clientRemote.IsValid() {
		target = netip.AddrPortFrom(b.clientRemote, uint16(b.nattRemotePort))
	} else {
		rep, ok := ep.(*RawEndpoint)
		if !ok { return conn.ErrWrongEndpointType }
		target = rep.RealAddr
	}
	
	if !target.Addr().IsValid() { return nil }

	if b.useNATT {
		if b.udpConn == nil { return net.ErrClosed }
		addr := &net.UDPAddr{IP: target.Addr().AsSlice(), Port: int(target.Port())}
		for _, buf := range bufs {
			if len(buf) > 0 {
				b.udpConn.WriteToUDP(buf, addr)
			}
		}
		return nil
	}

	addr, _ := net.ResolveIPAddr("ip", target.Addr().String())
	var c *net.IPConn
	if target.Addr().Is4() {
		c = b.ipv4
	} else {
		c = b.ipv6
	}
	if c == nil { return net.ErrClosed }

	for _, buf := range bufs {
		if len(buf) > 0 {
			if b.useTCP {
				// Zero-allocation TCP encapsulation:
				// Use a pre-allocated header (though we still need to write both to socket)
				// Unfortunately, IPConn.WriteToIP doesn't support multiple buffers like writev.
				// But we can avoid one append by calculating checksum separately and then doing a single concatenation.
				// Even better, avoid append by using a reuseable buffer from a pool if needed.
				
				tcpHeader := make([]byte, 20)
				localPort := b.nattLocalPort
				if localPort == 0 { localPort = 34567 }
				binary.BigEndian.PutUint16(tcpHeader[0:2], uint16(localPort))
				binary.BigEndian.PutUint16(tcpHeader[2:4], target.Port())
				binary.BigEndian.PutUint32(tcpHeader[4:8], 0xDEADBEEF)
				binary.BigEndian.PutUint32(tcpHeader[8:12], 0xCAFEBABE)
				tcpHeader[12] = 0x50 // Offset
				tcpHeader[13] = 0x18 // Flags: PSH+ACK
				binary.BigEndian.PutUint16(tcpHeader[14:16], 0x1000) // Win
				
				// Calculate Checksum without append
				checksum := b.calculateTCPChecksum(tcpHeader, buf, netip.IPv4Unspecified(), target.Addr())
				binary.BigEndian.PutUint16(tcpHeader[16:18], checksum)
				
				// Here we still must concatenate for WriteToIP
				// But we've optimized the checksum part.
				finalBuf := make([]byte, 20+len(buf))
				copy(finalBuf, tcpHeader)
				copy(finalBuf[20:], buf)
				c.WriteToIP(finalBuf, addr)
			} else {
				c.WriteToIP(buf, addr)
			}
		}
	}
	return nil
}

// SendRaw allows sending control packets (e.g. handshake) bypassing WireGuard
func (b *RawBind) SendRaw(data []byte, remote netip.AddrPort) error {
	if b.useNATT {
		if b.udpConn == nil { return net.ErrClosed }
		port := int(remote.Port())
		if port == 0 {
			port = b.nattRemotePort
		}
		addr := &net.UDPAddr{IP: remote.Addr().AsSlice(), Port: port}
		_, err := b.udpConn.WriteToUDP(data, addr)
		return err
	}

	addr, _ := net.ResolveIPAddr("ip", remote.Addr().String())
	var c *net.IPConn
	if remote.Addr().Is4() {
		c = b.ipv4
	} else {
		c = b.ipv6
	}
	if c == nil { return net.ErrClosed }
	
	finalBuf := data
	if b.useTCP {
		tcpHeader := make([]byte, 20)
		localPort := b.nattLocalPort
		if localPort == 0 { localPort = 34567 }
		binary.BigEndian.PutUint16(tcpHeader[0:2], uint16(localPort))
		binary.BigEndian.PutUint16(tcpHeader[2:4], remote.Port())
		binary.BigEndian.PutUint32(tcpHeader[4:8], 0xDEADBEEF)
		tcpHeader[12] = 0x50
		tcpHeader[13] = 0x18
		binary.BigEndian.PutUint16(tcpHeader[14:16], 0x1000)
		
		checksum := b.calculateTCPChecksum(tcpHeader, data, netip.IPv4Unspecified(), remote.Addr())
		binary.BigEndian.PutUint16(tcpHeader[16:18], checksum)
		
		finalBuf = make([]byte, 20+len(data))
		copy(finalBuf, tcpHeader)
		copy(finalBuf[20:], data)
	}

	_, err := c.WriteToIP(finalBuf, addr)
	return err
}

func (b *RawBind) Close() error {
	if b.ipv4 != nil { b.ipv4.Close() }
	if b.ipv6 != nil { b.ipv6.Close() }
	if b.udpConn != nil { b.udpConn.Close() }
	return nil
}

func (b *RawBind) SetMark(mark uint32) error {
	// SO_MARK not critical for basic functionality, skipping for now
	return nil
}
func (b *RawBind) BatchSize() int { return conn.IdealBatchSize }
func (b *RawBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	// UAPI might pass "127.0.0.1:xxx" or real IP.
	// Since handlePeerLine passes what SetEndpoint recvd.
	// We just parse sending IP. 
	// Note: Auto-Config will use IpcSet with 127.0.0.1 to mask.
	// But internally we want RealAddr.
	// Actually, ParseEndpoint is used when *setting* config.
	// If we set Loopback, we get Loopback here.
	// But in Client mode, we force Send to clientRemote.
	// In Server mode? WireGuard learns Endpoint from Receive path usually (Roaming).
	// So ParseEndpoint is often just for initial config.
	return &RawEndpoint{RealAddr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0)}, nil 
}
