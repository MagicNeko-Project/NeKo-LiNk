package main

import (
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
	useNATT      bool
	nattLocalPort int
	nattRemotePort int
	handshakeCb  func(data []byte, remote netip.Addr) bool
	
	// For Client mode fix: optionally force a remote address if set
	clientRemote netip.Addr
}

func NewRawBind(proto int, useNATT bool, localPort, remotePort int) *RawBind {
	return &RawBind{
		protoNum:       proto,
		useNATT:        useNATT,
		nattLocalPort:  localPort,
		nattRemotePort: remotePort,
	}
}

func (b *RawBind) SetHandshakeCallback(cb func([]byte, netip.Addr) bool) {
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
	v4Conn.SetReadBuffer(10 * 1024 * 1024)
	v4Conn.SetWriteBuffer(10 * 1024 * 1024)
	b.ipv4 = v4Conn

	// IPv6
	protoStr6 := fmt.Sprintf("ip6:%d", b.protoNum)
	v6Addr, _ := net.ResolveIPAddr("ip6", "::")
	v6Conn, err := net.ListenIP(protoStr6, v6Addr)
	if err == nil {
		v6Conn.SetReadBuffer(10 * 1024 * 1024)
		v6Conn.SetWriteBuffer(10 * 1024 * 1024)
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
			go b.handshakeCb(packetCopy, ip)
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
	
	ip, ok := netip.AddrFromSlice(addr.IP)
	if !ok { return 0, nil }
	ip = ip.Unmap()

	// Check for Handshake/Control Packet (0xFE)
	if nRead > 0 && buf[0] == 0xFE {
		if b.handshakeCb != nil {
			// Copy buffer because we might overwrite it or it's reused
			packetCopy := make([]byte, nRead)
			copy(packetCopy, buf[:nRead])
			go b.handshakeCb(packetCopy, ip)
		}
		// Consume packet, don't pass to WireGuard
		return 0, nil
	}
	
	sizes[0] = nRead
	eps[0] = &RawEndpoint{RealAddr: netip.AddrPortFrom(ip, 0)}
	return 1, nil
}

func (b *RawBind) receiveIPv6(packets [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
	if b.ipv6 == nil { return 0, net.ErrClosed }
	if len(packets) == 0 { return 0, nil }
	
	buf := packets[0]
	nRead, addr, err := b.ipv6.ReadFromIP(buf)
	if err != nil { return 0, err }
	
	ip, ok := netip.AddrFromSlice(addr.IP)
	if !ok { return 0, nil }

	if nRead > 0 && buf[0] == 0xFE {
		if b.handshakeCb != nil {
			packetCopy := make([]byte, nRead)
			copy(packetCopy, buf[:nRead])
			go b.handshakeCb(packetCopy, ip)
		}
		return 0, nil
	}

	sizes[0] = nRead
	eps[0] = &RawEndpoint{RealAddr: netip.AddrPortFrom(ip, 0)}
	return 1, nil
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
			c.WriteToIP(buf, addr)
		}
	}
	return nil
}

// SendRaw allows sending control packets (e.g. handshake) bypassing WireGuard
func (b *RawBind) SendRaw(data []byte, remote netip.Addr) error {
	if b.useNATT {
		if b.udpConn == nil { return net.ErrClosed }
		addr := &net.UDPAddr{IP: remote.AsSlice(), Port: b.nattRemotePort}
		_, err := b.udpConn.WriteToUDP(data, addr)
		return err
	}

	addr, _ := net.ResolveIPAddr("ip", remote.String())
	var c *net.IPConn
	if remote.Is4() {
		c = b.ipv4
	} else {
		c = b.ipv6
	}
	if c == nil { return net.ErrClosed }
	_, err := c.WriteToIP(data, addr)
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
