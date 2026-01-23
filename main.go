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

	"golang.zx2c4.com/wireguard/tun"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
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

	IPProtocolNum int  `json:"ip_protocol_num"`
	PortCount     int  `json:"port_count"`
	UseXDP        bool `json:"use_xdp"`

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
	// MaxReorderBuffer 增加缓冲区以适应高速链接下的抖动
	MaxReorderBuffer = 1024
	// TunOffset 保持 0，WireGuard 库会处理必要的头部
	TunOffset = 0
)

// --- Memory Pool ---
// 使用足够承载 GSO 大包（65535+）的缓冲区
var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 65536+256) // 预留包头和加密开销
		return &b
	},
}

// --- VPN Instance ---

type VPNInstance struct {
	Cfg Config

	TunDev tun.Device
	AEAD   cipher.AEAD

	ConnUDP     []*net.UDPConn
	ConnBatch   []*ipv4.PacketConn
	ConnTCP     net.Conn
	ConnRaw     *net.IPConn
	TCPMutex    sync.Mutex

	PeerMap sync.Map

	ClientRemoteUDP []*net.UDPAddr
	ClientRemoteIP  *net.IPAddr

	SessionID uint32
	TxSeq     uint32

	Reorderer *PacketReorderer
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

	return v
}

func (v *VPNInstance) Start() {
	log.Printf("[%s] Starting %s mode on %s...", v.Cfg.InterfaceName, v.Cfg.Mode, v.Cfg.LocalAddr)
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
	// 使用 WireGuard 的 tun 库
	dev, err := tun.CreateTUN(v.Cfg.InterfaceName, v.Cfg.MTU)
	if err != nil {
		log.Fatalf("TUN Init Fail: %v", err)
	}
	v.TunDev = dev

	go func() {
		time.Sleep(500 * time.Millisecond)
		realName, _ := dev.Name()
		runCmd("ip", "addr", "add", v.Cfg.LocalAddr, "dev", realName)
		runCmd("ip", "link", "set", realName, "mtu", fmt.Sprintf("%d", v.Cfg.MTU))
		runCmd("ip", "link", "set", realName, "up")
		log.Printf("[%s] Interface Up (WireGuard-TUN)", realName)
	}()
}

func (v *VPNInstance) IfaceWrite(data []byte) {
	// tun.Device 的 Write 接口接受 [][]byte，我们包装一下
	// 这里以后可以优化成批量写入
	v.TunDev.Write([][]byte{data}, TunOffset)
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
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("[%s] TCP Listen %s", v.Cfg.InterfaceName, addr)
			go v.TCPAcceptLoop(ln)
		} else {
			go v.TCPClientDial(addr)
		}
		return
	}

	if v.Cfg.Protocol == "udp" {
		v.ConnUDP = make([]*net.UDPConn, v.Cfg.PortCount)
		v.ConnBatch = make([]*ipv4.PacketConn, v.Cfg.PortCount)
		v.ClientRemoteUDP = make([]*net.UDPAddr, v.Cfg.PortCount)
		for i := 0; i < v.Cfg.PortCount; i++ {
			var bindAddrStr string
			if v.Cfg.Mode == "server" {
				bindAddrStr = fmt.Sprintf("%s:%d", v.Cfg.ServerBindAddr, v.Cfg.BasePort+i)
			} else {
				bindAddrStr = ":0"
			}
			lAddr, _ := net.ResolveUDPAddr("udp", bindAddrStr)
			c, err := net.ListenUDP("udp", lAddr)
			if err != nil {
				log.Fatal(err)
			}
			// 增加系统级缓冲区
			c.SetReadBuffer(16 << 20)
			c.SetWriteBuffer(16 << 20)
			v.ConnUDP[i] = c
			// 包装成高性能批处理连接
			v.ConnBatch[i] = ipv4.NewPacketConn(c)

			if v.Cfg.Mode == "client" {
				rAddrStr := fmt.Sprintf("%s:%d", v.Cfg.RemoteIP, v.Cfg.RemotePort+i)
				rAddr, _ := net.ResolveUDPAddr("udp", rAddrStr)
				v.ClientRemoteUDP[i] = rAddr
			}
			go v.UDPListenerLoop(i, v.ConnBatch[i])
		}
		return
	}

	if v.Cfg.Protocol == "raw" {
		protoStr := fmt.Sprintf("ip4:%d", v.Cfg.IPProtocolNum)
		var lAddr *net.IPAddr
		if v.Cfg.Mode == "server" && v.Cfg.ServerBindAddr != "0.0.0.0" {
			lAddr, _ = net.ResolveIPAddr("ip", v.Cfg.ServerBindAddr)
		}
		c, err := net.ListenIP(protoStr, lAddr)
		if err != nil {
			log.Fatal(err)
		}
		c.SetReadBuffer(16 << 20)
		c.SetWriteBuffer(16 << 20)
		v.ConnRaw = c
		if v.Cfg.Mode == "client" {
			v.ClientRemoteIP, _ = net.ResolveIPAddr("ip", v.Cfg.RemoteIP)
		}
		go v.RawListenerLoop(c)
	}
}

func (v *VPNInstance) UDPListenerLoop(idx int, pc *ipv4.PacketConn) {
	// 关键优化：一次读取多个包 (recvmmsg)
	const batchSize = 16
	msgs := make([]ipv4.Message, batchSize)
	bufPtrs := make([]*[]byte, batchSize)

	// 初始化缓冲区
	for i := range msgs {
		bufPtrs[i] = bufPool.Get().(*[]byte)
		msgs[i].Buffers = [][]byte{*bufPtrs[i]}
	}

	for {
		nMsgs, err := pc.ReadBatch(msgs, 0)
		if err != nil {
			// 如果出错，稍等片刻尝试重新准备缓冲区
			log.Printf("ReadBatch error: %v", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}

		for i := 0; i < nMsgs; i++ {
			msg := &msgs[i]
			// 处理接收到的包
			// 注意：ProcessPacket 会负责回收或复制数据，因此我们可以直接重用这个槽位
			v.ProcessPacket((*bufPtrs[i])[:msg.N], msg.Addr, idx)

			// 这里我们选择直接重用当前的缓冲区进行下一次 ReadBatch
			// 因为 ProcessPacket 内部发生了解密，结果通常会被传给重排序器（Deep Copy 或 Immutable Slice）
			// 如果 ProcessPacket 以后改为全零拷贝，这里需要更复杂的管理逻辑
		}
	}
}

func (v *VPNInstance) RawListenerLoop(c *net.IPConn) {
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
		// Raw 模式下的处理：跳过 4 字节 IDX
		v.ProcessPacket(buf[4:n], src, 0)
		bufPool.Put(bufPtr)
	}
}

// TCP 暂时保持简单实现，因为本优化指南侧重于 UDP/TUN
func (v *VPNInstance) TCPAcceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
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
	header := make([]byte, 2)
	for {
		if _, err := io.ReadFull(c, header); err != nil {
			return
		}
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
		v.ProcessPacket(body, c.RemoteAddr(), 0)
		bufPool.Put(bufPtr)
	}
}

func (v *VPNInstance) ProcessPacket(encrypted []byte, srcAddr net.Addr, idx int) {
	if len(encrypted) < NonceSize+Overhead {
		return
	}
	nonce := encrypted[:NonceSize]
	ciphertext := encrypted[NonceSize:]

	// 内存优化：直接作为 dst 传入以重用缓冲区（假设不重合）
	// AEAD.Open 可以在底层缓冲区上就地解密
	plaintext, err := v.AEAD.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		return
	}

	// [Sess 4][Seq 4][Ethernet[IP...]]
	if len(plaintext) < 38 {
		return
	}

	// 提取 Session 和 Seq
	sessionID := binary.BigEndian.Uint32(plaintext[0:4])
	seq := binary.BigEndian.Uint32(plaintext[4:8])
	payload := plaintext[8:]

	// 简单的服务端路由学习 (IPv4)
	if v.Cfg.Mode == "server" && len(payload) >= 34 {
		ethType := binary.BigEndian.Uint16(payload[12:14])
		if ethType == 0x0800 {
			srcIP := binary.BigEndian.Uint32(payload[14+12 : 14+16])
			v.PeerMap.Store(srcIP, srcAddr)
		}
	}

	// 传递给重排序器。注意：由于我们要重用缓冲区，这里必须进行深度拷贝。
	// 但如果是在高速链路上，可以在重排序器中管理内存池。
	dataCopy := make([]byte, len(payload))
	copy(dataCopy, payload)
	v.Reorderer.Push(sessionID, seq, dataCopy)
}

func (v *VPNInstance) TUNReaderLoop() {
	// WireGuard TUN 设备支持批量读取
	const batchSize = 16
	buffs := make([][]byte, batchSize)
	for i := range buffs {
		buffs[i] = make([]byte, 65536) // 准备接收 GSO 大包
	}
	sizes := make([]int, batchSize)

	for {
		n, err := v.TunDev.Read(buffs, sizes, TunOffset)
		if err != nil {
			log.Printf("TUN Read Error: %v", err)
			break
		}

		for i := 0; i < n; i++ {
			data := buffs[i][:sizes[i]]
			v.handleOutgoingPacket(data)
		}
	}
}

func (v *VPNInstance) handleOutgoingPacket(data []byte) {
	var destAddr net.Addr
	seq := atomic.AddUint32(&v.TxSeq, 1) - 1
	idx := int(uint64(seq) % uint64(v.Cfg.PortCount))

	if v.Cfg.Mode == "server" {
		// Server 路由逻辑
		if len(data) >= 34 {
			ethType := binary.BigEndian.Uint16(data[12:14])
			var dstIP uint32
			if ethType == 0x0800 { // IPv4
				dstIP = binary.BigEndian.Uint32(data[14+16 : 14+20])
			} else if ethType == 0x0806 { // ARP
				dstIP = binary.BigEndian.Uint32(data[14+24 : 14+28])
			}
			if dstIP != 0 {
				if val, ok := v.PeerMap.Load(dstIP); ok {
					destAddr = val.(net.Addr)
				}
			}
		}
		if destAddr == nil {
			return // 丢弃未知目标
		}
	}

	// 构造加密包
	// [Nonce][Encrypted[Session 4][Seq 4][Payload]]
	ptLen := 8 + len(data)
	ptPtr := bufPool.Get().(*[]byte)
	pt := (*ptPtr)[:ptLen]
	binary.BigEndian.PutUint32(pt[0:4], v.SessionID)
	binary.BigEndian.PutUint32(pt[4:8], seq)
	copy(pt[8:], data)

	// 获取加密结果容器
	dstPtr := bufPool.Get().(*[]byte)
	dst := (*dstPtr)[:0]
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)
	dst = append(dst, nonce...)
	dst = v.AEAD.Seal(dst, nonce, pt, nil)

	v.SendPacket(dst, idx, destAddr)

	bufPool.Put(ptPtr)
	bufPool.Put(dstPtr)
}

func (v *VPNInstance) SendPacket(data []byte, idx int, destAddr net.Addr) {
	if v.Cfg.Protocol == "tcp" {
		v.TCPMutex.Lock()
		c := v.ConnTCP
		v.TCPMutex.Unlock()
		if c == nil {
			return
		}
		l := len(data)
		h := make([]byte, 2)
		binary.BigEndian.PutUint16(h, uint16(l))
		c.Write(h)
		c.Write(data)
		return
	}

	if v.Cfg.Protocol == "udp" {
		pc := v.ConnBatch[idx]
		var addr net.Addr
		if v.Cfg.Mode == "client" {
			addr = v.ClientRemoteUDP[idx]
		} else {
			if destAddr == nil {
				return
			}
			addr = destAddr
		}
		// 这里可以使用 WriteBatch 进行进一步优化，目前先保持 WriteTo
		pc.WriteTo(data, nil, addr)
		return
	}

	if v.Cfg.Protocol == "raw" {
		payload := make([]byte, 4+len(data))
		binary.BigEndian.PutUint32(payload[0:4], uint32(idx))
		copy(payload[4:], data)
		var addr *net.IPAddr
		if v.Cfg.Mode == "client" {
			addr = v.ClientRemoteIP
		} else {
			if destAddr == nil {
				return
			}
			addr = destAddr.(*net.IPAddr)
		}
		v.ConnRaw.WriteToIP(payload, addr)
	}
}

// --- SOCKS5 ---

func (v *VPNInstance) StartSocks5() {
	l, err := net.Listen("tcp", v.Cfg.SocksBind)
	if err != nil {
		log.Printf("SOCKS5 Fail: %v", err)
		return
	}
	log.Printf("[%s] SOCKS5 Listening %s", v.Cfg.InterfaceName, v.Cfg.SocksBind)
	for {
		c, err := l.Accept()
		if err == nil {
			go v.HandleSocks5(c)
		}
	}
}

func (v *VPNInstance) HandleSocks5(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 260)
	if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 0x05 {
		return
	}
	n := int(buf[1])
	io.ReadFull(c, buf[:n])
	c.Write([]byte{0x05, 0x00})

	if _, err := io.ReadFull(c, buf[:4]); err != nil || buf[1] != 0x01 {
		return
	}

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
	default:
		return
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
	if err != nil {
		return
	}
	defer rc.Close()

	go io.Copy(c, rc)
	io.Copy(rc, c)
}

func (v *VPNInstance) KeepaliveLoop() {
	tick := time.NewTicker(15 * time.Second)

	ip, _, err := net.ParseCIDR(v.Cfg.LocalAddr)
	if err != nil {
		return
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return
	}

	// 伪造一个 ARP 请求或类似的 L2 包作为 Keepalive
	pkt := make([]byte, 42)
	copy(pkt[0:6], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) // Broadcast
	rand.Read(pkt[6:12])                                     // Random Src MAC
	pkt[12] = 0x08; pkt[13] = 0x06                             // ARP
	pkt[20] = 0x00; pkt[21] = 0x01                             // Request
	copy(pkt[28:32], ip4)                                    // Sender IP

	for range tick.C {
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
}

func NewReorderer() *PacketReorderer {
	r := &PacketReorderer{buffer: make(PacketHeap, 0)}
	heap.Init(&r.buffer)
	go r.watchdog()
	return r
}

func (pr *PacketReorderer) Push(sess uint32, seq uint32, data []byte) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	if sess != pr.lastSession {
		pr.lastSession = sess
		pr.nextSeq = seq
		pr.buffer = make(PacketHeap, 0)
	}
	if int32(seq-pr.nextSeq) < 0 {
		return
	}
	if seq == pr.nextSeq {
		if pr.WriteFunc != nil {
			pr.WriteFunc(data)
		}
		pr.nextSeq++
		pr.drain()
		return
	}
	if pr.buffer.Len() > MaxReorderBuffer {
		min := heap.Pop(&pr.buffer).(SeqPacket)
		pr.nextSeq = min.Seq
		if pr.WriteFunc != nil {
			pr.WriteFunc(min.Data)
		}
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
			if pr.WriteFunc != nil {
				pr.WriteFunc(min.Data)
			}
			pr.nextSeq++
		} else {
			break
		}
	}
}

func (pr *PacketReorderer) watchdog() {
	tick := time.NewTicker(20 * time.Millisecond) // 更快的触发响应
	for range tick.C {
		pr.mu.Lock()
		if pr.buffer.Len() > 0 {
			head := pr.buffer[0]
			if time.Since(head.T) > 100*time.Millisecond {
				pr.nextSeq = head.Seq
				heap.Pop(&pr.buffer)
				if pr.WriteFunc != nil {
					pr.WriteFunc(head.Data)
				}
				pr.nextSeq++
				pr.drain()
			}
		}
		pr.mu.Unlock()
	}
}

func main() {
	fmt.Println("NekoLink High-Performance Edition starting...")
	cfgPath := flag.String("c", "config.json", "")
	flag.Parse()
	data, _ := os.ReadFile(*cfgPath)

	var configs []Config
	if err := json.Unmarshal(data, &configs); err != nil {
		var single Config
		json.Unmarshal(data, &single)
		configs = append(configs, single)
	}

	seen := make(map[string]bool)
	for _, c := range configs {
		if seen[c.InterfaceName] {
			log.Fatalf("Duplicate Interface Name detected: %s", c.InterfaceName)
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
