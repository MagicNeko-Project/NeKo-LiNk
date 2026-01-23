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
)

// Config 结构定义
type Config struct {
	ServerAddr    string `json:"server_addr"`
	Protocol      string `json:"protocol"`
	IPProtocolNum int    `json:"ip_protocol_num"`
	BasePort      int    `json:"base_port"`
	PortCount     int    `json:"port_count"`
	Key           string `json:"key"`
	LocalAddr     string `json:"local_addr"`
	Mode          string `json:"mode"`
	InterfaceName string `json:"interface_name"`
	MTU           int    `json:"mtu"`
}

const (
	NonceSize = chacha20poly1305.NonceSizeX
	Overhead  = chacha20poly1305.Overhead
	SeqSize   = 4                         // 序号占用 4 字节
	MaxReorderBuffer = 256                // 最大乱序缓存包数，超过这个均值认为丢包，强制推进
)

var (
	config        Config
	aead          cipher.AEAD
	iface         *water.Interface
	remoteAddrUDP []*net.UDPAddr
	remoteAddrIP  *net.IPAddr
	
	connUDP       []*net.UDPConn
	connIP        *net.IPConn
	
	peerPathsUDP  []atomic.Value
	peerPathIP    atomic.Value

	// 轮询索引
	currTxIdx uint64
	// 发送序列号
	globalTxSeq uint32

	// 内存池 (复用 buffer)
	// Buffer size: MTU + Overhead + SeqSize + Nonce + safe margin
	bufPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 2048)
			return &b
		},
	}
	
	// 重排序器
	reorderer *PacketReorderer
)

// --- Min-Heap for Reordering ---
type SeqPacket struct {
	Seq  uint32
	Data []byte // data from pool
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
	totalLost   uint64
}

func NewReorderer() *PacketReorderer {
	r := &PacketReorderer{
		buffer: make(PacketHeap, 0),
		nextSeq: 0, 
	}
	heap.Init(&r.buffer)
	return r
}

// Push 接收一个带序号的包，如果正好是 nextSeq 则直接写入 TUN，
// 否则缓存。如果缓存满了，强制丢弃中间缺失的包，推进 nextSeq。
func (pr *PacketReorderer) Push(seq uint32, data []byte) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	// 1. 初始化 (如果是第一个包，或者序列号回绕很大？)
	// 简单处理：如果是 0 (刚启动)，则接受任何序号? 不，我们 assume start from 0 or 1.
	// 实际上发送端从 0 或 1 开始。我们这里先认为 seq 是单调增的。
	// 为防重启不同步，如果收到 seq 和 nextSeq 差非常大(比如重启了)，重置?
	// 这里简单实现：如果 buffer 为空且 seq >> nextSeq，也许是重置了。
	// 但 VPN 长连接 seq 会一直涨，所以只是简单的 gap check.

	// Case 1: 这是一个旧包/重复包
	// 注意 seq 是 uint32，处理回绕比较麻烦，这里暂时假设连接不会跑满 42亿 包 (4TB流量)
	// 或者简单用差值判断. int32(seq - nextSeq) < 0
	if int32(seq - pr.nextSeq) < 0 {
		// Old packet, drop
		// buffer pool recycle handled by caller? No, we took ownership.
		// Caller passed a slice, possibly from pool. We must Return it if we don't use it.
		// Wait, the 'data' passed here is usually 'plaintext'. 
		// If we use 'bufPool' we should store pointer to the buffer wrapper?
		// For simplicity, let's assume 'data' is a copy or we handle memory higher up.
		// Current design: data is a slice OF the buffer.
		return 
	}

	// Case 2: 正是我们要的包
	if seq == pr.nextSeq {
		writeToTun(data)
		pr.nextSeq++
		pr.drain()
		return
	}

	// Case 3: 未来的包 (乱序)，缓存
	// 检查 buffer 大小防止 OOM
	if pr.buffer.Len() > MaxReorderBuffer {
		// 缓冲区爆了，说明丢包严重。
		// 策略：放弃等待缺失的包，直接跳到堆顶最小的那个包，或者强行插入这个包?
		// 最好是 Pop 堆顶最小的，因为它最接近 nextSeq
		// 我们把 nextSeq 强行提升到堆顶 seq
		pr.forceAdvance()
	}
	
	heap.Push(&pr.buffer, SeqPacket{Seq: seq, Data: data})
}

// drain 尝试处理缓存中连续的包
func (pr *PacketReorderer) drain() {
	for pr.buffer.Len() > 0 {
		minItem := pr.buffer[0] // Peek
		if minItem.Seq == pr.nextSeq {
			heap.Pop(&pr.buffer)
			writeToTun(minItem.Data)
			pr.nextSeq++
		} else if minItem.Seq < pr.nextSeq {
			// 甚至比 nextSeq 还小？说明之前重复Push或者因为forceAdvance导致的旧包残留
			heap.Pop(&pr.buffer)
			// drop
		} else {
			// minItem.Seq > pr.nextSeq (Gap)
			break
		}
	}
}

// forceAdvance 强制推进，丢弃缺失的包
func (pr *PacketReorderer) forceAdvance() {
	if pr.buffer.Len() == 0 { return }
	
	// 找到缓存里最小的 packet
	minItem := heap.Pop(&pr.buffer).(SeqPacket)
	
	// 既然我们等不到 nextSeq ... minItem.Seq-1 之间的包了
	// 就跳过它们
	log.Printf("Packet Loss Detected: Skip %d -> %d", pr.nextSeq, minItem.Seq)
	pr.totalLost += uint64(minItem.Seq - pr.nextSeq)
	pr.nextSeq = minItem.Seq
	
	writeToTun(minItem.Data)
	pr.nextSeq++
	
	pr.drain()
}

func writeToTun(data []byte) {
	if _, err := iface.Write(data); err != nil {
		log.Println("TAP Write Error:", err)
	}
}

// ---------------------------

func main() {
	configFile := flag.String("c", "config.json", "Path to config file")
	flag.Parse()

	loadConfig(*configFile)
	initCrypto()
	initTAP()
	initNetwork()

	reorderer = NewReorderer()

	// 启动主循环
	go startTAPReader()
	startNetworkListeners()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("Shutting down...")
}

func loadConfig(path string) {
	// Fallback logic
	if path == "config.json" {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if _, err := os.Stat("/etc/neko-link/config.json"); err == nil {
				path = "/etc/neko-link/config.json"
				log.Println("Using system config: /etc/neko-link/config.json")
			}
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Error reading config: %v", err)
	}
	if err := json.Unmarshal(data, &config); err != nil {
		log.Fatalf("Error parsing config: %v", err)
	}
	if config.PortCount <= 0 { config.PortCount = 1 }
	if config.MTU <= 0 { config.MTU = 1400 }
	if config.IPProtocolNum <= 0 { config.IPProtocolNum = 233 }
	if config.Protocol == "" { config.Protocol = "udp" }

	log.Printf("Loaded config: Mode=%s, Proto=%s, Local=%s", config.Mode, config.Protocol, config.LocalAddr)
}

func initCrypto() {
	keyHash := sha256.Sum256([]byte(config.Key))
	var err error
	aead, err = chacha20poly1305.NewX(keyHash[:])
	if err != nil {
		log.Fatalf("Failed to create AEAD: %v", err)
	}
}

func initTAP() {
	configIface := water.Config{ DeviceType: water.TAP }
	if config.InterfaceName == "" { config.InterfaceName = "tap0" }
	configIface.Name = config.InterfaceName
	var err error
	iface, err = water.New(configIface)
	if err != nil {
		log.Fatalf("Failed to create TAP interface: %v", err)
	}
	go func() {
		time.Sleep(1 * time.Second)
		runCmd("ip", "addr", "add", config.LocalAddr, "dev", iface.Name())
		runCmd("ip", "link", "set", iface.Name(), "mtu", fmt.Sprintf("%d", config.MTU))
		runCmd("ip", "link", "set", iface.Name(), "up")
		log.Printf("Interface configured: %s", config.LocalAddr)
	}()
}

func runCmd(name string, args ...string) {
	proc, err := os.StartProcess("/usr/bin/env", append([]string{"env", name}, args...), &os.ProcAttr{
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	})
	if err != nil {
		log.Printf("Cmd failed %s: %v", name, err)
		return
	}
	proc.Wait()
}

func initNetwork() {
	if config.Protocol == "udp" {
		initUDP()
	} else {
		initRawIP()
	}
}

func initUDP() {
	connUDP = make([]*net.UDPConn, config.PortCount)
	peerPathsUDP = make([]atomic.Value, config.PortCount)

	if config.Mode == "server" {
		for i := 0; i < config.PortCount; i++ {
			addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", config.ServerAddr, config.BasePort+i))
			if err != nil { log.Fatalf("ResolveUDP failed: %v", err) }
			conn, err := net.ListenUDP("udp", addr)
			if err != nil { log.Fatalf("ListenUDP failed: %v", err) }
			// 优化 Buffer
			conn.SetReadBuffer(4 * 1024 * 1024)
			conn.SetWriteBuffer(4 * 1024 * 1024)
			connUDP[i] = conn
			log.Printf("UDP Listening on %s", addr.String())
		}
	} else {
		remoteAddrUDP = make([]*net.UDPAddr, config.PortCount)
		for i := 0; i < config.PortCount; i++ {
			rAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", config.ServerAddr, config.BasePort+i))
			if err != nil { log.Fatalf("Resolve Remote failed: %v", err) }
			remoteAddrUDP[i] = rAddr
			
			conn, err := net.ListenUDP("udp", nil) // Client Random Port
			if err != nil { log.Fatalf("Client Dial failed: %v", err) }
			conn.SetReadBuffer(4 * 1024 * 1024)
			conn.SetWriteBuffer(4 * 1024 * 1024)
			connUDP[i] = conn
			peerPathsUDP[i].Store(rAddr) 
			log.Printf("UDP Client channel %d ready", i)
		}
	}
}

func initRawIP() {
	protoStr := fmt.Sprintf("ip4:%d", config.IPProtocolNum)
	if isIPv6(config.ServerAddr) {
		protoStr = fmt.Sprintf("ip6:%d", config.IPProtocolNum)
	}

	var lAddr *net.IPAddr
	if config.Mode == "server" {
		if config.ServerAddr != "" && config.ServerAddr != "[::]" && config.ServerAddr != "0.0.0.0" {
			var err error
			lAddr, err = net.ResolveIPAddr("ip", config.ServerAddr)
			if err != nil {
				log.Fatalf("Resolve Server Bind IP failed: %v", err)
			}
		} else {
			lAddr = nil 
		}
	} else {
		lAddr = nil 
	}

	conn, err := net.ListenIP(protoStr, lAddr)
	if err != nil {
		log.Fatalf("ListenIP failed (Need Root?): %v", err)
	}
	// RawIP buffer size
	conn.SetReadBuffer(4 * 1024 * 1024)
	conn.SetWriteBuffer(4 * 1024 * 1024)
	
	connIP = conn
	log.Printf("Raw IP Listening on proto %d (%s)", config.IPProtocolNum, protoStr)

	if config.Mode == "client" {
		rAddr, err := net.ResolveIPAddr("ip", config.ServerAddr)
		if err != nil { log.Fatalf("Resolve Remote IP failed: %v", err) }
		remoteAddrIP = rAddr
		peerPathIP.Store(rAddr)
	}
}

func isIPv6(addr string) bool {
	for i := 0; i < len(addr); i++ {
		if addr[i] == ':' { return true }
	}
	return false
}

// TAP -> Network
func startTAPReader() {
	// Note: We use one buffer from pool, read, encrypt, send.
	for {
		bufPtr := bufPool.Get().(*[]byte)
		buf := *bufPtr
		
		// Read from TAP
		// Leave space for SeqNum (4 bytes) at the beginning of PLAINTEXT
		// Actually, we are prepending SeqNum to PLAINTEXT before encryption.
		// Structure: [Nonce] + Encrypt([SeqNum] + [EthernetPayload]) + [Tag]
		
		// So we read EthernetPayload into buf[4:]
		n, err := iface.Read(buf[4:])
		if err != nil {
			log.Printf("TAP Read Error: %v", err)
			break
		}
		
		// Fill SeqNum at buf[0:4]
		// atomic.AddUint32 returns new value. 
		// Sender start: 0. Receiver start: 0.
		// So we want 0, 1, 2...
		seq := atomic.AddUint32(&globalTxSeq, 1) - 1
		binary.BigEndian.PutUint32(buf[0:4], seq)
		
		packetWithSeq := buf[:n+4] // This is the plaintext

		// Encrypt
		// We need a separate buffer for ciphertext if we want to be clean, 
		// OR we can encrypt in-place if capacity allows.
		// AEAD.Seal appends to dst.
		
		// dst buffer
		dstPtr := bufPool.Get().(*[]byte)
		dst := *dstPtr
		// Reset dst len
		dst = dst[:0]

		nonce := make([]byte, NonceSize)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil { 
			bufPool.Put(bufPtr)
			bufPool.Put(dstPtr)
			continue 
		}
		
		// Seal: appends Nonce + Ciphertext + Tag
		// dst = nonce...
		dst = append(dst, nonce...)
		dst = aead.Seal(dst, nonce, packetWithSeq, nil) // dst now holds full payload
		
		// We are done with plaintext buffer
		bufPool.Put(bufPtr)

		// Send
		idx := uint64(seq) % uint64(config.PortCount)

		if config.Protocol == "udp" {
			sendUDP(idx, dst)
		} else {
			sendRawIP(uint32(idx), dst)
		}
		
		// We can't put dstPtr back immediately because WriteToUDP might be async?
		// No, WriteToUDP is blocking (copies data to kernel). So safe to reuse.
		bufPool.Put(dstPtr)
	}
}

func sendUDP(idx uint64, ciphertext []byte) {
	conn := connUDP[idx]
	var dest *net.UDPAddr

	if config.Mode == "client" {
		dest = remoteAddrUDP[idx]
	} else {
		val := peerPathsUDP[idx].Load()
		if val == nil { return }
		dest = val.(*net.UDPAddr)
	}
	conn.WriteToUDP(ciphertext, dest)
}

func sendRawIP(channelID uint32, ciphertext []byte) {
	// Payload = [ChannelID 4bytes] + [Ciphertext]
	// Need another allocation or use larger buffer?
	// Let's alloc for Raw Mode (simplicity) or optimize later
	payload := make([]byte, 4 + len(ciphertext))
	binary.BigEndian.PutUint32(payload[0:4], channelID)
	copy(payload[4:], ciphertext)

	var dest *net.IPAddr
	if config.Mode == "client" {
		dest = remoteAddrIP
	} else {
		val := peerPathIP.Load()
		if val == nil { return }
		dest = val.(*net.IPAddr)
	}
	connIP.WriteToIP(payload, dest)
}


// Network -> TAP
func startNetworkListeners() {
	if config.Protocol == "udp" {
		startUDPListeners()
	} else {
		startRawIPListener()
	}
}

func startUDPListeners() {
	for i, conn := range connUDP {
		go func(idx int, c *net.UDPConn) {
			// Each listener needs its own buffer
			// Actually ReadFromUDP needs a slice.
			for {
				bufPtr := bufPool.Get().(*[]byte)
				buf := *bufPtr
				
				n, src, err := c.ReadFromUDP(buf)
				if err != nil { 
					bufPool.Put(bufPtr)
					return 
				}
				
				if config.Mode == "server" {
					peerPathsUDP[idx].Store(src)
				}
				
				packet := make([]byte, n)
				copy(packet, buf[:n])
				bufPool.Put(bufPtr)
				
				processIncoming(packet)
			}
		}(i, conn)
	}
}

func startRawIPListener() {
	go func() {
		for {
			bufPtr := bufPool.Get().(*[]byte)
			buf := *bufPtr
			
			n, src, err := connIP.ReadFromIP(buf)
			if err != nil { 
				log.Println("IP Read Error:", err)
				return 
			}
			
			if config.Mode == "server" {
				peerPathIP.Store(src)
			}

			if n < 4 { 
				bufPool.Put(bufPtr)
				continue 
			}
			
			// data := buf[4:n] without copy?
			// Need copy because we put back buffer
			data := make([]byte, n-4)
			copy(data, buf[4:n])
			bufPool.Put(bufPtr)
			
			// We can spawn goroutine if needed, but Reorderer push is fast
			processIncoming(data)
		}
	}()
}

func processIncoming(encrypted []byte) {
	if len(encrypted) < NonceSize+Overhead { return }
	nonce := encrypted[:NonceSize]
	ciphertext := encrypted[NonceSize:]
	
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil { 
		// Decrypt fail
		return 
	}
	
	// Plaintext = [Seq 4] + [Ethernet Payload]
	if len(plaintext) < 4 { return }
	
	seq := binary.BigEndian.Uint32(plaintext[0:4])
	ethPayload := plaintext[4:]
	
	// Push to Reorderer
	// We need to copy ethPayload? 
	// aead.Open reuses storage usually if passed? 
	// 'plaintext' is a new slice or slice of 'ciphertext' backing array?
	// Since 'encrypted' was allocated in listener loop (packet := make...), 
	// it is safe to hand over ownership to Reorderer.
	
	reorderer.Push(seq, ethPayload)
}
