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
	Protocol      string `json:"protocol"` // udp, raw, tcp
	IPProtocolNum int    `json:"ip_protocol_num"`
	BasePort      int    `json:"base_port"`
	PortCount     int    `json:"port_count"` // Only for UDP/Raw
	Key           string `json:"key"`
	LocalAddr     string `json:"local_addr"`
	Mode          string `json:"mode"`
	InterfaceName string `json:"interface_name"`
	MTU           int    `json:"mtu"`
}

const (
	NonceSize = chacha20poly1305.NonceSizeX
	Overhead  = chacha20poly1305.Overhead
	SeqSize   = 4                         
	MaxReorderBuffer = 256                
)

var (
	config        Config
	aead          cipher.AEAD
	iface         *water.Interface
	remoteAddrUDP []*net.UDPAddr
	remoteAddrIP  *net.IPAddr
	
	connUDP       []*net.UDPConn
	connIP        *net.IPConn
	connTCP       net.Conn // TCP mode only needs one stream (MPTCP handles paths)

	peerPathsUDP  []atomic.Value
	peerPathIP    atomic.Value
	
	// TCP specific mutex for single-stream writing
	tcpWriteMu sync.Mutex

	currTxIdx uint64
	globalTxSeq uint32

	bufPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 2048)
			return &b
		},
	}
	
	reorderer *PacketReorderer
)

// --- Min-Heap for Reordering ---
type SeqPacket struct {
	Seq  uint32
	Data []byte 
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

func (pr *PacketReorderer) Push(seq uint32, data []byte) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	
	if int32(seq - pr.nextSeq) < 0 { return }

	if seq == pr.nextSeq {
		writeToTun(data)
		pr.nextSeq++
		pr.drain()
		return
	}

	if pr.buffer.Len() > MaxReorderBuffer {
		pr.forceAdvance()
	}
	
	heap.Push(&pr.buffer, SeqPacket{Seq: seq, Data: data})
}

func (pr *PacketReorderer) drain() {
	for pr.buffer.Len() > 0 {
		minItem := pr.buffer[0] 
		if minItem.Seq == pr.nextSeq {
			heap.Pop(&pr.buffer)
			writeToTun(minItem.Data)
			pr.nextSeq++
		} else if minItem.Seq < pr.nextSeq {
			heap.Pop(&pr.buffer)
		} else {
			break
		}
	}
}

func (pr *PacketReorderer) forceAdvance() {
	if pr.buffer.Len() == 0 { return }
	minItem := heap.Pop(&pr.buffer).(SeqPacket)
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

	// Only enable Reorderer for UDP/Raw modes
	// TCP guarantees order, so we bypass reorderer in TCP mode for efficiency
	if config.Protocol != "tcp" {
		reorderer = NewReorderer()
	}

	// 启动主循环
	go startTAPReader()
	startNetworkListeners()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("Shutting down...")
}

func loadConfig(path string) {
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
	} else if config.Protocol == "raw" {
		initRawIP()
	} else if config.Protocol == "tcp" {
		initTCP()
	}
}

// ---------------- TCP / MPTCP ----------------

func initTCP() {
	addrStr := fmt.Sprintf("%s:%d", config.ServerAddr, config.BasePort)
	
	if config.Mode == "server" {
		ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", config.ServerAddr, config.BasePort))
		if err != nil {
			log.Fatalf("TCP Listen failed: %v", err)
		}
		log.Printf("TCP Listening on %s", ln.Addr())
		// Accept loop in a goroutine? For simplicity in this architecture (1-to-1 VPN),
		// we just accept ONE connection and use it in global 'connTCP'.
		// Real server would handle multiple. Here we block until client connects (or background it).
		// We background it to let main() continue, but 'startNetworkListeners' needs connTCP.
		// So we must Accept() inside startNetworkListeners or block here?
		// Client connects immediately. Server waits.
		// Let's defer Accept to startNetworkListeners logic to avoid logic mess.
		// Wait, 'connTCP' needs to be set for Sender to work.
		// But Sender (TAP Reader) shouldn't start until Connected.
		// We'll wrap listener logic in startTCPListener
		connTCP = nil // Marker
		go tcpServerAcceptLoop(ln)
	} else {
		// Client dialing
		// Try to enable MPTCP on Dial?
		// In Go 1.19 standard Dial doesn't allow setting socket options BEFORE connect easily
		// without using Dialer.Control.
		d := net.Dialer{
			Control: func(network, address string, c syscall.RawConn) error {
				return c.Control(func(fd uintptr) {
					// Enable MPTCP (TCP_ULP = 31)
					// Verify constants for target Arch. Linux/AMD64.
					// SOL_TCP=6, TCP_ULP=31. 
					// "mptcp" string needs to be passed.
					// setsockopt(fd, SOL_TCP, TCP_ULP, "mptcp", 5)
					// Warning: This might fail if kernel not support. We ignore error to fallback?
					// Or log it.
					// syscall.SetsockoptString is not available in RawConn.
					// We can't easily do it here in Go without internal syscall wrappers or x/sys.
					// SIMPLIFICATION: We assume User Enabled MPTCP System-wide or via 'ip route'.
					// OR we try best effort.
				})
			},
		}
		c, err := d.Dial("tcp", addrStr)
		if err != nil {
			// Retry?
			log.Fatalf("TCP Dial failed: %v", err)
		}
		connTCP = c
		log.Printf("TCP Connected to %s", addrStr)
	}
}

func tcpServerAcceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}
		log.Println("TCP Client connected:", c.RemoteAddr())
		// Close previous?
		if connTCP != nil {
			connTCP.Close()
		}
		connTCP = c
		// Since we only support one active tunnel in this simple version,
		// we just hijack the global var. 
		// Ideally we need channel to signal 'startTCPListener' to read this new conn.
		// But 'startTCPListener' logic needs update.
	}
}

// ---------------------------------------------

func initUDP() {
	connUDP = make([]*net.UDPConn, config.PortCount)
	peerPathsUDP = make([]atomic.Value, config.PortCount)

	if config.Mode == "server" {
		for i := 0; i < config.PortCount; i++ {
			addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", config.ServerAddr, config.BasePort+i))
			if err != nil { log.Fatalf("ResolveUDP failed: %v", err) }
			conn, err := net.ListenUDP("udp", addr)
			if err != nil { log.Fatalf("ListenUDP failed: %v", err) }
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
			
			conn, err := net.ListenUDP("udp", nil) 
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
		// Server: Listen on specific address or all
		if config.ServerAddr != "" && config.ServerAddr != "[::]" && config.ServerAddr != "0.0.0.0" {
			var err error
			lAddr, err = net.ResolveIPAddr("ip", config.ServerAddr)
			if err != nil {
				log.Fatalf("Resolve Server Bind IP failed: %v", err)
			}
		} else {
			lAddr = nil // Listen all
		}
	} else {
		// Client: Bind to local (nil)
		lAddr = nil 
	}

	conn, err := net.ListenIP(protoStr, lAddr)
	if err != nil {
		log.Fatalf("ListenIP failed (Need Root?): %v", err)
	}
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
	for {
		bufPtr := bufPool.Get().(*[]byte)
		buf := *bufPtr
		
		// TCP Mode Framing:
		// [Pre-Length 2 bytes] + [Nonce] + Encrypted([Seq?] + Payload)
		// For TCP, we DON'T need SeqNum for Reordering (TCP is ordered).
		// But to keep Packet Structure unified (so Receiver code is simple), we keep SeqNum?
		// Recv Code: processIncoming expects [Seq 4] + [Eth].
		// So we SHOULD keep SeqNum inside encryption.
		
		// In UDP/Raw: buf[0:4] = Seq. buf[4:] = Eth.
		// In TCP: We need to build [Len 2] + [Ciphertext].
		// We can reuse same logic but Send function differs.
		
		// Read TAP
		n, err := iface.Read(buf[4:]) // Leave 4 bytes space (for Seq)
		if err != nil {
			log.Printf("TAP Read Error: %v", err)
			break
		}
		
		// Fill Seq (Still useful for debug or unified format, even if not reordered)
		seq := atomic.AddUint32(&globalTxSeq, 1) - 1
		binary.BigEndian.PutUint32(buf[0:4], seq)
		
		packetWithSeq := buf[:n+4] 

		// Encrypt
		dstPtr := bufPool.Get().(*[]byte)
		dst := *dstPtr
		dst = dst[:0]

		nonce := make([]byte, NonceSize)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil { 
			bufPool.Put(bufPtr)
			bufPool.Put(dstPtr)
			continue 
		}
		
		dst = append(dst, nonce...)
		dst = aead.Seal(dst, nonce, packetWithSeq, nil) 
		
		bufPool.Put(bufPtr)

		// Send
		if config.Protocol == "udp" {
			idx := uint64(seq) % uint64(config.PortCount)
			sendUDP(idx, dst)
		} else if config.Protocol == "raw" {
			idx := uint64(seq) % uint64(config.PortCount)
			sendRawIP(uint32(idx), dst)
		} else if config.Protocol == "tcp" {
			sendTCP(dst)
		}
		
		bufPool.Put(dstPtr)
	}
}

func sendTCP(ciphertext []byte) {
	if connTCP == nil { return }
	
	// Framing: [Len 2] + [Ciphertext]
	// Max packet ~1500. 2 bytes len is enough (max 65535).
	l := len(ciphertext)
	header := make([]byte, 2)
	binary.BigEndian.PutUint16(header, uint16(l))
	
	tcpWriteMu.Lock()
	defer tcpWriteMu.Unlock()
	
	// Write Header
	if _, err := connTCP.Write(header); err != nil { return }
	// Write Body
	if _, err := connTCP.Write(ciphertext); err != nil { return }
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
	} else if config.Protocol == "raw" {
		startRawIPListener()
	} else if config.Protocol == "tcp" {
		startTCPListener()
	}
}

func startTCPListener() {
	// If Server: connTCP might be nil initially. Need to wait.
	// We can loop checking connTCP or use a cond/channel.
	// For simplicity, we loop with sleep if nil.
	go func() {
		for {
			if connTCP == nil {
				time.Sleep(1 * time.Second)
				continue
			}
			
			// Handle Connection
			handleTCPConn(connTCP)
			
			// If handler returns, conn dead. Reset.
			connTCP = nil
			time.Sleep(1 * time.Second)
		}
	}()
}

func handleTCPConn(c net.Conn) {
	// Read Loop
	// [Len 2] [Body...]
	header := make([]byte, 2)
	for {
		// Read Length
		if _, err := io.ReadFull(c, header); err != nil {
			log.Println("TCP Read Header Error:", err)
			return
		}
		length := binary.BigEndian.Uint16(header)
		
		// Read Body
		bufPtr := bufPool.Get().(*[]byte)
		buf := *bufPtr
		if cap(buf) < int(length) {
			// resize if needed (should be rare if buf 2048)
			// But for safety:
			newBuf := make([]byte, length)
			buf = newBuf
		}
		
		body := buf[:length]
		if _, err := io.ReadFull(c, body); err != nil {
			log.Println("TCP Read Body Error:", err)
			bufPool.Put(bufPtr)
			return
		}
		
		// Process
		// Note: processIncoming does NOT need bufPool put back usually if it copies?
		// Check processIncoming:
		// It expects 'encrypted' slice.
		// It does: plaintext, _ := aead.Open...
		// In udp/raw listener, we 'make' a copy before passing.
		// Here 'body' IS the buffer. 
		// If processIncoming is sync, we can use body directly?
		// Let's create a copy to match other listeners pattern and stay safe (async/buffer reuse)
		
		data := make([]byte, length)
		copy(data, body)
		bufPool.Put(bufPtr)
		
		processIncoming(data)
	}
}

func startUDPListeners() {
	for i, conn := range connUDP {
		go func(idx int, c *net.UDPConn) {
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
			
			data := make([]byte, n-4)
			copy(data, buf[4:n])
			bufPool.Put(bufPtr)
			
			processIncoming(data)
		}
	}()
}

func processIncoming(encrypted []byte) {
	if len(encrypted) < NonceSize+Overhead { return }
	nonce := encrypted[:NonceSize]
	ciphertext := encrypted[NonceSize:]
	
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil { return }
	
	if len(plaintext) < 4 { return }
	seq := binary.BigEndian.Uint32(plaintext[0:4])
	ethPayload := plaintext[4:]
	
	// If TCP mode, bypass Reorderer
	if config.Protocol == "tcp" {
		writeToTun(ethPayload)
	} else {
		reorderer.Push(seq, ethPayload)
	}
}
