package main

import (
	"crypto/cipher"
	"crypto/sha256"
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

	"golang.zx2c4.com/wireguard/tun"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
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
	Key           string `json:"key"`
	Protocol      string `json:"protocol"`
	MTU           int    `json:"mtu"`

	ServerBindAddr string `json:"server_addr"`
	BasePort       int    `json:"base_port"`

	RemoteIP   string `json:"server_ip"`
	RemotePort int    `json:"server_port"`

	IPProtocolNum int  `json:"ip_protocol_num"`
	Debug         bool `json:"debug"`
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
	if c.MTU == 0 {
		c.MTU = 1400
	}
	if c.InterfaceName == "" {
		c.InterfaceName = "neko0"
	}
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
	AEAD   cipher.AEAD

	// 多核加密
	aeadPool []cipher.AEAD

	// UDP 模式 (双协议支持)
	ConnUDP         *net.UDPConn
	ConnBatchV4     *ipv4.PacketConn
	ConnBatchV6     *ipv6.PacketConn
	IsIPv6          bool
	ClientRemoteUDP *net.UDPAddr
	ServerPeerAddr  atomic.Pointer[net.UDPAddr]

	// Raw 模式
	ConnRaw        []*net.IPConn
	ClientRemoteIP *net.IPAddr
	ServerPeerIP   atomic.Pointer[net.IPAddr]
	rawSendIdx     uint32

	// 性能
	nonceCounter uint64
	SessionID    uint32
	numWorkers   int
	
	// Pipeline Channels
	jobsChan       chan Job
	resultsChanTUN chan Result
	resultsChanUDP chan Result
}

func NewVPNInstance(cfg Config) *VPNInstance {
	cfg.ParseLegacy()
	v := &VPNInstance{Cfg: cfg}

	keyHash := sha256.Sum256([]byte(cfg.Key))
	// 准备 AEAD 算力池 (16核并行预备)
	v.aeadPool = make([]cipher.AEAD, 16)
	for i := 0; i < 16; i++ {
		v.aeadPool[i], _ = chacha20poly1305.NewX(keyHash[:])
	}
	v.AEAD = v.aeadPool[0]

	v.numWorkers = runtime.NumCPU()
	if v.numWorkers > 8 {
		v.numWorkers = 8
	}
	
	// 初始化流水线 Channels
	v.jobsChan = make(chan Job, BatchSize*4) // 加大 Job 缓冲
	v.resultsChanTUN = make(chan Result, BatchSize*4) // 加密结果 -> Net
	v.resultsChanUDP = make(chan Result, BatchSize*4) // 解密结果 -> TUN
	
	v.SessionID = uint32(os.Getpid()) ^ uint32(keyHash[0])<<24
	return v
}

func (v *VPNInstance) StartWorkerPool() {
	for i := 0; i < v.numWorkers; i++ {
		go v.workerLoop(i)
	}
}

func (v *VPNInstance) workerLoop(id int) {
	// 每个 Worker 绑定一个 AEAD
	aead := v.aeadPool[id%len(v.aeadPool)]
	
	for job := range v.jobsChan {
		res := Result{ID: job.ID, Addr: job.Addr}
		
		// 从 pool 获取内存
		dstPtr := bufPool.Get().(*[]byte)
		res.RecyclePtr = dstPtr
		
		if job.Type == 0 { // Encrypt: TUN -> Net
			// encryptInto 会自己处理 dst
			encrypted := v.encryptInto(job.Plain, aead, *dstPtr)
			if encrypted != nil {
				res.Data = encrypted
			} else {
				// Encrypt failed, logic below will handle Recycle via consumer or here?
				// If we send error, Consumer handles recycle.
				res.Err = fmt.Errorf("encrypt failed")
			}
			v.resultsChanTUN <- res
			
		} else { // Decrypt: Net -> TUN
			// 解密逻辑
			buf := *dstPtr
			plain, err := aead.Open(buf[TunOffset:TunOffset], job.Nonce, job.Enc, nil)
			if err == nil {
				res.Data = plain 
			} else {
				res.Err = err
			}
			v.resultsChanUDP <- res
		}
		
		// 原始数据的回收?
		// Job.Plain 是从 TUN Batch Read 来的 buffer slice。
		// 如果是 TUN Read，buffer 是 reusing 的 吗？
		// TUNReaderLoopUDP_Pipeline 里我们会看到。
		// 如果是 new buffer，需要回收。
		// 但 Job 结构体没带 RecyclePtr。
		// 为了简单，我们假设 Reader 负责 Job 的内存管理？
		// 不，Channel 传递所有权。Worker 用完 Job.Plain/Enc 后，需要回收吗？
		// Job.Plain/Enc 通常是 slice。
		// 让我们在 Producer 侧看。
	}
}

// --- Producer: TUN -> Pipeline ---
func (v *VPNInstance) TUNReaderLoopUDP_Pipeline() {
	// 准备 Batch Read 容器
	// 为了避免频繁分配 Job struct，我们可以 reusing?
	// 简单起见，先正常分配。
	
	// 我们需要维护 buffer pool 吗？
	// TUN Read 需要 slice。
	
	jobID := 0
	
	// Batch buffers
	buffs := make([][]byte, BatchSize)
	for i := range buffs {
		buffs[i] = make([]byte, BufSize)
	}
	sizes := make([]int, BatchSize)
	
	for {
		// Batch Read
		n, err := v.TunDev.Read(buffs, sizes, TunOffset)
		if err != nil {
			continue
		}
		if n == 0 {
			// Backoff?
			continue
		}
		
		// 远端地址
		addr := v.ClientRemoteUDP
		if v.Cfg.Mode == "server" {
			addr = v.ServerPeerAddr.Load()
		}
		
		if addr == nil {
			continue
		}

		for i := 0; i < n; i++ {
			if sizes[i] == 0 { continue }
			
			// 必须 copy 数据！因为 buffs 是复用的，而 Job 会被 Worker 异步持有。
			// 如果不 copy，下一次 Read 会覆盖正在处理的数据。
			// 这就是 Pipeline 模式的代价：额外的 Memory Copy。
			// 除非我们由 Pool 分配 buffs，并把 ownership 转给 Job，然后 Reader 拿新 buffer。
			
			// 优化方案：从 Pool 拿 buffer 给 TUN Read。
			// 但 TUN Read 接口需要 [][]byte。
			// 我们可以在这里 copy。300Mbps copy 开销不大。
			// 或者，我们维护一个 Buffer Ring？
			// 简单起见：Copy。
			
			plain := make([]byte, sizes[i] + TunOffset) 
			copy(plain, buffs[i][TunOffset:TunOffset+sizes[i]]) 
			// Wait, encryptInto 不依赖 TunOffset (它只读 payload)。
			// encryptInto(plain, ...)
			// 我们只需要 Payload。
			
			payload := make([]byte, sizes[i])
			copy(payload, buffs[i][TunOffset:TunOffset+sizes[i]])
			
			v.jobsChan <- Job{
				ID:    jobID,
				Plain: payload, // 纯 payload
				Addr:  addr,
				Type:  0, // Encrypt
			}
			jobID++
		}
	}
}

func (v *VPNInstance) Start() {
	if v.Cfg.Debug {
		debugMode = true
	}

	log.Printf("[%s] NekoLink v5.28 (Stable Pipeline 修正版) 启动中 - 核心: %d, MTU: %d",
		v.Cfg.InterfaceName, v.numWorkers, v.Cfg.MTU)

	v.InitTUN()
	v.InitNetwork()
	
	v.StartWorkerPool()
	// 启动双向结果处理协程 (Consumers)
	go v.orderedOutputLoopTUN()
	go v.orderedOutputLoopUDP()

	// v5.26 全新保序流水线架构
	// ... (Reader 启动逻辑同上)
	if v.Cfg.Protocol == "udp" {
		go v.TUNReaderLoopUDP_Pipeline() // TUN -> Pipeline -> resultsChanUDP -> UDP
		go v.udpReaderLoop_Pipeline()    // UDP -> Pipeline -> resultsChanTUN -> TUN
	} else {
		// Raw 模式：TUN 读取使用 numWorkers (8)，网络读取使用 ConnRaw 的实际数量 (4)
		for i := 0; i < v.numWorkers; i++ {
			go v.TUNReaderLoopRaw(i)
		}
		for i := 0; i < len(v.ConnRaw); i++ {
			go v.rawReaderLoop(i)
		}
	}
}

// --- Producer: UDP (Net) -> Pipeline ---
func (v *VPNInstance) udpReaderLoop_Pipeline() {
	if v.IsIPv6 {
		v.udpReaderLoopV6_Pipeline()
	} else {
		v.udpReaderLoopV4_Pipeline()
	}
}

func (v *VPNInstance) udpReaderLoopV4_Pipeline() {
	jobID := 0
	msgs := make([]ipv4.Message, BatchSize)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{make([]byte, BufSize)}
	}
	
	for {
		n, err := v.ConnBatchV4.ReadBatch(msgs, 0)
		if err != nil || n == 0 {
			continue
		}
		
		// Server 模式 Peer 更新 (仅首包)
		if v.Cfg.Mode == "server" {
			if addr, ok := msgs[0].Addr.(*net.UDPAddr); ok {
				v.ServerPeerAddr.Store(addr)
			}
		}

		for i := 0; i < n; i++ {
			nLen := msgs[i].N
			if nLen < NonceSize+Overhead { continue }
			
			// Extract Nonce & Ciphertext
			// struct layout: [Nonce][Ciphertext][Tag]
			// aead.Open expects: nonce, ciphertext(with tag)
			
			raw := msgs[i].Buffers[0][:nLen]
			
			nonce := make([]byte, NonceSize)
			copy(nonce, raw[:NonceSize])
			
			ciphertext := make([]byte, nLen-NonceSize)
			copy(ciphertext, raw[NonceSize:])
			
			v.jobsChan <- Job{
				ID:    jobID,
				Enc:   ciphertext,
				Nonce: nonce,
				Type:  1, // Decrypt
			}
			jobID++
		}
	}
}

func (v *VPNInstance) udpReaderLoopV6_Pipeline() {
	// 类似 V4，结构占位，逻辑相同
	jobID := 0
	msgs := make([]ipv6.Message, BatchSize)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{make([]byte, BufSize)}
	}
	for {
		n, err := v.ConnBatchV6.ReadBatch(msgs, 0)
		if err != nil || n == 0 { continue }
		
		if v.Cfg.Mode == "server" {
			if addr, ok := msgs[0].Addr.(*net.UDPAddr); ok { v.ServerPeerAddr.Store(addr) }
		}
		
		for i := 0; i < n; i++ {
			nLen := msgs[i].N
			if nLen < NonceSize+Overhead { continue }
			
			raw := msgs[i].Buffers[0][:nLen]
			
			nonce := make([]byte, NonceSize)
			copy(nonce, raw[:NonceSize])
			
			ciphertext := make([]byte, nLen-NonceSize)
			copy(ciphertext, raw[NonceSize:])
			
			v.jobsChan <- Job{
				ID: jobID, Enc: ciphertext, Nonce: nonce, Type: 1,
			}
			jobID++
		}
	}
}

// --- Consumer: Pipeline -> UDP (TUN->Net Encrypted) ---
func (v *VPNInstance) orderedOutputLoopUDP() {
	pending := make(map[int]Result)
	expID := 0
	
	for res := range v.resultsChanTUN {
		if res.ID == expID {
			// Fast path: 刚好是下一个
			v.sendResultUDP(res)
			expID++
			// 检查 backlog
			for {
				if next, ok := pending[expID]; ok {
					delete(pending, expID)
					v.sendResultUDP(next)
					expID++
				} else {
					break
				}
			}
		} else {
			// Out of order
			pending[res.ID] = res
		}
	}
}

func (v *VPNInstance) sendResultUDP(res Result) {
	if res.Err == nil && res.Data != nil && res.Addr != nil {
		if addr, ok := res.Addr.(*net.UDPAddr); ok {
			v.ConnUDP.WriteToUDP(res.Data, addr)
		}
	}
	// Recycle
	if res.RecyclePtr != nil {
		bufPool.Put(res.RecyclePtr)
	}
}

// --- Consumer: Pipeline -> TUN (Net->TUN Decrypted) ---
func (v *VPNInstance) orderedOutputLoopTUN() {
	pending := make(map[int]Result)
	expID := 0
	
	// 为了平滑写入 TUN，我们是否需要 batch write? 
	// TunDev.Write 支持 [][]byte。
	// 为了降低系统调用，我们可以小批量聚合 (e.g. 连续 seq 的包)。
	// 但这会增加复杂性。先单包写入 (size=1 batch) 验证功能。
	
	for res := range v.resultsChanUDP {
		if res.ID == expID {
			v.sendResultTUN(res)
			expID++
			for {
				if next, ok := pending[expID]; ok {
					delete(pending, expID)
					v.sendResultTUN(next)
					expID++
				} else {
					break
				}
			}
		} else {
			pending[res.ID] = res
		}
	}
}

func (v *VPNInstance) sendResultTUN(res Result) {
	if res.Err == nil && res.Data != nil {
		// Data 是 plain payload。TUN 需要 Packet with Offset。
		// 在 Worker 中，我们使用的 buf 是从 bufPool 获取的，包含 Offset。
		// Worker: res.Data = plain (slice of dstPtr)
		// Worker Decrypt: plain starts at TunOffset.
		// 所以 res.Data 实际上是 buf[TunOffset:]
		// 我们需要还原完整的 buf [:TunOffset+len(data)]
		// 基于 RecyclePtr，它是 *[]byte -> buf
		
		if res.RecyclePtr != nil {
			buf := *res.RecyclePtr
			// Reconstruct packet with offset
			// data len = plain len
			packetLen := TunOffset + len(res.Data)
			packet := buf[:packetLen]
			
			// 单包写入 TUN
			// 虽然 Write 接受 [][]byte，我们传一个
			v.TunDev.Write([][]byte{packet}, TunOffset)
		}
	}
	// Recycle
	if res.RecyclePtr != nil {
		bufPool.Put(res.RecyclePtr)
	}
}

// --- TUN 初始化 ---

func (v *VPNInstance) InitTUN() {
	dev, err := tun.CreateTUN(v.Cfg.InterfaceName, v.Cfg.MTU)
	if err != nil {
		log.Fatalf("TUN 创建失败: %v", err)
	}
	v.TunDev = dev

	realName, _ := dev.Name()

	runCmd("ip", "addr", "add", v.Cfg.LocalAddr, "dev", realName)
	runCmd("ip", "link", "set", realName, "mtu", fmt.Sprintf("%d", v.Cfg.MTU))
	runCmd("ip", "link", "set", realName, "up")

	// IPv4 转发优化
	runCmdQuiet("sysctl", "-w", "net.ipv4.conf.all.rp_filter=0")
	runCmdQuiet("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", realName))
	
	// IPv6 基础支持
	runCmdQuiet("sysctl", "-w", "net.ipv6.conf.all.forwarding=1")

	v.setupNFTables(realName)
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

	if v.Cfg.Protocol == "raw" {
		protoNum := v.Cfg.IPProtocolNum
		runCmd("nft", "add", "rule", "inet", tableName, "input", "meta", "l4proto", fmt.Sprintf("%d", protoNum), "accept")
	} else {
		port := v.Cfg.BasePort
		runCmd("nft", "add", "rule", "inet", tableName, "input", "udp", "dport", fmt.Sprintf("%d", port), "accept")
	}

	runCmd("nft", "add", "rule", "inet", tableName, "input", "ct", "state", "invalid", "drop")
}

// --- 网络初始化 ---

func (v *VPNInstance) InitNetwork() {
	if v.Cfg.Protocol == "udp" {
		v.initUDP()
	} else {
		v.initRaw()
	}
}

func (v *VPNInstance) initUDP() {
	bindAddr := ":0"
	if v.Cfg.Mode == "server" {
		bindAddr = fmt.Sprintf("%s:%d", v.Cfg.ServerBindAddr, v.Cfg.BasePort)
	} else {
		// 客户端模式检测远端地址类型
		rAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", v.Cfg.RemoteIP, v.Cfg.RemotePort))
		if err == nil {
			v.ClientRemoteUDP = rAddr
			if strings.Contains(rAddr.IP.String(), ":") {
				v.IsIPv6 = true
				bindAddr = "[::]:0"
			}
		}
	}

	// 如果服务端配置了 IPv6 绑定
	if v.Cfg.Mode == "server" && strings.Contains(v.Cfg.ServerBindAddr, ":") {
		v.IsIPv6 = true
	}

	lAddr, _ := net.ResolveUDPAddr("udp", bindAddr)
	conn, err := net.ListenUDP("udp", lAddr)
	if err != nil {
		log.Fatalf("UDP 监听失败: %v", err)
	}

	conn.SetReadBuffer(32 << 20)
	conn.SetWriteBuffer(32 << 20)
	v.ConnUDP = conn

	if v.IsIPv6 {
		v.ConnBatchV6 = ipv6.NewPacketConn(conn)
		log.Printf("[UDP] IPv6 模式已启用 (MTU建议 1400 以下)")
	} else {
		v.ConnBatchV4 = ipv4.NewPacketConn(conn)
		log.Printf("[UDP] IPv4 模式运行中")
	}
}

func (v *VPNInstance) initRaw() {
	numConns := 4
	if runtime.NumCPU() < 4 {
		numConns = runtime.NumCPU()
	}

	// 检测 IP 类型
	testIP := v.Cfg.RemoteIP
	if v.Cfg.Mode == "server" {
		testIP = v.Cfg.ServerBindAddr
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
		if v.Cfg.Mode == "server" && v.Cfg.ServerBindAddr != "0.0.0.0" && v.Cfg.ServerBindAddr != "[::]" {
			lAddr, _ = net.ResolveIPAddr("ip", v.Cfg.ServerBindAddr)
		}
		conn, err := net.ListenIP(protoStr, lAddr)
		if err != nil {
			log.Fatalf("Raw 监听失败: %v", err)
		}
		conn.SetReadBuffer(32 << 20)
		conn.SetWriteBuffer(32 << 20)
		v.ConnRaw[i] = conn
	}

	// v5.17 [重要] 消除 DUP! 重复包
	// 无论开启多少个发送 Socket，只启动一个接收协程，防止 Linux 内核重复投递包
	// go v.rawReaderLoop(0) // Moved to Start()
	if v.Cfg.Mode == "client" {
		v.ClientRemoteIP, _ = net.ResolveIPAddr("ip", v.Cfg.RemoteIP)
	}
}

// --- 读取循环 ---

func (v *VPNInstance) udpReaderLoop() {
	if v.IsIPv6 {
		v.udpReaderLoopV6()
		return
	}
	msgs := make([]ipv4.Message, BatchSize)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{make([]byte, BufSize)}
	}
	for {
		n, err := v.ConnBatchV4.ReadBatch(msgs, 0)
		if err != nil { continue }
		for i := 0; i < n; i++ {
			if msgs[i].N == 0 { continue }
			if v.Cfg.Mode == "server" {
				if addr, ok := msgs[i].Addr.(*net.UDPAddr); ok { v.ServerPeerAddr.Store(addr) }
			}
			v.handleIncomingPacket(msgs[i].Buffers[0][:msgs[i].N])
		}
	}
}

func (v *VPNInstance) udpReaderLoopV6() {
	msgs := make([]ipv6.Message, BatchSize)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{make([]byte, BufSize)}
	}
	for {
		n, err := v.ConnBatchV6.ReadBatch(msgs, 0)
		if err != nil { continue }
		for i := 0; i < n; i++ {
			if msgs[i].N == 0 { continue }
			if v.Cfg.Mode == "server" {
				if addr, ok := msgs[i].Addr.(*net.UDPAddr); ok { v.ServerPeerAddr.Store(addr) }
			}
			v.handleIncomingPacket(msgs[i].Buffers[0][:msgs[i].N])
		}
	}
}

// --- UDP 接收端保序流水线 (v5.23 对称升级版) ---
func (v *VPNInstance) udpReaderLoop_Ordered() {
	if v.IsIPv6 {
		v.udpReaderLoopV6_Batch()
	} else {
		v.udpReaderLoopV4_Batch()
	}
}

func (v *VPNInstance) udpReaderLoopV4_Batch() {
	// 1. 准备 Batch Read 容器
	msgs := make([]ipv4.Message, BatchSize)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{make([]byte, BufSize)}
	}
	
	// 2. 准备解密结果容器
	decryptedBuffs := make([][]byte, BatchSize)
	ptrs := make([]*[]byte, BatchSize)

	for {
		// 3. Batch Read: 一次性吸入大量包，防止 Socket 缓冲区溢出
		n, err := v.ConnBatchV4.ReadBatch(msgs, 0)
		if err != nil {
			continue
		}
		if n == 0 {
			continue
		}

		// 4. 并行解密 (Fork-Join)
		var wg sync.WaitGroup
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func(idx int) {
				defer wg.Done()
				nLen := msgs[idx].N
				if nLen < NonceSize+Overhead {
					return
				}
				
				// Server 模式下更新 Peer 地址 (仅取第一个或每个都更？通常第一个够了，但为了严谨...)
				// 注意：高并发下 Store 可能有性能损耗，但 atomic 很快。
				// 为了性能，我们可以在主线程 Loop 里做，或者这里不做（假设 Session 已建立）
				// 这里为了简单，暂不频繁 Store，或者仅在 idx==0 时 Store
				
				enc := msgs[idx].Buffers[0][:nLen]
				
				// 申请内存用于 TUN Write
				// TUN 需要头部预留 TunOffset
				dstPtr := bufPool.Get().(*[]byte)
				ptrs[idx] = dstPtr
				
				// 解密直接写入偏移后的位置
				buf := *dstPtr
				plain, err := v.aeadPool[idx%16].Open(buf[TunOffset:TunOffset], enc[:NonceSize], enc[NonceSize:], nil)
				if err == nil {
					decryptedBuffs[idx] = plain // slice pointing to dstPtr/buf
				}
			}(i)
		}
		wg.Wait()

		// 5. Server 模式更新 Peer (取第一个包的地址)
		if v.Cfg.Mode == "server" && n > 0 {
			if addr, ok := msgs[0].Addr.(*net.UDPAddr); ok {
				v.ServerPeerAddr.Store(addr)
			}
		}

		// 6. 批量写入 TUN
		// TUN Write 需要 [][]byte，其中每个包前要有 TunOffset 空间
		// 我们在解密时已经留好了。
		var tunBatch [][]byte
		for i := 0; i < n; i++ {
			if decryptedBuffs[i] != nil {
				// decryptedBuffs[i] 是 plain slice，它底层指向 ptrs[i] + TunOffset
				// 我们需要传入包含 TunOffset 头的完整 buffer slice
				// 重构一下：v.TunDev.Write 需要的是包含头部的 buf
				// Open 的 dst 参数我们传的是 buf[TunOffset:TunOffset]，Open 会 append 到这里
				// 所以 decryptedBuffs[i] 现在的长度是 plain len，容量是 buf cap - Offset
				// 我们需要还原出由于 append 增长的 slice，还是说 Open 返回的是 payload?
				// Open(dst, nonce, ciphertext, ad) appends decrypted to dst and returns parallel slice
				
				// 修正：TUN Write 需要整个 buffer 包含 TunOffset
				// 指针是 ptrs[i]
				fullBuf := (*ptrs[i])[:TunOffset+len(decryptedBuffs[i])]
				tunBatch = append(tunBatch, fullBuf)
			}
		}

		if len(tunBatch) > 0 {
			v.TunDev.Write(tunBatch, TunOffset)
		}

		// 7. 清理回收
		for i := 0; i < n; i++ {
			if ptrs[i] != nil {
				bufPool.Put(ptrs[i])
				ptrs[i] = nil
			}
			decryptedBuffs[i] = nil
		}
	}
}

func (v *VPNInstance) udpReaderLoopV6_Batch() {
	// IPv6 对应实现... 为节省篇幅暂略，逻辑相同，除非用户明确需要
	// 鉴于用户使用的是 100.64.x.x (IPv4 CGNAT)，重点保 v4
	// 但为了完整性，这里放一个简单的占位或复制 v4 逻辑改类型
	msgs := make([]ipv6.Message, BatchSize)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{make([]byte, BufSize)}
	}
	decryptedBuffs := make([][]byte, BatchSize)
	ptrs := make([]*[]byte, BatchSize)

	for {
		n, err := v.ConnBatchV6.ReadBatch(msgs, 0)
		if err != nil { continue }
		if n == 0 { continue }

		var wg sync.WaitGroup
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func(idx int) {
				defer wg.Done()
				nLen := msgs[idx].N
				if nLen < NonceSize+Overhead { return }
				enc := msgs[idx].Buffers[0][:nLen]
				dstPtr := bufPool.Get().(*[]byte)
				ptrs[idx] = dstPtr
				buf := *dstPtr
				plain, err := v.aeadPool[idx%16].Open(buf[TunOffset:TunOffset], enc[:NonceSize], enc[NonceSize:], nil)
				if err == nil { decryptedBuffs[idx] = plain }
			}(i)
		}
		wg.Wait()

		if v.Cfg.Mode == "server" && n > 0 {
			if addr, ok := msgs[0].Addr.(*net.UDPAddr); ok { v.ServerPeerAddr.Store(addr) }
		}

		var tunBatch [][]byte
		for i := 0; i < n; i++ {
			if decryptedBuffs[i] != nil {
				fullBuf := (*ptrs[i])[:TunOffset+len(decryptedBuffs[i])]
				tunBatch = append(tunBatch, fullBuf)
			}
		}
		if len(tunBatch) > 0 {
			v.TunDev.Write(tunBatch, TunOffset)
		}
		for i := 0; i < n; i++ {
			if ptrs[i] != nil {
				bufPool.Put(ptrs[i])
				ptrs[i] = nil
			}
			decryptedBuffs[i] = nil
		}
	}
}

func (v *VPNInstance) rawReaderLoop(idx int) {
	conn := v.ConnRaw[idx]
	buf := make([]byte, BufSize)
	for {
		n, addr, err := conn.ReadFromIP(buf)
		if err != nil { continue }
		if n < NonceSize+Overhead { continue }
		if v.Cfg.Mode == "server" { v.ServerPeerIP.Store(addr) }
		v.handleIncomingPacket(buf[:n])
	}
}

// --- UDP 专用 TUN 读取与发送循环 (v5.22 融合保序版) ---
func (v *VPNInstance) TUNReaderLoopUDP_Ordered() {
	buffs := make([][]byte, BatchSize)
	for i := range buffs {
		buffs[i] = make([]byte, BufSize)
	}
	sizes := make([]int, BatchSize)

	// 提前申请好并行结果位
	results := make([][]byte, BatchSize)
	ptrs := make([]*[]byte, BatchSize)

	for {
		// 1. 批捕获：一次抓一波包（高效），杜绝单包系统调用瓶颈
		n, err := v.TunDev.Read(buffs, sizes, TunOffset)
		if err != nil || n == 0 {
			continue
		}

		// 2. 并行加工：多核切菜但不打乱顺序
		var wg sync.WaitGroup
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func(idx int) {
				defer wg.Done()
				if sizes[idx] <= 0 {
					return
				}
				dstPtr := bufPool.Get().(*[]byte)
				ptrs[idx] = dstPtr
				// 使用独占 AEAD (idx%16) 保证线程安全
				results[idx] = v.encryptInto(buffs[idx][TunOffset:TunOffset+sizes[idx]], v.aeadPool[idx%16], *dstPtr)
			}(i)
		}
		wg.Wait()

		// 3. 落地：获取远端地址
		addr := v.ClientRemoteUDP
		if v.Cfg.Mode == "server" {
			addr = v.ServerPeerAddr.Load()
		}

		// 4. 平滑发送：循环调用 WriteToUDP，利用系统调用间隙形成天然 Pacing
		if addr != nil {
			for i := 0; i < n; i++ {
				if results[i] != nil {
					v.ConnUDP.WriteToUDP(results[i], addr)
				}
				// 立即回收内存
				if ptrs[i] != nil {
					bufPool.Put(ptrs[i])
					ptrs[i] = nil
				}
				results[i] = nil
			}
		} else {
			// 仅做内存回收
			for i := 0; i < n; i++ {
				if ptrs[i] != nil {
					bufPool.Put(ptrs[i])
					ptrs[i] = nil
				}
				results[i] = nil
			}
		}
	}
}

// --- Raw 专用 TUN 读取与发送循环 (v5.17) ---
func (v *VPNInstance) TUNReaderLoopRaw(workerID int) {
	buffs := make([][]byte, BatchSize)
	for i := range buffs {
		buffs[i] = make([]byte, BufSize)
	}
	sizes := make([]int, BatchSize)
	aead := v.aeadPool[workerID]

	for {
		n, err := v.TunDev.Read(buffs, sizes, TunOffset)
		if err != nil {
			continue
		}
		for i := 0; i < n; i++ {
			if sizes[i] > 0 {
				v.sendRawOptimized(buffs[i][TunOffset:TunOffset+sizes[i]], aead)
			}
		}
	}
}

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

func (v *VPNInstance) handleIncomingPacket(enc []byte) {
	if len(enc) < NonceSize+Overhead { return }
	plain, err := v.AEAD.Open(enc[NonceSize:NonceSize], enc[:NonceSize], enc[NonceSize:], nil)
	if err == nil && len(plain) > 0 { v.writeTUN(plain) }
}

func (v *VPNInstance) writeTUN(data []byte) {
	bufPtr := bufPool.Get().(*[]byte)
	buf := (*bufPtr)[:TunOffset+len(data)]
	copy(buf[TunOffset:], data)
	v.TunDev.Write([][]byte{buf}, TunOffset)
	bufPool.Put(bufPtr)
}

func main() {
	cfgPath := flag.String("c", "config.json", "Config path")
	debug := flag.Bool("debug", false, "Debug mode")
	flag.Parse()
	debugMode = *debug

	data, _ := os.ReadFile(*cfgPath)
	var configs []Config
	if err := json.Unmarshal(data, &configs); err != nil {
		var single Config
		if err2 := json.Unmarshal(data, &single); err2 == nil { configs = append(configs, single) }
	}

	for _, cfg := range configs { NewVPNInstance(cfg).Start() }
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c
}

func runCmd(name string, args ...string) {
	exec.Command(name, args...).Run()
}
func runCmdQuiet(name string, args ...string) {
	exec.Command(name, args...).Run()
}
