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
	"sync"
	"sync/atomic"
	"syscall"

	"golang.zx2c4.com/wireguard/tun"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
)

// --- 全局调试开关 ---
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
	BatchSize = 16
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

	// UDP 模式 (支持批处理)
	ConnUDP         *net.UDPConn
	ConnBatch       *ipv4.PacketConn
	ClientRemoteUDP *net.UDPAddr
	ServerPeerAddr  *net.UDPAddr

	// Raw 模式 (多连接并发)
	ConnRaw        []*net.IPConn
	ClientRemoteIP *net.IPAddr
	ServerPeerIP   *net.IPAddr
	rawSendIdx     uint32 // 轮询发送索引

	// 性能优化
	nonceCounter uint64
	SessionID    uint32
}

func NewVPNInstance(cfg Config) *VPNInstance {
	cfg.ParseLegacy()
	v := &VPNInstance{Cfg: cfg}

	keyHash := sha256.Sum256([]byte(cfg.Key))
	var err error
	v.AEAD, err = chacha20poly1305.NewX(keyHash[:])
	if err != nil {
		log.Fatalf("加密初始化失败: %v", err)
	}

	v.SessionID = uint32(os.Getpid()) ^ uint32(keyHash[0])<<24

	return v
}

func (v *VPNInstance) Start() {
	if v.Cfg.Debug {
		debugMode = true
	}

	log.Printf("[%s] NekoLink v5.3 (Raw优化版) 启动中 - 模式: %s, 协议: %s",
		v.Cfg.InterfaceName, v.Cfg.Mode, v.Cfg.Protocol)

	v.InitTUN()
	v.InitNetwork()

	go v.TUNReaderLoop()
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

	runCmd("sysctl", "-w", "net.ipv4.conf.all.rp_filter=0")
	runCmd("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", realName))

	log.Printf("[%s] TUN 接口已启动 (IP: %s, MTU: %d) Nya~",
		realName, v.Cfg.LocalAddr, v.Cfg.MTU)
}

// --- 网络初始化 ---

func (v *VPNInstance) InitNetwork() {
	switch v.Cfg.Protocol {
	case "udp":
		v.initUDP()
	case "raw":
		v.initRaw()
	default:
		log.Fatalf("不支持的协议: %s", v.Cfg.Protocol)
	}
}

func (v *VPNInstance) initUDP() {
	var bindAddr string
	if v.Cfg.Mode == "server" {
		bindAddr = fmt.Sprintf("%s:%d", v.Cfg.ServerBindAddr, v.Cfg.BasePort)
	} else {
		bindAddr = ":0"
	}

	lAddr, _ := net.ResolveUDPAddr("udp", bindAddr)
	conn, err := net.ListenUDP("udp", lAddr)
	if err != nil {
		log.Fatalf("UDP 监听失败: %v", err)
	}

	conn.SetReadBuffer(16 << 20)
	conn.SetWriteBuffer(16 << 20)
	v.ConnUDP = conn
	v.ConnBatch = ipv4.NewPacketConn(conn)

	if v.Cfg.Mode == "client" {
		rAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", v.Cfg.RemoteIP, v.Cfg.RemotePort))
		v.ClientRemoteUDP = rAddr
		log.Printf("[UDP] 客户端模式 -> %s (批处理已启用)", rAddr)
	} else {
		log.Printf("[UDP] 服务端监听 %s (批处理已启用)", bindAddr)
	}

	go v.udpReaderLoop()
}

func (v *VPNInstance) initRaw() {
	protoStr := fmt.Sprintf("ip4:%d", v.Cfg.IPProtocolNum)

	// 多连接并发 - 提升吞吐量
	numConns := runtime.NumCPU()
	if numConns > 4 {
		numConns = 4 // 最多 4 个并发连接
	}

	v.ConnRaw = make([]*net.IPConn, numConns)

	for i := 0; i < numConns; i++ {
		var lAddr *net.IPAddr
		if v.Cfg.Mode == "server" && v.Cfg.ServerBindAddr != "0.0.0.0" {
			lAddr, _ = net.ResolveIPAddr("ip", v.Cfg.ServerBindAddr)
		}

		conn, err := net.ListenIP(protoStr, lAddr)
		if err != nil {
			log.Fatalf("Raw Socket 监听失败: %v", err)
		}

		conn.SetReadBuffer(16 << 20)
		conn.SetWriteBuffer(16 << 20)
		v.ConnRaw[i] = conn

		// 启动读取循环
		go v.rawReaderLoop(i)
	}

	if v.Cfg.Mode == "client" {
		v.ClientRemoteIP, _ = net.ResolveIPAddr("ip", v.Cfg.RemoteIP)
		log.Printf("[RAW] 客户端模式 -> %s (Proto: %d, 并发: %d)",
			v.ClientRemoteIP, v.Cfg.IPProtocolNum, numConns)
	} else {
		log.Printf("[RAW] 服务端监听 (Proto: %d, 并发: %d)",
			v.Cfg.IPProtocolNum, numConns)
	}
}

// --- 网络读取循环 ---

func (v *VPNInstance) udpReaderLoop() {
	msgs := make([]ipv4.Message, BatchSize)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{make([]byte, BufSize)}
	}

	for {
		n, err := v.ConnBatch.ReadBatch(msgs, 0)
		if err != nil {
			log.Printf("UDP ReadBatch 错误: %v", err)
			continue
		}

		for i := 0; i < n; i++ {
			msg := &msgs[i]
			if msg.N == 0 {
				continue
			}

			if v.Cfg.Mode == "server" {
				if udpAddr, ok := msg.Addr.(*net.UDPAddr); ok {
					v.ServerPeerAddr = udpAddr
				}
			}

			v.handleIncomingPacket(msgs[i].Buffers[0][:msg.N])
		}
	}
}

func (v *VPNInstance) rawReaderLoop(idx int) {
	conn := v.ConnRaw[idx]
	buf := make([]byte, BufSize)

	for {
		n, addr, err := conn.ReadFromIP(buf)
		if err != nil {
			log.Printf("Raw[%d] 读取错误: %v", idx, err)
			continue
		}

		// Raw 协议直接传输加密数据，无额外头部
		if n < NonceSize+Overhead {
			continue
		}

		if v.Cfg.Mode == "server" {
			v.ServerPeerIP = addr
		}

		v.handleIncomingPacket(buf[:n])
	}
}

// --- TUN 读取循环 ---

func (v *VPNInstance) TUNReaderLoop() {
	buffs := make([][]byte, BatchSize)
	for i := range buffs {
		buffs[i] = make([]byte, BufSize)
	}
	sizes := make([]int, BatchSize)

	// UDP 批处理发送队列
	var sendMsgs []ipv4.Message
	if v.Cfg.Protocol == "udp" {
		sendMsgs = make([]ipv4.Message, 0, BatchSize)
	}

	for {
		n, err := v.TunDev.Read(buffs, sizes, TunOffset)
		if err != nil {
			log.Printf("TUN 读取错误: %v", err)
			continue
		}

		if v.Cfg.Protocol == "udp" {
			// UDP 批处理模式
			sendMsgs = sendMsgs[:0]
			
			// 服务端：检查是否有客户端连接
			if v.Cfg.Mode == "server" && v.ServerPeerAddr == nil {
				continue
			}
			
			// 客户端：检查是否配置了远程地址
			if v.Cfg.Mode == "client" && v.ClientRemoteUDP == nil {
				continue
			}

			for i := 0; i < n; i++ {
				if sizes[i] == 0 {
					continue
				}
				data := buffs[i][TunOffset : TunOffset+sizes[i]]
				encrypted := v.encryptPacket(data)
				if encrypted != nil {
					var addr net.Addr
					if v.Cfg.Mode == "client" {
						addr = v.ClientRemoteUDP
					} else {
						addr = v.ServerPeerAddr
					}
					sendMsgs = append(sendMsgs, ipv4.Message{
						Buffers: [][]byte{encrypted},
						Addr:    addr,
					})
				}
			}
			if len(sendMsgs) > 0 {
				v.ConnBatch.WriteBatch(sendMsgs, 0)
			}
		} else {
			// Raw 模式 - 并发发送
			for i := 0; i < n; i++ {
				if sizes[i] == 0 {
					continue
				}
				data := buffs[i][TunOffset : TunOffset+sizes[i]]
				v.sendRawPacket(data)
			}
		}
	}
}

// --- 数据包处理 ---

func (v *VPNInstance) handleIncomingPacket(encrypted []byte) {
	if len(encrypted) < NonceSize+Overhead {
		return
	}

	nonce := encrypted[:NonceSize]
	ciphertext := encrypted[NonceSize:]

	plaintext, err := v.AEAD.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		logDebug("解密失败: %v", err)
		return
	}

	if len(plaintext) > 0 {
		v.writeTUN(plaintext)
	}
}

func (v *VPNInstance) encryptPacket(ipPacket []byte) []byte {
	if len(ipPacket) == 0 {
		return nil
	}

	dstPtr := bufPool.Get().(*[]byte)
	dst := (*dstPtr)[:NonceSize+len(ipPacket)+Overhead]

	// Nonce (计数器模式)
	nonce := dst[:NonceSize]
	nonceVal := atomic.AddUint64(&v.nonceCounter, 1)
	binary.BigEndian.PutUint64(nonce[0:8], nonceVal)
	binary.BigEndian.PutUint32(nonce[8:12], v.SessionID)
	for i := 12; i < NonceSize; i++ {
		nonce[i] = 0
	}

	v.AEAD.Seal(dst[NonceSize:NonceSize], nonce, ipPacket, nil)

	// 拷贝结果（因为池会复用）
	result := make([]byte, len(dst))
	copy(result, dst)
	bufPool.Put(dstPtr)

	return result
}

func (v *VPNInstance) sendRawPacket(ipPacket []byte) {
	if len(ipPacket) == 0 {
		return
	}

	encrypted := v.encryptPacket(ipPacket)
	if encrypted == nil {
		return
	}

	var addr *net.IPAddr
	if v.Cfg.Mode == "client" {
		addr = v.ClientRemoteIP
	} else {
		addr = v.ServerPeerIP
	}
	if addr == nil {
		return
	}

	// 轮询选择连接发送 (负载均衡)
	idx := atomic.AddUint32(&v.rawSendIdx, 1) % uint32(len(v.ConnRaw))
	v.ConnRaw[idx].WriteToIP(encrypted, addr)
}

func (v *VPNInstance) writeTUN(data []byte) {
	bufPtr := bufPool.Get().(*[]byte)
	buf := (*bufPtr)[:TunOffset+len(data)]
	copy(buf[TunOffset:], data)

	v.TunDev.Write([][]byte{buf}, TunOffset)
	bufPool.Put(bufPtr)
}

// --- 主函数 ---

func main() {
	cfgPath := flag.String("c", "config.json", "配置文件路径")
	flag.BoolVar(&debugMode, "debug", false, "开启调试模式")
	flag.Parse()

	data, err := os.ReadFile(*cfgPath)
	if err != nil {
		log.Fatalf("读取配置失败: %v", err)
	}

	var configs []Config
	if err := json.Unmarshal(data, &configs); err != nil {
		var single Config
		if err2 := json.Unmarshal(data, &single); err2 == nil {
			configs = append(configs, single)
		} else {
			log.Fatalf("解析配置失败: %v", err)
		}
	}

	seen := make(map[string]bool)
	for _, c := range configs {
		if seen[c.InterfaceName] {
			log.Fatalf("接口名重复: %s", c.InterfaceName)
		}
		seen[c.InterfaceName] = true
	}

	for _, cfg := range configs {
		instance := NewVPNInstance(cfg)
		instance.Start()
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c
	log.Println("收到退出信号，再见喵~ (Nya~)")
}

func runCmd(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}
