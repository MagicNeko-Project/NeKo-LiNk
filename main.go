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
	"sync"
	"sync/atomic"
	"syscall"

	"golang.zx2c4.com/wireguard/tun"
	"golang.org/x/crypto/chacha20poly1305"
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

	// 服务端设置
	ServerBindAddr string `json:"server_addr"`
	BasePort       int    `json:"base_port"`

	// 客户端设置
	RemoteIP   string `json:"server_ip"`
	RemotePort int    `json:"server_port"`

	// RAW 模式
	IPProtocolNum int `json:"ip_protocol_num"`

	// 调试
	Debug bool `json:"debug"`
}

func (c *Config) ParseLegacy() {
	// 兼容旧配置字段
	if c.Mode == "client" && c.RemoteIP == "" && c.ServerBindAddr != "" {
		c.RemoteIP = c.ServerBindAddr
	}
	if c.Mode == "client" && c.RemotePort == 0 && c.BasePort != 0 {
		c.RemotePort = c.BasePort
	}
	// 默认值
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
	NonceSize = chacha20poly1305.NonceSizeX // 24 bytes
	Overhead  = chacha20poly1305.Overhead   // 16 bytes
	TunOffset = 16                          // wireguard-go TUN offset
	BufSize   = 65536
)

// --- 内存池 (性能优化) ---

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

	// UDP 模式
	ConnUDP         *net.UDPConn
	ClientRemoteUDP *net.UDPAddr
	ServerPeerAddr  *net.UDPAddr // 服务端记录的客户端地址

	// Raw 模式
	ConnRaw        *net.IPConn
	ClientRemoteIP *net.IPAddr
	ServerPeerIP   *net.IPAddr

	// Nonce 计数器 (性能优化)
	nonceCounter uint64
	SessionID    uint32

	// 预分配的 Nonce 缓冲区 (避免每包分配)
	nonceBuf [NonceSize]byte
}

func NewVPNInstance(cfg Config) *VPNInstance {
	cfg.ParseLegacy()
	v := &VPNInstance{Cfg: cfg}

	// 初始化加密
	keyHash := sha256.Sum256([]byte(cfg.Key))
	var err error
	v.AEAD, err = chacha20poly1305.NewX(keyHash[:])
	if err != nil {
		log.Fatalf("加密初始化失败: %v", err)
	}

	// 生成 Session ID (用于 Nonce)
	v.SessionID = uint32(os.Getpid()) ^ uint32(keyHash[0])<<24

	return v
}

func (v *VPNInstance) Start() {
	if v.Cfg.Debug {
		debugMode = true
	}

	log.Printf("[%s] NekoLink v5.1 (高性能版) 启动中 - 模式: %s, 协议: %s",
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

	// 配置网络接口
	runCmd("ip", "addr", "add", v.Cfg.LocalAddr, "dev", realName)
	runCmd("ip", "link", "set", realName, "mtu", fmt.Sprintf("%d", v.Cfg.MTU))
	runCmd("ip", "link", "set", realName, "up")

	// 禁用反向路径过滤
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
		log.Fatalf("不支持的协议: %s (支持: udp, raw)", v.Cfg.Protocol)
	}
}

func (v *VPNInstance) initUDP() {
	var bindAddr string
	if v.Cfg.Mode == "server" {
		bindAddr = fmt.Sprintf("%s:%d", v.Cfg.ServerBindAddr, v.Cfg.BasePort)
	} else {
		bindAddr = ":0" // 客户端随机端口
	}

	lAddr, _ := net.ResolveUDPAddr("udp", bindAddr)
	conn, err := net.ListenUDP("udp", lAddr)
	if err != nil {
		log.Fatalf("UDP 监听失败: %v", err)
	}

	// 大缓冲区减少丢包
	conn.SetReadBuffer(16 << 20)  // 16MB
	conn.SetWriteBuffer(16 << 20) // 16MB
	v.ConnUDP = conn

	if v.Cfg.Mode == "client" {
		rAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", v.Cfg.RemoteIP, v.Cfg.RemotePort))
		v.ClientRemoteUDP = rAddr
		log.Printf("[UDP] 客户端模式 -> %s", rAddr)
	} else {
		log.Printf("[UDP] 服务端监听 %s", bindAddr)
	}

	go v.udpReaderLoop()
}

func (v *VPNInstance) initRaw() {
	protoStr := fmt.Sprintf("ip4:%d", v.Cfg.IPProtocolNum)

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
	v.ConnRaw = conn

	if v.Cfg.Mode == "client" {
		v.ClientRemoteIP, _ = net.ResolveIPAddr("ip", v.Cfg.RemoteIP)
		log.Printf("[RAW] 客户端模式 -> %s (Proto: %d)", v.ClientRemoteIP, v.Cfg.IPProtocolNum)
	} else {
		log.Printf("[RAW] 服务端监听 (Proto: %d)", v.Cfg.IPProtocolNum)
	}

	go v.rawReaderLoop()
}

// --- 网络读取循环 ---

func (v *VPNInstance) udpReaderLoop() {
	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	for {
		n, addr, err := v.ConnUDP.ReadFromUDP(buf)
		if err != nil {
			log.Printf("UDP 读取错误: %v", err)
			continue
		}
		logDebug("UDP-RX: %d bytes from %s", n, addr)

		// 服务端记录对端地址
		if v.Cfg.Mode == "server" {
			v.ServerPeerAddr = addr
		}

		v.handleIncomingPacket(buf[:n])
	}
}

func (v *VPNInstance) rawReaderLoop() {
	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	for {
		n, addr, err := v.ConnRaw.ReadFromIP(buf)
		if err != nil {
			log.Printf("Raw 读取错误: %v", err)
			continue
		}

		// Raw 包头前 4 字节是填充，跳过
		if n < 4 {
			continue
		}
		logDebug("RAW-RX: %d bytes from %s", n, addr)

		// 服务端记录对端地址
		if v.Cfg.Mode == "server" {
			v.ServerPeerIP = addr
		}

		v.handleIncomingPacket(buf[4:n])
	}
}

// --- TUN 读取循环 ---

func (v *VPNInstance) TUNReaderLoop() {
	// wireguard-go TUN 需要足够的缓冲区槽位来进行批量读取
	const batchSize = 16
	buffs := make([][]byte, batchSize)
	for i := range buffs {
		buffs[i] = make([]byte, BufSize)
	}
	sizes := make([]int, batchSize)

	for {
		n, err := v.TunDev.Read(buffs, sizes, TunOffset)
		if err != nil {
			log.Printf("TUN 读取错误: %v", err)
			continue
		}

		for i := 0; i < n; i++ {
			if sizes[i] == 0 {
				continue
			}
			data := buffs[i][TunOffset : TunOffset+sizes[i]]
			logDebug("TUN-RX: %d bytes", sizes[i])
			v.handleOutgoingPacket(data)
		}
	}
}

// --- 数据包处理 ---

func (v *VPNInstance) handleIncomingPacket(encrypted []byte) {
	// 检查最小长度: Nonce + Overhead
	if len(encrypted) < NonceSize+Overhead {
		logDebug("包太短，丢弃")
		return
	}

	nonce := encrypted[:NonceSize]
	ciphertext := encrypted[NonceSize:]

	// 解密 (原地解密，避免分配)
	plaintext, err := v.AEAD.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		logDebug("解密失败: %v", err)
		return
	}

	// 写入 TUN
	if len(plaintext) > 0 {
		v.writeTUN(plaintext)
	}
}

func (v *VPNInstance) handleOutgoingPacket(ipPacket []byte) {
	if len(ipPacket) == 0 {
		return
	}

	// 从池获取缓冲区
	dstPtr := bufPool.Get().(*[]byte)
	dst := (*dstPtr)[:NonceSize+len(ipPacket)+Overhead]

	// 生成 Nonce (计数器模式，使用预分配缓冲区)
	nonce := dst[:NonceSize]
	nonceVal := atomic.AddUint64(&v.nonceCounter, 1)
	binary.BigEndian.PutUint64(nonce[0:8], nonceVal)
	binary.BigEndian.PutUint32(nonce[8:12], v.SessionID)
	// 清零剩余部分
	for i := 12; i < NonceSize; i++ {
		nonce[i] = 0
	}

	// 加密到 dst[NonceSize:]
	v.AEAD.Seal(dst[NonceSize:NonceSize], nonce, ipPacket, nil)

	// 发送
	v.sendPacket(dst)

	// 归还缓冲区
	bufPool.Put(dstPtr)
}

func (v *VPNInstance) writeTUN(data []byte) {
	// 从池获取缓冲区
	bufPtr := bufPool.Get().(*[]byte)
	buf := (*bufPtr)[:TunOffset+len(data)]
	copy(buf[TunOffset:], data)

	_, err := v.TunDev.Write([][]byte{buf}, TunOffset)
	if err != nil {
		logDebug("TUN 写入错误: %v", err)
	}

	bufPool.Put(bufPtr)
}

func (v *VPNInstance) sendPacket(data []byte) {
	switch v.Cfg.Protocol {
	case "udp":
		var addr *net.UDPAddr
		if v.Cfg.Mode == "client" {
			addr = v.ClientRemoteUDP
		} else {
			addr = v.ServerPeerAddr
			if addr == nil {
				logDebug("服务端: 尚无客户端连接，丢弃")
				return
			}
		}
		_, err := v.ConnUDP.WriteToUDP(data, addr)
		if err != nil {
			logDebug("UDP 发送错误: %v", err)
		}

	case "raw":
		// 从池获取缓冲区
		payloadPtr := bufPool.Get().(*[]byte)
		payload := (*payloadPtr)[:4+len(data)]
		// 清零头部
		payload[0], payload[1], payload[2], payload[3] = 0, 0, 0, 0
		copy(payload[4:], data)

		var addr *net.IPAddr
		if v.Cfg.Mode == "client" {
			addr = v.ClientRemoteIP
		} else {
			addr = v.ServerPeerIP
			if addr == nil {
				bufPool.Put(payloadPtr)
				logDebug("服务端: 尚无客户端连接，丢弃")
				return
			}
		}
		_, err := v.ConnRaw.WriteToIP(payload, addr)
		if err != nil {
			logDebug("Raw 发送错误: %v", err)
		}
		bufPool.Put(payloadPtr)
	}
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

	// 支持单配置和数组配置
	var configs []Config
	if err := json.Unmarshal(data, &configs); err != nil {
		var single Config
		if err2 := json.Unmarshal(data, &single); err2 == nil {
			configs = append(configs, single)
		} else {
			log.Fatalf("解析配置失败: %v", err)
		}
	}

	// 检查接口名重复
	seen := make(map[string]bool)
	for _, c := range configs {
		if seen[c.InterfaceName] {
			log.Fatalf("接口名重复: %s", c.InterfaceName)
		}
		seen[c.InterfaceName] = true
	}

	// 启动所有实例
	for _, cfg := range configs {
		instance := NewVPNInstance(cfg)
		instance.Start()
	}

	// 等待信号退出
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c
	log.Println("收到退出信号，再见喵~ (Nya~)")
}

// --- 工具函数 ---

func runCmd(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}
