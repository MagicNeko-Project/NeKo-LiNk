package main

import (
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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/songgao/water"
	"golang.org/x/crypto/chacha20poly1305"
)

// Config 结构定义
type Config struct {
	ServerAddr    string `json:"server_addr"`     // 对 Client: 服务器 IP; 对 Server: 监听 IP (通常是 0.0.0.0 或 ::)
	Protocol      string `json:"protocol"`        // "udp" or "raw"
	IPProtocolNum int    `json:"ip_protocol_num"` // IP 协议号 (default 250)
	BasePort      int    `json:"base_port"`       // 起始端口 (UDP用)
	PortCount     int    `json:"port_count"`      // 端口/通道数量
	Key           string `json:"key"`             // 共享密钥
	LocalAddr     string `json:"local_addr"`      // 虚拟网卡 IP/CIDR (例如 10.0.0.1/24)
	Mode          string `json:"mode"`            // "server" or "client"
	InterfaceName string `json:"interface_name"`  // 自定义接口名称 (e.g. tap233)
	MTU           int    `json:"mtu"`             // TAP MTU
}

const (
	NonceSize = chacha20poly1305.NonceSizeX
	Overhead  = chacha20poly1305.Overhead
)

var (
	config        Config
	aead          cipher.AEAD
	iface         *water.Interface
	remoteAddrUDP []*net.UDPAddr // Client模式 UDP 目标
	remoteAddrIP  *net.IPAddr    // Client模式 RawIP 目标 (公用一个IP，靠Payload区分通道)
	
	connUDP       []*net.UDPConn // UDP 连接数组
	connIP        *net.IPConn    // Raw IP 连接 (Go 的 ListenIP 通常返回单个 Conn 对象用于读写)
	
	// Server 模式回包地址管理
	peerPathsUDP  []atomic.Value // []*net.UDPAddr
	peerPathIP    atomic.Value   // *net.IPAddr (Raw IP 只要这一个就行，因为协议内含 Channel ID)

	// 轮询索引
	currTxIdx uint64
)

func main() {
	configFile := flag.String("c", "config.json", "Path to config file")
	flag.Parse()

	loadConfig(*configFile)
	initCrypto()
	initTAP()
	initNetwork()

	// 启动主循环
	go startTAPReader()
	startNetworkListeners()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("Shutting down...")
}

func loadConfig(path string) {
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
			connUDP[i] = conn
			peerPathsUDP[i].Store(rAddr) // Pre-fill server addr
			log.Printf("UDP Client channel %d ready", i)
		}
	}
}

func initRawIP() {
	// Raw IP requires only ONE listener for the Protocol Number
	// We handle multiplexing via payload header
	
	// Create Listen IP
	// For "ip4:250" or "ip6:250"
	// Note: net.ListenIP needs specific network string like "ip4:250"
	// To support both automatically, we might try to listen on "ip".
	// But usually we specify "ip4:protocol"
	
	protoStr := fmt.Sprintf("ip4:%d", config.IPProtocolNum) // Simplify to IPv4 for now, or detect server addr type
	// If server addr contains ':', assumption IPv6
	if isIPv6(config.ServerAddr) {
		protoStr = fmt.Sprintf("ip6:%d", config.IPProtocolNum)
	}

	lAddr, err := net.ResolveIPAddr("ip", config.ServerAddr) 
	if err != nil {
		// handle empty -> listen all
		if config.Mode == "server" && (config.ServerAddr == "" || config.ServerAddr == "[::]" || config.ServerAddr == "0.0.0.0") {
			lAddr = nil // Listen all
		} else {
			log.Fatalf("ResolveIPAddr failed: %v", err)
		}
	}

	conn, err := net.ListenIP(protoStr, lAddr)
	if err != nil {
		log.Fatalf("ListenIP failed (Need Root?): %v", err)
	}
	connIP = conn
	log.Printf("Raw IP Listening on proto %d (%s)", config.IPProtocolNum, protoStr)

	if config.Mode == "client" {
		// Resolve Remote Server
		rAddr, err := net.ResolveIPAddr("ip", config.ServerAddr)
		if err != nil { log.Fatalf("Resolve Remote IP failed: %v", err) }
		remoteAddrIP = rAddr
		peerPathIP.Store(rAddr)
	}
}

func isIPv6(addr string) bool {
	// Simplified check
	for i := 0; i < len(addr); i++ {
		if addr[i] == ':' { return true }
	}
	return false
}


// TAP -> Network
func startTAPReader() {
	buf := make([]byte, 2000)
	for {
		n, err := iface.Read(buf)
		if err != nil {
			log.Printf("TAP Read Error: %v", err)
			break
		}
		packet := buf[:n]

		// Encrypt
		nonce := make([]byte, NonceSize)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil { continue }
		ciphertext := aead.Seal(nonce, nonce, packet, nil)

		// Send
		idx := atomic.AddUint64(&currTxIdx, 1) % uint64(config.PortCount)

		if config.Protocol == "udp" {
			sendUDP(idx, ciphertext)
		} else {
			sendRawIP(uint32(idx), ciphertext)
		}
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
			buf := make([]byte, 2000)
			for {
				n, src, err := c.ReadFromUDP(buf)
				if err != nil { return }
				
				if config.Mode == "server" {
					peerPathsUDP[idx].Store(src)
				}
				processIncoming(buf[:n])
			}
		}(i, conn)
	}
}

func startRawIPListener() {
	go func() {
		buf := make([]byte, 2000)
		for {
			n, src, err := connIP.ReadFromIP(buf) // Reads IP Payload (Protocol Data)
			if err != nil { 
				log.Println("IP Read Error:", err)
				return 
			}
			
			if config.Mode == "server" {
				peerPathIP.Store(src)
			}

			// Format: [ChannelID 4] + [Data...]
			if n < 4 { continue }
			
			// channelID := binary.BigEndian.Uint32(buf[0:4])
			// In Raw mode, we just process it. ChannelID was for balancing on receive side?
			// Actually since we only have ONE ListenIP, we receive ALL packets here.
			// To truly load balance Decryption, we should dispatch logic to workers based on ChannelID.
			// For simplicity in this step, we just process it directly. 
			// (Go schedule handles concurrency well, creating a goroutine per packet is also an option, 
			// but better simply decoding it here or pushing to a work queue).
			
			// For minimal latency:
			data := buf[4:n]
			go processIncoming(data) // Simple parallel processing
		}
	}()
}

func processIncoming(encrypted []byte) {
	if len(encrypted) < NonceSize+Overhead { return }
	nonce := encrypted[:NonceSize]
	ciphertext := encrypted[NonceSize:]
	
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil { return }
	
	iface.Write(plaintext)
}
