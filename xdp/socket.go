package xdp

import (
	"bytes"
	"embed"
	"fmt"
	"log"
	"net"
	"os/exec"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:embed neko_ebpf.o
var bpfContent embed.FS

// --- Kernel Structs ---

type shadowConfig struct {
	Mode      uint32
	ProtoNum  uint32
	LocalPort uint16
	Reserved  uint16
}

// --- Manager Logic ---

var (
	engineRegistry = make(map[string]*ShadowXEngine)
	registryMutex  sync.Mutex
)

type ShadowXConfig struct {
	InterfaceName string
	Mode          uint32 // 1=Raw-IP, 2=Fake-TCP
	LocalPort     uint16
	RawProto      uint8
}

type ShadowXEngine struct {
	ifaceName string
	
	// TCX links (Modern kernels)
	tcLinkEgress  link.Link
	tcLinkIngress link.Link
	
	// Legacy TC links (Manual cleanup needed if using Shell)
	isLegacy bool
	
	portMap  *ebpf.Map
	protoMap *ebpf.Map
	
	refCount int
	mu       sync.Mutex
}

func GetShadowXEngine(ifaceName string) (*ShadowXEngine, error) {
	registryMutex.Lock()
	defer registryMutex.Unlock()

	if e, ok := engineRegistry[ifaceName]; ok {
		e.refCount++
		return e, nil
	}

	// Create new engine
	bpfBytes, err := bpfContent.ReadFile("neko_ebpf.o")
	if err != nil { return nil, err }

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfBytes))
	if err != nil { return nil, err }

	var objs struct {
		TcIngress  *ebpf.Program `ebpf:"tc_shadow_ingress"`
		TcEgress   *ebpf.Program `ebpf:"tc_shadow_egress"`
		PortMap    *ebpf.Map     `ebpf:"port_shadow_map"`
		ProtoMap   *ebpf.Map     `ebpf:"proto_shadow_map"`
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil { return nil, err }

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil { return nil, err }

	e := &ShadowXEngine{
		ifaceName: ifaceName,
		portMap:   objs.PortMap,
		protoMap:  objs.ProtoMap,
		refCount:  1,
	}

	// 1. Try Modern TCX
	te, errE := link.AttachTCX(link.TCXOptions{
		Program:   objs.TcEgress,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXEgress,
	})
	ti, errI := link.AttachTCX(link.TCXOptions{
		Program:   objs.TcIngress,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXIngress,
	})

	if errE == nil && errI == nil {
		e.tcLinkEgress = te
		e.tcLinkIngress = ti
		log.Printf("[eBPF] Modern TCX attached on %s", ifaceName)
	} else {
		// 2. Fallback to Legacy TC (Command line)
		log.Printf("[eBPF] TCX not supported, falling back to Legacy TC (clsact)...")
		e.isLegacy = true
		
		// Setup clsact qdisc (ignore error if exists)
		exec.Command("tc", "qdisc", "add", "dev", ifaceName, "clsact").Run()
		
		pinPath := fmt.Sprintf("/sys/fs/bpf/neko_%s", ifaceName)
		exec.Command("rm", "-rf", pinPath).Run()
		exec.Command("mkdir", "-p", pinPath).Run()
		
		if err := objs.TcEgress.Pin(pinPath + "/egp"); err != nil {
			log.Printf("[eBPF] Failed to pin egress: %v", err)
		}
		if err := objs.TcIngress.Pin(pinPath + "/igp"); err != nil {
			log.Printf("[eBPF] Failed to pin ingress: %v", err)
		}
		
		exec.Command("tc", "filter", "replace", "dev", ifaceName, "egress", "bpf", "da", "pinned", pinPath+"/egp").Run()
		exec.Command("tc", "filter", "replace", "dev", ifaceName, "ingress", "bpf", "da", "pinned", pinPath+"/igp").Run()
		log.Printf("[eBPF] Legacy TC attached on %s via shell commands", ifaceName)
	}

	engineRegistry[ifaceName] = e
	return e, nil
}

func (e *ShadowXEngine) Register(cfg ShadowXConfig) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	conf := shadowConfig{
		Mode:      cfg.Mode,
		ProtoNum:  uint32(cfg.RawProto),
		LocalPort: htons(cfg.LocalPort),
	}

	port := htons(cfg.LocalPort)
	
	// Check for Port Collision
	var existing shadowConfig
	if err := e.portMap.Lookup(&port, &existing); err == nil {
		log.Printf("[eBPF] ⚠️ 警告: 端口 %d 已被其它隧道占用！这会导致流量冲突喵！请确保每个 NekoLink 实例使用唯一的监听端口。", cfg.LocalPort)
	}

	if err := e.portMap.Put(&port, &conf); err != nil {
		return fmt.Errorf("failed to register port %d: %v", cfg.LocalPort, err)
	}

	if cfg.Mode == 1 { // Raw-IP
		proto := uint8(cfg.RawProto)
		// Check for Proto Collision
		if err := e.protoMap.Lookup(&proto, &existing); err == nil {
			log.Printf("[eBPF] ⚠️ 冲突警告: 协议号 %d 已被其它隧道使用 (对应端口 %d)！在同一网卡上使用相同协议号会导致无法正确区分入站流量喵！请为主人的每个 Raw 隧道分配唯一的协议号。", cfg.RawProto, ntohs(existing.LocalPort))
		}
		if err := e.protoMap.Put(&proto, &conf); err != nil {
			return fmt.Errorf("failed to register proto %d: %v", cfg.RawProto, err)
		}
	}

	log.Printf("[eBPF] 实例注册成功: 模式=%d, 端口=%d, 协议=%d", cfg.Mode, cfg.LocalPort, cfg.RawProto)
	return nil
}

func (e *ShadowXEngine) Unregister(cfg ShadowXConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()

	port := htons(cfg.LocalPort)
	e.portMap.Delete(&port)

	if cfg.Mode == 1 {
		proto := uint8(cfg.RawProto)
		e.protoMap.Delete(&proto)
	}
	log.Printf("[eBPF] 实例已注销 (端口 %d)", cfg.LocalPort)
}

func (e *ShadowXEngine) Close() {
	registryMutex.Lock()
	e.refCount--
	if e.refCount <= 0 {
		if e.isLegacy {
			exec.Command("tc", "filter", "del", "dev", e.ifaceName, "egress").Run()
			exec.Command("tc", "filter", "del", "dev", e.ifaceName, "ingress").Run()
			exec.Command("rm", "-rf", fmt.Sprintf("/sys/fs/bpf/neko_%s", e.ifaceName)).Run()
		} else {
			if e.tcLinkEgress != nil { e.tcLinkEgress.Close() }
			if e.tcLinkIngress != nil { e.tcLinkIngress.Close() }
		}
		delete(engineRegistry, e.ifaceName)
		log.Printf("[eBPF] 共享引擎已关闭并从接口 %s 卸载", e.ifaceName)
	}
	registryMutex.Unlock()
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

func ntohs(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}
