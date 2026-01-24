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

//go:embed neko_tcp.o neko_raw.o
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
	Mode          uint32 // 1=Raw-IP (Legacy), 2=Fake-TCP
	LocalPort     uint16
	RawProto      uint8
}

type ShadowXEngine struct {
	ifaceName string
	engineType string // "raw" or "tcp"
	
	// TCX links (Modern kernels)
	tcLinkEgress  link.Link
	tcLinkIngress link.Link
	
	// Legacy TC links (Manual cleanup needed if using Shell)
	isLegacy bool
	
	portMap     *ebpf.Map // port_shadow_map (Fake-TCP Only)
	rawAllowMap *ebpf.Map // raw_allow_map (Raw Mode Only)
	
	refCount int
	mu       sync.Mutex
}

// GetShadowXEngine retrieves or creates an engine.
// modeHint: "raw" or "tcp" - indicates which BPF to load if creating new.
func GetShadowXEngine(ifaceName string, modeHint string) (*ShadowXEngine, error) {
	registryMutex.Lock()
	defer registryMutex.Unlock()

	if e, ok := engineRegistry[ifaceName]; ok {
		if e.engineType != modeHint {
			return nil, fmt.Errorf("interface %s already has %s engine loaded, cannot load %s", ifaceName, e.engineType, modeHint)
		}
		e.refCount++
		return e, nil
	}

	// Create new engine
	fileName := "neko_tcp.o"
	if modeHint == "raw" {
		fileName = "neko_raw.o"
	}

	bpfBytes, err := bpfContent.ReadFile(fileName)
	if err != nil { return nil, fmt.Errorf("failed to read %s: %v", fileName, err) }

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfBytes))
	if err != nil { return nil, fmt.Errorf("failed to load spec from %s: %v", fileName, err) }

	// Prepare objects struct (Union-like)
	var objs struct {
		TcIngress   *ebpf.Program `ebpf:"tc_shadow_ingress"`
		TcEgress    *ebpf.Program `ebpf:"tc_shadow_egress"`
		PortMap     *ebpf.Map     `ebpf:"port_shadow_map"`
		RawAllowMap *ebpf.Map     `ebpf:"raw_allow_map"`
	}

	// Disable BTF for maps to support kernels without BTF support
	spec.Types = nil
	for i, m := range spec.Maps {
		if m.Key != nil || m.Value != nil {
			log.Printf("[eBPF] Map %s 包含 BTF 信息，正在清理...", i)
		}
		m.Key = nil
		m.Value = nil
	}
	
	for i := range spec.Programs {
		log.Printf("[eBPF] 准备加载 Program (%s): %s", modeHint, i)
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil { return nil, err }

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil { return nil, err }

	e := &ShadowXEngine{
		ifaceName:   ifaceName,
		engineType:  modeHint,
		portMap:     objs.PortMap,     // May be nil if raw
		rawAllowMap: objs.RawAllowMap, // May be nil if tcp
		refCount:    1,
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
		log.Printf("[eBPF] 喵！Modern TCX (%s) 挂载成功在 %s 上！✨", modeHint, ifaceName)
	} else {
		// 2. Fallback to Legacy TC (Command line)
		log.Printf("[eBPF] TCX 不支持喵，正在回退到 Legacy TC (%s)...", modeHint)
		e.isLegacy = true
		
		// Setup clsact qdisc (ignore error if exists)
		exec.Command("tc", "qdisc", "add", "dev", ifaceName, "clsact").Run()
		
		pinPath := fmt.Sprintf("/sys/fs/bpf/neko_%s", ifaceName)
		exec.Command("rm", "-rf", pinPath).Run()
		exec.Command("mkdir", "-p", pinPath).Run()
		
		if err := objs.TcEgress.Pin(pinPath + "/egp"); err != nil {
			log.Printf("[eBPF] Egress 固定失败: %v", err)
		}
		if err := objs.TcIngress.Pin(pinPath + "/igp"); err != nil {
			log.Printf("[eBPF] Ingress 固定失败: %v", err)
		}
		
		exec.Command("tc", "filter", "replace", "dev", ifaceName, "egress", "bpf", "da", "pinned", pinPath+"/egp").Run()
		exec.Command("tc", "filter", "replace", "dev", ifaceName, "ingress", "bpf", "da", "pinned", pinPath+"/igp").Run()
		log.Printf("[eBPF] Legacy TC 已通过 Shell 命令挂载在 %s 上！🐾", ifaceName)
	}

	engineRegistry[ifaceName] = e
	return e, nil
}

func (e *ShadowXEngine) Register(cfg ShadowXConfig) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	portNet := htons(cfg.LocalPort) // 大端序

	// === Raw Mode (Legacy) ===
	if cfg.Mode == 1 {
		if e.engineType != "raw" {
			return fmt.Errorf("引擎类型不匹配: 当前=%s, 请求=raw", e.engineType)
		}
		proto := cfg.RawProto
		placeholder := uint8(0)

		var existingVal uint8
		if err := e.rawAllowMap.Lookup(&proto, &existingVal); err == nil {
			log.Printf("[eBPF] ⚠️ 冲突警告: 协议号 %d 已被其它隧道占用！", proto)
		}
		
		if err := e.rawAllowMap.Put(&proto, &placeholder); err != nil {
			return fmt.Errorf("注册 Raw 允许列表失败: %v", err)
		}

		log.Printf("[eBPF] Raw 实例注册成功: 协议=%d (Legacy Mode) ✨", cfg.RawProto)
		return nil
	}

	// === TCP Mode ===
	if cfg.Mode == 2 {
		if e.engineType != "tcp" {
			return fmt.Errorf("引擎类型不匹配: 当前=%s, 请求=tcp", e.engineType)
		}
		conf := shadowConfig{
			Mode:      cfg.Mode,
			ProtoNum:  0,
			LocalPort: portNet,
		}

		var existing shadowConfig
		if err := e.portMap.Lookup(&portNet, &existing); err == nil {
			log.Printf("[eBPF] ⚠️ 警告: 端口 %d 已被其它隧道占用！", cfg.LocalPort)
		}

		if err := e.portMap.Put(&portNet, &conf); err != nil {
			return fmt.Errorf("注册 Fake-TCP 失败: %v", err)
		}

		log.Printf("[eBPF] Fake-TCP 实例注册成功: 端口=%d 🐾", cfg.LocalPort)
		return nil
	}
	
	return fmt.Errorf("未知模式: %d", cfg.Mode)
}

func (e *ShadowXEngine) Unregister(cfg ShadowXConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()

	portNet := htons(cfg.LocalPort)

	if cfg.Mode == 1 {
		if e.rawAllowMap != nil {
			proto := cfg.RawProto
			e.rawAllowMap.Delete(&proto)
			log.Printf("[eBPF] Raw 实例已注销 (协议 %d) 👋", proto)
		}
	} else {
		if e.portMap != nil {
			e.portMap.Delete(&portNet)
			log.Printf("[eBPF] Fake-TCP 实例已注销 (端口 %d) 👋", cfg.LocalPort)
		}
	}
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
		log.Printf("[eBPF] 共享引擎 (%s) 已关闭并从接口 %s 卸载。💤", e.engineType, e.ifaceName)
	}
	registryMutex.Unlock()
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

func ntohs(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}
