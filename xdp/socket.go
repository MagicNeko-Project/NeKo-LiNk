package xdp

import (
	"bytes"
	"embed"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:embed neko_ebpf.o
var bpfContent embed.FS

// --- Kernel Structs ---

type shadowConfig struct {
	Mode     uint32
	ProtoNum uint32
	Reserved [2]uint32
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
	xdpLink   link.Link
	tcLink    link.Link
	
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
		XdpIngress *ebpf.Program `ebpf:"xdp_shadow_ingress"`
		TcEgress   *ebpf.Program `ebpf:"tc_shadow_egress"`
		PortMap    *ebpf.Map     `ebpf:"port_shadow_map"`
		ProtoMap   *ebpf.Map     `ebpf:"proto_shadow_map"`
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil { return nil, err }

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil { return nil, err }

	// Attach XDP
	xl, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpIngress,
		Interface: iface.Index,
	})
	if err != nil {
		log.Printf("[eBPF] Native XDP failed, falling back to Generic mode...")
		xl, err = link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpIngress,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
	}
	if err != nil { return nil, err }

	// Attach TCX
	tl, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.TcEgress,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Printf("[eBPF] tcx failed, egress acceleration might be unavailable (%v)", err)
	}

	e := &ShadowXEngine{
		ifaceName: ifaceName,
		xdpLink:   xl,
		tcLink:    tl,
		portMap:   objs.PortMap,
		protoMap:  objs.ProtoMap,
		refCount:  1,
	}

	engineRegistry[ifaceName] = e
	return e, nil
}

func (e *ShadowXEngine) Register(cfg ShadowXConfig) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	conf := shadowConfig{
		Mode:     cfg.Mode,
		ProtoNum: uint32(cfg.RawProto),
	}

	if cfg.Mode == 2 { // Fake-TCP
		port := htons(cfg.LocalPort)
		if err := e.portMap.Put(&port, &conf); err != nil {
			return fmt.Errorf("failed to register port %d: %v", cfg.LocalPort, err)
		}
	} else if cfg.Mode == 1 { // Raw-IP
		proto := uint8(cfg.RawProto)
		if err := e.protoMap.Put(&proto, &conf); err != nil {
			return fmt.Errorf("failed to register proto %d: %v", cfg.RawProto, err)
		}
		// In Mode 1, we also often need to check ports for the TC egress part
		port := htons(cfg.LocalPort)
		e.portMap.Put(&port, &conf)
	}

	return nil
}

func (e *ShadowXEngine) Unregister(cfg ShadowXConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if cfg.Mode == 2 {
		port := htons(cfg.LocalPort)
		e.portMap.Delete(&port)
	} else if cfg.Mode == 1 {
		proto := uint8(cfg.RawProto)
		e.protoMap.Delete(&proto)
		port := htons(cfg.LocalPort)
		e.portMap.Delete(&port)
	}
}

func (e *ShadowXEngine) Close() {
	registryMutex.Lock()
	e.refCount--
	if e.refCount <= 0 {
		if e.xdpLink != nil { e.xdpLink.Close() }
		if e.tcLink != nil { e.tcLink.Close() }
		delete(engineRegistry, e.ifaceName)
	}
	registryMutex.Unlock()
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}
