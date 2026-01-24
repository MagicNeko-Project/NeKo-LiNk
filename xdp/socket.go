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
	tcLinkEgress  link.Link
	tcLinkIngress link.Link
	
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

	// Attach TCX Egress
	te, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.TcEgress,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Printf("[eBPF] tcx egress failed (%v), kernel might be too old.", err)
	}

	// Attach TCX Ingress
	ti, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.TcIngress,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Printf("[eBPF] tcx ingress failed (%v), kernel might be too old.", err)
	}

	e := &ShadowXEngine{
		ifaceName:     ifaceName,
		tcLinkEgress:  te,
		tcLinkIngress: ti,
		portMap:       objs.PortMap,
		protoMap:      objs.ProtoMap,
		refCount:      1,
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

	// For both modes, we usually want to register the local port 
	// so the Egress hook identifies our app's traffic.
	port := htons(cfg.LocalPort)
	if err := e.portMap.Put(&port, &conf); err != nil {
		return fmt.Errorf("failed to register port %d: %v", cfg.LocalPort, err)
	}

	if cfg.Mode == 1 { // Raw-IP
		proto := uint8(cfg.RawProto)
		if err := e.protoMap.Put(&proto, &conf); err != nil {
			return fmt.Errorf("failed to register proto %d: %v", cfg.RawProto, err)
		}
	}

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
}

func (e *ShadowXEngine) Close() {
	registryMutex.Lock()
	e.refCount--
	if e.refCount <= 0 {
		if e.tcLinkEgress != nil { e.tcLinkEgress.Close() }
		if e.tcLinkIngress != nil { e.tcLinkIngress.Close() }
		delete(engineRegistry, e.ifaceName)
	}
	registryMutex.Unlock()
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}
