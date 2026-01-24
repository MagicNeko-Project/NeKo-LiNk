package xdp

import (
	"bytes"
	"embed"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:embed neko_ebpf.o
var bpfContent embed.FS

type ShadowXConfig struct {
	InterfaceName string
	Mode          uint32 // 1=Raw-IP, 2=Fake-TCP
	LocalPort     uint16
	RawProto      uint8
}

type ShadowXEngine struct {
	Cfg        ShadowXConfig
	xdpLink    link.Link
	tcLink     link.Link
	ConfigMap  *ebpf.Map
}

func NewShadowXEngine(cfg ShadowXConfig) (*ShadowXEngine, error) {
	bpfBytes, err := bpfContent.ReadFile("neko_ebpf.o")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded bpf object: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to load bpf spec: %v", err)
	}

	var objs struct {
		XdpIngress *ebpf.Program `ebpf:"xdp_shadow_ingress"`
		TcEgress   *ebpf.Program `ebpf:"tc_shadow_egress"`
		ConfigMap  *ebpf.Map     `ebpf:"config_map"`
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load and assign bpf objects: %v", err)
	}

	iface, err := net.InterfaceByName(cfg.InterfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to find interface %s: %v", cfg.InterfaceName, err)
	}

	// 1. Attach XDP (Ingress)
	// Try Native mode first, fallback to Generic (SKB) mode if driver doesn't support it
	xl, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpIngress,
		Interface: iface.Index,
	})
	if err != nil {
		log.Printf("[eBPF] Native XDP failed (%v), attempting Generic (SKB) mode...", err)
		xl, err = link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpIngress,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
	}
	
	if err != nil {
		return nil, fmt.Errorf("failed to attach XDP (even in Generic mode): %v", err)
	}

	// 2. Attach TC (Egress)
	// Note: TCX is the modern attachment point for TC programs on kernels 6.6+
	tl, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.TcEgress,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Printf("[eBPF] tcx failed (%v), kernel might be too old. Shadow X Egress might not work.", err)
	}

	// 3. Write Config
	mode := cfg.Mode
	port := uint32(cfg.LocalPort)
	proto := uint32(cfg.RawProto)

	k0, k1, k2 := uint32(0), uint32(1), uint32(2)
	objs.ConfigMap.Put(&k0, &mode)
	objs.ConfigMap.Put(&k1, &port)
	objs.ConfigMap.Put(&k2, &proto)

	log.Printf("[eBPF] Shadow X Engine Loaded on %s (Mode: %d)", cfg.InterfaceName, cfg.Mode)

	return &ShadowXEngine{
		Cfg:       cfg,
		xdpLink:   xl,
		tcLink:    tl,
		ConfigMap: objs.ConfigMap,
	}, nil
}

func (e *ShadowXEngine) Close() {
	if e.xdpLink != nil {
		e.xdpLink.Close()
	}
	if e.tcLink != nil {
		e.tcLink.Close()
	}
}
