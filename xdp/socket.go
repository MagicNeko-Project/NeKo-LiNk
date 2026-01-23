package xdp

import (
	"bytes"
	"embed"
	"fmt"
	"log"
	"net"
	"time"
	
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:embed xdp_kern.o
var bpfContent embed.FS

type XDPConfig struct {
	InterfaceName string
	QueueID       int
	Mode          int // 1=UDP, 2=Raw
	Target        int // Port or Proto
}

type XDPSocket struct {
	Cfg       XDPConfig
	Link      link.Link
	BpfMap    *ebpf.Map
	ConfigMap *ebpf.Map
	
	RxChan    chan []byte
}

func NewXDPSocket(cfg XDPConfig) (*XDPSocket, error) {
	// Load from Embed
	bpfBytes, err := bpfContent.ReadFile("xdp_kern.o")
	if err != nil { return nil, fmt.Errorf("embed load failed: %v", err) }

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfBytes))
	if err != nil { return nil, err }
	
	var objs struct {
		XdpProg   *ebpf.Program `ebpf:"xdp_prog"`
		XsksMap   *ebpf.Map     `ebpf:"xsks_map"`
		ConfigMap *ebpf.Map     `ebpf:"config_map"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil { return nil, err }
	
	iface, err := net.InterfaceByName(cfg.InterfaceName)
	if err != nil { return nil, err }
	
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProg,
		Interface: iface.Index,
	})
	if err != nil { return nil, err }
	
	// Write Config
	m := uint32(cfg.Mode)
	v := uint32(cfg.Target)
	
	// If UDP, Target is Port. Convert to Big Endian (Net Order)
	if cfg.Mode == 1 {
		v = uint32(htons(uint16(cfg.Target)))
	}
	
	k0 := uint32(0); objs.ConfigMap.Put(&k0, &m)
	k1 := uint32(1); objs.ConfigMap.Put(&k1, &v)
	
	log.Printf("XDP Attached to %s (Mode %d, Target %d)", cfg.InterfaceName, cfg.Mode, cfg.Target)
	
	xs := &XDPSocket{
		Cfg: cfg,
		Link: l,
		BpfMap: objs.XsksMap,
		ConfigMap: objs.ConfigMap,
		RxChan: make(chan []byte, 1024),
	}
	
	// Start Polling (Mock)
	go xs.Poll()
	
	return xs, nil
}

func (s *XDPSocket) Poll() {
	// Real AF_XDP Poll logic...
	// For now, mock
}

func (s *XDPSocket) ReadPacket() ([]byte, error) {
	// Return from RxChan or Ring
	time.Sleep(100 * time.Millisecond)
	return nil, nil // Return Mock
}

func (s *XDPSocket) WritePacket(data []byte) error {
	// TX Ring
	return nil
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}
