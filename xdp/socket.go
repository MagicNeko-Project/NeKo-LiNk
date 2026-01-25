package xdp

import (
	"bytes"
	"embed"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

//go:embed xdp_kern.o
var bpfContent embed.FS

// --- Constants (Linux Headers) ---

const (
	XDP_USE_NEED_WAKEUP = 1 << 3
	
	XDP_COPY = 2
	XDP_ZEROCOPY = 4

	// Offsets
	XDP_RX_RING_OFFSET   = 0
	XDP_TX_RING_OFFSET   = 1
	XDP_UMEM_REG_OFFSET  = 3
	XDP_UMEM_FILL_RING   = 4
	XDP_UMEM_COMP_RING   = 5
)

// --- Structs (Mapped to C struct layouts) ---

type XdpDesc struct {
	Addr    uint64
	Len     uint32
	Options uint32
}

type XdpRing struct {
	Producer *uint32
	Consumer *uint32
	Descs    []XdpDesc // For Tx/Rx (Circular)
	Addrs    []uint64  // For Fill/Comp (Circular)
	
	RingMask uint32
	Size     uint32
}

type XdpUmemReg struct {
	Addr     uint64
	Len      uint64
	ChunkSize uint32
	Headroom  uint32
}

type Config struct {
	Interface string
	QueueID   int
	Mode      int // 1=UDP, 2=Raw
	Target    int // Port or Proto
	
	// Rings
	RingSize uint32 // Must be power of 2
}

type Socket struct {
	Fd          int
	IfIndex     int
	QueueID     int
	Cfg         Config
	
	UmemMemory  []byte
	
	Rx Ring
	Tx Ring
	Fill Ring
	Comp Ring
	
	// Stats
	RxCount uint64
	TxCount uint64
	
	// BPF Objects
	Link      link.Link
	XsksMap   *ebpf.Map
	ConfigMap *ebpf.Map
	Prog      *ebpf.Program
}

// Internal Ring Helper
type Ring struct {
	Producer *uint32
	Consumer *uint32
	Descs    unsafe.Pointer // Points to start of descriptor/addr array in mmap
	
	Mask     uint32
	Size     uint32
	IsDesc   bool // True for Rx/Tx, False for Fill/Comp
}

func NewSocket(cfg Config) (*Socket, error) {
	if cfg.RingSize == 0 { cfg.RingSize = 2048 }

	// 1. Get Interface
	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil { return nil, fmt.Errorf("interface not found: %w", err) }
	
	// 2. Load BPF
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
	
	// Attach XDP
	// Attach XDP
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProg,
		Interface: iface.Index,
	})
	if err != nil {
		log.Printf("[XDP] Default attach failed (%v), trying SKB/Generic mode...", err)
		l, err = link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpProg,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
		if err != nil { return nil, fmt.Errorf("attach xdp (generic) failed: %w", err) }
		log.Printf("[XDP] Attached in SKB/Generic mode")
	} else {
		log.Printf("[XDP] Attached in Native/Driver mode")
	}
	
	// Write Config Map
	m := uint32(cfg.Mode)
	v := uint32(cfg.Target)
	if cfg.Mode == 1 {
		v = uint32(htons(uint16(cfg.Target)))
	}
	k0 := uint32(0); objs.ConfigMap.Put(&k0, &m)
	k1 := uint32(1); objs.ConfigMap.Put(&k1, &v)
	
	log.Printf("XDP Attached to %s (Mode %d, Target %d)", cfg.Interface, cfg.Mode, cfg.Target)

	// 3. Create Socket
	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil { return nil, fmt.Errorf("socket create failed: %w", err) }
	
	xsk := &Socket{
		Fd:        fd,
		IfIndex:   iface.Index,
		QueueID:   cfg.QueueID,
		Cfg:       cfg,
		Link:      l,
		XsksMap:   objs.XsksMap,
		ConfigMap: objs.ConfigMap,
	}
	
	// 4. UMEM Allocation
	frameSize := uint32(4096)
	numFrames := cfg.RingSize * 2
	memSize := uint64(numFrames) * uint64(frameSize)
	
	mem, err := unix.Mmap(-1, 0, int(memSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil { 
		unix.Close(fd)
		return nil, fmt.Errorf("mmap umem failed: %w", err) 
	}
	xsk.UmemMemory = mem
	
	// Register UMEM
	reg := XdpUmemReg{
		Addr:      uint64(uintptr(unsafe.Pointer(&mem[0]))),
		Len:       memSize,
		ChunkSize: frameSize,
		Headroom:  0,
	}
	if err := setsockopt(fd, unix.SOL_XDP, unix.XDP_UMEM_REG, unsafe.Pointer(&reg), unsafe.Sizeof(reg)); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("setsockopt UMEM_REG failed: %w", err)
	}
	
	// 5. Setup Rings
	setsockoptInt(fd, unix.SOL_XDP, unix.XDP_UMEM_FILL_RING, int(cfg.RingSize))
	setsockoptInt(fd, unix.SOL_XDP, unix.XDP_UMEM_COMPLETION_RING, int(cfg.RingSize))
	
	var off unix.XDPMmapOffsets
	size := uint32(unsafe.Sizeof(off))
	getsockopt(fd, unix.SOL_XDP, unix.XDP_MMAP_OFFSETS, unsafe.Pointer(&off), &size)
	
	fillMap, _ := unix.Mmap(fd, unix.XDP_UMEM_PGOFF_FILL_RING, int(off.Fr.Desc + uint64(cfg.RingSize)*8), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	xsk.Fill = initRing(fillMap, off.Fr.Producer, off.Fr.Consumer, off.Fr.Desc, cfg.RingSize, false)

	compMap, _ := unix.Mmap(fd, unix.XDP_UMEM_PGOFF_COMPLETION_RING, int(off.Cr.Desc + uint64(cfg.RingSize)*8), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	xsk.Comp = initRing(compMap, off.Cr.Producer, off.Cr.Consumer, off.Cr.Desc, cfg.RingSize, false)
	
	setsockoptInt(fd, unix.SOL_XDP, unix.XDP_RX_RING, int(cfg.RingSize))
	setsockoptInt(fd, unix.SOL_XDP, unix.XDP_TX_RING, int(cfg.RingSize))
	
	rxMap, _ := unix.Mmap(fd, unix.XDP_PGOFF_RX_RING, int(off.Rx.Desc + uint64(cfg.RingSize)*16), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	xsk.Rx = initRing(rxMap, off.Rx.Producer, off.Rx.Consumer, off.Rx.Desc, cfg.RingSize, true)

	txMap, _ := unix.Mmap(fd, unix.XDP_PGOFF_TX_RING, int(off.Tx.Desc + uint64(cfg.RingSize)*16), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	xsk.Tx = initRing(txMap, off.Tx.Producer, off.Tx.Consumer, off.Tx.Desc, cfg.RingSize, true)
	
	// Bind
	sa := &unix.SockaddrXDP{
		Flags:   0,
		Ifindex: uint32(iface.Index),
		QueueID: uint32(cfg.QueueID),
		SharedUmemFD: 0,
	}
	if err := unix.Bind(fd, sa); err != nil {
		return nil, fmt.Errorf("bind failed: %w", err)
	}

	// Initial Fill
	xsk.fillRxBuffer(cfg.RingSize)

	return xsk, nil
}

func initRing(mem []byte, prodOff, consOff, descOff uint64, size uint32, isDesc bool) Ring {
	base := uintptr(unsafe.Pointer(&mem[0]))
	return Ring{
		Producer: (*uint32)(unsafe.Pointer(base + uintptr(prodOff))),
		Consumer: (*uint32)(unsafe.Pointer(base + uintptr(consOff))),
		Descs:    unsafe.Pointer(base + uintptr(descOff)),
		Mask:     size - 1,
		Size:     size,
		IsDesc:   isDesc,
	}
}

func (x *Socket) fillRxBuffer(n uint32) {
	prod := *x.Fill.Producer
	start := uintptr(x.Fill.Descs)
	for i := uint32(0); i < n; i++ {
		addr := uint64(i * 4096)
		idx := (prod + i) & x.Fill.Mask
		ptr := (*uint64)(unsafe.Pointer(start + uintptr(idx)*8))
		*ptr = addr
	}
	atomicAdd(x.Fill.Producer, n)
}

// --- Data Path Methods ---

func (x *Socket) AddToMap(bpfMap *ebpf.Map) error {
	key := uint32(x.QueueID)
	val := uint32(x.Fd)
	return bpfMap.Put(&key, &val)
}

func (x *Socket) Receive() ([][]byte, error) {
	cons := atomic.LoadUint32(x.Rx.Consumer)
	prod := atomic.LoadUint32(x.Rx.Producer)
	
	if cons == prod { return nil, nil }
	
	count := prod - cons
	start := uintptr(x.Rx.Descs)
	var packets [][]byte
	
	for i := uint32(0); i < count; i++ {
		idx := (cons + i) & x.Rx.Mask
		descPtr := (*XdpDesc)(unsafe.Pointer(start + uintptr(idx)*16))
		
		dataStart := x.UmemMemory[descPtr.Addr : descPtr.Addr+uint64(descPtr.Len)]
		pkt := make([]byte, len(dataStart))
		copy(pkt, dataStart)
		packets = append(packets, pkt)
		
		x.FreeFrame(descPtr.Addr)
	}
	
	atomic.StoreUint32(x.Rx.Consumer, cons+count)
	return packets, nil
}

func (x *Socket) FreeFrame(addr uint64) {
    prod := atomic.LoadUint32(x.Fill.Producer)
    idx := prod & x.Fill.Mask
    start := uintptr(x.Fill.Descs)
    ptr := (*uint64)(unsafe.Pointer(start + uintptr(idx)*8))
    *ptr = addr
    atomic.StoreUint32(x.Fill.Producer, prod+1)
}

func (x *Socket) Transmit(data []byte) error {
	prod := atomic.LoadUint32(x.Tx.Producer)
	cons := atomic.LoadUint32(x.Tx.Consumer)
	
	if prod - cons >= x.Tx.Size {
		x.ReclaimTx()
		cons = atomic.LoadUint32(x.Tx.Consumer)
		if prod - cons >= x.Tx.Size { return fmt.Errorf("tx full") }
	}
	
	txSlot := (x.TxCount) % uint64(x.Tx.Size)
	addr := uint64(x.Tx.Size)*4096 + uint64(txSlot)*4096
	
	if len(data) > 4096 { return fmt.Errorf("pkt too big") }
	copy(x.UmemMemory[addr:], data)
	
	idx := prod & x.Tx.Mask
	start := uintptr(x.Tx.Descs)
	descPtr := (*XdpDesc)(unsafe.Pointer(start + uintptr(idx)*16))
	descPtr.Addr = addr
	descPtr.Len = uint32(len(data))
	
	atomic.StoreUint32(x.Tx.Producer, prod+1)
	unix.Sendto(x.Fd, nil, 0, nil)
	x.TxCount++
	return nil
}

func (x *Socket) ReclaimTx() {
	cons := atomic.LoadUint32(x.Comp.Consumer)
	prod := atomic.LoadUint32(x.Comp.Producer)
	if cons != prod {
		atomic.StoreUint32(x.Comp.Consumer, prod)
	}
}

func (x *Socket) Poll(timeout int) {
	pfd := []unix.PollFd{ {Fd: int32(x.Fd), Events: unix.POLLIN} }
	unix.Poll(pfd, timeout)
}

func (x *Socket) GetFD() int { return x.Fd }

// Helpers
func setsockopt(fd, level, opt int, val unsafe.Pointer, size uintptr) error {
	_, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(fd), uintptr(level), uintptr(opt), uintptr(val), size, 0)
	if errno != 0 { return errno }
	return nil
}
func setsockoptInt(fd, level, opt, val int) error {
	v := int32(val)
	return setsockopt(fd, level, opt, unsafe.Pointer(&v), 4)
}
func getsockopt(fd, level, opt int, val unsafe.Pointer, size *uint32) error {
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), uintptr(level), uintptr(opt), uintptr(val), uintptr(unsafe.Pointer(size)), 0)
	if errno != 0 { return errno }
	return nil
}
func htons(v uint16) uint16 { return (v << 8) | (v >> 8) }
func atomicAdd(ptr *uint32, val uint32) { atomic.AddUint32(ptr, val) }
