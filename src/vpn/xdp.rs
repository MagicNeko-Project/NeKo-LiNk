use aya::Bpf;
use aya::programs::{Xdp, XdpFlags, SchedClassifier, TcAttachType};
use aya::programs::xdp::XdpLinkId;
use aya::programs::tc::SchedClassifierLinkId;
use std::convert::TryInto;
use log::{info, warn, error};

pub struct BpfHandle {
    // Keep Bpf instances alive
    _xdp_bpf: Bpf,
    _tc_bpf: Bpf,
    _xdp_link: Option<XdpLinkId>,
    _tc_link: Option<SchedClassifierLinkId>,
}

pub fn init_bpf(interface_name: &str) -> anyhow::Result<Option<BpfHandle>> {
    info!("Loading eBPF programs (XDP + TC)...");

    // --- 1. XDP (Ingress) ---
    let mut xdp_bpf = Bpf::load(include_bytes!(concat!(env!("OUT_DIR"), "/xdp_kern.o")))?;
    
    // Program name in C: "xdp_pass_func" (section "xdp.frags")
    // Aya might key it by function name "xdp_pass_func" or section "xdp.frags" depending on loader.
    // Try function name first.
    let xdp_program: &mut Xdp = xdp_bpf.program_mut("xdp_pass_func").unwrap().try_into()?;
    xdp_program.load()?;

    let xdp_link = match xdp_program.attach(interface_name, XdpFlags::default()) {
        Ok(l) => {
            info!("XDP Program attached to {}", interface_name);
            Some(l)
        },
        Err(e) => {
            warn!("Failed to attach XDP program: {}. (Packet processing might be slower)", e);
            None
        }
    };

    // --- 2. TC (Egress) ---
    // Note: Requires 'clsact' qdisc. We assume it's created by init_interface.
    let mut tc_bpf = Bpf::load(include_bytes!(concat!(env!("OUT_DIR"), "/tc_kern.o")))?;
    
    // Program name in C: "tc_egress_func" (section "classifier")
    let tc_program: &mut SchedClassifier = tc_bpf.program_mut("tc_egress_func").unwrap().try_into()?;
    tc_program.load()?;
    
    let tc_link = match tc_program.attach(interface_name, TcAttachType::Egress) {
        Ok(l) => {
            info!("TC Egress Program attached to {}", interface_name);
            Some(l)
        },
        Err(e) => {
             warn!("Failed to attach TC Egress program: {}. (TX Offload might be limited)", e);
             None
        }
    };

    Ok(Some(BpfHandle { 
        _xdp_bpf: xdp_bpf, 
        _tc_bpf: tc_bpf,
        _xdp_link: xdp_link,
        _tc_link: tc_link,
    }))
}
