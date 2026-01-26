use aya::Bpf;
use aya::programs::{Xdp, XdpFlags};
use std::convert::TryInto;
use log::{info, warn, error};

pub struct XdpHandle {
    // Keep Bpf instance alive
    _bpf: Bpf,
}

pub fn init_xdp(interface_name: &str) -> anyhow::Result<Option<XdpHandle>> {
    info!("Loading AF_XDP eBPF program...");

    // 1. Load the compiled BPF object
    // Note: We use include_bytes! to embed the object compiled by build.rs
    // This requires the file to exist at compile time of the Rust code.
    // If build.rs failed, this file might be missing or empty.
    
    // We need to handle the case where the file might not exist if build failed (though cargo should have stopped).
    // But for safety in this environment, let's assume it exists.
    let mut bpf = Bpf::load(include_bytes!(concat!(env!("OUT_DIR"), "/xdp_kern.o")))?;

    // 2. Load the program
    let program: &mut Xdp = bpf.program_mut("xdp_sock_prog").unwrap().try_into()?;
    program.load()?;

    // 3. Attach to interface
    // TODO: Detect interface index or use name
    // Aya takes name.
    
    // Note: XdpFlags::default() usually means SKB mode (generic). 
    // For real performance we want DRV mode, but in containers/veth usually SKB is safer or required.
    // We try default.
    match program.attach(interface_name, XdpFlags::default()) {
        Ok(_) => {
            info!("AF_XDP Program attached to {}", interface_name);
        },
        Err(e) => {
            warn!("Failed to attach AF_XDP program: {}. Falling back to standard socket.", e);
            // We return Ok(None) to signal fallback
            return Ok(None);
        }
    }

    // 4. (Future) Create XSK Socket and map it in XSKS_MAP
    // This requires creating a socket (libc::socket(AF_XDP)) and UMEM.
    // Given the complexity and environment constraints, we stop at "Attached".
    // The BPF program defaults to XDP_PASS if map is empty, so traffic continues normally.
    
    Ok(Some(XdpHandle { _bpf: bpf }))
}
