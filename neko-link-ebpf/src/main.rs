#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{xdp, classifier, map},
    programs::{XdpContext, TcContext},
    maps::{HashMap},
    EbpfContext,
};
use aya_log_ebpf::info;
use neko_link_common::{CryptoConfig, MAX_CRYPTO_CONTEXTS};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[map]
static mut CRYPTO_CONFIG: HashMap<u32, CryptoConfig> = HashMap::with_max_entries(1, 0);

#[map]
static mut CRYPTO_CTX: HashMap<u32, u64> = HashMap::with_max_entries(MAX_CRYPTO_CONTEXTS, 0);

// kfunc declarations
extern "C" {
    pub fn bpf_crypto_ctx_create(
        algo_name: *const i8,
        cipher_opt: *const core::ffi::c_void,
        opt_len: u32,
        err: *mut i32,
    ) -> *mut core::ffi::c_void;
    
    pub fn bpf_crypto_ctx_release(ctx: *mut core::ffi::c_void);
    
    pub fn bpf_crypto_encrypt(
        ctx: *mut core::ffi::c_void,
        src: *const core::ffi::c_void, // bpf_dynptr
        dst: *mut core::ffi::c_void,   // bpf_dynptr
        siv: *const core::ffi::c_void,  // bpf_dynptr
    ) -> i32;

    pub fn bpf_crypto_decrypt(
        ctx: *mut core::ffi::c_void,
        src: *const core::ffi::c_void, // bpf_dynptr
        dst: *mut core::ffi::c_void,   // bpf_dynptr
        siv: *const core::ffi::c_void,  // bpf_dynptr
    ) -> i32;
}

#[no_mangle]
#[link_section = "syscall"]
pub fn init_crypto_ctx(_ctx: *mut core::ffi::c_void) -> u32 {
    let config = unsafe { CRYPTO_CONFIG.get(&0) };
    if config.is_none() { return 1; }
    let config = config.unwrap();

    let algo = match config.cipher_suite {
        1 => b"aes(gcm)\0".as_ptr() as *const i8,
        2 => b"rfc7539(chacha20,poly1305)\0".as_ptr() as *const i8,
        _ => return 2,
    };

    let mut err: i32 = 0;
    let crypto_ctx = unsafe { bpf_crypto_ctx_create(algo, core::ptr::null(), 0, &mut err) };
    
    if crypto_ctx.is_null() {
        return err as u32;
    }

    unsafe { let _ = CRYPTO_CTX.insert(&0, &(crypto_ctx as u64), 0); };
    0
}

use core::mem;
use network_types::{
    eth::EthHdr,
    ip::Ipv4Hdr,
};

#[xdp(frags)]
pub fn xdp_ingress(ctx: XdpContext) -> u32 {
    match try_xdp_ingress(ctx) {
        Ok(ret) => ret,
        Err(_) => 2, // XDP_PASS
    }
}

fn try_xdp_ingress(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *mut EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        network_types::eth::EtherType::Ipv4 => {}
        _ => return Ok(2),
    }

    let ipv4hdr: *mut Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let config = unsafe { CRYPTO_CONFIG.get(&0).ok_or(())? };

    if (unsafe { (*ipv4hdr).proto } as u8) != config.protocol_number {
        return Ok(2);
    }
    
    info!(&ctx, "Received tunnel packet");
    Ok(2)
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end { return Err(()); }
    Ok((start + offset) as *mut T)
}

use network_types::{tcp::TcpHdr, ip::IpProto};
use aya_ebpf::helpers::bpf_l4_csum_replace;

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // TC_ACT_OK
    }
}

fn try_tc_egress(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: *mut EthHdr = unsafe { ptr_at_tc(&ctx, 0)? };
    if unsafe { (*ethhdr).ether_type } != network_types::eth::EtherType::Ipv4 {
        return Ok(0);
    }

    let ipv4hdr_ptr: *mut Ipv4Hdr = unsafe { ptr_at_tc(&ctx, EthHdr::LEN)? };
    let ipv4hdr = unsafe { &mut *ipv4hdr_ptr };
    
    if ipv4hdr.proto != IpProto::Tcp { return Ok(0); }

    let tcphdr_ptr: *mut TcpHdr = unsafe { ptr_at_tc(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
    let tcphdr = unsafe { &mut *tcphdr_ptr };
    
    if tcphdr.syn() != 0 {
        let old_mss = get_mss_option(&ctx, tcphdr_ptr)?;
        if let Some((offset, mss)) = old_mss {
            if mss > 1360 {
                let new_mss = 1360u16;
                let mss_ptr: *mut u16 = unsafe { ptr_at_tc(&ctx, offset)? };
                unsafe { *mss_ptr = new_mss.to_be() };

                unsafe {
                    bpf_l4_csum_replace(
                        ctx.as_ptr() as *mut _,
                        (EthHdr::LEN + Ipv4Hdr::LEN + 16) as u32,
                        mss.to_be() as u64,
                        new_mss.to_be() as u64,
                        2,
                    );
                }
                info!(&ctx, "Clamped MSS");
            }
        }
    }
    Ok(0)
}

fn get_mss_option(ctx: &TcContext, tcphdr: *mut TcpHdr) -> Result<Option<(usize, u16)>, ()> {
    let doff = unsafe { (*tcphdr).doff() as usize * 4 };
    if doff <= TcpHdr::LEN { return Ok(None); }

    let mut offset = EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN;
    let end_offset = EthHdr::LEN + Ipv4Hdr::LEN + doff;

    while offset + 1 < end_offset {
        let opt_type = unsafe { *(ptr_at_tc::<u8>(ctx, offset)?) };
        if opt_type == 0 { break; }
        if opt_type == 1 { offset += 1; continue; }
        let opt_len = unsafe { *(ptr_at_tc::<u8>(ctx, offset + 1)?) } as usize;
        if opt_len < 2 { break; }
        if opt_type == 2 && opt_len == 4 {
            let mss = u16::from_be(unsafe { *(ptr_at_tc::<u16>(ctx, offset + 2)?) });
            return Ok(Some((offset + 2, mss)));
        }
        offset += opt_len;
    }
    Ok(None)
}

#[inline(always)]
unsafe fn ptr_at_tc<T>(ctx: &TcContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end { return Err(()); }
    Ok((start + offset) as *mut T)
}
