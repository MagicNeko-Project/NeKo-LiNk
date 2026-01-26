#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{xdp, classifier, map},
    programs::{XdpContext, TcContext},
    maps::{HashMap, Array},
    EbpfContext,
    bindings::{__sk_buff, xdp_md},
};
use aya_log_ebpf::info;
use neko_link_common::{CryptoConfig, MAX_CRYPTO_CONTEXTS};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[repr(C)]
pub struct bpf_dynptr {
    pub reserved1: u64,
    pub reserved2: u64,
}

#[map]
static mut CRYPTO_CONFIG: HashMap<u32, CryptoConfig> = HashMap::with_max_entries(1, 0);

#[map]
static mut CRYPTO_CTX: HashMap<u32, u64> = HashMap::with_max_entries(MAX_CRYPTO_CONTEXTS, 0);

#[map]
static mut SEQ_COUNTER: Array<u64> = Array::with_max_entries(1, 0);

// kfunc declarations
extern "C" {
    pub fn bpf_ktime_get_ns() -> u64;
    pub fn bpf_skb_adjust_room(skb: *mut __sk_buff, len_diff: i32, mode: u32, flags: u64) -> i32;
    pub fn bpf_skb_change_tail(skb: *mut __sk_buff, len: u32, flags: u64) -> i32;
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

    pub fn bpf_dynptr_from_skb(
        skb: *mut __sk_buff,
        flags: u64,
        ptr: *mut bpf_dynptr,
    ) -> i32;

    pub fn bpf_dynptr_from_xdp(
        xdp: *mut xdp_md,
        flags: u64,
        ptr: *mut bpf_dynptr,
    ) -> i32;

    pub fn bpf_dynptr_from_mem(
        data: *const core::ffi::c_void,
        size: u32,
        flags: u64,
        ptr: *mut bpf_dynptr,
    ) -> i32;

    pub fn bpf_xdp_adjust_head(xdp_md: *mut xdp_md, delta: i32) -> i32;
    pub fn bpf_redirect(ifindex: u32, flags: u64) -> i32;
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

    // IV Extraction (12 Bytes)
    let iv_offset = EthHdr::LEN + Ipv4Hdr::LEN;
    let iv_len = 12;

    if ctx.data() + iv_offset + iv_len > ctx.data_end() {
        return Ok(2);
    }

    let mut iv = [0u8; 12];
    unsafe {
        let iv_ptr = (ctx.data() + iv_offset) as *const u8;
        core::ptr::copy_nonoverlapping(iv_ptr, iv.as_mut_ptr(), 12);
    }

    // Strip Outer Eth + Outer IP + IV
    let delta = (iv_offset + iv_len) as i32;
    unsafe {
        if bpf_xdp_adjust_head(ctx.ctx, delta) != 0 {
            return Ok(2);
        }
    }

    // Crypto Setup
    let crypto_ctx_addr = unsafe { CRYPTO_CTX.get(&0).ok_or(())? };
    let crypto_ctx = *crypto_ctx_addr as *mut core::ffi::c_void;

    let mut data_ptr = bpf_dynptr { reserved1: 0, reserved2: 0 };
    unsafe {
        if bpf_dynptr_from_xdp(ctx.ctx, 0, &mut data_ptr) != 0 {
            return Ok(1); // Drop
        }
    }

    let mut iv_ptr = bpf_dynptr { reserved1: 0, reserved2: 0 };
    unsafe {
        if bpf_dynptr_from_mem(iv.as_ptr() as *const _, 12, 0, &mut iv_ptr) != 0 {
            return Ok(1);
        }
    }

    // Decrypt
    unsafe {
        if bpf_crypto_decrypt(
            crypto_ctx,
            &data_ptr as *const _ as *const _,
            &mut data_ptr as *mut _ as *mut _,
            &iv_ptr as *const _ as *const _
        ) != 0 {
            return Ok(1);
        }
    }
    
    // Redirect to Veth
    unsafe {
        Ok(bpf_redirect(config.veth_if_index, 0) as u32)
    }
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
    // 1. MSS Clamping
    {
        let ethhdr: *mut EthHdr = unsafe { ptr_at_tc(&ctx, 0)? };
        if unsafe { (*ethhdr).ether_type } == network_types::eth::EtherType::Ipv4 {
            let ipv4hdr_ptr: *mut Ipv4Hdr = unsafe { ptr_at_tc(&ctx, EthHdr::LEN)? };
            let ipv4hdr = unsafe { &mut *ipv4hdr_ptr };

            if ipv4hdr.proto == IpProto::Tcp {
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
            }
        }
    }

    // 2. Encryption & Encapsulation
    let config = unsafe { CRYPTO_CONFIG.get(&0).ok_or(())? };
    let crypto_ctx_addr = unsafe { CRYPTO_CTX.get(&0).ok_or(())? };
    let crypto_ctx = *crypto_ctx_addr as *mut core::ffi::c_void;

    // IV Gen
    let seq_ptr = unsafe { SEQ_COUNTER.get_ptr_mut(0).ok_or(())? };
    let seq = unsafe { *seq_ptr };
    unsafe { *seq_ptr = seq.wrapping_add(1); }

    let mut iv = [0u8; 12];
    iv[0..8].copy_from_slice(&seq.to_be_bytes());
    
    let mut iv_ptr = bpf_dynptr { reserved1: 0, reserved2: 0 };
    unsafe {
        if bpf_dynptr_from_mem(iv.as_ptr() as *const _, 12, 0, &mut iv_ptr) != 0 {
            return Ok(0);
        }
    }

    // Expand Tail for Tag (16 bytes)
    // Calculate new len
    let old_len = ctx.len();
    let new_len = old_len + 16;
    unsafe {
        if bpf_skb_change_tail(ctx.skb.skb, new_len, 0) != 0 {
             return Ok(0);
        }
    }

    // Encrypt
    let mut data_ptr = bpf_dynptr { reserved1: 0, reserved2: 0 };
    unsafe {
        if bpf_dynptr_from_skb(ctx.skb.skb, 0, &mut data_ptr) == 0 {
             if bpf_crypto_encrypt(crypto_ctx, &data_ptr as *const _ as *const _, &mut data_ptr as *mut _ as *mut _, &iv_ptr as *const _ as *const _) != 0 {
                 return Ok(0);
             }
        }
    }

    // 3. Encapsulate (Header Prepend)
    let encap_len = EthHdr::LEN + Ipv4Hdr::LEN + 12;
    unsafe {
        // Mode 1 = MAC (push before Mac header)
        if bpf_skb_adjust_room(ctx.skb.skb, encap_len as i32, 1, 0) != 0 {
            return Ok(0);
        }

        // Write Headers
        let ethhdr: *mut EthHdr = ptr_at_tc(&ctx, 0)?;
        (*ethhdr).dst_addr = [0; 6];
        (*ethhdr).src_addr = [0; 6];
        (*ethhdr).ether_type = network_types::eth::EtherType::Ipv4;

        let ipv4hdr: *mut Ipv4Hdr = ptr_at_tc(&ctx, EthHdr::LEN)?;
        // network-types Ipv4Hdr uses setters/getters for bitfields
        (*ipv4hdr).set_version(4);
        (*ipv4hdr).set_ihl(5);
        (*ipv4hdr).tos = 0;
        (*ipv4hdr).tot_len = ((new_len as usize) + Ipv4Hdr::LEN + 12).to_be() as u16;
        (*ipv4hdr).id = 0;
        (*ipv4hdr).frag_off = 0x4000u16.to_be(); // DF set
        (*ipv4hdr).ttl = 64;
        (*ipv4hdr).proto = core::mem::transmute(config.protocol_number);
        (*ipv4hdr).check = 0;
        (*ipv4hdr).src_addr = config.local_ip;
        (*ipv4hdr).dst_addr = config.remote_ip;

        let iv_dest: *mut u8 = ptr_at_tc(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
        core::ptr::copy_nonoverlapping(iv.as_ptr(), iv_dest, 12);
    }

    // Redirect
    unsafe {
        Ok(bpf_redirect(config.phys_if_index, 0))
    }
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
