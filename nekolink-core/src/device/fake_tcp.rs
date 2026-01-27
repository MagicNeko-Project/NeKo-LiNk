// NekoLink Fake-TCP Module ฅ^•ﻌ•^ฅ
// 这个模块负责在用户态模拟 TCP 头部，让 UDP 数据包看起来像标准 TCP 流量。

use std::net::{IpAddr, Ipv4Addr};
use std::io;

#[derive(Debug, Clone, Copy)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u16,
    pub window: u16,
}

pub const TCP_FLAG_FIN: u16 = 0x01;
pub const TCP_FLAG_SYN: u16 = 0x02;
pub const TCP_FLAG_RST: u16 = 0x04;
pub const TCP_FLAG_PSH: u16 = 0x08;
pub const TCP_FLAG_ACK: u16 = 0x10;

impl TcpHeader {
    pub fn new(src_port: u16, dst_port: u16, seq: u32, ack: u32, flags: u16) -> Self {
        Self {
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            window: 64240, // 模仿 Windows/Linux 的默认窗口大小喵
        }
    }

    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        buf[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        buf[4..8].copy_from_slice(&self.seq.to_be_bytes());
        buf[8..12].copy_from_slice(&self.ack.to_be_bytes());
        buf[12] = 0x50; // Data offset (5 * 4 = 20 bytes)
        buf[13] = self.flags as u8;
        buf[14..16].copy_from_slice(&self.window.to_be_bytes());
        buf[16..18].copy_from_slice(&[0, 0]); // Checksum (placeholder)
        buf[18..20].copy_from_slice(&[0, 0]); // Urgent Pointer
    }

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 20 { return None; }
        
        Some(Self {
            src_port: u16::from_be_bytes([buf[0], buf[1]]),
            dst_port: u16::from_be_bytes([buf[2], buf[3]]),
            seq: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            ack: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
            flags: buf[13] as u16,
            window: u16::from_be_bytes([buf[14], buf[15]]),
        })
    }
}

/// 计算 TCP 校验和喵
pub fn calculate_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // IPv4 伪头部喵
    let src_octets = src_ip.octets();
    let dst_octets = dst_ip.octets();
    
    sum += u16::from_be_bytes([src_octets[0], src_octets[1]]) as u32;
    sum += u16::from_be_bytes([src_octets[2], src_octets[3]]) as u32;
    sum += u16::from_be_bytes([dst_octets[0], dst_octets[1]]) as u32;
    sum += u16::from_be_bytes([dst_octets[2], dst_octets[3]]) as u32;
    sum += 6 as u32; // Protocol (TCP = 6)
    sum += tcp_segment.len() as u32;

    // TCP 段喵
    for i in (0..tcp_segment.len()).step_by(2) {
        if i + 1 < tcp_segment.len() {
            sum += u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]) as u32;
        } else {
            sum += u16::from_be_bytes([tcp_segment[i], 0]) as u32;
        }
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

/// 准备一个完整的 TCP 报文喵
/// src_ip 和 dst_ip 用于计算校验和喵
pub fn prepare_tcp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u16,
    payload: &[u8],
    out_buf: &mut [u8],
) -> usize {
    let header = TcpHeader::new(src_port, dst_port, seq, ack, flags);
    header.write_to(&mut out_buf[0..20]);
    out_buf[20..20 + payload.len()].copy_from_slice(payload);
    
    let checksum = calculate_checksum(src_ip, dst_ip, &out_buf[0..20 + payload.len()]);
    out_buf[16..18].copy_from_slice(&checksum.to_be_bytes());
    
    20 + payload.len()
}
