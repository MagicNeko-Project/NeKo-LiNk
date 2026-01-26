use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::MutableTcpPacket;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Instant, Duration};

const ETH_HEADER_LEN: usize = 14;

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
struct FlowKey {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
}

struct Flow {
    buffer: Vec<u8>,
    #[allow(dead_code)]
    next_seq: u32,
    last_seen: Instant,
}

pub struct GROTable {
    flows: HashMap<FlowKey, Flow>,
}

impl GROTable {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
        }
    }

    /// Ingest a packet.
    /// Returns a list of packets that are ready to be written to the Veth interface.
    /// Currently acts as a pass-through (GRO disabled).
    pub fn ingest(&mut self, packet: &[u8]) -> Vec<Vec<u8>> {
        let mut output = Vec::new();

        // 1. Parse Headers (Eth + IP + TCP)
        // DISABLE GRO: Immediately return packet to avoid MTU issues on Veth write.
        output.push(packet.to_vec());
        output
    }
    
    // Check for stale flows and flush them
    pub fn flush_stale(&mut self) -> Vec<Vec<u8>> {
        let mut output = Vec::new();
        let now = Instant::now();
        // Drain logic: iter & collect keys
        let keys_to_remove: Vec<FlowKey> = self.flows.iter()
            .filter(|(_, flow)| now.duration_since(flow.last_seen) > Duration::from_millis(10)) 
            .map(|(k, _)| k.clone())
            .collect();

        for k in keys_to_remove {
            if let Some(mut flow) = self.flows.remove(&k) {
                 Self::fixup_headers(&mut flow.buffer, 0);
                 output.push(flow.buffer);
            }
        }
        output
    }
    
    fn fixup_headers(buffer: &mut Vec<u8>, _next_seq: u32) {
        // Update IP Length
        let total_len = buffer.len();
        {
             let mut new_ip = MutableIpv4Packet::new(&mut buffer[ETH_HEADER_LEN..]).unwrap();
             new_ip.set_total_length(total_len as u16);
             new_ip.set_checksum(pnet::packet::ipv4::checksum(&new_ip.to_immutable()));
             
             let src = new_ip.get_source();
             let dst = new_ip.get_destination();
             let ip_header_len = (new_ip.get_header_length() as usize) * 4;
             let tcp_start = ETH_HEADER_LEN + ip_header_len;
             
             if tcp_start < buffer.len() {
                 if let Some(mut new_tcp) = MutableTcpPacket::new(&mut buffer[tcp_start..]) {
                     new_tcp.set_checksum(0);
                     new_tcp.set_checksum(pnet::packet::tcp::ipv4_checksum(
                         &new_tcp.to_immutable(),
                         &src,
                         &dst
                     ));
                 }
             }
        }
    }
}
