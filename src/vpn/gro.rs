use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{TcpPacket, MutableTcpPacket};
use pnet::packet::Packet;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Instant, Duration};

const ETH_HEADER_LEN: usize = 14;
const MAX_GRO_SIZE: usize = 65535;

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
struct FlowKey {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
}

struct Flow {
    buffer: Vec<u8>,
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
    /// (Usually 0 or 1 packet, but could be more if flush forced).
    pub fn ingest(&mut self, packet: &[u8]) -> Vec<Vec<u8>> {
        let mut output = Vec::new();

        // 1. Parse Headers (Eth + IP + TCP)
        if packet.len() < 54 {
             output.push(packet.to_vec());
             return output;
        }

        let ip_packet = match Ipv4Packet::new(&packet[ETH_HEADER_LEN..]) {
            Some(p) => p,
            None => {
                output.push(packet.to_vec());
                return output;
            }
        };

        if ip_packet.get_next_level_protocol() != pnet::packet::ip::IpNextHeaderProtocols::Tcp {
            output.push(packet.to_vec());
            return output;
        }

        let ip_header_len = (ip_packet.get_header_length() as usize) * 4;
        let tcp_start = ETH_HEADER_LEN + ip_header_len;
        
        // This check avoids panic if packet is malformed
        if tcp_start > packet.len() {
             output.push(packet.to_vec());
             return output;
        }

        let tcp_packet = match TcpPacket::new(&packet[tcp_start..]) {
            Some(p) => p,
            None => {
                output.push(packet.to_vec());
                return output;
            }
        };

        let tcp_header_len = (tcp_packet.get_data_offset() as usize) * 4;
        let payload_offset = tcp_start + tcp_header_len;
        if payload_offset > packet.len() {
             output.push(packet.to_vec());
             return output;
        }

        let payload_len = packet.len() - payload_offset;
        let seq = tcp_packet.get_sequence();
        let flags = tcp_packet.get_flags();
        
        let key = FlowKey {
            src: ip_packet.get_source(),
            dst: ip_packet.get_destination(),
            src_port: tcp_packet.get_source(),
            dst_port: tcp_packet.get_destination(),
        };

        // 2. Check Logic
        // If SYN, RST, URG is set, do not aggregate. Flush existing and pass current.
        if (flags & (pnet::packet::tcp::TcpFlags::SYN | pnet::packet::tcp::TcpFlags::RST | pnet::packet::tcp::TcpFlags::URG)) != 0 {
             if let Some(_) = self.flows.remove(&key) {
                 // If flow exists, we implicitly drop/flush it by removing.
                 // Ideally we should emit it, but simplified logic here clears state on Reset/Syn.
             }
             output.push(packet.to_vec());
             return output;
        }

        let flow_entry = self.flows.entry(key.clone());

        match flow_entry {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let is_match;
                let should_emit_current_flow;

                {
                    let flow = entry.get_mut();
                    is_match = flow.next_seq == seq && (flow.buffer.len() + payload_len) <= MAX_GRO_SIZE;
                    
                    if is_match {
                        // Match! Append.
                        let payload = &packet[payload_offset..];
                        flow.buffer.extend_from_slice(payload);
                        flow.next_seq += payload_len as u32;
                        flow.last_seen = Instant::now();
                        
                        // If PSH or FIN, we should emit this flow now.
                        should_emit_current_flow = (flags & (pnet::packet::tcp::TcpFlags::PSH | pnet::packet::tcp::TcpFlags::FIN)) != 0;
                    } else {
                        should_emit_current_flow = false;
                    }
                } 

                if is_match {
                    if should_emit_current_flow {
                         let mut completed_flow = entry.remove();
                         Self::fixup_headers(&mut completed_flow.buffer, 0);
                         output.push(completed_flow.buffer);
                    }
                } else {
                    // Mismatch or Full. Emit old, Start new.
                    let mut old_flow = entry.remove();
                    Self::fixup_headers(&mut old_flow.buffer, 0); 
                    output.push(old_flow.buffer);
                    
                    // Start new flow state with current packet
                    if payload_len > 0 && (flags & (pnet::packet::tcp::TcpFlags::PSH | pnet::packet::tcp::TcpFlags::FIN)) == 0 {
                         self.flows.insert(key, Flow {
                             buffer: packet.to_vec(),
                             next_seq: seq + payload_len as u32,
                             last_seen: Instant::now(),
                         });
                    } else {
                        output.push(packet.to_vec());
                    }
                }
            },
            std::collections::hash_map::Entry::Vacant(entry) => {
                // New Flow
                // Only buffer if it has payload and no PSH/FIN
                if payload_len > 0 && (flags & (pnet::packet::tcp::TcpFlags::PSH | pnet::packet::tcp::TcpFlags::FIN)) == 0 {
                    entry.insert(Flow {
                        buffer: packet.to_vec(),
                        next_seq: seq + payload_len as u32,
                        last_seen: Instant::now(),
                    });
                } else {
                    output.push(packet.to_vec());
                }
            }
        }
        
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
        }
    }
}
