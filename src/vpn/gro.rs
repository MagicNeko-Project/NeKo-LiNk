use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{TcpPacket, MutableTcpPacket, TcpFlags};
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
    // We store the *header* of the first packet as the template
    headers: Vec<u8>,
    // We store the payload separately to append easily
    payload: Vec<u8>,
    next_seq: u32,
    last_seen: Instant,
    // Accumulate flags (OR logic)
    flags: u8,
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
    /// Returns a list of packets ready to be emitted.
    pub fn ingest(&mut self, packet: &[u8]) -> Vec<Vec<u8>> {
        let mut output = Vec::new();

        // 1. Basic Validation
        if packet.len() < ETH_HEADER_LEN + 20 + 20 { // Eth + IP + TCP min
             output.push(packet.to_vec());
             return output;
        }

        // 2. Parse Headers
        // We use simple offset checks to avoid full parsing overhead if possible,
        // but pnet is safe.

        // Ethernet
        use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
        let eth = match EthernetPacket::new(&packet[..ETH_HEADER_LEN]) {
            Some(p) => p,
            None => { output.push(packet.to_vec()); return output; }
        };
        if eth.get_ethertype() != EtherTypes::Ipv4 {
            output.push(packet.to_vec());
            return output;
        }

        // IP
        let ip = match Ipv4Packet::new(&packet[ETH_HEADER_LEN..]) {
            Some(p) => p,
            None => { output.push(packet.to_vec()); return output; }
        };

        if ip.get_next_level_protocol() != pnet::packet::ip::IpNextHeaderProtocols::Tcp {
            output.push(packet.to_vec());
            return output;
        }

        let ip_header_len = (ip.get_header_length() as usize) * 4;
        let tcp_start = ETH_HEADER_LEN + ip_header_len;

        if tcp_start > packet.len() {
            output.push(packet.to_vec());
            return output;
        }

        // TCP
        let tcp = match TcpPacket::new(&packet[tcp_start..]) {
            Some(p) => p,
            None => { output.push(packet.to_vec()); return output; }
        };

        let tcp_header_len = (tcp.get_data_offset() as usize) * 4;
        let payload_offset = tcp_start + tcp_header_len;

        if payload_offset > packet.len() {
            output.push(packet.to_vec());
            return output;
        }

        let payload = &packet[payload_offset..];
        let payload_len = payload.len();
        let flags = tcp.get_flags();
        let seq = tcp.get_sequence();

        // 3. Control Flags Check
        // If SYN, RST, URG: Do not coalesce.
        if (flags & (TcpFlags::SYN | TcpFlags::RST | TcpFlags::URG)) != 0 {
             // Flush any existing flow for this key
             let key = FlowKey {
                 src: ip.get_source(),
                 dst: ip.get_destination(),
                 src_port: tcp.get_source(),
                 dst_port: tcp.get_destination(),
             };
             if let Some(mut flow) = self.flows.remove(&key) {
                 output.push(flow.assemble());
             }
             output.push(packet.to_vec());
             return output;
        }

        let key = FlowKey {
            src: ip.get_source(),
            dst: ip.get_destination(),
            src_port: tcp.get_source(),
            dst_port: tcp.get_destination(),
        };

        // 4. Flow Matching
        match self.flows.entry(key.clone()) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let flow = entry.get_mut();

                // Rules for coalescing:
                // 1. Sequence match (Flow Next Seq == Packet Seq)
                // 2. Ack match (Flow Ack == Packet Ack) - Simplified: we assume same Ack for bulk data
                // 3. Size limit
                let is_sequential = flow.next_seq == seq;
                let fits_size = (flow.headers.len() + flow.payload.len() + payload_len) <= MAX_GRO_SIZE;

                // Note: We should technically check ACK numbers too, but for RX GRO
                // typically if Seq matches, it's the next segment.
                // A mismatch in ACK usually implies a different flow state or bidirectional chatter.
                // For safety, let's just check seq.

                if is_sequential && fits_size {
                    // Append
                    flow.payload.extend_from_slice(payload);
                    flow.next_seq += payload_len as u32;
                    flow.last_seen = Instant::now();
                    flow.flags |= flags; // Merge flags (e.g. if one has PSH)

                    // If PSH or FIN, flush immediately
                    if (flags & (TcpFlags::PSH | TcpFlags::FIN)) != 0 {
                        let mut flow = entry.remove();
                        output.push(flow.assemble());
                    }
                } else {
                    // Mismatch: Flush old, start new
                    let mut old_flow = entry.remove();
                    output.push(old_flow.assemble());

                    // Start new (recurse or inline? Inline for safety)
                    // If current has PSH/FIN, don't buffer, just pass through (optimization)
                    if (flags & (TcpFlags::PSH | TcpFlags::FIN)) != 0 {
                        output.push(packet.to_vec());
                    } else if payload_len > 0 {
                        self.flows.insert(key, Flow::new(packet, payload_offset, seq, payload_len));
                    } else {
                        // Empty packet (pure ACK?), just pass
                        output.push(packet.to_vec());
                    }
                }
            },
            std::collections::hash_map::Entry::Vacant(entry) => {
                // New Flow
                // Buffer if no PSH/FIN and has payload
                if payload_len > 0 && (flags & (TcpFlags::PSH | TcpFlags::FIN)) == 0 {
                    entry.insert(Flow::new(packet, payload_offset, seq, payload_len));
                } else {
                    output.push(packet.to_vec());
                }
            }
        }

        output
    }

    /// Flush flows that haven't been updated recently.
    pub fn flush_stale(&mut self) -> Vec<Vec<u8>> {
        let mut output = Vec::new();
        let now = Instant::now();
        // 1ms timeout for GRO is typical for high performance
        let timeout = Duration::from_millis(1);

        let keys: Vec<FlowKey> = self.flows.iter()
            .filter(|(_, f)| now.duration_since(f.last_seen) > timeout)
            .map(|(k, _)| k.clone())
            .collect();

        for k in keys {
            if let Some(mut flow) = self.flows.remove(&k) {
                output.push(flow.assemble());
            }
        }
        output
    }
}

impl Flow {
    fn new(packet: &[u8], payload_offset: usize, seq: u32, payload_len: usize) -> Self {
        Self {
            headers: packet[..payload_offset].to_vec(),
            payload: packet[payload_offset..].to_vec(),
            next_seq: seq + payload_len as u32,
            last_seen: Instant::now(),
            flags: 0, // Flags from the *first* packet? No, we need to preserve them.
            // Actually, usually we take flags from the last packet (e.g. PSH).
            // But we might have accumulated flags.
            // Let's set initial flags from packet.
            // But wait, the `headers` contains the flags of the first packet.
            // We'll update the headers on assemble.
        }
    }

    fn assemble(&mut self) -> Vec<u8> {
        let mut pkt = self.headers.clone();
        pkt.extend_from_slice(&self.payload);

        let total_len = pkt.len();

        // Fixup IP
        {
             let mut ip = MutableIpv4Packet::new(&mut pkt[ETH_HEADER_LEN..]).unwrap();
             ip.set_total_length(total_len as u16 - ETH_HEADER_LEN as u16);
             ip.set_checksum(pnet::packet::ipv4::checksum(&ip.to_immutable()));
             
             let src = ip.get_source();
             let dst = ip.get_destination();
             let ip_hl = (ip.get_header_length() as usize) * 4;
             let tcp_start = ETH_HEADER_LEN + ip_hl;
             
             // Fixup TCP
             if tcp_start < total_len {
                 if let Some(mut tcp) = MutableTcpPacket::new(&mut pkt[tcp_start..]) {
                     // Update accumulated flags?
                     // If we had PSH in the middle, we should probably set it?
                     // Or just keep the flags from the first packet + accumulated?
                     // For GRO, usually the last packet's flags matter (like PSH).
                     // But we kept the first packet's headers.
                     // Let's OR the accumulated flags.
                     let old_flags = tcp.get_flags();
                     tcp.set_flags(old_flags | self.flags);

                     tcp.set_checksum(0);
                     tcp.set_checksum(pnet::packet::tcp::ipv4_checksum(
                         &tcp.to_immutable(),
                         &src,
                         &dst
                     ));
                 }
             }
        }

        pkt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::ipv4::{MutableIpv4Packet};
    use pnet::packet::tcp::{MutableTcpPacket, TcpPacket, TcpFlags};
    use pnet::packet::ethernet::{MutableEthernetPacket, EtherTypes};
    use std::net::Ipv4Addr;

    fn build_packet(seq: u32, payload: &[u8], flags: u8) -> Vec<u8> {
        let mut pkt = vec![0u8; 14 + 20 + 20 + payload.len()];
        // Eth
        {
            let mut eth = MutableEthernetPacket::new(&mut pkt[..14]).unwrap();
            eth.set_ethertype(EtherTypes::Ipv4);
        }
        // IP
        {
            let mut ip = MutableIpv4Packet::new(&mut pkt[14..34]).unwrap();
            ip.set_total_length((20 + 20 + payload.len()) as u16);
            ip.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Tcp);
            ip.set_source(Ipv4Addr::new(10,0,0,1));
            ip.set_destination(Ipv4Addr::new(10,0,0,2));
            ip.set_header_length(5);
            ip.set_version(4);
            ip.set_checksum(pnet::packet::ipv4::checksum(&ip.to_immutable()));
        }
        // TCP
        {
            let mut tcp = MutableTcpPacket::new(&mut pkt[34..54]).unwrap();
            tcp.set_sequence(seq);
            tcp.set_source(1234);
            tcp.set_destination(80);
            tcp.set_data_offset(5);
            tcp.set_flags(flags);
        }
        // Payload
        pkt[54..].copy_from_slice(payload);
        pkt
    }

    #[test]
    fn test_gro_coalescing() {
        let mut gro = GROTable::new();

        let p1 = build_packet(1000, &[1u8; 10], 0);
        let p2 = build_packet(1010, &[2u8; 10], 0);
        let p3 = build_packet(1020, &[3u8; 10], TcpFlags::PSH); // PSH should trigger flush

        // Ingest 1: Buffered
        let out1 = gro.ingest(&p1);
        assert_eq!(out1.len(), 0);

        // Ingest 2: Buffered (Sequential)
        let out2 = gro.ingest(&p2);
        assert_eq!(out2.len(), 0);

        // Ingest 3: Flush due to PSH
        let out3 = gro.ingest(&p3);
        assert_eq!(out3.len(), 1);

        let merged = &out3[0];
        assert_eq!(merged.len(), 54 + 30);

        let tcp = TcpPacket::new(&merged[34..]).unwrap();
        assert_eq!(tcp.get_sequence(), 1000);
        assert_eq!(tcp.get_flags() & TcpFlags::PSH, TcpFlags::PSH);

        // Verify payload content
        assert_eq!(&merged[54..64], &[1u8; 10]);
        assert_eq!(&merged[64..74], &[2u8; 10]);
        assert_eq!(&merged[74..84], &[3u8; 10]);
    }

    #[test]
    fn test_gro_out_of_order() {
        let mut gro = GROTable::new();

        let p1 = build_packet(1000, &[1u8; 10], 0);
        let p3 = build_packet(1020, &[3u8; 10], 0); // Gap!

        let out1 = gro.ingest(&p1);
        assert_eq!(out1.len(), 0);

        let out3 = gro.ingest(&p3);
        // Should flush p1 (old) and buffer p3 (new)
        // Or if p3 has no PSH, it buffers p3.
        // Wait, ingest returns vector.
        assert_eq!(out3.len(), 1); // Emits p1

        // p3 is buffered. Flush stale to get it.
        // We can't easily advance time in test without mocking Instant.
        // But we can check internal state or just rely on flush logic behavior if implemented manually.
        // Or ingest another packet.
    }

    #[test]
    fn test_gro_syn_bypass() {
        let mut gro = GROTable::new();
        let p_syn = build_packet(1000, &[], TcpFlags::SYN);
        let out = gro.ingest(&p_syn);
        assert_eq!(out.len(), 1); // Pass through
    }
}
