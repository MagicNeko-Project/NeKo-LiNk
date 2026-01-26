use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, Ipv4Flags};
use pnet::packet::tcp::{TcpPacket, MutableTcpPacket};

fn fragment_ip(packet_data: &[u8], mtu: usize) -> Vec<Vec<u8>> {
    const ETH_HEADER_LEN: usize = 14;
    use pnet::packet::ethernet::{EthernetPacket, EtherTypes};

    // Check min length
    if packet_data.len() < ETH_HEADER_LEN + 20 {
        return vec![packet_data.to_vec()];
    }

    // Parse Headers
    let eth_packet = match EthernetPacket::new(&packet_data[..ETH_HEADER_LEN]) {
        Some(p) => p,
        None => return vec![packet_data.to_vec()],
    };

    if eth_packet.get_ethertype() != EtherTypes::Ipv4 {
         return vec![packet_data.to_vec()];
    }

    let ip_packet = match Ipv4Packet::new(&packet_data[ETH_HEADER_LEN..]) {
        Some(p) => p,
        None => return vec![packet_data.to_vec()],
    };

    let ip_header_len = (ip_packet.get_header_length() as usize) * 4;
    let payload_offset = ETH_HEADER_LEN + ip_header_len;

    if payload_offset > packet_data.len() {
         return vec![packet_data.to_vec()];
    }

    // Headers length (Eth + IP)
    let headers_len = payload_offset;

    // Max payload per fragment (MTU - IP Header - Eth Header)
    // Must be multiple of 8 (requirement for Fragment Offset)
    let max_payload = (mtu - headers_len) & !7;

    if max_payload == 0 {
         return vec![packet_data.to_vec()];
    }

    let payload = &packet_data[payload_offset..];

    // Check if fragmentation is needed
    if payload.len() <= max_payload && packet_data.len() <= mtu {
        // Already fits
        return vec![packet_data.to_vec()];
    }

    let mut fragments = Vec::new();
    let mut offset = 0;

    // Handle existing fragmentation
    let original_offset = ip_packet.get_fragment_offset() as u16 * 8;
    let original_mf = (ip_packet.get_flags() & Ipv4Flags::MoreFragments) != 0;
    let ident = ip_packet.get_identification();

    while offset < payload.len() {
        let len = std::cmp::min(max_payload, payload.len() - offset);
        let fragment_payload = &payload[offset..offset+len];

        let mut new_pkt = vec![0u8; headers_len + len];

        // Copy headers
        new_pkt[..headers_len].copy_from_slice(&packet_data[..headers_len]);
        // Copy payload
        new_pkt[headers_len..].copy_from_slice(fragment_payload);

        // Update IPv4 Header
        {
            let mut new_ip = MutableIpv4Packet::new(&mut new_pkt[ETH_HEADER_LEN..]).unwrap();

            new_ip.set_total_length((ip_header_len + len) as u16);
            new_ip.set_identification(ident);

            // Fragment Offset (in 8-byte units)
            let new_frag_offset = (original_offset + offset as u16) / 8;
            new_ip.set_fragment_offset(new_frag_offset);

            // Flags
            // MF set if:
            // 1. Not the last chunk of *this* buffer.
            // 2. OR the original packet had MF set.
            let more_fragments = (offset + len < payload.len()) || original_mf;

            let mut flags = new_ip.get_flags(); // existing flags

            // We must clear DF if we are fragmenting
            flags &= !Ipv4Flags::DontFragment;

            if more_fragments {
                flags |= Ipv4Flags::MoreFragments;
            } else {
                flags &= !Ipv4Flags::MoreFragments;
            }
            new_ip.set_flags(flags);

            new_ip.set_checksum(pnet::packet::ipv4::checksum(&new_ip.to_immutable()));
        }

        fragments.push(new_pkt);
        offset += len;
    }

    fragments
}

/// Segment a large packet into smaller packets.
/// Supports TCP GSO and IPv4 Fragmentation.
pub fn segment_packet(packet_data: &[u8], mtu: usize) -> Vec<Vec<u8>> {
    const ETH_HEADER_LEN: usize = 14;
    use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
    use pnet::packet::ipv4::{Ipv4Packet, Ipv4Flags};

    // Basic size check
    if packet_data.len() <= mtu {
        return vec![packet_data.to_vec()];
    }

    // Parse Headers to decide strategy
    if packet_data.len() < ETH_HEADER_LEN + 20 {
        return vec![packet_data.to_vec()];
    }

    let eth_packet = match EthernetPacket::new(&packet_data[..ETH_HEADER_LEN]) {
        Some(p) => p,
        None => return vec![packet_data.to_vec()],
    };

    if eth_packet.get_ethertype() != EtherTypes::Ipv4 {
        return vec![packet_data.to_vec()];
    }

    let ip_packet = match Ipv4Packet::new(&packet_data[ETH_HEADER_LEN..]) {
        Some(p) => p,
        None => return vec![packet_data.to_vec()],
    };

    let is_tcp = ip_packet.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Tcp;
    let is_fragment = (ip_packet.get_flags() & Ipv4Flags::MoreFragments) != 0 || ip_packet.get_fragment_offset() > 0;

    if is_tcp && !is_fragment {
        // Try TCP GSO
        let segments = segment_tcp(packet_data, mtu);
        // If GSO returns a single packet that is still too large, it failed to segment (e.g. malformed TCP or logic fallback).
        // In that case, fallback to IP fragmentation.
        if segments.len() == 1 && segments[0].len() > mtu {
             return fragment_ip(packet_data, mtu);
        }
        return segments;
    }

    // Fallback: IP Fragmentation for UDP / Fragments / Others
    fragment_ip(packet_data, mtu)
}

fn segment_tcp(packet_data: &[u8], mtu: usize) -> Vec<Vec<u8>> {
    const ETH_HEADER_LEN: usize = 14; 
    // Basic check for min length (Eth + IP(20) + TCP(20))
    if packet_data.len() <= mtu || packet_data.len() < 54 {
        // No segmentation needed or too small
        return vec![packet_data.to_vec()];
    }

    // Parse Headers
    // Assume standard Ethernet II
    use pnet::packet::ethernet::{EthernetPacket, EtherTypes};

    // Parse Headers
    // Check EtherType
    let eth_packet = match EthernetPacket::new(&packet_data[..ETH_HEADER_LEN]) {
        Some(p) => p,
        None => return vec![packet_data.to_vec()],
    };
    
    if eth_packet.get_ethertype() != EtherTypes::Ipv4 {
        return vec![packet_data.to_vec()];
    }

    let ip_packet = match Ipv4Packet::new(&packet_data[ETH_HEADER_LEN..]) {
        Some(p) => p,
        None => return vec![packet_data.to_vec()],
    };

    let ip_header_len = (ip_packet.get_header_length() as usize) * 4;
    // Assume TCP check done by caller or implicitly handled by next check
    if ip_packet.get_next_level_protocol() != pnet::packet::ip::IpNextHeaderProtocols::Tcp {
         return vec![packet_data.to_vec()];
    }

    let tcp_start = ETH_HEADER_LEN + ip_header_len;
    let tcp_packet = match TcpPacket::new(&packet_data[tcp_start..]) {
        Some(p) => p,
        None => return vec![packet_data.to_vec()],
    };

    let tcp_header_len = (tcp_packet.get_data_offset() as usize) * 4;
    let payload_offset = tcp_start + tcp_header_len;
    
    // Validate offsets
    if payload_offset > packet_data.len() {
        return vec![packet_data.to_vec()];
    }

    let payload = &packet_data[payload_offset..];
    let headers_len = payload_offset;
    // Calculate MSS (Max payload per segment)
    // MSS = MTU - Headers
    let mss = mtu - headers_len;
    if mss == 0 || payload.is_empty() {
         return vec![packet_data.to_vec()];
    }

    let mut segments = Vec::new();
    let mut offset = 0;
    let mut seq_num = tcp_packet.get_sequence();

    while offset < payload.len() {
        let len = std::cmp::min(mss, payload.len() - offset);
        let segment_payload = &payload[offset..offset+len];
        
        // Construct new packet
        let mut new_pkt = vec![0u8; headers_len + len];
        
        // Copy headers
        new_pkt[..headers_len].copy_from_slice(&packet_data[..headers_len]);
        // Copy payload
        new_pkt[headers_len..].copy_from_slice(segment_payload);

        // Update IPv4 Header
        {
            let mut new_ip = MutableIpv4Packet::new(&mut new_pkt[ETH_HEADER_LEN..]).unwrap();
            new_ip.set_total_length((ip_header_len + tcp_header_len + len) as u16);
            // new_ip.set_flags(Ipv4Flags::DontFragment); // Keep original flags? or set DF?
            new_ip.set_checksum(pnet::packet::ipv4::checksum(&new_ip.to_immutable()));
        }

        // Update TCP Header
        {
            let mut new_tcp = MutableTcpPacket::new(&mut new_pkt[tcp_start..]).unwrap();
            new_tcp.set_sequence(seq_num);
            // FIN/PSH flags should only be on the last segment?
            // Actually GSO usually copies flags but clears PSH/FIN on non-last segments.
            // Simplified: If not last, clear PSH/FIN?
            // Let's keep it simple: Copy everything. 
            // In reality, only the *last* segment should have PSH/FIN if the original had it.
            // Intermediate segments should not have FIN.
            if offset + len < payload.len() {
                 let flags = new_tcp.get_flags();
                 // Clear FIN (bit 0) and PSH (bit 3)?
                 // Using pnet flags consts
                 new_tcp.set_flags(flags & !pnet::packet::tcp::TcpFlags::FIN & !pnet::packet::tcp::TcpFlags::PSH);
            }
            
            // Re-calculate checksum
            // IMPORTANT: Must set to 0 before calculation
            new_tcp.set_checksum(0);
            let src = ip_packet.get_source();
            let dst = ip_packet.get_destination();
            new_tcp.set_checksum(pnet::packet::tcp::ipv4_checksum(
                &new_tcp.to_immutable(),
                &src, 
                &dst
            ));
        }

        segments.push(new_pkt);

        offset += len;
        seq_num = seq_num.wrapping_add(len as u32);
    }

    segments
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::ipv4::{MutableIpv4Packet};
    use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};
    use pnet::packet::ethernet::{MutableEthernetPacket, EtherTypes};
    use std::net::Ipv4Addr;

    #[test]
    fn test_fragment_ip() {
        let mut packet_buffer = vec![0u8; 234];

        // Ethernet
        {
            let mut eth = MutableEthernetPacket::new(&mut packet_buffer[..14]).unwrap();
            eth.set_ethertype(EtherTypes::Ipv4);
        }

        // IP
        {
            let mut ip = MutableIpv4Packet::new(&mut packet_buffer[14..34]).unwrap();
            ip.set_total_length(220); // 20 + 200
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_source(Ipv4Addr::new(10, 0, 0, 1));
            ip.set_destination(Ipv4Addr::new(10, 0, 0, 2));
            ip.set_identification(12345);
            ip.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Udp);
            ip.set_checksum(pnet::packet::ipv4::checksum(&ip.to_immutable()));
        }

        // Payload (200 bytes)
        for i in 0..200 {
            packet_buffer[34 + i] = i as u8;
        }

        // MTU 100. Headers 34. Max Payload 64.
        let fragments = fragment_ip(&packet_buffer, 100);

        assert_eq!(fragments.len(), 4);

        // Check Frag 1
        let f1 = &fragments[0];
        assert_eq!(f1.len(), 34 + 64);
        let ip1 = Ipv4Packet::new(&f1[14..]).unwrap();
        assert_eq!(ip1.get_fragment_offset(), 0);
        assert_eq!(ip1.get_flags() & Ipv4Flags::MoreFragments, Ipv4Flags::MoreFragments);
        assert_eq!(ip1.get_identification(), 12345);

        // Check Frag 2
        let f2 = &fragments[1];
        assert_eq!(f2.len(), 34 + 64);
        let ip2 = Ipv4Packet::new(&f2[14..]).unwrap();
        assert_eq!(ip2.get_fragment_offset(), 8); // 64 / 8
        assert_eq!(ip2.get_flags() & Ipv4Flags::MoreFragments, Ipv4Flags::MoreFragments);

        // Check Frag 4
        let f4 = &fragments[3];
        assert_eq!(f4.len(), 34 + 8);
        let ip4 = Ipv4Packet::new(&f4[14..]).unwrap();
        assert_eq!(ip4.get_fragment_offset(), 24); // 192 / 8
        assert_eq!(ip4.get_flags() & Ipv4Flags::MoreFragments, 0);
    }

    #[test]
    fn test_segment_packet() {
        // Construct a 200 byte payload packet.
        // Headers: Eth(14) + IP(20) + TCP(20) = 54.
        // Total: 254 bytes.
        // Set MTU = 100.
        // MSS = 100 - 54 = 46.
        // Segments needed: ceil(200 / 46) = 5 segments.
        // 46, 46, 46, 46, 16.

        let mut packet_buffer = vec![0u8; 254];

        // Ethernet
        {
            let mut eth = MutableEthernetPacket::new(&mut packet_buffer[..14]).unwrap();
            eth.set_ethertype(EtherTypes::Ipv4);
        }

        // IP
        {
            let mut ip = MutableIpv4Packet::new(&mut packet_buffer[14..34]).unwrap();
            ip.set_total_length(240); // 20 + 20 + 200
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_source(Ipv4Addr::new(10, 0, 0, 1));
            ip.set_destination(Ipv4Addr::new(10, 0, 0, 2));
            ip.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Tcp);
            ip.set_checksum(pnet::packet::ipv4::checksum(&ip.to_immutable()));
        }

        // TCP
        {
            let mut tcp = MutableTcpPacket::new(&mut packet_buffer[34..54]).unwrap();
            tcp.set_source(1234);
            tcp.set_destination(80);
            tcp.set_sequence(1000);
            tcp.set_data_offset(5);
            tcp.set_flags(pnet::packet::tcp::TcpFlags::PSH | pnet::packet::tcp::TcpFlags::ACK);
        }

        // Payload
        for i in 0..200 {
            packet_buffer[54 + i] = i as u8;
        }

        let segments = segment_packet(&packet_buffer, 100);

        assert_eq!(segments.len(), 5);

        // Check Segment 1
        let s1 = &segments[0];
        assert_eq!(s1.len(), 54 + 46);
        let tcp1 = TcpPacket::new(&s1[34..]).unwrap();
        assert_eq!(tcp1.get_sequence(), 1000);
        // Flags should clear PSH?
        assert_eq!(tcp1.get_flags() & pnet::packet::tcp::TcpFlags::PSH, 0);

        // Check Segment 5
        let s5 = &segments[4];
        assert_eq!(s5.len(), 54 + 16);
        let tcp5 = TcpPacket::new(&s5[34..]).unwrap();
        assert_eq!(tcp5.get_sequence(), 1000 + 46*4);
        // Last segment should keep PSH
        assert_eq!(tcp5.get_flags() & pnet::packet::tcp::TcpFlags::PSH, pnet::packet::tcp::TcpFlags::PSH);
    }
}
