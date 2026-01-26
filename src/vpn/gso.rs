use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{TcpPacket, MutableTcpPacket};

/// Segment a large packet into smaller packets (GSO).
/// Only supports IPv4 TCP packets for now.
/// Returns a list of segments.
pub fn segment_packet(packet_data: &[u8], mtu: usize) -> Vec<Vec<u8>> {
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
    if ip_packet.get_next_level_protocol() != pnet::packet::ip::IpNextHeaderProtocols::Tcp {
         return vec![packet_data.to_vec()]; // Not TCP
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
            
            // Re-calculate checksum is complex due to pseudo-header.
            // However, since we are tunneling via Raw IP (Protocol 233), 
            // and the receiver (kernel) might re-verify, we SHOULD update checksums.
            // OR we can rely on hardware or set it to 0 if valid.
            // For correctness, let's update it.
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
