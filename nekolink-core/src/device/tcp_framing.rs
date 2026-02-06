// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::mem;

/// A UDP datagram header has a 16 bit field containing an unsigned integer
/// describing the length of the datagram (including the header itself).
/// The max value is 2^16 = 65536 bytes. But since that includes the
/// UDP header, this constant is 8 bytes more than any UDP socket
/// read operation would ever return. We are going to use that extra space
/// to store our 2 byte udp-over-tcp header.
pub const MAX_DATAGRAM_SIZE: usize = u16::MAX as usize;
pub const HEADER_LEN: usize = mem::size_of::<u16>();

/// TCP Framing helper
pub struct TcpFraming {
    buffer: Box<[u8; MAX_DATAGRAM_SIZE]>,
    unprocessed_i: usize,
}

impl TcpFraming {
    pub fn new() -> Self {
        Self {
            buffer: Box::new([0u8; MAX_DATAGRAM_SIZE]),
            unprocessed_i: 0,
        }
    }

    /// Get mutable slice to the free space in buffer for reading from socket
    pub fn get_free_space(&mut self) -> &mut [u8] {
        &mut self.buffer[self.unprocessed_i..]
    }

    /// Notify that `len` bytes have been read into the buffer
    pub fn advance(&mut self, len: usize) {
        self.unprocessed_i += len;
    }

    /// Try to parse and return the next packet from the buffer starting at `offset`.
    /// Returns `None` if there is not enough data for a full packet.
    /// Returns `Some((total_len, packet_slice))` if a packet is found.
    /// * `total_len` includes the header size.
    /// * `packet_slice` is the payload.
    pub fn peek_packet(&self, offset: usize) -> Option<(usize, &[u8])> {
        if self.unprocessed_i < offset + HEADER_LEN {
            return None;
        }

        let header = &self.buffer[offset..offset+HEADER_LEN];
        // Parse big-endian u16 length
        let datagram_len = u16::from_be_bytes([header[0], header[1]]) as usize;

        let total_packet_len = HEADER_LEN + datagram_len;

        if self.unprocessed_i < offset + total_packet_len {
            return None;
        }

        // Return the payload
        let payload_start = offset + HEADER_LEN;
        let payload_end = offset + total_packet_len;
        Some((total_packet_len, &self.buffer[payload_start..payload_end]))
    }

    /// Shift unprocessed data to the beginning of the buffer.
    /// Should be called after processing packets to make room for new reads.
    /// `bytes_consumed` is the total bytes (header + payload) of all packets processed since last read.
    pub fn compact(&mut self, bytes_consumed: usize) {
        if bytes_consumed > 0 {
            if self.unprocessed_i > bytes_consumed {
                self.buffer.copy_within(bytes_consumed..self.unprocessed_i, 0);
            }
            self.unprocessed_i -= bytes_consumed;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_framing_simple_packet() {
        let mut framing = TcpFraming::new();
        let buf = framing.get_free_space();
        
        let payload = b"hello";
        let len = payload.len() as u16;
        let len_bytes = len.to_be_bytes();
        
        // Write header
        buf[0] = len_bytes[0];
        buf[1] = len_bytes[1];
        // Write payload
        buf[2..2+payload.len()].copy_from_slice(payload);
        
        framing.advance(2 + payload.len());
        
        let (total_len, packet) = framing.peek_packet(0).expect("Should have packet");
        assert_eq!(packet, payload);
        assert_eq!(total_len, 2 + payload.len());
        
        framing.compact(total_len);
        assert_eq!(framing.unprocessed_i, 0);
    }

    #[test]
    fn test_framing_partial_header() {
        let mut framing = TcpFraming::new();
        let buf = framing.get_free_space();
        
        let len_bytes = (5u16).to_be_bytes();
        buf[0] = len_bytes[0];
        
        framing.advance(1);
        assert!(framing.peek_packet(0).is_none());
        
        let buf = framing.get_free_space();
        buf[0] = len_bytes[1];
        framing.advance(1);
        assert!(framing.peek_packet(0).is_none()); // header ok, but no payload
        
        let buf = framing.get_free_space();
        buf[0..5].copy_from_slice(b"hello");
        framing.advance(5);
        
        let (_, packet) = framing.peek_packet(0).expect("Should have packet");
        assert_eq!(packet, b"hello");
    }

    #[test]
    fn test_framing_multiple_packets() {
        let mut framing = TcpFraming::new();
        
        // Packet 1: "hi"
        let p1 = b"hi";
        let l1 = p1.len() as u16;
        
        // Packet 2: "world"
        let p2 = b"world";
        let l2 = p2.len() as u16;
        
        let buf = framing.get_free_space();
        let mut cursor = 0;
        
        // Write P1
        buf[cursor..cursor+2].copy_from_slice(&l1.to_be_bytes());
        cursor += 2;
        buf[cursor..cursor+p1.len()].copy_from_slice(p1);
        cursor += p1.len();
        
        // Write P2
        buf[cursor..cursor+2].copy_from_slice(&l2.to_be_bytes());
        cursor += 2;
        buf[cursor..cursor+p2.len()].copy_from_slice(p2);
        cursor += p2.len();
        
        framing.advance(cursor);
        
        // Peek P1 at offset 0
        let (len1, packet1) = framing.peek_packet(0).expect("P1");
        assert_eq!(packet1, p1);
        
        // Peek P2 at offset len1
        let (len2, packet2) = framing.peek_packet(len1).expect("P2");
        assert_eq!(packet2, p2);
        
        // Compact
        framing.compact(len1 + len2);
        assert_eq!(framing.unprocessed_i, 0);
    }
}
