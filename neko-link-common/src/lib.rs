#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub ipv4_address: u32,
    pub action: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CryptoConfig {
    pub cipher_suite: u32, // 1 for AES-GCM, 2 for Chacha20-Poly1305
    pub key: [u8; 32],
    pub protocol_number: u8,
    pub local_ip: u32,
    pub remote_ip: u32,
    pub phys_if_index: u32,
    pub veth_if_index: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for CryptoConfig {}

pub const MAX_CRYPTO_CONTEXTS: u32 = 1;
