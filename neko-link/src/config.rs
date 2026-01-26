use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use log::{info, warn};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Config {
    #[serde(default)]
    pub interface_name: String,
    
    #[serde(default = "default_mode")]
    pub mode: String,
    
    // Legacy Fields
    #[serde(default)]
    pub local_addr: String,
    #[serde(default)]
    pub local_addr_v4: String,
    #[serde(default)]
    pub local_addr_v6: String,
    
    #[serde(default)]
    pub key: String,
    
    #[serde(default = "default_protocol")]
    pub protocol: String,
    
    #[serde(default = "default_mtu")]
    pub mtu: u16,

    // Networking
    #[serde(default)]
    pub listen_addr: String,
    #[serde(default)]
    pub peer_addr: String,
    
    #[serde(default = "default_proto_num")]
    pub ip_protocol_num: u8,
    
    #[serde(default)]
    pub debug: bool,
    
    #[serde(default)]
    pub app_interface: String,

    #[serde(default)]
    pub phys_interface: String,
    
    // Legacy Mappings
    #[serde(default)]
    pub server_addr: String,
    #[serde(default)]
    pub server_ip: String,
}

fn default_mode() -> String { "server".to_string() }
fn default_protocol() -> String { "raw".to_string() }
fn default_mtu() -> u16 { 1400 }
fn default_proto_num() -> u8 { 233 }

impl Config {
    pub fn parse_legacy(&mut self) -> bool {
        let mut changed = false;

        // 1. Force Raw Protocol
        if self.protocol != "raw" {
            self.protocol = "raw".to_string();
            changed = true;
        }
        if self.ip_protocol_num != 233 {
            self.ip_protocol_num = 233;
            changed = true;
        }

        // 2. Name Migration
        if self.listen_addr.is_empty() && !self.server_addr.is_empty() {
            self.listen_addr = self.server_addr.clone();
            changed = true;
        }
        self.server_addr.clear();

        if self.peer_addr.is_empty() && !self.server_ip.is_empty() {
            self.peer_addr = self.server_ip.clone();
            changed = true;
        }
        self.server_ip.clear();

        // 3. IP Version Split
        if !self.local_addr.is_empty() {
            if self.local_addr_v4.is_empty() && !self.local_addr.contains(':') {
                self.local_addr_v4 = self.local_addr.clone();
            } else if self.local_addr_v6.is_empty() && self.local_addr.contains(':') {
                self.local_addr_v6 = self.local_addr.clone();
            }
        }
        if self.local_addr.is_empty() {
            if !self.local_addr_v4.is_empty() {
                self.local_addr = self.local_addr_v4.clone();
            } else if !self.local_addr_v6.is_empty() {
                self.local_addr = self.local_addr_v6.clone();
            }
        }

        // 4. MTU Optimization
        if self.mtu == 0 || self.mtu > 1400 {
            if self.mtu != 0 {
                info!("[{}] Optimizing MTU: {} -> 1400", self.interface_name, self.mtu);
                changed = true;
            }
            self.mtu = 1400;
        }

        // Client Mode Fixes
        if self.mode == "client" && self.peer_addr.is_empty() && !self.listen_addr.is_empty() {
            self.peer_addr = self.listen_addr.clone();
            self.listen_addr.clear();
            info!("[{}] Fixed Config: Moved ListenAddr to PeerAddr (Client Mode)", self.interface_name);
            changed = true;
        }

        if self.interface_name.is_empty() {
            self.interface_name = "neko0".to_string();
            changed = true;
        }

        if self.app_interface.is_empty() {
            let mut prefix = self.interface_name.clone();
            if prefix.len() > 11 {
                prefix.truncate(11);
            }
            self.app_interface = format!("{}_app", prefix);
            info!("[{}] Auto-assigned AppInterface: {}", self.interface_name, self.app_interface);
            changed = true;
        }

        if self.phys_interface.is_empty() {
            self.phys_interface = "eth0".to_string();
            info!("[{}] Defaulting PhysInterface to eth0", self.interface_name);
            changed = true;
        }

        // Truncate
        if self.interface_name.len() > 15 {
            self.interface_name.truncate(15);
            changed = true;
        }
        if self.app_interface.len() > 15 {
            self.app_interface.truncate(15);
            changed = true;
        }

        changed
    }
}
