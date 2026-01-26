mod socket;
mod buffers;
mod gso;
mod gro;
mod xdp;
use crate::config::Config;
use std::process::Command;
use log::{info, error, warn};
use std::sync::Arc;
use chacha20poly1305::{XChaCha20Poly1305, Key, KeyInit};
#[allow(unused_imports)]
use chacha20poly1305::aead::{Aead, Payload}; 
use sha2::{Sha256, Digest};
use std::net::SocketAddr;
use tokio::io::unix::AsyncFd;
use std::os::unix::io::FromRawFd;
use rand::RngCore;
use chacha20poly1305::aead::generic_array::GenericArray;

const NONCE_SIZE: usize = 24;

struct PeerState {
    remote_addr: std::sync::RwLock<Option<std::net::SocketAddr>>, 
    nonce_counter: std::sync::atomic::AtomicU64,
    session_id: u32,
}

type SharedState = Arc<PeerState>;

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    info!("[{}] NekoLink (Rust Edition) Starting - MTU: {}", cfg.interface_name, cfg.mtu);
    
    init_interface(&cfg)?;
    
    // Create sockets using socket helper module
    let raw_socket = socket::create_raw_socket(&cfg)?;
    raw_socket.set_nonblocking(true)?;
    let raw_socket = tokio::net::UdpSocket::from_std(raw_socket)?;
    let fallback_fd = socket::create_fallback_socket(&cfg)?;

    log::info!("Sockets Init: Raw={:?}, FallbackFD={}", raw_socket, fallback_fd);

    let raw_socket = Arc::new(raw_socket);
    // Wrap Fallback FD in AsyncFd for Tokio poll
    let fallback_async = AsyncFd::new(fallback_fd)?;

    // Crypto Setup
    let mut hasher = Sha256::new();
    hasher.update(cfg.key.as_bytes());
    let key_hash = hasher.finalize();
    let aead = XChaCha20Poly1305::new(Key::from_slice(&key_hash));
    let aead = Arc::new(aead);

    let mut tasks = Vec::new();

    // State Init
    let initial_peer = if !cfg.peer_addr.is_empty() {
        // Parse peer_addr (it might be IP or IP:Port)
        // Go logic: if no port, maybe default? Or just IP.
        // Raw socket send_to expects SocketAddr.
        // For Raw IP, port is irrelevant but SocketAddr requires it.
        // We use port 0.
        let ip: std::net::IpAddr = cfg.peer_addr.parse().unwrap_or_else(|_| "0.0.0.0".parse().unwrap());
        Some(SocketAddr::new(ip, 0))
    } else {
        None
    };

    let state = Arc::new(PeerState {
        remote_addr: std::sync::RwLock::new(initial_peer),
        nonce_counter: std::sync::atomic::AtomicU64::new(0),
        session_id: std::process::id() ^ (u32::from_be_bytes(key_hash[0..4].try_into().unwrap()) << 24),
    });

    // Start Handshake Loop
    let hs_state = state.clone();
    let hs_socket = raw_socket.clone();
    let hs_aead = aead.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        let magic = b"NEKO_HEARTBEAT";
        loop {
            interval.tick().await;
            
            let target = {
                *hs_state.remote_addr.read().unwrap()
            };
            
            if let Some(addr) = target {
                // Construct Handshake Packet
                // [0xFE] [Nonce 24] [Cipher]
                let mut pkt = vec![0u8; 1 + NONCE_SIZE + magic.len() + 16]; // 16 overhead
                pkt[0] = 0xFE;
                
                // Random Nonce
                let nonce_slice = &mut pkt[1..1 + NONCE_SIZE];
                rand::thread_rng().fill_bytes(nonce_slice);
                let nonce = *GenericArray::from_slice(nonce_slice);
                
                // Encrypt
                // Checksum/Tag is appended
                 match hs_aead.encrypt(&nonce, Payload {
                    msg: magic,
                    aad: &[],
                }) {
                    Ok(ciphertext) => {
                         // Copy ciphertext after nonce
                         pkt[1+NONCE_SIZE..].copy_from_slice(&ciphertext);
                         // socket2 send
                         let _ = hs_socket.send_to(&pkt, addr).await;
                    },
                    Err(e) => error!("Handshake Encrypt Fail: {}", e),
                }
            }
        }
    });

    // RX: Fallback (AF_PACKET) -> Decrypt -> ...
    // Note: We need to implement the reader loop.
    // For now, let's just test connectivity (receive packets)
    
    let f_async = Arc::new(fallback_async); // AsyncFd isn't easily cloneable/shareable like Arc<Socket>
    // Actually AsyncFd holds the fd. We might need a structural change to share it or just move it.
    // Since we have one reader, move is fine.

    let rx_aead = aead.clone();

    let rx_cfg_state = state.clone();
    let raw_socket = raw_socket.clone();
    
    let raw_rx_target = f_async.clone();
    let raw_rx_socket = raw_socket.clone();
    let raw_rx_aead = aead.clone();
    let raw_rx_state = state.clone();

    let raw_rx_cfg = cfg.clone(); // Clone config for RX loop

    // Raw RX Loop (Peer -> Raw -> Decrypt -> Veth)
    tasks.push(tokio::spawn(async move {
         let mut buf = [0u8; 65536];
         let mut gro_table = gro::GROTable::new();
         // Flush stale flows every 10ms
         let mut flush_interval = tokio::time::interval(tokio::time::Duration::from_millis(10));

         loop {
             tokio::select! {
                _ = flush_interval.tick() => {
                    let packets = gro_table.flush_stale();
                    for p in packets {
                         if let Ok(mut guard) = raw_rx_target.writable().await {
                             let _ = guard.try_io(|inner_fd| unsafe {
                                  let fd = *inner_fd.get_ref();
                                  let res = libc::send(fd, p.as_ptr() as *const _, p.len(), 0);
                                  if res < 0 { 
                                      Err(std::io::Error::last_os_error()) 
                                  } else { 
                                      Ok(res as usize) 
                                  }
                             });
                         }
                    }
                }
                res = raw_rx_socket.recv_from(&mut buf) => {
                     match res {
                         Ok((n, addr)) => {
                             // Linux SOCK_RAW includes IP header (usually 20 bytes)
                             // Simple heuristic: Skip 20 bytes. 
                             let payload_offset = if n > 20 { 20 } else { 0 };
                             if n <= payload_offset { continue; }
                             
                             let pkt = &buf[payload_offset..n];
                             
                             // Handshake? [0xFE] ...
                             if !pkt.is_empty() && pkt[0] == 0xFE {
                                 if pkt.len() < 1 + NONCE_SIZE + 16 { continue; } 
                                 
                                 let nonce = GenericArray::from_slice(&pkt[1..1+NONCE_SIZE]);
                                 let ciphertext = &pkt[1+NONCE_SIZE..];
                                 
                                 match raw_rx_aead.decrypt(nonce, Payload { msg: ciphertext, aad: &[] }) {
                                     Ok(plain) => {
                                         if plain == b"NEKO_HEARTBEAT" {
                                              if raw_rx_cfg.debug {
                                                  info!("[{}] RX Heartbeat from {}", raw_rx_cfg.interface_name, addr);
                                              }
                                              // Update Peer
                                              let update = {
                                                  let lock = raw_rx_state.remote_addr.read().unwrap();
                                                  lock.map_or(true, |a| a != addr)
                                              };
                                              
                                              if update {
                                                  let mut lock = raw_rx_state.remote_addr.write().unwrap();
                                                  *lock = Some(addr);
                                                  info!("Peer Updated: {}", addr);
                                              }
                                         }
                                     },
                                     Err(_) => {}
                                 }
                             } else {
                                 // Data Packet: [Nonce][Ciphertext]
                                 if pkt.len() < NONCE_SIZE + 16 { continue; }
                                 let nonce = GenericArray::from_slice(&pkt[..NONCE_SIZE]);
                                 let ciphertext = &pkt[NONCE_SIZE..];
                                 
                                 match raw_rx_aead.decrypt(nonce, Payload { msg: ciphertext, aad: &[] }) {
                                     Ok(plain) => {
                                          if raw_rx_cfg.debug {
                                              info!("[{}] RX Data: {} bytes from {}", raw_rx_cfg.interface_name, plain.len(), addr);
                                          }
                                          // Ingest to GRO
                                          let packets = gro_table.ingest(&plain);
                                          for p in packets {
                                              // Write to Veth
                                              if let Ok(mut guard) = raw_rx_target.writable().await {
                                                  let _ = guard.try_io(|inner_fd| unsafe {
                                                       let fd = *inner_fd.get_ref();
                                                       let res = libc::send(fd, p.as_ptr() as *const _, p.len(), 0);
                                                       if res < 0 { 
                                                           Err(std::io::Error::last_os_error()) 
                                                       } else { 
                                                           Ok(res as usize) 
                                                       }
                                                  });
                                              }
                                          }
                                     },
                                     Err(_) => {
                                         // Decrypt failed
                                     }
                                 }
                             }
                         },
                         Err(e) => warn!("Raw RX Error: {}", e),
                     }
                }
             }
         }
    }));
    
    let buffers = Arc::new(buffers::BufferPool::new(1024));
    let buffers = buffers.clone();
    let rx_cfg = cfg.clone(); // This is for the TX loop (reading Veth RX -> Sending Raw TX)
    
    // Start simple loop
    tasks.push(tokio::spawn(async move {
        // ... (Keep existing fallback loop for now, we will replace it next)
        loop {
            // Wait for readability
            let mut guard = f_async.readable().await.unwrap();
            
            let mut buf = buffers.acquire();
            // Capacity is 64KB
            let buf_slice = unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr(), buf.capacity()) };
            
            let n = match guard.try_io(|inner_fd| unsafe {
                 let fd = *inner_fd.get_ref();
                 let res = libc::recvfrom(fd, 
                    buf_slice.as_mut_ptr() as *mut libc::c_void, 
                    buf_slice.len(), 
                    0, 
                    std::ptr::null_mut(), 
                    std::ptr::null_mut());
                 if res < 0 {
                     Err(std::io::Error::last_os_error())
                 } else {
                     Ok(res as usize)
                 }
            }) {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    warn!("Read Error: {}", e);
                    buffers.release(buf); // Release on failure
                    continue;
                },
                Err(_would_block) => {
                    buffers.release(buf); // Release on would_block (recv didn't happen)
                    continue;
                }
            };

            // Set content length for logic
            unsafe { buf.set_len(n); }
            
            if rx_cfg.debug {
                 info!("[{}] TX Data: {} bytes (Veth -> Raw)", rx_cfg.interface_name, n);
            }

            // GSO Segmentation
            // TODO: Detect MTU from config? Assuming 1400 from config
            let segments = gso::segment_packet(&buf, rx_cfg.mtu as usize);
            
            // We no longer need the original large buffer if we have segments 
            // (segments are copies for now, optimization: use slices/Cow later)
            buffers.release(buf);

            // Process Each Segment
            for segment in segments {
                let mut nonce_bytes = [0u8; NONCE_SIZE];
                
                // Use Atomic Counter
                let counter = rx_cfg_state.nonce_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                nonce_bytes[0..8].copy_from_slice(&counter.to_be_bytes());
                nonce_bytes[8..12].copy_from_slice(&rx_cfg_state.session_id.to_be_bytes());

                let nonce = GenericArray::from_slice(&nonce_bytes);
                
                match rx_aead.encrypt(nonce, Payload {
                    msg: &segment,
                    aad: &[],
                }) {
                    Ok(ciphertext) => {
                         // Packet: [Nonce][Ciphertext]
                         // TODO: Use BufferPool for valid packet construction too?
                         // For now simplified vec.
                         let mut pkt = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
                         pkt.extend_from_slice(&nonce_bytes);
                         pkt.extend_from_slice(&ciphertext);
                         
                         // Send to Peer
                         let target = *rx_cfg_state.remote_addr.read().unwrap();
                         if let Some(addr) = target {
                             let _ = raw_socket.send_to(&pkt, addr).await;
                         }
                    },
                    Err(e) => {
                        warn!("Encryption Error: {}", e);
                    }
                }
            }
        }
    }));
    
    // Keep alive until signal
    match tokio::signal::ctrl_c().await {
        Ok(()) => {
             info!("Received Shutdown Signal");
        },
        Err(err) => {
             error!("Unable to listen for shutdown signal: {}", err);
        },
    }
    
    cleanup(&cfg);
    Ok(())
}

fn init_interface(cfg: &Config) -> anyhow::Result<()> {
    let host_if = &cfg.interface_name;
    let app_if = &cfg.app_interface;
    
    // Cleanup
    let _ = Command::new("ip").args(&["link", "del", host_if]).status();
    
    // Veth Pair
    info!("[{}] Creating Veth Pair: {} <-> {}", host_if, host_if, app_if);
    let status = Command::new("ip").args(&["link", "add", host_if, "type", "veth", "peer", "name", app_if]).status()?;
    if !status.success() {
        return Err(anyhow::anyhow!("Failed to create veth pair"));
    }
    
    // Host Config
    run_cmd("ip", &["addr", "add", &cfg.local_addr, "dev", host_if])?;
    run_cmd("ip", &["link", "set", host_if, "mtu", &cfg.mtu.to_string()])?;
    run_cmd("ip", &["link", "set", host_if, "arp", "on"])?;
    run_cmd_ignore_fail("ethtool", &["-K", host_if, "tx", "on", "rx", "on", "tso", "on", "gso", "on", "gro", "on"]);
    run_cmd("ip", &["link", "set", host_if, "up"])?;
    
    // App Config
    run_cmd("ip", &["link", "set", app_if, "arp", "on"])?;
    run_cmd("ip", &["link", "set", app_if, "promisc", "on"])?;
    run_cmd_ignore_fail("ethtool", &["-K", app_if, "tx", "on", "rx", "on", "tso", "on", "gso", "on", "gro", "on"]);
    run_cmd("ip", &["link", "set", app_if, "mtu", &cfg.mtu.to_string()])?;
    run_cmd("ip", &["link", "set", app_if, "up"])?;
    
    // Try AF_XDP
    let _xdp_handle = match xdp::init_xdp(app_if) {
        Ok(Some(h)) => {
            info!("AF_XDP Enabled (BPF Side Only)");
            Some(h)
        },
        Ok(None) => None,
        Err(e) => {
            warn!("AF_XDP Init Failed: {}", e);
            None
        }
    };
    
    // Sysctl
    let _ = Command::new("sysctl").args(&["-w", &format!("net.ipv6.conf.{}.disable_ipv6=1", app_if)]).status();
    let _ = Command::new("sysctl").args(&["-w", "net.ipv4.conf.all.rp_filter=0"]).status();
    
    setup_nftables(cfg)?;
    
    Ok(())
}

fn setup_nftables(cfg: &Config) -> anyhow::Result<()> {
    let iface = &cfg.interface_name;
    run_cmd("nft", &["add", "table", "inet", "nekolink"])?;
    let chain = format!("mss_{}", iface);
    let _ = Command::new("nft").args(&["delete", "chain", "inet", "nekolink", &chain]).status();
    run_cmd("nft", &["add", "chain", "inet", "nekolink", &chain, "{ type filter hook forward priority mangle; policy accept; }"])?;
    
    run_cmd("nft", &["add", "rule", "inet", "nekolink", &chain, "iifname", iface, "tcp", "flags", "syn", "tcp", "option", "maxseg", "size", "set", "rt", "mtu"])?;
    run_cmd("nft", &["add", "rule", "inet", "nekolink", &chain, "oifname", iface, "tcp", "flags", "syn", "tcp", "option", "maxseg", "size", "set", "rt", "mtu"])?;
    
    Ok(())
}

// Helpers removed (create_raw/tun_socket) as they are now in socket module or inlined



fn run_cmd_ignore_fail(cmd: &str, args: &[&str]) {
    if let Err(e) = run_cmd(cmd, args) {
        warn!("Command {} {:?} failed (ignored): {}", cmd, args, e);
    }
}

fn run_cmd(cmd: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new(cmd).args(args).status()
        .map_err(|e| anyhow::anyhow!("Failed to execute command '{}': {}", cmd, e))?;
    if !status.success() {
        return Err(anyhow::anyhow!("Command {} {:?} failed", cmd, args));
    }
    Ok(())
}

fn cleanup(cfg: &Config) {
    if !cfg.interface_name.is_empty() {
        let _ = Command::new("ip").args(&["link", "del", &cfg.interface_name]).status();
    }
}
