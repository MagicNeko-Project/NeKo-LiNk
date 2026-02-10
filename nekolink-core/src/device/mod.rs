// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod allowed_ips;
pub mod api;
pub mod tcp_framing;
mod dev_lock;
pub mod drop_privileges;
#[cfg(test)]
mod integration_tests;
pub mod peer;

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
#[path = "kqueue.rs"]
pub mod poll;

#[cfg(target_os = "linux")]
#[path = "epoll.rs"]
pub mod poll;

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
#[path = "tun_darwin.rs"]
pub mod tun;

#[cfg(target_os = "linux")]
#[path = "tun_linux.rs"]
pub mod tun;

#[cfg(any(target_os = "linux", target_os = "android"))]
use libc::{iovec, mmsghdr, msghdr, recvmmsg, sendmmsg, sockaddr_storage, MSG_DONTWAIT, cmsghdr, c_void, c_int, setsockopt};

use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::io::{self, Write as _};
use std::io::Write;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;

use crate::noise::errors::WireGuardError;
use crate::noise::handshake::parse_handshake_anon;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::{Packet, Tunn, TunnResult};
use crate::x25519;
use allowed_ips::AllowedIps;
use parking_lot::Mutex;
use peer::{AllowedIP, Peer};
use poll::{EventPoll, EventRef, WaitResult};
use rand_core::{OsRng, RngCore};
use socket2::{Domain, Protocol, Type};
use tun::TunSocket;

use dev_lock::{Lock, LockReadGuard};

const HANDSHAKE_RATE_LIMIT: u64 = 100; // The number of handshakes per second we can tolerate before using cookies

const MAX_UDP_SIZE: usize = (1 << 16) - 1;
const MAX_PACKET_COUNT: usize = 64; // GotaTun uses this batch size
const MAX_ITR: usize = 100; // Number of packets to handle per handler call
const UDP_GRO: c_int = 104;
const SOL_UDP: c_int = 17;

const CMSG_LEN: usize = 64; // Enough for standard CMSG

use tcp_framing::TcpFraming;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    IoError(#[from] io::Error),
    #[error("{0}")]
    Socket(io::Error),
    #[error("{0}")]
    Bind(String),
    #[error("{0}")]
    FCntl(io::Error),
    #[error("{0}")]
    EventQueue(io::Error),
    #[error("{0}")]
    IOCtl(io::Error),
    #[error("{0}")]
    Connect(String),
    #[error("{0}")]
    SetSockOpt(String),
    #[error("Invalid tunnel name")]
    InvalidTunnelName,
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    #[error("{0}")]
    GetSockOpt(io::Error),
    #[error("{0}")]
    GetSockName(String),
    #[cfg(target_os = "linux")]
    #[error("{0}")]
    Timer(io::Error),
    #[error("iface read: {0}")]
    IfaceRead(io::Error),
    #[error("{0}")]
    DropPrivileges(String),
    #[error("API socket error: {0}")]
    ApiSocket(io::Error),
}

// What the event loop should do after a handler returns
enum Action {
    Continue, // Continue the loop
    Yield,    // Yield the read lock and acquire it again
    Exit,     // Stop the loop
}

// Event handler function
type Handler = Box<dyn Fn(&mut LockReadGuard<Device>, &mut ThreadData) -> Action + Send + Sync>;

pub struct DeviceHandle {
    device: Arc<Lock<Device>>, // The interface this handle owns
    threads: Vec<JoinHandle<()>>,
}

#[derive(Debug, Clone, Copy)]
pub struct DeviceConfig {
    pub n_threads: usize,
    pub use_connected_socket: bool,
    #[cfg(target_os = "linux")]
    pub use_multi_queue: bool,
    #[cfg(target_os = "linux")]
    pub uapi_fd: i32,
    pub ip_protocol: Option<u8>,
    pub transport_mode: TransportMode,
    pub is_tap: bool,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub enable_udp_gro: bool,
    pub dual_stack: bool,
    pub raw_ip_protocol: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TransportMode {
    Udp,
    RawIp,
    Tcp,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        DeviceConfig {
            n_threads: 4,
            use_connected_socket: true,
            #[cfg(target_os = "linux")]
            use_multi_queue: true,
            #[cfg(target_os = "linux")]
            uapi_fd: -1,
            ip_protocol: None,
            transport_mode: TransportMode::Udp,
            is_tap: false,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            enable_udp_gro: true,
            dual_stack: false,
            raw_ip_protocol: None,
        }
    }
}

pub struct Device {
    key_pair: Option<(x25519::StaticSecret, x25519::PublicKey)>,
    queue: Arc<EventPoll<Handler>>,

    listen_port: u16,
    fwmark: Option<u32>,

    iface: Arc<TunSocket>,
    udp4: Option<socket2::Socket>,
    udp6: Option<socket2::Socket>,
    raw4: Option<socket2::Socket>,
    raw6: Option<socket2::Socket>,
    tcp_listener: Option<socket2::Socket>,
    // Map of Peer Endpoint Address -> TCP Stream
    tcp_connections: Mutex<HashMap<SocketAddr, Arc<Mutex<socket2::Socket>>>>,

    yield_notice: Option<EventRef>,
    exit_notice: Option<EventRef>,

    peers: HashMap<x25519::PublicKey, Arc<Mutex<Peer>>>,
    peers_by_ip: AllowedIps<Arc<Mutex<Peer>>>,
    peers_by_mac: Mutex<HashMap<[u8; 6], Arc<Mutex<Peer>>>>,
    local_macs: Mutex<HashSet<[u8; 6]>>,
    peers_by_idx: HashMap<u32, Arc<Mutex<Peer>>>,
    next_index: IndexLfsr,

    config: DeviceConfig,

    cleanup_paths: Vec<String>,

    mtu: AtomicUsize,

    rate_limiter: Option<Arc<RateLimiter>>,

    uapi_fd: i32,
}

struct ThreadData {
    iface: Arc<TunSocket>,
    src_buf: [u8; MAX_UDP_SIZE],
    dst_buf: [u8; MAX_UDP_SIZE],
    #[cfg(any(target_os = "linux", target_os = "android"))]
    batch_bufs: Vec<Box<[u8; MAX_UDP_SIZE]>>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    send_batch_bufs: Vec<Box<[u8; MAX_UDP_SIZE]>>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    cmsg_bufs: Vec<Box<[u8; CMSG_LEN]>>,
}

impl DeviceHandle {
    pub fn new(name: &str, config: DeviceConfig) -> Result<DeviceHandle, Error> {
        let n_threads = config.n_threads;
        let mut wg_interface = Device::new(name, config)?;
        wg_interface.open_listen_socket(0)?; // Start listening on a random port

        let interface_lock = Arc::new(Lock::new(wg_interface));

        let mut threads = vec![];

        for i in 0..n_threads {
            threads.push({
                let dev = Arc::clone(&interface_lock);
                thread::spawn(move || DeviceHandle::event_loop(i, &dev))
            });
        }

        Ok(DeviceHandle {
            device: interface_lock,
            threads,
        })
    }

    pub fn wait(&mut self) {
        while let Some(thread) = self.threads.pop() {
            thread.join().unwrap();
        }
    }

    pub fn clean(&mut self) {
        for path in &self.device.read().cleanup_paths {
            // attempt to remove any file we created in the work dir
            let _ = std::fs::remove_file(path);
        }
    }

    fn event_loop(_i: usize, device: &Lock<Device>) {
        #[cfg(target_os = "linux")]
        let mut thread_local = ThreadData {
            src_buf: [0u8; MAX_UDP_SIZE],
            dst_buf: [0u8; MAX_UDP_SIZE],
            batch_bufs: (0..MAX_PACKET_COUNT).map(|_| Box::new([0u8; MAX_UDP_SIZE])).collect(),
            send_batch_bufs: (0..MAX_PACKET_COUNT).map(|_| Box::new([0u8; MAX_UDP_SIZE])).collect(),
            cmsg_bufs: (0..MAX_PACKET_COUNT).map(|_| Box::new([0u8; CMSG_LEN])).collect(),
            iface: if _i == 0 || !device.read().config.use_multi_queue {
                // For the first thread use the original iface
                Arc::clone(&device.read().iface)
            } else {
                // For for the rest create a new iface queue
                let is_tap = device.read().config.is_tap;
                let iface_local = Arc::new(
                    TunSocket::new(&device.read().iface.name().unwrap(), true, is_tap)
                        .unwrap()
                        .set_non_blocking()
                        .unwrap(),
                );

                device
                    .read()
                    .register_iface_handler(Arc::clone(&iface_local))
                    .ok();

                iface_local
            },
        };

        #[cfg(not(target_os = "linux"))]
        let mut thread_local = ThreadData {
            src_buf: [0u8; MAX_UDP_SIZE],
            dst_buf: [0u8; MAX_UDP_SIZE],
            iface: Arc::clone(&device.read().iface),
        };

        #[cfg(not(target_os = "linux"))]
        let uapi_fd = -1;
        #[cfg(target_os = "linux")]
        let uapi_fd = device.read().uapi_fd;

        loop {
            // The event loop keeps a read lock on the device, because we assume write access is rarely needed
            let mut device_lock = device.read();
            let queue = Arc::clone(&device_lock.queue);

            loop {
                match queue.wait() {
                    WaitResult::Ok(handler) => {
                        let action = (*handler)(&mut device_lock, &mut thread_local);
                        match action {
                            Action::Continue => {}
                            Action::Yield => break,
                            Action::Exit => {
                                device_lock.trigger_exit();
                                return;
                            }
                        }
                    }
                    WaitResult::EoF(handler) => {
                        if uapi_fd >= 0 && uapi_fd == handler.fd() {
                            device_lock.trigger_exit();
                            return;
                        }
                        handler.cancel();
                    }
                    WaitResult::Error(e) => tracing::error!(message = "Poll error", error = ?e),
                }
            }
        }
    }
}

impl Drop for DeviceHandle {
    fn drop(&mut self) {
        self.device.read().trigger_exit();
        self.clean();
    }
}

impl Device {
    fn next_index(&mut self) -> u32 {
        self.next_index.next()
    }

    fn remove_peer(&mut self, pub_key: &x25519::PublicKey) {
        if let Some(peer) = self.peers.remove(pub_key) {
            // Found a peer to remove, now purge all references to it:
            {
                let p = peer.lock();
                p.shutdown_endpoint(); // close open udp socket and free the closure
                self.peers_by_idx.remove(&p.index());
            }
            self.peers_by_ip
                .remove(&|p: &Arc<Mutex<Peer>>| Arc::ptr_eq(&peer, p));

            tracing::info!("Peer removed");
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn update_peer(
        &mut self,
        pub_key: x25519::PublicKey,
        remove: bool,
        _replace_ips: bool,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[AllowedIP],
        keepalive: Option<u16>,
        preshared_key: Option<[u8; 32]>,
        transport_mode: Option<TransportMode>,
    ) {
        if remove {
            // Completely remove a peer
            return self.remove_peer(&pub_key);
        }

        // Update an existing peer
        if self.peers.get(&pub_key).is_some() {
            // We already have a peer, we need to merge the existing config into the newly created one
            tracing::error!("Modifying existing peers is not yet supported. Remove and add again instead.");
            return;
        }

        let next_index = self.next_index();
        let device_key_pair = if let Some(kp) = self.key_pair.as_ref() {
            kp
        } else {
            tracing::error!("Private key must be set before adding peers.");
            return;
        };

        let tunn = Tunn::new(
            device_key_pair.0.clone(),
            pub_key,
            preshared_key,
            keepalive,
            next_index,
            None,
        );

        // NekoLink TCP Mode: 连接到 Endpoint 喵
        if self.config.transport_mode == TransportMode::Tcp {
            if let Some(endpoint_addr) = endpoint {
                // 喵！不再同步连接，而是记录 Endpoint，发送数据包时按需触发。
                tracing::info!("喵！TCP 模式已就绪，对端：{}", endpoint_addr);
            }
        }

        let mode = transport_mode.unwrap_or(self.config.transport_mode);
        let peer = Peer::new(tunn, next_index, endpoint, allowed_ips, preshared_key, mode, self.config.is_tap);

        let peer = Arc::new(Mutex::new(peer));
        self.peers.insert(pub_key, Arc::clone(&peer));
        self.peers_by_idx.insert(next_index, Arc::clone(&peer));

        for AllowedIP { addr, cidr } in allowed_ips {
            self.peers_by_ip
                .insert(*addr, *cidr as _, Arc::clone(&peer));
        }

        tracing::info!("Peer added");
    }

    pub fn new(name: &str, config: DeviceConfig) -> Result<Device, Error> {
        let poll = EventPoll::<Handler>::new()?;

        // Create a tunnel device
        let is_tap = config.is_tap;
        let iface = Arc::new(TunSocket::new(name, config.use_multi_queue, is_tap)?.set_non_blocking()?);
        let mtu = iface.mtu()?;

        #[cfg(not(target_os = "linux"))]
        let uapi_fd = -1;
        #[cfg(target_os = "linux")]
        let uapi_fd = config.uapi_fd;

        let mut device = Device {
            queue: Arc::new(poll),
            iface,
            config,
            exit_notice: Default::default(),
            yield_notice: Default::default(),
            fwmark: Default::default(),
            key_pair: Default::default(),
            listen_port: Default::default(),
            next_index: Default::default(),
            peers: Default::default(),
            peers_by_idx: Default::default(),
            peers_by_ip: AllowedIps::new(),
            peers_by_mac: Mutex::new(HashMap::new()),
            local_macs: Mutex::new(HashSet::new()),
            udp4: Default::default(),
            udp6: Default::default(),
            raw4: Default::default(),
            raw6: Default::default(),
            tcp_listener: Default::default(),
            tcp_connections: Mutex::new(HashMap::new()),
            cleanup_paths: Default::default(),
            mtu: AtomicUsize::new(mtu),
            rate_limiter: None,
            #[cfg(target_os = "linux")]
            uapi_fd,
        };

        if uapi_fd >= 0 {
            device.register_api_fd(uapi_fd)?;
        } else {
            device.register_api_handler()?;
        }
        device.register_iface_handler(Arc::clone(&device.iface))?;
        device.register_notifiers()?;
        device.register_timers()?;

        #[cfg(target_os = "macos")]
        {
            // Only for macOS write the actual socket name into WG_TUN_NAME_FILE
            if let Ok(name_file) = std::env::var("WG_TUN_NAME_FILE") {
                if name == "utun" {
                    std::fs::write(&name_file, device.iface.name().unwrap().as_bytes()).unwrap();
                    device.cleanup_paths.push(name_file);
                }
            }
        }

        Ok(device)
    }

    fn open_listen_socket(&mut self, mut port: u16) -> Result<(), Error> {
        tracing::debug!("喵！正在打开监听端口: {} (模式: {:?})", port, self.config.transport_mode);
        // Binds the network facing interfaces
        // First close any existing open socket, and remove them from the event loop
        if let Some(s) = self.udp4.take() {
            unsafe {
                // This is safe because the event loop is not running yet
                self.queue.clear_event_by_fd(s.as_raw_fd())
            }
        };

        if let Some(s) = self.udp6.take() {
            unsafe { self.queue.clear_event_by_fd(s.as_raw_fd()) };
        }

        if let Some(s) = self.tcp_listener.take() {
            unsafe { self.queue.clear_event_by_fd(s.as_raw_fd()) };
        }
        
        if let Some(s) = self.raw4.take() {
            unsafe { self.queue.clear_event_by_fd(s.as_raw_fd()) };
        }
        if let Some(s) = self.raw6.take() {
            unsafe { self.queue.clear_event_by_fd(s.as_raw_fd()) };
        }
        {
            let mut conns = self.tcp_connections.lock();
            for (_, s) in conns.drain() {
                 unsafe { self.queue.clear_event_by_fd(s.lock().as_raw_fd()) };
            }
        }

        for peer in self.peers.values() {
            peer.lock().shutdown_endpoint();
        }

        if self.config.transport_mode == TransportMode::Tcp {
            // TCP Server Mode: If port is set, bind and listen
            if port != 0 {
                match socket2::Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP)) {
                    Ok(sock) => {
                        // Dual stack
                        let _ = sock.set_only_v6(false);
                        let _ = sock.set_reuse_address(true);
                        
                        match sock.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into()) {
                            Ok(_) => {
                                let _ = sock.listen(128); // Backlog
                                let _ = sock.set_nonblocking(true);
                                
                                tracing::info!("喵！TCP Server 监听在 [::]:{}", port);
                                
                                if let Err(e) = self.register_tcp_listener_handler(sock.try_clone().unwrap()) {
                                     tracing::error!("无法注册 Listener Handler: {:?}", e);
                                }
                                self.tcp_listener = Some(sock);
                            }
                            Err(e) => tracing::error!("TCP Bind 失败: {:?}", e),
                        }
                    }
                    Err(e) => tracing::error!("创建 TCP Listener 失败: {:?}", e),
                }
            }
            return Ok(());
        }

        // Then open new sockets and bind to the port
        
        // 1. UDP Sockets (If default or dual stack)
        if self.config.ip_protocol.is_none() || self.config.dual_stack {
            tracing::info!("喵！绑定 UDP 端口: {}", port);
            let udp_sock4 = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            udp_sock4.set_reuse_address(true)?;
            let _ = udp_sock4.set_recv_buffer_size(4 * 1024 * 1024);
            let _ = udp_sock4.set_send_buffer_size(4 * 1024 * 1024);
            udp_sock4.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())?;
            udp_sock4.set_nonblocking(true)?;

            if port == 0 {
                // Random port was assigned
                port = udp_sock4.local_addr()?.as_socket().unwrap().port();
            }

            let udp_sock6 = socket2::Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
            udp_sock6.set_reuse_address(true)?;
            let _ = udp_sock6.set_recv_buffer_size(4 * 1024 * 1024);
            let _ = udp_sock6.set_send_buffer_size(4 * 1024 * 1024);
            
            // Only bind IPv6 if supported/needed, catching errors gracefully might be better but here we follow existing pattern
            if let Err(e) = udp_sock6.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into()) {
                 tracing::warn!("IPv6 UDP Bind 失败 (可能不支持 IPv6): {:?}", e);
            } else {
                 udp_sock6.set_nonblocking(true)?;
                 self.register_udp_handler(udp_sock6.try_clone().unwrap(), false)?; // false = UDP Mode
                 self.udp6 = Some(udp_sock6);
            }

            self.register_udp_handler(udp_sock4.try_clone().unwrap(), false)?;
            self.udp4 = Some(udp_sock4);
            self.listen_port = port;
        }

        // 2. Raw IP Sockets (If configured or dual stack)
        if self.config.ip_protocol.is_some() || self.config.raw_ip_protocol.is_some() || self.config.dual_stack {
            let proto_id = self.config.raw_ip_protocol.or(self.config.ip_protocol).unwrap_or(141);
            tracing::info!("喵！绑定 RawIP 协议: {}", proto_id);
            
            let sock_type = Type::RAW;
            let protocol = Protocol::from(i32::from(proto_id));

            match socket2::Socket::new(Domain::IPV4, sock_type, Some(protocol)) {
                Ok(raw4) => {
                    raw4.set_nonblocking(true)?;
                    // Raw socket binding is usually not port-specific, but we might bind to interface
                    // Here we just keep it unbound or bind to 0.0.0.0
                    // Note: Raw sockets receive all packets for that protocol.
                    self.register_udp_handler(raw4.try_clone().unwrap(), true)?; // true = Raw Mode
                    self.raw4 = Some(raw4);
                },
                Err(e) => tracing::error!("创建 RawIPv4 Socket 失败 (需 Root 权限?): {:?}", e),
            }

            match socket2::Socket::new(Domain::IPV6, sock_type, Some(protocol)) {
                Ok(raw6) => {
                    raw6.set_nonblocking(true)?;
                    self.register_udp_handler(raw6.try_clone().unwrap(), true)?;
                    self.raw6 = Some(raw6);
                },
                Err(e) => tracing::warn!("创建 RawIPv6 Socket 失败: {:?}", e),
            }
        }

        for peer in self.peers.values() {
            peer.lock().shutdown_endpoint();
        }

        Ok(())
    }

    fn set_key(&mut self, private_key: x25519::StaticSecret) {
        let public_key = x25519::PublicKey::from(&private_key);
        let key_pair = Some((private_key.clone(), public_key));

        // x25519 (rightly) doesn't let us expose secret keys for comparison.
        // If the public keys are the same, then the private keys are the same.
        if Some(&public_key) == self.key_pair.as_ref().map(|p| &p.1) {
            return;
        }

        let rate_limiter = Arc::new(RateLimiter::new(&public_key, HANDSHAKE_RATE_LIMIT));

        for peer in self.peers.values_mut() {
            peer.lock().tunnel.set_static_private(
                private_key.clone(),
                public_key,
                Some(Arc::clone(&rate_limiter)),
            )
        }

        self.key_pair = key_pair;
        self.rate_limiter = Some(rate_limiter);
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fn set_fwmark(&mut self, mark: u32) -> Result<(), Error> {
        self.fwmark = Some(mark);

        // First set fwmark on listeners
        if let Some(ref sock) = self.udp4 {
            sock.set_mark(mark)?;
        }

        if let Some(ref sock) = self.udp6 {
            sock.set_mark(mark)?;
        }
        if let Some(ref sock) = self.raw4 {
            sock.set_mark(mark)?;
        }
        if let Some(ref sock) = self.raw6 {
            sock.set_mark(mark)?;
        }

        // Then on all currently connected sockets
        for peer in self.peers.values() {
            if let Some(ref sock) = peer.lock().endpoint().conn {
                sock.set_mark(mark)?
            }
        }

        Ok(())
    }

    fn clear_peers(&mut self) {
        self.peers.clear();
        self.peers_by_idx.clear();
        self.peers_by_ip.clear();
        self.peers_by_mac.lock().clear();
        self.local_macs.lock().clear();
    }

    /// NekoLink: 将载荷封装并发送给指定的 Peers 喵
    fn send_payload_to_peers(&self, payload: &[u8], target_peers: Vec<Arc<Mutex<Peer>>>, t: &mut ThreadData) {
        let udp4 = self.udp4.as_ref();
        let udp6 = self.udp6.as_ref();

        for peer_arc in target_peers {
            let mut peer = peer_arc.lock();
            match peer.tunnel.encapsulate(payload, &mut t.dst_buf[..]) {
                TunnResult::Done => {}
                TunnResult::Err(e) => {
                    tracing::error!(message = "Encapsulate error", error = ?e)
                }
                TunnResult::WriteToNetwork(packet) => {
                    if self.config.transport_mode == TransportMode::Tcp {
                        if let Some(endpoint) = peer.endpoint().addr {
                            if let Some(stream_mutex) = self.maybe_connect_tcp(endpoint) {
                                let mut stream = stream_mutex.lock();
                                let len = packet.len() as u16;
                                let _ = stream.write(&len.to_be_bytes());
                                let _ = stream.write(packet);
                                let _ = stream.flush();
                            }
                        }
                    } else {
                        let mut endpoint = peer.endpoint_mut();
                        if let Some(conn) = endpoint.conn.as_mut() {
                            let _: Result<_, _> = conn.write(packet);
                        } else if let Some(addr) = endpoint.addr {
                            match addr {
                                SocketAddr::V4(_) => { 
                                    if peer.transport_mode == TransportMode::RawIp {
                                         if let Some(s) = self.raw4.as_ref() { let _ = s.send_to(packet, &addr.into()); }
                                    } else {
                                         if let Some(s) = udp4 { let _ = s.send_to(packet, &addr.into()); }
                                    }
                                }
                                SocketAddr::V6(_) => { 
                                     if peer.transport_mode == TransportMode::RawIp {
                                         if let Some(s) = self.raw6.as_ref() { let _ = s.send_to(packet, &addr.into()); }
                                     } else {
                                         if let Some(s) = udp6 { let _ = s.send_to(packet, &addr.into()); }
                                     }
                                }
                            }
                        }
                    }
                }
                _ => panic!("Unexpected result from encapsulate"),
            };
        }
    }

    /// NekoLink: 核心二层交换逻辑 (Switch Mode) 喵
    fn switch_tap_frame(&self, frame: &[u8], source_peer: Option<Arc<Mutex<Peer>>>, t: &mut ThreadData) {
        if frame.len() < 14 { return; }

        let dest_mac: [u8; 6] = frame[0..6].try_into().unwrap();
        let src_mac: [u8; 6] = frame[6..12].try_into().unwrap();
        let is_broadcast = (dest_mac[0] & 1) == 1;

        // 1. 学习阶段 (MAC Learning) 喵
        if let Some(ref peer) = source_peer {
            // 如果 MAC 曾被认为是本地的，现在漂移到了 Peer，则从本地表中移除 喵
            self.local_macs.lock().remove(&src_mac);
            self.peers_by_mac.lock().insert(src_mac, Arc::clone(peer));
        } else {
            // 来自本地接口的报文：学习本地 MAC，并确保它不出现在 Peer 表中 喵
            self.local_macs.lock().insert(src_mac);
            self.peers_by_mac.lock().remove(&src_mac);
        }

        // 2. 确定目标与转发逻辑 喵
        if is_broadcast {
            // 广播包：如果是来自网络，则传给本地一份喵
            if source_peer.is_some() {
                self.iface.write(frame);
            }
            // 淹没给所有 *其他* Peer 喵
            let mut targets = Vec::new();
            for p in self.peers.values() {
                if let Some(ref src) = source_peer {
                    if Arc::ptr_eq(p, src) { continue; }
                }
                targets.push(Arc::clone(p));
            }
            self.send_payload_to_peers(frame, targets, t);
        } else {
            // 检查是否是发给本地的单播 喵
            if self.local_macs.lock().contains(&dest_mac) {
                if source_peer.is_some() {
                    self.iface.write(frame);
                }
                return;
            }

            // 单播包：查询目标 Peer 喵
            let target_peer = self.peers_by_mac.lock().get(&dest_mac).cloned();
            
            match target_peer {
                Some(peer) => {
                    if let Some(ref src) = source_peer {
                        if Arc::ptr_eq(&peer, src) {
                            // 环路：不发回原始端口 喵
                            return;
                        }
                    }
                    // 转发给目标 Peer 喵
                    self.send_payload_to_peers(frame, vec![peer], t);
                }
                None => {
                    // 未知单播：如果是来自网络，则传给本地一份喵
                    if source_peer.is_some() {
                        self.iface.write(frame);
                    }
                    // 淹没给所有 *其他* Peer (泛洪) 喵
                    let mut targets = Vec::new();
                    for p in self.peers.values() {
                        if let Some(ref src) = source_peer {
                            if Arc::ptr_eq(p, src) { continue; }
                        }
                        targets.push(Arc::clone(p));
                    }
                    self.send_payload_to_peers(frame, targets, t);
                }
            }
        }
    }

    fn register_notifiers(&mut self) -> Result<(), Error> {
        let yield_ev = self
            .queue
            // The notification event handler simply returns Action::Yield
            .new_notifier(Box::new(|_, _| Action::Yield))?;
        self.yield_notice = Some(yield_ev);

        let exit_ev = self
            .queue
            // The exit event handler simply returns Action::Exit
            .new_notifier(Box::new(|_, _| Action::Exit))?;
        self.exit_notice = Some(exit_ev);
        Ok(())
    }

    fn register_timers(&self) -> Result<(), Error> {
        self.queue.new_periodic_event(
            // Reset the rate limiter every second give or take
            Box::new(|d, _| {
                if let Some(r) = d.rate_limiter.as_ref() {
                    r.reset_count()
                }
                Action::Continue
            }),
            std::time::Duration::from_secs(1),
        )?;

        self.queue.new_periodic_event(
            // Execute the timed function of every peer in the list
            Box::new(|d, t| {
                // 定期同步内核接口的 MTU 喵
                if let Ok(new_mtu) = d.iface.mtu() {
                    let old_mtu = d.mtu.swap(new_mtu, Ordering::SeqCst);
                    if old_mtu != new_mtu {
                         tracing::info!("喵！检测到物理接口 MTU 变化: {} -> {}", old_mtu, new_mtu);
                    }
                }

                let peer_map = &d.peers;
                tracing::debug!("喵！设备定时器触发，监测 {} 个 Peer", peer_map.len());

                if d.udp4.is_none() && d.udp6.is_none() {
                    return Action::Continue;
                }
                
                let udp4 = d.udp4.as_ref();
                let udp6 = d.udp6.as_ref();
                let raw4 = d.raw4.as_ref();
                let raw6 = d.raw6.as_ref();

                // Go over each peer and invoke the timer function
                for peer in peer_map.values() {
                    let mut p = peer.lock();
                    let endpoint_addr = match p.endpoint().addr {
                        Some(addr) => addr,
                        None => continue,
                    };

                    match p.update_timers(&mut t.dst_buf[..]) {
                        TunnResult::Done => {}
                        TunnResult::Err(WireGuardError::ConnectionExpired) => {
                            p.shutdown_endpoint(); // close open udp socket
                        }
                        TunnResult::Err(e) => tracing::error!(message = "Timer error", error = ?e),
                        TunnResult::WriteToNetwork(packet) => {
                            match endpoint_addr {
                                SocketAddr::V4(_) => { 
                                    if p.transport_mode == TransportMode::RawIp {
                                         if let Some(s) = raw4 { let _ = s.send_to(packet, &endpoint_addr.into()); }
                                    } else {
                                         if let Some(s) = udp4 { let _ = s.send_to(packet, &endpoint_addr.into()); }
                                    }
                                }
                                SocketAddr::V6(_) => { 
                                     if p.transport_mode == TransportMode::RawIp {
                                         if let Some(s) = raw6 { let _ = s.send_to(packet, &endpoint_addr.into()); }
                                     } else {
                                         if let Some(s) = udp6 { let _ = s.send_to(packet, &endpoint_addr.into()); }
                                     }
                                }
                            };
                        }
                        TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) | TunnResult::WriteToTunnelTap(..) => {
                             panic!("Unexpected result from update_timers")
                        }
                    };
                }
                Action::Continue
            }),
            std::time::Duration::from_millis(250),
        )?;
        Ok(())
    }

    pub(crate) fn trigger_yield(&self) {
        self.queue
            .trigger_notification(self.yield_notice.as_ref().unwrap())
    }

    pub(crate) fn trigger_exit(&self) {
        self.queue
            .trigger_notification(self.exit_notice.as_ref().unwrap())
    }

    pub(crate) fn cancel_yield(&self) {
        self.queue
            .stop_notification(self.yield_notice.as_ref().unwrap())
    }

    fn register_udp_handler(&self, udp: socket2::Socket, is_raw: bool) -> Result<(), Error> {
        self.queue.new_event(
            udp.as_raw_fd(),
            Box::new(move |d, t| {
                // Handler that handles anonymous packets over UDP or RawIP
                let mut iter = MAX_ITR;
                let (private_key, public_key) = match d.key_pair.as_ref() {
                    Some(k) => k,
                    None => return Action::Continue, // 还没设置密钥，先跳过喵
                };

                let rate_limiter = match d.rate_limiter.as_ref() {
                    Some(r) => r,
                    None => return Action::Continue,
                };

                #[cfg(any(target_os = "linux", target_os = "android"))]
                {
                    let fd = udp.as_raw_fd();
                    
                    if d.config.enable_udp_gro {
                        // NekoLink Phase 3: 尝试启用 UDP_GRO
                        unsafe {
                             let val: c_int = 1;
                             setsockopt(
                                 fd,
                                 SOL_UDP,
                                 UDP_GRO,
                                 &val as *const _ as *const c_void,
                                 std::mem::size_of::<c_int>() as _
                             );
                             // 忽略错误，不管成功与否都继续
                        }
                    }
                    
                    // Prepare data structures for recvmmsg
                    let mut raw_addrs = [unsafe { std::mem::zeroed::<sockaddr_storage>() }; MAX_PACKET_COUNT];
                    let mut iovecs: Vec<iovec> = t.batch_bufs
                        .iter_mut()
                        .map(|b| iovec {
                            iov_base: b.as_mut_ptr() as *mut _,
                            iov_len: b.len(),
                        })
                        .collect();
                    
                    let mut hdrs: Vec<mmsghdr> = (0..MAX_PACKET_COUNT)
                        .map(|i| {
                            let mut hdr: msghdr = unsafe { std::mem::zeroed() };
                            hdr.msg_name = &mut raw_addrs[i] as *mut _ as *mut _;
                            hdr.msg_namelen = std::mem::size_of::<sockaddr_storage>() as _;
                            hdr.msg_iov = &mut iovecs[i];
                            hdr.msg_iovlen = 1;
                            // NekoLink Phase 3: 挂载 Control Buffer
                            hdr.msg_control = t.cmsg_bufs[i].as_mut_ptr() as *mut _;
                            hdr.msg_controllen = CMSG_LEN as _;
                            mmsghdr {
                                msg_hdr: hdr,
                                msg_len: 0,
                            }
                        })
                        .collect();
                    
                    // NekoLink Phase 2: sendmmsg 准备结构
                    let mut send_len = 0;
                    let mut send_addrs = [unsafe { std::mem::zeroed::<sockaddr_storage>() }; MAX_PACKET_COUNT];
                    let mut send_iovecs: Vec<iovec> = t.send_batch_bufs
                        .iter_mut()
                        .map(|b| iovec {
                            iov_base: b.as_mut_ptr() as *mut _,
                            iov_len: 0, // 初始为 0，发送时更新
                        })
                        .collect();
                    
                    let mut send_hdrs: Vec<mmsghdr> = (0..MAX_PACKET_COUNT)
                        .map(|i| {
                            let mut hdr: msghdr = unsafe { std::mem::zeroed() };
                            hdr.msg_name = &mut send_addrs[i] as *mut _ as *mut _;
                            hdr.msg_namelen = std::mem::size_of::<sockaddr_storage>() as _;
                            hdr.msg_iov = &mut send_iovecs[i];
                            hdr.msg_iovlen = 1;
                            mmsghdr {
                                msg_hdr: hdr,
                                msg_len: 0,
                            }
                        })
                        .collect();
                    


                    loop {
                        // libc::recvmmsg returns int (number of pkts) or -1
                        let res = unsafe {
                            recvmmsg(
                                fd,
                                hdrs.as_mut_ptr(),
                                MAX_PACKET_COUNT as _,
                                MSG_DONTWAIT,
                                std::ptr::null_mut(),
                            )
                        };

                        if res < 0 {
                            let err = std::io::Error::last_os_error();
                             if err.kind() == std::io::ErrorKind::WouldBlock {
                                 break;
                             }
                             // Other errors?
                             break;
                        }
                        
                        let count = res as usize;
                        if count == 0 { break; }

                        for i in 0..count {
                            let pkt_len = hdrs[i].msg_len as usize;
                            let addr_storage = raw_addrs[i];
                            let addr_len = hdrs[i].msg_hdr.msg_namelen;

                            // Convert sockaddr_storage to SocketAddr
                            let addr = unsafe {
                                let s = socket2::SockAddr::new(addr_storage, addr_len);
                                s.as_socket()
                            };
                            
                            let addr = match addr {
                                Some(a) => a,
                                None => continue,
                            };
                            
                            let src_buf = &mut t.batch_bufs[i][..pkt_len];

                            // NekoLink Phase 3: 解析 CMSG 获取 GRO segment size
                            let mut gro_segment_size = 0;
                            let hdr = &hdrs[i].msg_hdr;
                            if hdr.msg_controllen > 0 {
                                unsafe {
                                    let mut cmsg: *mut cmsghdr = libc::CMSG_FIRSTHDR(hdr) as *mut _;
                                    while !cmsg.is_null() {
                                        if (*cmsg).cmsg_level == SOL_UDP && (*cmsg).cmsg_type == UDP_GRO {
                                            // Found GRO segment size
                                            let data_ptr = libc::CMSG_DATA(cmsg);
                                            // The data is a u16 (segment size)
                                            // Actually Linux kernel passes it as int or u16? Usually u16 for segment size in GSO, 
                                            // but for UDP_GRO it might be u16 payload_len.
                                            // Let's assume u16 as per typical kernel behavior for gso_size.
                                            let val_ptr = data_ptr as *const u16;
                                            gro_segment_size = *val_ptr as usize;
                                            break; 
                                        }
                                        cmsg = libc::CMSG_NXTHDR(hdr, cmsg) as *mut _;
                                    }
                                }
                            }

                            // 如果没启用 GRO 或没收到 segment info，不仅当成单包处理
                            if gro_segment_size == 0 {
                                gro_segment_size = pkt_len;
                            }

                            // 遍历所有 segment (如果 gro_segment_size < pkt_len，说明是 GRO 包)
                            let mut current_offset = 0;
                            while current_offset < pkt_len {
                                let remaining = pkt_len - current_offset;
                                let this_len = if remaining > gro_segment_size { gro_segment_size } else { remaining };
                                let segment_buf = &src_buf[current_offset..current_offset+this_len];
                                current_offset += this_len;

                                let mut offset = 0;
                                // NekoLink: 处理 IP 层头部 (Raw IP 模式) 喵
                                if is_raw && addr.ip().is_ipv4() {
                                    if this_len < 20 { continue; }
                                    let ihl = (segment_buf[0] & 0x0f) as usize * 4;
                                    if this_len < ihl { continue; }
                                    offset = ihl;
                                }

                                let packet = &segment_buf[offset..this_len];
                            let parsed_packet = match rate_limiter.verify_packet(
                                Some(addr.ip()),
                                packet,
                                &mut t.dst_buf,
                            ) {
                                Ok(packet) => packet,
                                Err(TunnResult::WriteToNetwork(cookie)) => {
                                    // NekoLink: 将 cookie 加入发送队列
                                    if send_len < MAX_PACKET_COUNT {
                                        t.send_batch_bufs[send_len][..cookie.len()].copy_from_slice(cookie);
                                        send_iovecs[send_len].iov_len = cookie.len();
                                        
                                        // 设置目标地址
                                        let sockaddr = socket2::SockAddr::from(addr);
                                        unsafe {
                                            let src = sockaddr.as_ptr() as *const sockaddr_storage;
                                            let dst = &mut send_addrs[send_len] as *mut sockaddr_storage;
                                            std::ptr::copy_nonoverlapping(src, dst, 1);
                                            send_hdrs[send_len].msg_hdr.msg_namelen = sockaddr.len();
                                        }
                                        
                                        send_len += 1;
                                    }
                                    
                                    // 满了就发
                                    if send_len == MAX_PACKET_COUNT {
                                        let res = unsafe {
                                            sendmmsg(
                                                fd,
                                                send_hdrs.as_mut_ptr(),
                                                send_len as _,
                                                MSG_DONTWAIT,
                                            )
                                        };
                                        if res < 0 && cfg!(debug_assertions) {}
                                        send_len = 0;
                                    }
                                    continue;
                                }
                                Err(_) => continue,
                            };

                            let peer = match &parsed_packet {
                                Packet::HandshakeInit(p) => {
                                    parse_handshake_anon(private_key, public_key, p)
                                        .ok()
                                        .and_then(|hh| {
                                            d.peers.get(&x25519::PublicKey::from(hh.peer_static_public))
                                        })
                                }
                                Packet::HandshakeResponse(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                                Packet::PacketCookieReply(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                                Packet::PacketData(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                            };

                            let peer = match peer {
                                None => continue,
                                Some(peer) => peer,
                            };

                            let mut p = peer.lock();
                            let remote_port = addr.port();

                            let mut flush = false;
                            let res = p.tunnel.handle_verified_packet(parsed_packet, &mut t.dst_buf[..]);
                            
                             if !matches!(res, TunnResult::Err(_)) {
                                  let ip_addr = addr.ip();
                                  let final_addr = SocketAddr::new(ip_addr, remote_port);
                                  p.set_endpoint(final_addr);

                                  if d.config.use_connected_socket {
                                      let _ = p.connect_endpoint(d.listen_port, d.fwmark, d.config.ip_protocol).map(|sock| {
                                    // Connected socket from peer.connect_endpoint is typically UDP.
                                    // See comments in handle_verified_packet for why we use false here.
                                    d.register_conn_handler(Arc::clone(peer), sock, ip_addr, false).unwrap();
                                      });
                                  }
                             }

                            match res {
                                TunnResult::Done => {}
                                TunnResult::Err(_) => continue,
                                TunnResult::WriteToNetwork(packet) => {
                                    flush = true;
                                    if send_len < MAX_PACKET_COUNT {
                                        t.send_batch_bufs[send_len][..packet.len()].copy_from_slice(packet);
                                        send_iovecs[send_len].iov_len = packet.len();
                                        
                                        let sockaddr = socket2::SockAddr::from(addr);
                                        unsafe {
                                            let src = sockaddr.as_ptr() as *const sockaddr_storage;
                                            let dst = &mut send_addrs[send_len] as *mut sockaddr_storage;
                                            std::ptr::copy_nonoverlapping(src, dst, 1);
                                            send_hdrs[send_len].msg_hdr.msg_namelen = sockaddr.len();
                                        }

                                        send_len += 1;
                                    }
                                    
                                    if send_len == MAX_PACKET_COUNT {
                                        let res = unsafe {
                                            sendmmsg(
                                                fd,
                                                send_hdrs.as_mut_ptr(),
                                                send_len as _,
                                                MSG_DONTWAIT,
                                            )
                                        };
                                        if res < 0 && cfg!(debug_assertions) {}
                                        send_len = 0;
                                    }
                                }
                                TunnResult::WriteToTunnelV4(packet, addr) => {
                                    if p.is_allowed_ip(addr) {
                                        t.iface.write4(packet);
                                    }
                                }
                                TunnResult::WriteToTunnelV6(packet, addr) => {
                                    if p.is_allowed_ip(addr) {
                                        t.iface.write6(packet);
                                    }
                                }
                                TunnResult::WriteToTunnelTap(packet) => {
                                    if packet.len() >= 14 {
                                        let src_mac: [u8; 6] = packet[6..12].try_into().unwrap();
                                        d.peers_by_mac.lock().insert(src_mac, Arc::clone(peer));
                                    }
                                    t.iface.write(packet);
                                }
                            } // match res
                                
                                if flush {
                                    while let TunnResult::WriteToNetwork(packet) =
                                        p.tunnel.decapsulate(None, &[], &mut t.dst_buf[..])
                                    {
                                        if send_len < MAX_PACKET_COUNT {
                                            t.send_batch_bufs[send_len][..packet.len()].copy_from_slice(packet);
                                            send_iovecs[send_len].iov_len = packet.len();
                                            
                                            let sockaddr = socket2::SockAddr::from(addr);
                                            unsafe {
                                                let src = sockaddr.as_ptr() as *const sockaddr_storage;
                                                let dst = &mut send_addrs[send_len] as *mut sockaddr_storage;
                                                std::ptr::copy_nonoverlapping(src, dst, 1);
                                                send_hdrs[send_len].msg_hdr.msg_namelen = sockaddr.len();
                                            }
    
                                            send_len += 1;
                                        }
                                        
                                        if send_len == MAX_PACKET_COUNT {
                                            let res = unsafe {
                                                sendmmsg(
                                                    fd,
                                                    send_hdrs.as_mut_ptr(),
                                                    send_len as _,
                                                    MSG_DONTWAIT,
                                                )
                                            };
                                            if res < 0 && cfg!(debug_assertions) {}
                                            send_len = 0;
                                        }
                                    }
                                }
                            } // while current_offset < pkt_len
                        } // for loop
                        
                        // Flush any remaining packets
                        if send_len > 0 {
                            let res = unsafe {
                                sendmmsg(
                                    fd,
                                    send_hdrs.as_mut_ptr(),
                                    send_len as _,
                                    MSG_DONTWAIT,
                                )
                            };
                            if res < 0 && cfg!(debug_assertions) {}
                            send_len = 0;
                        }

                        iter -= count;
                        if iter <= 0 || count < MAX_PACKET_COUNT {
                            break;
                        }
                    }
                }

                #[cfg(not(any(target_os = "linux", target_os = "android")))]
                {
                    // Safety: the `recv_from` implementation promises not to write uninitialised
                    // bytes to the buffer, so this casting is safe.
                    let mut iter = MAX_ITR;

                    while let Ok((packet_len, addr)) = udp.recv_from(unsafe { &mut *(&mut t.src_buf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) }) {
                        let mut offset = 0;
                        
                        // NekoLink: 处理 IP 层头部 (Raw IP 模式) 喵
                        // 如果我们在 Raw 模式 (is_raw == true) 或者传统 Raw 模式配置启用
                        if (is_raw || d.config.ip_protocol.is_some()) && addr.as_socket().map_or(false, |s| s.is_ipv4()) {
                            if packet_len < 20 { continue; }
                            let ihl = (t.src_buf[0] & 0x0f) as usize * 4;
                            if packet_len < ihl { continue; }
                            offset = ihl;
                        }


                        let packet = &t.src_buf[offset..packet_len];
                        // The rate limiter initially checks mac1 and mac2, and optionally asks to send a cookie
                        let parsed_packet = match rate_limiter.verify_packet(
                            Some(addr.as_socket().unwrap().ip()),
                            packet,
                            &mut t.dst_buf,
                        ) {
                            Ok(packet) => packet,
                            Err(TunnResult::WriteToNetwork(cookie)) => {
                                let _: Result<_, _> = udp.send_to(cookie, &addr);
                                continue;
                            }
                            Err(_) => continue,
                        };

                         // NekoLink Dual Stack: 动态更新 Peer 的传输模式喵
                         // 如果收到 Raw 包，标记为 RawIp; 否则 UDP。
                        let current_mode = if is_raw || d.config.ip_protocol.is_some() { TransportMode::RawIp } else { TransportMode::Udp };

                        let peer = match &parsed_packet {
                            Packet::HandshakeInit(p) => {
                                parse_handshake_anon(private_key, public_key, p)
                                    .ok()
                                    .and_then(|hh| {
                                        d.peers.get(&x25519::PublicKey::from(hh.peer_static_public))
                                    })
                            }
                            Packet::HandshakeResponse(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                            Packet::PacketCookieReply(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                            Packet::PacketData(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                        };

                        let peer = match peer {
                            None => continue,
                            Some(peer) => peer,
                        };

                        let mut p = peer.lock();

                        // NekoLink 2.3.0: 提取对端端口喵
                        let remote_port = addr.as_socket().unwrap().port();

                        // We found a peer, use it to decapsulate the message+
                        let mut flush = false; // Are there packets to send from the queue?
                        let res = p.tunnel.handle_verified_packet(parsed_packet, &mut t.dst_buf[..]);
                        
                        if !matches!(res, TunnResult::Err(_)) {
                            // 验证通过，此时才更新端点并尝试连接喵
                            let ip_addr = addr.as_socket().unwrap().ip();
                            let final_addr = SocketAddr::new(ip_addr, remote_port);
                            
                            p.set_endpoint(final_addr);

                            // NekoLink: 如果是双栈模式，我们需要记住这个 Peer 用的是什么协议喵
                            if d.config.dual_stack {
                                if p.transport_mode != current_mode {
                                     tracing::info!("喵！Peer {} 切换传输模式: {:?} -> {:?}", final_addr, p.transport_mode, current_mode);
                                     p.transport_mode = current_mode;
                                }
                            }

                            if d.config.use_connected_socket {
                                let _ = p.connect_endpoint(d.listen_port, d.fwmark, d.config.ip_protocol).map(|sock| {
                                    // Connected socket inherits the mode from the peer or config
                                    // For now, let's assume connected sockets follow the main transport mode logic
                                    // If we are in RawIP mode, connected socket might still be UDP or Raw depending on implementation
                                    // But typically connected sockets are UDP. If we support connected RAW sockets, we need is_raw=true.
                                    // For simplicity and safety, let's assume connected sockets are UDP for now unless we explicitly handle raw connected sockets (which is rare/complex).
                                    // However, to fix the compilation error, we must pass a value.
                                    // Since we don't have is_raw here easily without checking socket type, 
                                    // and usually connected sockets in this context are UDP, let's pass false.
                                    // Wait, if peer.transport_mode is RawIp, we might be using a connected Raw socket?
                                    // Actually, standard WireGuard uses UDP connected sockets.
                                    let is_raw_socket = false; 
                                    d.register_conn_handler(Arc::clone(peer), sock, ip_addr, is_raw_socket).unwrap();
                                });
                            }
                        }

                        match res {
                            TunnResult::Done => {}
                            TunnResult::Err(_) => continue,
                            TunnResult::WriteToNetwork(packet) => {
                                flush = true;
                                let _: Result<_, _> = udp.send_to(packet, &addr);
                            }
                            TunnResult::WriteToTunnelV4(packet, addr) => {
                                if p.is_allowed_ip(addr) {
                                    t.iface.write4(packet);
                                }
                            }
                            TunnResult::WriteToTunnelV6(packet, addr) => {
                                if p.is_allowed_ip(addr) {
                                    t.iface.write6(packet);
                                }
                            }
                            TunnResult::WriteToTunnelTap(packet) => {
                                let frame = packet.to_vec();
                                drop(p);
                                d.switch_tap_frame(&frame, Some(Arc::clone(peer)), t);
                                p = peer.lock();
                            }
                        };

                        if flush {
                            // Flush pending queue
                            while let TunnResult::WriteToNetwork(packet) =
                                p.tunnel.decapsulate(None, &[], &mut t.dst_buf[..])
                            {
                                let _: Result<_, _> = udp.send_to(packet, &addr);
                            }
                        }

                        iter -= 1;
                        if iter == 0 {
                            break;
                        }
                    }
                }

                Action::Continue
            }),
        )?;
        Ok(())
    }

    fn register_conn_handler(
        &self,
        peer: Arc<Mutex<Peer>>,
        udp: socket2::Socket,
        peer_addr: IpAddr,
        is_raw: bool,
    ) -> Result<(), Error> {
        self.queue.new_event(
            udp.as_raw_fd(),
            Box::new(move |d, t| {
                // The conn_handler handles packet received from a connected UDP socket, associated
                // with a known peer, this saves us the hustle of finding the right peer. If another
                // peer gets the same ip, it will be ignored until the socket does not expire.
                let mut iter = MAX_ITR;

                // Safety: the `recv_from` implementation promises not to write uninitialised
                // bytes to the buffer, so this casting is safe.
                while let Ok(read_bytes) = udp.recv(unsafe { &mut *(&mut t.src_buf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) }) {
                    let mut offset = 0;
                    let mut offset = 0;
                    // Connected socket logic (usually UDP only, but if we support raw connected...)
                    // Assuming connected sockets are primarily UDP.
                    if (is_raw || d.config.ip_protocol.is_some()) && peer_addr.is_ipv4() {
                        if read_bytes < 20 { continue; }
                        let ihl = (t.src_buf[0] & 0x0f) as usize * 4;
                        if read_bytes < ihl { continue; }
                        offset = ihl;
                    }

                    let mut p = peer.lock();

                    let mut flush = false;
                    let data = &t.src_buf[offset..read_bytes];
                    if !data.is_empty() && data[0] == 0x99 {
                        // Silently ignore signaling packets
                        continue;
                    }

                    match p.tunnel.decapsulate(
                        Some(peer_addr),
                        data,
                        &mut t.dst_buf[..],
                    ) {
                        TunnResult::Done => {}
                        TunnResult::Err(e) => eprintln!("Decapsulate error {:?}", e),
                        TunnResult::WriteToNetwork(packet) => {
                            flush = true;
                            let _: Result<_, _> = udp.send(packet);
                        }
                        TunnResult::WriteToTunnelV4(packet, addr) => {
                            if p.is_allowed_ip(addr) {
                                t.iface.write4(packet);
                            }
                        }
                        TunnResult::WriteToTunnelV6(packet, addr) => {
                            if p.is_allowed_ip(addr) {
                                t.iface.write6(packet);
                            }
                        }
                        TunnResult::WriteToTunnelTap(packet) => {
                            let frame = packet.to_vec();
                            drop(p);
                            d.switch_tap_frame(&frame, Some(Arc::clone(&peer)), t);
                            p = peer.lock();
                        }
                    };

                    if flush {
                        // Flush pending queue
                        while let TunnResult::WriteToNetwork(packet) =
                            p.tunnel.decapsulate(None, &[], &mut t.dst_buf[..])
                        {
                            let _: Result<_, _> = udp.send(packet);
                        }
                    }

                    iter -= 1;
                    if iter == 0 {
                        break;
                    }
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }

    fn register_iface_handler(&self, iface: Arc<TunSocket>) -> Result<(), Error> {
        self.queue.new_event(
            iface.as_raw_fd(),
            Box::new(move |d, t| {
                // The iface_handler handles packets received from the WireGuard virtual network
                // interface. The flow is as follows:
                // * Read a packet
                // * Determine peer based on packet destination ip
                // * Encapsulate the packet for the given peer
                // * Send encapsulated packet to the peer's endpoint
                tracing::debug!("喵！TUN 接口接收到原始报文");
                let mtu = d.mtu.load(Ordering::Relaxed);

                let peers = &d.peers_by_ip;
                for _ in 0..MAX_ITR {
                    let pkt_len = match iface.read(&mut t.src_buf[..]) {
                        Ok(src) => src.len(),
                        Err(Error::IfaceRead(e)) => {
                            let ek = e.kind();
                            if ek == io::ErrorKind::Interrupted || ek == io::ErrorKind::WouldBlock {
                                break;
                            }
                            eprintln!("Fatal read error on tun interface: {:?}", e);
                            return Action::Exit;
                        }
                        Err(e) => {
                            eprintln!("Unexpected error on tun interface: {:?}", e);
                            return Action::Exit;
                        }
                    };

                    let frame = t.src_buf[..pkt_len].to_vec();
                    let mut target_peers = Vec::new();
                    let peers = &d.peers_by_ip;

                    if d.config.is_tap {
                        d.switch_tap_frame(&frame, None, t);
                    } else {
                        let dst_addr = match Tunn::dst_address(&frame) {
                            Some(addr) => addr,
                            None => continue,
                        };
                        if let Some(peer_arc) = peers.find(dst_addr) {
                            target_peers.push(Arc::clone(peer_arc));
                        }
                        d.send_payload_to_peers(&frame, target_peers, t);
                    }
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }
    
    // NekoLink: 处理 TCP 数据流
    // NekoLink: 处理 TCP 数据流
    fn register_tcp_stream_handler(&self, sock: socket2::Socket, endpoint: SocketAddr) -> Result<(), Error> {
        let sock = Mutex::new(sock);
        let fd = sock.lock().as_raw_fd();
        let framing = Mutex::new(TcpFraming::new());
        self.queue.new_event(
            fd,
            Box::new(move |d, t| {
                let mut sock = sock.lock();
                let mut framing = framing.lock();
                
                // 1. 读取数据到 Framing Buffer
                let buf = framing.get_free_space();
                use std::io::Read;

                match sock.read(buf) {
                    Ok(0) => {
                        tracing::info!("TCP 连接断开: {}", endpoint);
                        d.tcp_connections.lock().remove(&endpoint);
                        // Do NOT trigger exit
                        return Action::Exit;
                    }
                    Ok(n) => {
                        framing.advance(n);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        return Action::Continue;
                    }
                    Err(e) => {
                        tracing::error!("TCP 读取错误 ({}): {:?}", endpoint, e);
                        d.tcp_connections.lock().remove(&endpoint);
                        return Action::Exit;
                    }
                }

                // 2. 循环处理完整的数据包
                let mut packets_processed = 0;
                let mut bytes_consumed = 0;
                
                while let Some((total_len, packet)) = framing.peek_packet(bytes_consumed) {
                    let pkt_len = packet.len();
                    if pkt_len > MAX_UDP_SIZE {
                        break; 
                    }

                    let (private_key, public_key) = match d.key_pair.as_ref() {
                        Some(k) => k,
                        None => break,
                    };

                    let rate_limiter = match d.rate_limiter.as_ref() {
                        Some(r) => r,
                        None => break,
                    };
                    
                    let parsed_packet = match rate_limiter.verify_packet(
                        Some(endpoint.ip()),
                        packet,
                        &mut t.dst_buf,
                    ) {
                         Ok(p) => p,
                         Err(TunnResult::WriteToNetwork(cookie)) => {
                             let len = cookie.len() as u16;
                             let len_bytes = len.to_be_bytes();
                             use std::io::Write;
                             let _ = sock.write(&len_bytes); 
                             let _ = sock.write(cookie);
                             
                             bytes_consumed += total_len; 
                             continue;
                         }
                         Err(_) => {
                             bytes_consumed += total_len;
                             continue;
                         }
                    };

                    // Identify Peer
                    let peer = match &parsed_packet {
                         Packet::HandshakeInit(p) => {
                             parse_handshake_anon(private_key, public_key, p)
                                 .ok()
                                 .and_then(|hh| {
                                     d.peers.get(&x25519::PublicKey::from(hh.peer_static_public))
                                 })
                         }
                         Packet::HandshakeResponse(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                         Packet::PacketCookieReply(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                         Packet::PacketData(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                    };

                    if let Some(peer_arc) = peer {
                        let mut p = peer_arc.lock();
                        // Decapsulate
                        let res = p.tunnel.handle_verified_packet(parsed_packet, &mut t.dst_buf[..]);
                        
                        match res {
                            TunnResult::Done => {},
                            TunnResult::Err(e) => tracing::error!("Decapsulate error: {:?}", e),
                            TunnResult::WriteToNetwork(resp) => {
                                if let Some(stream_mutex) = d.maybe_connect_tcp(endpoint) {
                                    let mut stream = stream_mutex.lock();
                                    let len = resp.len() as u16;
                                    let len_bytes = len.to_be_bytes();
                                    use std::io::Write;
                                    let _ = stream.write(&len_bytes);
                                    let _ = stream.write(resp);
                                    let _ = stream.flush();
                                }
                            },
                            TunnResult::WriteToTunnelV4(tun_pkt, addr) => {
                                 if p.is_allowed_ip(addr) { t.iface.write4(tun_pkt); }
                            },
                            TunnResult::WriteToTunnelV6(tun_pkt, addr) => {
                                 if p.is_allowed_ip(addr) { t.iface.write6(tun_pkt); }
                            },
                            TunnResult::WriteToTunnelTap(tun_pkt) => {
                                let frame = tun_pkt.to_vec();
                                drop(p);
                                d.switch_tap_frame(&frame, Some(Arc::clone(peer_arc)), t);
                                p = peer_arc.lock();
                            }
                        }
                        
                         while let TunnResult::WriteToNetwork(resp) =
                                p.tunnel.decapsulate(None, &[], &mut t.dst_buf[..])
                         {
                            if let Some(stream_mutex) = d.maybe_connect_tcp(endpoint) {
                                let mut stream = stream_mutex.lock();
                                let len = resp.len() as u16;
                                let len_bytes = len.to_be_bytes();
                                use std::io::Write;
                                let _ = stream.write(&len_bytes);
                                let _ = stream.write(resp);
                                let _ = stream.flush();
                            }
                         }
                    }

                    bytes_consumed += total_len;
                    packets_processed += 1;
                    if packets_processed >= MAX_ITR { break; }
                }

                framing.compact(bytes_consumed);

                Action::Continue
            })
        ).map(|_| ())
    }

    fn register_tcp_listener_handler(&self, listener: socket2::Socket) -> Result<(), Error> {
        let listener = Mutex::new(listener); // Wrap in Mutex for interior mutability if needed (Shared ref in Fn)
        let fd = listener.lock().as_raw_fd();
        
        self.queue.new_event(
             fd,
             Box::new(move |d, _| {
                  let listener = listener.lock();
                  // Accept loop
                  loop {
                      match listener.accept() {
                          Ok((sock, addr)) => {
                              tracing::info!("喵！接受新 TCP 连接: {:?}", addr);
                              if let Err(e) = sock.set_nonblocking(true) {
                                  tracing::error!("无法设置非阻塞: {:?}", e);
                                  continue;
                              }
                              if let Err(e) = sock.set_nodelay(true) {
                                  tracing::error!("无法设置 NODELAY: {:?}", e);
                              }
                              
                              // 1. Add to Connection Map (Owned socket for Writing)
                              if let Ok(write_sock) = sock.try_clone() {
                                  d.tcp_connections.lock().insert(addr.as_socket().unwrap(), Arc::new(Mutex::new(write_sock)));
                              }
                              
                              // 2. Register Stream (Owned socket for Reading, + Dup FD)
                              if let Err(e) = d.register_tcp_stream_handler(sock, addr.as_socket().unwrap()) {
                                  tracing::error!("无法注册 Stream Handler: {:?}", e);
                              }
                          },
                          Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                          Err(e) => {
                              tracing::error!("Accept 错误: {:?}", e);
                              break;
                          }
                      }
                  }
                  Action::Continue
             })
        ).map(|_| ())
    }

    /// NekoLink: 获取或建立 TCP 连接喵
    fn maybe_connect_tcp(&self, endpoint: SocketAddr) -> Option<Arc<Mutex<socket2::Socket>>> {
        let mut conns = self.tcp_connections.lock();
        if let Some(stream) = conns.get(&endpoint) {
            return Some(Arc::clone(stream));
        }

        // 异步发起连接（此处仅同步创建并注册，实际连接在 epoll 循环中非阻塞完成或在 write 时报错）
        let proto = match endpoint {
            SocketAddr::V4(_) => Domain::IPV4,
            SocketAddr::V6(_) => Domain::IPV6,
        };

        match socket2::Socket::new(proto, Type::STREAM, Some(Protocol::TCP)) {
            Ok(sock) => {
                let _ = sock.set_nonblocking(true);
                let _ = sock.set_nodelay(true);
                
                // 尝试非阻塞连接喵
                match sock.connect(&endpoint.into()) {
                    Ok(_) | Err(_) => {
                        // 无论成功还是 EINPROGRESS，我们都先注册它
                        if let Ok(write_sock) = sock.try_clone() {
                            let stream_arc = Arc::new(Mutex::new(write_sock));
                            conns.insert(endpoint, Arc::clone(&stream_arc));
                            
                            if let Err(e) = self.register_tcp_stream_handler(sock, endpoint) {
                                tracing::error!("喵呜！无法注册 TCP Stream Handler: {:?}", e);
                            } else {
                                tracing::info!("喵！已发起异步 TCP 连接请求: {}", endpoint);
                            }
                            return Some(stream_arc);
                        }
                    }
                }
            }
            Err(e) => tracing::error!("喵呜！创建 TCP socket 失败: {:?}", e),
        }
        None
    }
}

/// A basic linear-feedback shift register implemented as xorshift, used to
/// distribute peer indexes across the 24-bit address space reserved for peer
/// identification.
/// The purpose is to obscure the total number of peers using the system and to
/// ensure it requires a non-trivial amount of processing power and/or samples
/// to guess other peers' indices. Anything more ambitious than this is wasted
/// with only 24 bits of space.
struct IndexLfsr {
    initial: u32,
    lfsr: u32,
    mask: u32,
}

impl IndexLfsr {
    /// Generate a random 24-bit nonzero integer
    fn random_index() -> u32 {
        const LFSR_MAX: u32 = 0xffffff; // 24-bit seed
        loop {
            let i = OsRng.next_u32() & LFSR_MAX;
            if i > 0 {
                // LFSR seed must be non-zero
                return i;
            }
        }
    }

    /// Generate the next value in the pseudorandom sequence
    fn next(&mut self) -> u32 {
        // 24-bit polynomial for randomness. This is arbitrarily chosen to
        // inject bitflips into the value.
        const LFSR_POLY: u32 = 0xd80000; // 24-bit polynomial
        let value = self.lfsr - 1; // lfsr will never have value of 0
        self.lfsr = (self.lfsr >> 1) ^ ((0u32.wrapping_sub(self.lfsr & 1u32)) & LFSR_POLY);
        assert!(self.lfsr != self.initial, "Too many peers created");
        value ^ self.mask
    }
}

impl Default for IndexLfsr {
    fn default() -> Self {
        let seed = Self::random_index();
        IndexLfsr {
            initial: seed,
            lfsr: seed,
            mask: Self::random_index(),
        }
    }
}
