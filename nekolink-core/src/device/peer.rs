// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use parking_lot::RwLock;
use socket2::{Domain, Protocol, Type};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;
use crate::device::{AllowedIps, Error, TransportMode};
use crate::noise::{Tunn, TunnResult};
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Idle,
    SynSent,
    SynReceived,
    Established,
    Closed,
}

impl From<u8> for TcpState {
    fn from(v: u8) -> Self {
        match v {
            1 => TcpState::SynSent,
            2 => TcpState::SynReceived,
            3 => TcpState::Established,
            4 => TcpState::Closed,
            _ => TcpState::Idle,
        }
    }
}

#[derive(Default, Debug)]
pub struct Endpoint {
    pub addr: Option<SocketAddr>,
    pub conn: Option<socket2::Socket>,
}

pub struct Peer {
    /// The associated tunnel struct
    pub(crate) tunnel: Tunn,
    /// The index the tunnel uses
    index: u32,
    endpoint: RwLock<Endpoint>,
    allowed_ips: AllowedIps<()>,
    preshared_key: Option<[u8; 32]>,
    pub transport_mode: TransportMode,
    pub tcp_state: AtomicU8,
    pub tcp_seq: AtomicU32,
    pub tcp_ack: AtomicU32,
    pub tcp_init_seq: AtomicU32,
    pub local_ip: RwLock<Option<Ipv4Addr>>,
    pub local_port: RwLock<u16>,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct AllowedIP {
    pub addr: IpAddr,
    pub cidr: u8,
}

impl FromStr for AllowedIP {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ip: Vec<&str> = s.split('/').collect();
        if ip.len() != 2 {
            return Err("Invalid IP format".to_owned());
        }

        let (addr, cidr) = (ip[0].parse::<IpAddr>(), ip[1].parse::<u8>());
        match (addr, cidr) {
            (Ok(addr @ IpAddr::V4(_)), Ok(cidr)) if cidr <= 32 => Ok(AllowedIP { addr, cidr }),
            (Ok(addr @ IpAddr::V6(_)), Ok(cidr)) if cidr <= 128 => Ok(AllowedIP { addr, cidr }),
            _ => Err("Invalid IP format".to_owned()),
        }
    }
}

impl Peer {
    pub fn new(
        tunnel: Tunn,
        index: u32,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[AllowedIP],
        preshared_key: Option<[u8; 32]>,
        transport_mode: TransportMode,
    ) -> Peer {
        Peer {
            tunnel,
            index,
            endpoint: RwLock::new(Endpoint {
                addr: endpoint,
                conn: None,
            }),
            allowed_ips: allowed_ips.iter().map(|ip| (ip, ())).collect(),
            preshared_key,
            transport_mode,
            tcp_state: AtomicU8::new(0), // Idle
            tcp_seq: AtomicU32::new(0),
            tcp_ack: AtomicU32::new(0),
            tcp_init_seq: AtomicU32::new(0),
            local_ip: RwLock::new(None),
            local_port: RwLock::new(0),
        }
    }

    pub fn reset_tcp(&self, init_seq: u32) {
        self.tcp_init_seq.store(init_seq, Ordering::SeqCst);
        self.tcp_seq.store(init_seq, Ordering::SeqCst);
        self.tcp_ack.store(0, Ordering::SeqCst);
        self.tcp_state.store(0, Ordering::SeqCst);
    }

    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunnel.update_timers(dst)
    }

    pub fn endpoint(&self) -> parking_lot::RwLockReadGuard<'_, Endpoint> {
        self.endpoint.read()
    }

    pub(crate) fn endpoint_mut(&self) -> parking_lot::RwLockWriteGuard<'_, Endpoint> {
        self.endpoint.write()
    }

    pub fn shutdown_endpoint(&self) {
        if let Some(conn) = self.endpoint.write().conn.take() {
            tracing::info!("Disconnecting from endpoint");
            conn.shutdown(Shutdown::Both).unwrap();
        }
    }

    pub fn set_endpoint(&self, addr: SocketAddr) {
        let mut endpoint = self.endpoint.write();
        if endpoint.addr != Some(addr) {
            // We only need to update the endpoint if it differs from the current one
            if let Some(conn) = endpoint.conn.take() {
                conn.shutdown(Shutdown::Both).unwrap();
            }

            endpoint.addr = Some(addr);
        }
    }

    pub fn connect_endpoint(
        &self,
        port: u16,
        fwmark: Option<u32>,
        ip_protocol: Option<u8>,
    ) -> Result<socket2::Socket, Error> {
        let mut endpoint = self.endpoint.write();

        if endpoint.conn.is_some() {
            return Err(Error::Connect("Connected".to_owned()));
        }

        let addr = endpoint
            .addr
            .expect("Attempt to connect to undefined endpoint");

        let (sock_type, protocol) = match self.transport_mode {
            TransportMode::RawIp => (Type::RAW, Protocol::from(i32::from(ip_protocol.unwrap_or(141)))),
            TransportMode::FakeTcp => (Type::RAW, Protocol::TCP),
            TransportMode::Udp => (Type::DGRAM, Protocol::UDP),
        };

        let udp_conn = socket2::Socket::new(Domain::for_address(addr), sock_type, Some(protocol))?;
        udp_conn.set_reuse_address(true)?;
        let bind_addr = if addr.is_ipv4() {
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into()
        } else {
            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into()
        };
        udp_conn.bind(&bind_addr)?;
        udp_conn.connect(&addr.into())?;
        udp_conn.set_nonblocking(true)?;

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if let Some(fwmark) = fwmark {
            udp_conn.set_mark(fwmark)?;
        }

        if addr.is_ipv6() && ip_protocol.is_some() {
            // 设置 IPv6 DSCP 为最高优先级 (CS7 = 56, TCLASS = 56 << 2 = 224 = 0xE0)
            use std::os::unix::io::AsRawFd;
            let fd = udp_conn.as_raw_fd();
            unsafe {
                let val: libc::c_int = 224;
                libc::setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_TCLASS, &val as *const _ as *const libc::c_void, std::mem::size_of_val(&val) as libc::socklen_t);
            }
        }

        tracing::info!(
            message="Connected endpoint",
            port=port,
            endpoint=?endpoint.addr.unwrap()
        );

        if let Ok(local_addr) = udp_conn.local_addr() {
            if let Some(addr_v4) = local_addr.as_socket_ipv4() {
                *self.local_ip.write() = Some(*addr_v4.ip());
                // *self.local_port.write() = addr_v4.port(); // RAW 可能会返回 0 喵
            }
        }
        *self.local_port.write() = port;

        endpoint.conn = Some(udp_conn.try_clone().unwrap());

        Ok(udp_conn)
    }

    pub fn is_allowed_ip<I: Into<IpAddr>>(&self, addr: I) -> bool {
        self.allowed_ips.find(addr.into()).is_some()
    }

    pub fn allowed_ips(&self) -> impl Iterator<Item = (IpAddr, u8)> + '_ {
        self.allowed_ips.iter().map(|(_, ip, cidr)| (ip, cidr))
    }

    pub fn time_since_last_handshake(&self) -> Option<std::time::Duration> {
        self.tunnel.time_since_last_handshake()
    }

    pub fn persistent_keepalive(&self) -> Option<u16> {
        self.tunnel.persistent_keepalive()
    }

    pub fn preshared_key(&self) -> Option<&[u8; 32]> {
        self.preshared_key.as_ref()
    }

    pub fn index(&self) -> u32 {
        self.index
    }
}
