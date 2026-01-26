use crate::config::Config;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::ffi::CString;
use log::{info, warn};

// IP Protocol 233
const PROTO_NUM: i32 = 233;

pub fn create_raw_socket(cfg: &Config) -> anyhow::Result<std::net::UdpSocket> {
    // Determine Domain (IPv4 vs IPv6)
    let domain = if cfg.local_addr.contains(':') {
        Domain::IPV6
    } else {
        Domain::IPV4
    };

    let protocol = Protocol::from(cfg.ip_protocol_num as i32);
    let socket = Socket::new(domain, Type::RAW, Some(protocol))?;

    // Bind
    // Rust socket2 bind expects a loopback/any address for Raw sockets usually.
    let addr = if domain == Domain::IPV6 {
        "0.0.0.0:0".parse::<SocketAddr>().unwrap() // Placeholder, actually need IPv6 any
    } else {
        "0.0.0.0:0".parse::<SocketAddr>().unwrap()
    };
    
    // For Raw Sockets, binding to a specific IP might restrict receiving to that IP.
    // Go code: net.ListenIP("ip4:233", lAddr)
    
    socket.bind(&addr.into())?;
    
    // Set buffers
    let _ = socket.set_recv_buffer_size(32 * 1024 * 1024);
    let _ = socket.set_send_buffer_size(32 * 1024 * 1024);

    // Convert to std::net::UdpSocket to integrate with other parts (though it's a raw socket)
    // Note: Rust standard lib doesn't have "RawSocket" type, but UdpSocket is just a wrapper around an FD.
    // However, calling UdpSocket methods on a Raw Socket might behave unexpectedly if not careful.
    // But since we use it for AsRawFd mostly, it's fine.
    
    Ok(socket.into())
}

pub fn create_fallback_socket(cfg: &Config) -> anyhow::Result<i32> {
    // AF_PACKET is Linux specific
    use libc::{socket, AF_PACKET, SOCK_RAW, ETH_P_ALL};
    use libc::{sockaddr_ll, bind, if_nametoindex};
    use std::mem;

    unsafe {
        // htons(ETH_P_ALL)
        let protocol = (ETH_P_ALL as u16).to_be();
        
        let fd = socket(AF_PACKET, SOCK_RAW, protocol as i32);
        if fd < 0 {
            return Err(anyhow::anyhow!("Failed to create AF_PACKET socket"));
        }

        // Get Interface Index
        let iface_cstr = CString::new(cfg.app_interface.as_str())?;
        let if_index = if_nametoindex(iface_cstr.as_ptr());
        if if_index == 0 {
            libc::close(fd);
            return Err(anyhow::anyhow!("Interface {} not found", cfg.app_interface));
        }

        // Bind
        let mut sa: sockaddr_ll = mem::zeroed();
        sa.sll_family = AF_PACKET as u16;
        sa.sll_protocol = protocol;
        sa.sll_ifindex = if_index as i32;

        let res = bind(fd, &sa as *const _ as *const libc::sockaddr, mem::size_of::<sockaddr_ll>() as u32);
        if res < 0 {
            libc::close(fd);
            return Err(anyhow::anyhow!("Failed to bind AF_PACKET socket"));
        }
        
        // Set Non-Blocking
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        if flags < 0 {
            libc::close(fd);
            return Err(anyhow::anyhow!("Failed to get socket flags"));
        }
        if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            libc::close(fd);
            return Err(anyhow::anyhow!("Failed to set non-blocking"));
        }
        
        Ok(fd)
    }
}
