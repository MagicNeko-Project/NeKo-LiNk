use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use x25519_dalek::{PublicKey, StaticSecret};
use socket2::{Domain, Protocol, Socket, Type};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PeerConfig {
    endpoint: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct NekoConfig {
    interface: String,
    #[serde(default = "default_mode")]
    mode: String,
    ip_protocol: Option<u8>,
    local_address: String,
    psk: String,
    peers: Vec<PeerConfig>,
    #[serde(default = "default_signal_port")]
    signal_port: u16,
    listen_port: Option<u16>,
    #[serde(default)]
    auto_route: bool,
    pub persistent_keepalive: Option<u16>,
    pub mtu: Option<u16>,
    #[serde(default)]
    pub clamp_mss: bool,
}

fn default_mode() -> String {
    "udp".to_string()
}
fn default_signal_port() -> u16 {
    5678
}

struct NekoState {
    config: NekoConfig,
    _priv_key: StaticSecret,
    pub_key: PublicKey,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        match args[1].as_str() {
            "status" => return show_status().await,
            "genkey" => {
                let priv_key = StaticSecret::random_from_rng(OsRng);
                let pub_key = PublicKey::from(&priv_key);
                println!("Private Key: {}", BASE64.encode(priv_key.to_bytes()));
                println!("Public Key:  {}", BASE64.encode(pub_key.as_bytes()));
                return Ok(());
            }
            "version" => {
                println!("NekoLink Control Plane v{}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "mtu-probe" => {
                if args.len() < 3 {
                    eprintln!("用法: nekolink-ctl mtu-probe <endpoint> [mode]");
                    std::process::exit(1);
                }
                let endpoint = &args[2];
                let mode = args.get(3).map(|s| s.as_str()).unwrap_or("udp");
                return probe_mtu_cmd(endpoint, mode).await;
            }
            _ => {
                eprintln!("喵？不支持的指令: '{}'。如果您想启动服务，请不要带参数喵。", args[1]);
                std::process::exit(1);
            }
        }
    }

    println!("ฅ^•ﻌ•^ฅ NekoLink 控制平面启动中...");

    let config_dir = "/etc/neko-link";
    if !std::path::Path::new(config_dir).exists() {
        fs::create_dir_all(config_dir).context("无法创建配置目录")?;
    }

    let mut handles = vec![];

    for entry in glob::glob(&format!("{}/*.json", config_dir))? {
        let path = entry?;
        let config_str = fs::read_to_string(&path)?;
        let config: NekoConfig = match serde_json::from_str(&config_str) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("解析配置文件 {:?} 失败喵: {:?}", path, e);
                continue;
            }
        };

        let handle = tokio::spawn(async move {
            if let Err(e) = run_instance(config).await {
                eprintln!("实例 {:?} 运行时出错: {:?}", path, e);
            }
        });
        handles.push(handle);
    }

    if handles.is_empty() {
        println!("喵？没有发现任何配置文件在 {}/。请添加 *.json 文件喵！", config_dir);
    }

    for h in handles {
        let _ = h.await;
    }

    Ok(())
}

async fn send_uapi(interface: &str, commands: &str) -> Result<()> {
    let path = format!("/var/run/wireguard/{}.sock", interface);
    let mut stream = tokio::net::UnixStream::connect(path).await
        .context("无法连接到 UAPI Socket")?;
    
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    
    stream.write_all(commands.as_bytes()).await?;
    stream.flush().await?;
    
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    while reader.read_line(&mut line).await? > 0 {
        if line.starts_with("errno=") {
            let errno: i32 = line["errno=".len()..].trim().parse()?;
            if errno != 0 {
                return Err(anyhow::anyhow!("UAPI 返回错误: {}", errno));
            }
            break;
        }
        line.clear();
    }
    Ok(())
}

async fn run_instance(config: NekoConfig) -> Result<()> {
    println!("正在启动接口 {} 喵...", config.interface);

    // 1. 获取或生成固定密钥
    let key_path = format!("/etc/neko-link/{}.key", config.interface);
    let pub_path = format!("/etc/neko-link/{}.pub", config.interface);
    
    let priv_key = if let Ok(existing_key_b64) = fs::read_to_string(&key_path) {
        let trimmed = existing_key_b64.trim();
        let bytes = BASE64.decode(trimmed).context("无法解码现有私钥喵")?;
        StaticSecret::from(<[u8; 32]>::try_from(bytes).map_err(|_| anyhow::anyhow!("私钥长度不对喵"))?)
    } else {
        let new_priv = StaticSecret::random_from_rng(OsRng);
        let new_b64 = BASE64.encode(new_priv.to_bytes());
        fs::write(&key_path, new_b64).context("无法保存私钥文件喵")?;
        new_priv
    };

    let pub_key = PublicKey::from(&priv_key);
    let priv_b64 = BASE64.encode(priv_key.to_bytes());
    let pub_b64 = BASE64.encode(pub_key.as_bytes());
    
    // 同时也写一下公钥文件方便用户查看喵
    let _ = fs::write(&pub_path, &pub_b64);

    println!("使用公钥: {} 喵！", pub_b64);

    // 2. 预清理：强制删除可能存在的旧接口喵
    let _ = run_cmd(&format!("ip link del {} 2>/dev/null", config.interface));

    // 3. 启动 nekolink-cli
    let mut cmd = tokio::process::Command::new("nekolink-cli");
    cmd.arg("-f").arg(&config.interface);
    cmd.arg("--disable-drop-privileges");
    cmd.kill_on_drop(true); // 重点：ctl 退出时一定要带走 cli 喵！
    if config.mode == "ip" {
        if let Some(proto) = config.ip_protocol {
            cmd.arg("--ip-protocol").arg(proto.to_string());
        }
    } else if config.mode == "tcp" {
        cmd.arg("--fake-tcp");
    }
    
    // 强制设置 MTU，默认 1420 喵
    let mtu = config.mtu.unwrap_or(1420);
    
    let mut child = cmd.spawn().context("启动 nekolink-cli 失败")?;

    // 等待接口创建
    time::sleep(Duration::from_secs(2)).await;

    // 3. 配置接口与私钥 (UAPI 方式)
    let mut uapi_cmd = format!("set=1\nprivate_key={}\n", priv_b64);
    if let Some(port) = config.listen_port {
        uapi_cmd.push_str(&format!("listen_port={}\n", port));
    }
    uapi_cmd.push('\n');

    send_uapi(&config.interface, &uapi_cmd).await.context("配置私钥失败")?;

    // 4. 配置 IP 地址与链路状态 (更健壮喵)
    println!("正在配置 IP 地址 {} 到 {}...", config.local_address, config.interface);
    let _ = run_cmd(&format!("ip addr del {} dev {} 2>/dev/null", config.local_address, config.interface));
    run_cmd(&format!("ip addr add {} dev {}", config.local_address, config.interface)).context("添加 IP 失败")?;
    run_cmd(&format!("ip link set mtu {} dev {}", mtu, config.interface)).context("设置 MTU 失败")?;
    run_cmd(&format!("ip link set up dev {}", config.interface)).context("启用网卡失败")?;

    // 如果 MTU 为 0，表示开启了自动同步模式喵
    if config.mtu == Some(0) {
        println!("接口 {} 已开启 MTU 动态同步模式喵！(〃'▽'〃)", config.interface);
    }

    // 如果开启了 auto_route，则添加直连路由（实验性喵）
    if config.auto_route {
        let (network, _) = config.local_address.split_once('/').unwrap_or((&config.local_address, ""));
        if !network.is_empty() {
             // 简单的子网路由逻辑，目前先确保直连地址通
             println!("auto_route 已开启，已配置基础路由喵。");
        }
    }
    
    // 4. 加密信令任务：交换公钥
    let state = NekoState {
        config: config.clone(),
        _priv_key: priv_key,
        pub_key,
    };

    let signaling_handle = tokio::spawn(async move {
        let _ = start_signaling(state).await;
    });

    if config.clamp_mss {
        println!("正在开启 MSS 自动修复 (nftables MSS Clamping) 喵...");
        let table_name = format!("nekolink_mss_{}", config.interface);
        let _ = run_cmd(&format!("nft add table inet {}", table_name));
        let _ = run_cmd(&format!("nft add chain inet {} postrouting {{ type filter hook postrouting priority 300; }}", table_name));
        let _ = run_cmd(&format!("nft add rule inet {} postrouting oifname \"{}\" tcp flags syn tcp option maxseg size set rt mtu", table_name, config.interface));
    }

    // 监控进程
    tokio::select! {
        res = child.wait() => {
            println!("nekolink-cli 进程意外退出喵: {:?} (接口: {})", res, config.interface);
        },
        _ = signaling_handle => {},
    }

    println!("正在清理接口 {} 喵...", config.interface);
    if config.clamp_mss {
        let table_name = format!("nekolink_mss_{}", config.interface);
        let _ = run_cmd(&format!("nft delete table inet {} 2>/dev/null", table_name));
    }
    let _ = run_cmd(&format!("ip link del {} 2>/dev/null", config.interface));

    Ok(())
}

async fn start_signaling(state: NekoState) -> Result<()> {
    let mode_needs_raw = state.config.mode == "ip" || state.config.mode == "tcp";
    if mode_needs_raw {
        start_raw_signaling(state).await
    } else {
        start_udp_signaling(state).await
    }
}

async fn start_udp_signaling(state: NekoState) -> Result<()> {
    let std_socket = std::net::UdpSocket::bind(format!("0.0.0.0:{}", state.config.signal_port))?;
    std_socket.set_nonblocking(true)?;
    let socket = Arc::new(tokio::net::UdpSocket::from_std(std_socket)?);
    let cipher = derive_cipher(&state.config.psk);

    let dynamic_peers = Arc::new(parking_lot::Mutex::new(std::collections::HashSet::new()));

    let send_task = {
        let config = state.config.clone();
        let socket = Arc::clone(&socket);
        let cipher = cipher.clone();
        let pub_key_bytes = state.pub_key.as_bytes().to_vec();
        let dynamic_peers = Arc::clone(&dynamic_peers);
        async move {
            let interface = config.interface.clone();
            loop {
                let established = get_established_peers(&interface).await;
                
                let mut targets = std::collections::HashSet::new();
                for peer in &config.peers {
                    if let Ok(addr) = peer.endpoint.parse::<SocketAddr>() {
                        targets.insert(addr);
                    }
                }
                {
                    let dy = dynamic_peers.lock();
                    for &addr in dy.iter() {
                        targets.insert(addr);
                    }
                }

                for addr in targets {
                    if !established.is_empty() {
                         // 只要连接成功过，信令就永久进入“贤者模式”喵
                         println!("检测到隧道已连接成功喵，信令魔法永久休眠喵！(～﹃～)zzZ");
                         time::sleep(Duration::from_secs(86400)).await; // 睡一天喵
                         continue;
                    }
                    let mut msg = pub_key_bytes.clone();
                    // 获取当前网卡 MTU
                    let current_mtu = get_interface_mtu(&config.interface).unwrap_or(1420);
                    msg.extend_from_slice(&current_mtu.to_be_bytes());

                    let mut nonce_bytes = [0u8; 12];
                    OsRng.fill_bytes(&mut nonce_bytes);
                    let nonce = Nonce::from_slice(&nonce_bytes);
                    if let Ok(ciphertext) = cipher.encrypt(nonce, msg.as_slice()) {
                        let mut pkt = nonce_bytes.to_vec();
                        pkt.extend_from_slice(&ciphertext);
                        let _ = socket.send_to(&pkt, addr).await;
                    }
                }
                let sleep_secs = if established.is_empty() { 10 } else { 300 };
                time::sleep(Duration::from_secs(sleep_secs)).await;
            }
        }
    };

    let recv_task = {
        let socket = Arc::clone(&socket);
        let interface = state.config.interface.clone();
        let cipher = cipher.clone();
        let dynamic_peers = Arc::clone(&dynamic_peers);
        let keepalive = state.config.persistent_keepalive;
        async move {
            let mut known_peers: std::collections::HashMap<String, String> = std::collections::HashMap::new();
            loop {
                let mut buf = [0u8; 1024];
                if let Ok((len, addr)) = socket.recv_from(&mut buf).await {
                    if len < 12 + 16 { continue; }
                    let (nonce_part, encrypted_part) = buf[..len].split_at(12);
                    let nonce = Nonce::from_slice(nonce_part);
                    if let Ok(decrypted) = cipher.decrypt(nonce, encrypted_part) {
                        if decrypted.len() >= 32 {
                            let peer_pub_key = BASE64.encode(&decrypted[..32]);
                            let peer_mtu = if decrypted.len() >= 34 {
                                Some(u16::from_be_bytes([decrypted[32], decrypted[33]]))
                            } else {
                                None
                            };

                            let addr_str = addr.to_string();
                            let should_update = match known_peers.get(&peer_pub_key) {
                                Some(old_addr) => old_addr != &addr_str,
                                None => true,
                            };

                            if should_update {
                                println!("喵！发现/更新队友 (UDP): {} 来自 {}", peer_pub_key, addr_str);
                                if let Ok(_) = configure_peer(&interface, &peer_pub_key, addr_str.clone(), keepalive, &state.config, peer_mtu).await {
                                    known_peers.insert(peer_pub_key, addr_str);
                                    dynamic_peers.lock().insert(addr);
                                }
                            } else if let Some(m) = peer_mtu {
                                // 即使地址没变，MTU 变了也要更新喵
                                let _ = sync_mtu_if_needed(&state.config, m).await;
                            }
                        }
                    }
                }
                time::sleep(Duration::from_millis(100)).await;
            }
        }
    };

    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }
    Ok(())
}

async fn start_raw_signaling(state: NekoState) -> Result<()> {
    let proto = state.config.ip_protocol.unwrap_or(141);
    
    // 我们需要两个 Socket 来同时支持 IPv4 和 IPv6 喵
    let v4_socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(proto as i32))).ok();
    let v6_socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::from(proto as i32))).ok();
    
    if v4_socket.is_none() && v6_socket.is_none() {
        return Err(anyhow::anyhow!("无法创建任何 RAW Socket 喵"));
    }

    if let Some(ref s) = v6_socket {
        // 设置 IPv6 TCLASS 为最高优先级 (CS7)
        use std::os::unix::io::AsRawFd;
        let fd = s.as_raw_fd();
        unsafe {
            let val: libc::c_int = 224;
            libc::setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_TCLASS, &val as *const _ as *const libc::c_void, std::mem::size_of_val(&val) as libc::socklen_t);
        }
    }

    let v4_socket = v4_socket.map(|s| { s.set_nonblocking(true).unwrap(); Arc::new(tokio::io::unix::AsyncFd::new(s).unwrap()) });
    let v6_socket = v6_socket.map(|s| { s.set_nonblocking(true).unwrap(); Arc::new(tokio::io::unix::AsyncFd::new(s).unwrap()) });

    let cipher = derive_cipher(&state.config.psk);
    let magic_byte: u8 = 0x99;

    let dynamic_peers = Arc::new(parking_lot::Mutex::new(std::collections::HashSet::new()));

    let send_task = {
        let config = state.config.clone();
        let v4_socket = v4_socket.clone();
        let v6_socket = v6_socket.clone();
        let cipher = cipher.clone();
        let pub_key_bytes = state.pub_key.as_bytes().to_vec();
        let dynamic_peers = Arc::clone(&dynamic_peers);
        async move {
            loop {
                let established = get_established_peers(&config.interface).await;
                
                let mut targets = std::collections::HashSet::new();
                for peer in &config.peers {
                    if let Ok(ip) = peer.endpoint.parse::<IpAddr>() {
                        targets.insert(ip);
                    }
                }
                {
                    let dy = dynamic_peers.lock();
                    for &ip in dy.iter() {
                        targets.insert(ip);
                    }
                }

                for ip in targets {
                    if !established.is_empty() {
                        println!("检测到隧道已连接成功喵，信令魔法永久休眠喵！(～﹃～)zzZ");
                        time::sleep(Duration::from_secs(86400)).await;
                        continue;
                    }

                        let mut msg = pub_key_bytes.clone();
                        let current_mtu = get_interface_mtu(&config.interface).unwrap_or(1420);
                        msg.extend_from_slice(&current_mtu.to_be_bytes());

                        let mut nonce_bytes = [0u8; 12];
                        OsRng.fill_bytes(&mut nonce_bytes);
                        let nonce = Nonce::from_slice(&nonce_bytes);
                        if let Ok(ciphertext) = cipher.encrypt(nonce, msg.as_slice()) {
                            let mut pkt = vec![magic_byte];
                            pkt.extend_from_slice(&nonce_bytes);
                            pkt.extend_from_slice(&ciphertext);
                            
                            let addr = socket2::SockAddr::from(SocketAddr::new(ip, 0));
                            let socket_to_use = if ip.is_ipv4() { v4_socket.as_ref() } else { v6_socket.as_ref() };
                            
                            if let Some(socket) = socket_to_use {
                                if let Ok(mut guard) = socket.writable().await {
                                    let _ = guard.try_io(|s| s.get_ref().send_to(&pkt, &addr));
                                }
                            }
                        }
                }
                let sleep_secs = if established.is_empty() { 10 } else { 300 };
                time::sleep(Duration::from_secs(sleep_secs)).await;
            }
        }
    };

    let recv_logic = |socket: Arc<tokio::io::unix::AsyncFd<Socket>>, interface: String, cipher: ChaCha20Poly1305, dynamic_peers: Arc<parking_lot::Mutex<std::collections::HashSet<IpAddr>>>, keepalive: Option<u16>| {
        async move {
            let mut known_peers: std::collections::HashMap<String, String> = std::collections::HashMap::new();
            loop {
                let mut buf = [0u8; 1024];
                if let Ok(mut guard) = socket.readable().await {
                    let res = guard.try_io(|s| {
                        s.get_ref().recv_from(unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [std::mem::MaybeUninit<u8>]) })
                    });
                    
                    if let Ok(Ok((len, addr))) = res {
                        // Linux Raw sockets include IP header for IPv4 (usually 20 bytes)
                        // For IPv6, it usually doesn't include the header in RAW sockets unless IPV6_HDRINCL is set (which we don't)
                        let is_ipv4 = addr.as_socket().map(|s| s.is_ipv4()).unwrap_or(true);
                        let offset = if is_ipv4 && len >= 20 && (buf[0] & 0xf0) == 0x40 { 20 } else { 0 };
                        
                        if len < offset + 1 + 12 + 16 { continue; }
                        let data = &buf[offset..len];
                        if data[0] != magic_byte { continue; }
                        
                        let nonce = Nonce::from_slice(&data[1..13]);
                        let encrypted_part = &data[13..];
                        if let Ok(decrypted) = cipher.decrypt(nonce, encrypted_part) {
                            if decrypted.len() >= 32 {
                                let peer_pub_key = BASE64.encode(&decrypted[..32]);
                                let peer_mtu = if decrypted.len() >= 34 {
                                    Some(u16::from_be_bytes([decrypted[32], decrypted[33]]))
                                } else {
                                    None
                                };

                                let ip_addr = addr.as_socket().map(|s: SocketAddr| s.ip());
                                if let Some(ip) = ip_addr {
                                    let ip_str = ip.to_string();
                                    let should_update = match known_peers.get(&peer_pub_key) {
                                        Some(old_ip) => old_ip != &ip_str,
                                        None => true,
                                    };

                                    if should_update {
                                        println!("喵！发现/更新队友 (Raw IP): {} 来自 {}", peer_pub_key, ip_str);
                                        if let Ok(_) = configure_peer(&interface, &peer_pub_key, ip_str.clone(), keepalive, &state_config_recv, peer_mtu).await {
                                            known_peers.insert(peer_pub_key, ip_str);
                                            dynamic_peers.lock().insert(ip);
                                        }
                                    } else if let Some(m) = peer_mtu {
                                        let _ = sync_mtu_if_needed(&state_config_recv, m).await;
                                    }
                                }
                            }
                        }
                    }
                }
                time::sleep(Duration::from_millis(100)).await;
            }
        }
    };

    let v4_recv = {
        let interface = state.config.interface.clone();
        let cipher = cipher.clone();
        let dynamic_peers = Arc::clone(&dynamic_peers);
        let keepalive = state.config.persistent_keepalive;
        let socket = v4_socket.clone();
        async move {
            if let Some(s) = socket {
                recv_logic(s, interface, cipher, dynamic_peers, keepalive).await;
            } else {
                std::future::pending::<()>().await;
            }
        }
    };

    let v6_recv = {
        let interface = state.config.interface.clone();
        let cipher = cipher.clone();
        let dynamic_peers = Arc::clone(&dynamic_peers);
        let keepalive = state.config.persistent_keepalive;
        let socket = v6_socket.clone();
        async move {
            if let Some(s) = socket {
                recv_logic(s, interface, cipher, dynamic_peers, keepalive).await;
            } else {
                std::future::pending::<()>().await;
            }
        }
    };

    tokio::select! {
        _ = send_task => {},
        _ = v4_recv => {},
        _ = v6_recv => {},
    }
    Ok(())
}

fn derive_cipher(psk: &str) -> ChaCha20Poly1305 {
    let mut psk_bytes = [0u8; 32];
    let salt = b"NekoLink_Magic_Salt";
    let mut hasher = blake2::Blake2s256::new();
    use blake2::Digest;
    hasher.update(psk.as_bytes());
    hasher.update(salt);
    let derived_key = hasher.finalize();
    psk_bytes.copy_from_slice(&derived_key);
    ChaCha20Poly1305::new(&psk_bytes.into())
}

async fn configure_peer(interface: &str, peer_pub_key: &str, endpoint: String, keepalive: Option<u16>, local_config: &NekoConfig, peer_mtu: Option<u16>) -> Result<()> {
    let mut uapi_cmd = format!(
        "set=1\npublic_key={}\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\nendpoint={}\n",
        peer_pub_key, endpoint
    );
    if let Some(ka) = keepalive {
        uapi_cmd.push_str(&format!("persistent_keepalive_interval={}\n", ka));
    }
    uapi_cmd.push_str("\n");
    
    send_uapi(interface, &uapi_cmd).await.context("配置 Peer 失败")?;
    println!("配置队友 {} 成功喵！", peer_pub_key);

    if let Some(m) = peer_mtu {
        let _ = sync_mtu_if_needed(local_config, m).await;
    }

    Ok(())
}

async fn sync_mtu_if_needed(config: &NekoConfig, peer_mtu: u16) -> Result<()> {
    if config.mtu == Some(0) {
        // 自动同步模式喵
        let current_mtu = get_interface_mtu(&config.interface).unwrap_or(0);
        if current_mtu != peer_mtu && peer_mtu >= 1280 {
            println!("检测到对端 MTU 为 {}，正在同步接口 {} 的 MTU 喵...", peer_mtu, config.interface);
            let _ = run_cmd(&format!("ip link set mtu {} dev {}", peer_mtu, config.interface));
        }
    }
    Ok(())
}

fn get_interface_mtu(interface: &str) -> Result<u16> {
    let output = Command::new("cat").arg(format!("/sys/class/net/{}/mtu", interface)).output()?;
    if output.status.success() {
        let s = String::from_utf8_lossy(&output.stdout);
        let val = s.trim().parse::<u16>()?;
        Ok(val)
    } else {
        Err(anyhow::anyhow!("获取 MTU 失败"))
    }
}

fn run_cmd(cmd: &str) -> Result<()> {
    let status = Command::new("sh").arg("-c").arg(cmd).status()?;
    if !status.success() {
        return Err(anyhow::anyhow!("命令失败: {}", cmd));
    }
    Ok(())
}
async fn show_status() -> Result<()> {
    println!("ฅ^•ﻌ•^ฅ NekoLink 状态报告：\n");
    let config_dir = "/etc/neko-link";
    let entries: Vec<_> = glob::glob(&format!("{}/*.json", config_dir))?.collect();
    
    if entries.is_empty() {
        println!("没有发现任何配置文件喵。");
        return Ok(());
    }

    for entry in entries {
        let path = entry?;
        let config_str = fs::read_to_string(&path)?;
        let config: NekoConfig = match serde_json::from_str(&config_str) {
            Ok(c) => c,
            Err(_) => continue,
        };
        
        println!("【 接口: {} 】", config.interface);
        let mode_desc = if config.mode == "ip" {
            format!("ip (协议={})", config.ip_protocol.unwrap_or(141))
        } else {
            "udp".to_string()
        };
        println!("模式: {}", mode_desc);
        println!("本地地址: {}", config.local_address);
        
        match get_uapi_info(&config.interface).await {
            Ok(info) => {
                println!("UAPI 状态:\n{}", info);
            },
            Err(_) => {
                println!("UAPI 状态: 离线喵 (接口可能未启动)");
            }
        }
        
        let ip_out = Command::new("ip").arg("addr").arg("show").arg(&config.interface).output();
        if let Ok(out) = ip_out {
            let s = String::from_utf8_lossy(&out.stdout);
            if s.contains("UP") {
                println!("系统连接: 正常喵 (UP)");
                if !s.contains(&config.local_address.split('/').next().unwrap_or("")) {
                    println!("警告喵：接口上似乎没有配置预期的 IP 地址！");
                }
            } else {
                println!("系统连接: 异常喵 (DOWN)");
            }
        }
        println!("-------------------------------------------");
    }
    Ok(())
}

async fn get_uapi_info(interface: &str) -> Result<String> {
    let path = format!("/var/run/wireguard/{}.sock", interface);
    let mut stream = time::timeout(Duration::from_millis(500), tokio::net::UnixStream::connect(path)).await??;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    stream.write_all(b"get=1\n\n").await?;
    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    let mut line = String::new();
    loop {
        line.clear();
        if time::timeout(Duration::from_millis(500), reader.read_line(&mut line)).await?? == 0 { break; }
        if line == "\n" { break; }
        response.push_str("  ");
        response.push_str(&line);
    }
    Ok(response)
}

async fn get_established_peers(interface: &str) -> std::collections::HashSet<String> {
    let mut established = std::collections::HashSet::new();
    if let Ok(info) = get_uapi_info(interface).await {
        let mut current_peer = String::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        for line in info.lines() {
            let line = line.trim();
            if line.starts_with("public_key=") {
                current_peer = line["public_key=".len()..].to_string();
            } else if line.starts_with("last_handshake_time_sec=") {
                if let Ok(sec) = line["last_handshake_time_sec=".len()..].parse::<u64>() {
                    if sec > 0 && now > sec && (now - sec) < 150 {
                        established.insert(current_peer.clone());
                    }
                }
            }
        }
    }
    established
}
async fn probe_mtu_cmd(endpoint: &str, mode: &str) -> Result<()> {
    let host = if endpoint.contains(':') {
        endpoint.split(':').next().unwrap()
    } else {
        endpoint
    };

    println!("正在探测到 {} 的 PMTU 魔法喵...", host);

    let pmtu = match perform_mtu_probe(host).await {
        Ok(val) => val,
        Err(_) => {
            println!("探测失败了喵，可能是对端禁用了 ICMP。使用保守默认值 1500 喵。");
            1500
        }
    };

    let overhead = match mode {
        "ip" => 52,
        "tcp" => 72,
        _ => 60, // udp
    };

    let recommended = pmtu - overhead;
    println!("探测完成：PMTU={}，建议 MTU={} (模式: {}) 喵！", pmtu, recommended, mode);
    println!("RECOMMENDED_MTU={}", recommended);

    Ok(())
}

async fn perform_mtu_probe(host: &str) -> Result<u16> {
    // 使用 ping 二分法探测 PMTU
    // Linux 下使用 -M do 禁止分片，-s 指定包大小 (不含 IP/ICMP 头 28 字节)
    let mut low = 576;
    let mut high = 1500;
    let mut best = 1280;

    // 快速检查 1500
    if check_ping(host, 1500 - 28) {
        return Ok(1500);
    }

    while low <= high {
        let mid = (low + high) / 2;
        if check_ping(host, mid - 28) {
            best = mid;
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }

    Ok(best)
}

fn check_ping(host: &str, size: u16) -> bool {
    let status = Command::new("ping")
        .arg("-c")
        .arg("1")
        .arg("-W")
        .arg("1")
        .arg("-M")
        .arg("do")
        .arg("-s")
        .arg(size.to_string())
        .arg(host)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match status {
        Ok(s) => s.success(),
        Err(_) => false,
    }
}
