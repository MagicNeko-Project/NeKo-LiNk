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

    // 1. 生成密钥对
    let priv_key = StaticSecret::random_from_rng(OsRng);
    let pub_key = PublicKey::from(&priv_key);
    let priv_b64 = BASE64.encode(priv_key.to_bytes());
    let pub_b64 = BASE64.encode(pub_key.as_bytes());

    println!("生成的公钥: {} 喵！", pub_b64);

    // 2. 启动 nekolink-cli
    let mut cmd = Command::new("nekolink-cli");
    cmd.arg("-f").arg(&config.interface);
    if config.mode == "ip" {
        if let Some(proto) = config.ip_protocol {
            cmd.arg("--ip-protocol").arg(proto.to_string());
        }
    }
    
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

    run_cmd(&format!("ip addr add {} dev {}", config.local_address, config.interface))?;
    run_cmd(&format!("ip link set up dev {}", config.interface))?;

    // 如果开启了 auto_route，则添加默认路由（实验性，谨慎使用喵）
    if config.auto_route {
        println!("警告喵：正在尝试配置系统路由表...");
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

    // 监控进程
    tokio::select! {
        _ = signaling_handle => {},
        status = tokio::task::spawn_blocking(move || child.wait()) => {
            println!("nekolink-cli 退出: {:?}", status);
        }
    }

    Ok(())
}

async fn start_signaling(state: NekoState) -> Result<()> {
    let mode_is_ip = state.config.mode == "ip";
    if mode_is_ip {
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
            loop {
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
                    let mut nonce_bytes = [0u8; 12];
                    OsRng.fill_bytes(&mut nonce_bytes);
                    let nonce = Nonce::from_slice(&nonce_bytes);
                    if let Ok(ciphertext) = cipher.encrypt(nonce, pub_key_bytes.as_slice()) {
                        let mut pkt = nonce_bytes.to_vec();
                        pkt.extend_from_slice(&ciphertext);
                        let _ = socket.send_to(&pkt, addr).await;
                    }
                }
                time::sleep(Duration::from_secs(10)).await;
            }
        }
    };

    let recv_task = {
        let socket = Arc::clone(&socket);
        let interface = state.config.interface.clone();
        let cipher = cipher.clone();
        let dynamic_peers = Arc::clone(&dynamic_peers);
        async move {
            let mut known_peers = std::collections::HashSet::new();
            loop {
                let mut buf = [0u8; 1024];
                if let Ok((len, addr)) = socket.recv_from(&mut buf).await {
                    if len < 12 + 16 { continue; }
                    let (nonce_part, encrypted_part) = buf[..len].split_at(12);
                    let nonce = Nonce::from_slice(nonce_part);
                    if let Ok(decrypted) = cipher.decrypt(nonce, encrypted_part) {
                        if decrypted.len() == 32 {
                            let peer_pub_key = BASE64.encode(&decrypted);
                            if !known_peers.contains(&peer_pub_key) {
                                println!("喵！发现新队友 (UDP): {} 来自 {}", peer_pub_key, addr);
                                if let Ok(_) = configure_peer(&interface, &peer_pub_key, addr.to_string()).await {
                                    known_peers.insert(peer_pub_key);
                                    dynamic_peers.lock().insert(addr);
                                }
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
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(proto as i32)))?;
    socket.set_nonblocking(true)?;
    let socket = Arc::new(tokio::io::unix::AsyncFd::new(socket)?);
    let cipher = derive_cipher(&state.config.psk);
    let magic_byte: u8 = 0x99;

    let dynamic_peers = Arc::new(parking_lot::Mutex::new(std::collections::HashSet::new()));

    let send_task = {
        let config = state.config.clone();
        let socket = Arc::clone(&socket);
        let cipher = cipher.clone();
        let pub_key_bytes = state.pub_key.as_bytes().to_vec();
        let dynamic_peers = Arc::clone(&dynamic_peers);
        async move {
            loop {
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
                    let mut nonce_bytes = [0u8; 12];
                    OsRng.fill_bytes(&mut nonce_bytes);
                    let nonce = Nonce::from_slice(&nonce_bytes);
                    if let Ok(ciphertext) = cipher.encrypt(nonce, pub_key_bytes.as_slice()) {
                        let mut pkt = vec![magic_byte];
                        pkt.extend_from_slice(&nonce_bytes);
                        pkt.extend_from_slice(&ciphertext);
                        
                        let addr = socket2::SockAddr::from(SocketAddr::new(ip, 0));
                        if let Ok(mut guard) = socket.writable().await {
                            let _ = guard.try_io(|s| s.get_ref().send_to(&pkt, &addr));
                        }
                    }
                }
                time::sleep(Duration::from_secs(10)).await;
            }
        }
    };

    let recv_task = {
        let socket = Arc::clone(&socket);
        let interface = state.config.interface.clone();
        let cipher = cipher.clone();
        let dynamic_peers = Arc::clone(&dynamic_peers);
        async move {
            let mut known_peers = std::collections::HashSet::new();
            loop {
                let mut buf = [0u8; 1024];
                if let Ok(mut guard) = socket.readable().await {
                    let res = guard.try_io(|s| {
                        s.get_ref().recv_from(unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [std::mem::MaybeUninit<u8>]) })
                    });
                    
                    if let Ok(Ok((len, addr))) = res {
                        // Linux Raw sockets include IP header (usually 20 bytes)
                        let offset = if len >= 20 && (buf[0] & 0xf0) == 0x40 { 20 } else { 0 };
                        if len < offset + 1 + 12 + 16 { continue; }
                        let data = &buf[offset..len];
                        if data[0] != magic_byte { continue; }
                        
                        let nonce = Nonce::from_slice(&data[1..13]);
                        let encrypted_part = &data[13..];
                        if let Ok(decrypted) = cipher.decrypt(nonce, encrypted_part) {
                            if decrypted.len() == 32 {
                                let peer_pub_key = BASE64.encode(&decrypted);
                                if !known_peers.contains(&peer_pub_key) {
                                    let ip_addr = addr.as_socket().map(|s: SocketAddr| s.ip());
                                    if let Some(ip) = ip_addr {
                                        let ip_str = ip.to_string();
                                        println!("喵！发现新队友 (Raw IP): {} 来自 {}", peer_pub_key, ip_str);
                                        if let Ok(_) = configure_peer(&interface, &peer_pub_key, ip_str).await {
                                            known_peers.insert(peer_pub_key);
                                            dynamic_peers.lock().insert(ip);
                                        }
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

    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
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

async fn configure_peer(interface: &str, peer_pub_key: &str, endpoint: String) -> Result<()> {
    let uapi_cmd = format!(
        "set=1\npublic_key={}\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\nendpoint={}\n\n",
        peer_pub_key, endpoint
    );
    send_uapi(interface, &uapi_cmd).await.context("配置 Peer 失败")?;
    println!("配置队友 {} 成功喵！", peer_pub_key);
    Ok(())
}

fn run_cmd(cmd: &str) -> Result<()> {
    let status = Command::new("sh").arg("-c").arg(cmd).status()?;
    if !status.success() {
        return Err(anyhow::anyhow!("命令失败: {}", cmd));
    }
    Ok(())
}
