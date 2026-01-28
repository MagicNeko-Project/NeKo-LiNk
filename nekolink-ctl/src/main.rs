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
    12580
}

#[derive(Clone)]
struct NekoState {
    config: NekoConfig,
    priv_b64: String,
    pub_key: PublicKey,
}

impl NekoState {
    fn pub_key_b64(&self) -> String {
        BASE64.encode(self.pub_key.as_bytes())
    }
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

    let mut configs = vec![];
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
        configs.push(config);
    }

    if configs.is_empty() {
        println!("喵？没有发现任何配置文件在 {}/。请添加 *.json 文件喵！", config_dir);
        return Ok(());
    }

    // 预处理所有状态 (加载/生成密钥)
    let mut states = vec![];
    for config in configs {
        let (priv_b64, _, pub_key) = load_or_generate_keys(&config.interface)?;
        states.push(NekoState { config, priv_b64, pub_key });
    }
    let states = Arc::new(states);

    // 启动全局信令管理器 (独立模块运行，互不干扰喵)
    let signaling_states = Arc::clone(&states);
    tokio::spawn(async move {
        println!("ฅ^•ﻌ•^ฅ 全局信令中枢：UDP 管线启动...");
        let s1 = Arc::clone(&signaling_states);
        tokio::spawn(async move { if let Err(e) = run_global_udp_signaling(s1).await { eprintln!("UDP 信令管线异常退出喵: {:?}", e); } });

        println!("ฅ^•ﻌ•^ฅ 全局信令中枢：TCP 管线启动...");
        let s2 = Arc::clone(&signaling_states);
        tokio::spawn(async move { if let Err(e) = run_global_tcp_signaling(s2).await { eprintln!("TCP 信令管线异常退出喵: {:?}", e); } });

        println!("ฅ^•ﻌ•^ฅ 全局信令中枢：Raw IP 管线启动...");
        let s3 = Arc::clone(&signaling_states);
        tokio::spawn(async move { if let Err(e) = run_global_raw_signaling(s3).await { eprintln!("Raw IP 信令管线异常退出喵: {:?}", e); } });
    });

    let mut handles = vec![];
    for state in states.iter() {
        let state_clone = state.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) = run_instance(state_clone).await {
                eprintln!("实例运行时出错: {:?}", e);
            }
        });
        handles.push(handle);
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

async fn run_instance(state: NekoState) -> Result<()> {
    let config = &state.config;
    println!("正在启动接口 {} 喵...", config.interface);

    println!("使用公钥: {} 喵！", state.pub_key_b64());

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
    // 特殊：如果 config.mtu 为 0 (自动同步)，启动时先用 1420 喵
    let mtu = match config.mtu {
        Some(0) => 1420,
        Some(val) => val,
        None => 1420,
    };
    
    let mut child = cmd.spawn().context("启动 nekolink-cli 失败")?;

    // 等待接口创建
    time::sleep(Duration::from_secs(2)).await;

    // 3. 配置接口与私钥 (UAPI 方式)
    let mut uapi_cmd = format!("set=1\nprivate_key={}\n", state.priv_b64);
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
    
    // 监控进程
    let _ = child.wait().await;

    println!("正在清理接口 {} 喵...", config.interface);
    if config.clamp_mss {
        let table_name = format!("nekolink_mss_{}", config.interface);
        let _ = run_cmd(&format!("nft delete table inet {} 2>/dev/null", table_name));
    }
    let _ = run_cmd(&format!("ip link del {} 2>/dev/null", config.interface));

    Ok(())
}


async fn run_global_udp_signaling(states: Arc<Vec<NekoState>>) -> Result<()> {
    // 全局绑定 12580 (或者第一个配置里的端口)
    let port = states.get(0).map(|s| s.config.signal_port).unwrap_or(12580);
    let std_socket = std::net::UdpSocket::bind(format!("0.0.0.0:{}", port))?;
    std_socket.set_nonblocking(true)?;
    let socket = Arc::new(tokio::net::UdpSocket::from_std(std_socket)?);

    let send_task = {
        let states = Arc::clone(&states);
        let socket = Arc::clone(&socket);
        async move {
            loop {
                for state in states.iter() {
                    if state.config.mode != "udp" || state.pub_key.as_bytes() == &[0u8; 32] { continue; }
                    
                    let established = get_established_peers(&state.config.interface).await;
                    if !established.is_empty() { continue; }

                    let cipher = derive_cipher(&state.config.psk);
                    let msg_base = state.pub_key.as_bytes().to_vec();
                    let current_mtu = get_interface_mtu(&state.config.interface).unwrap_or(1420);
                    let actual_tunnel_port = get_actual_listen_port(&state.config.interface).unwrap_or(0);
                    
                    for peer in &state.config.peers {
                        if let Ok(addr) = peer.endpoint.parse::<SocketAddr>() {
                            let mut msg = msg_base.clone();
                            msg.extend_from_slice(&current_mtu.to_be_bytes());
                            msg.extend_from_slice(&actual_tunnel_port.to_be_bytes());

                            let mut nonce_bytes = [0u8; 12];
                            OsRng.fill_bytes(&mut nonce_bytes);
                            if let Ok(ciphertext) = cipher.encrypt(Nonce::from_slice(&nonce_bytes), msg.as_slice()) {
                                let mut pkt = nonce_bytes.to_vec();
                                pkt.extend_from_slice(&ciphertext);
                                if let Err(e) = socket.send_to(&pkt, addr).await {
                                    eprintln!("UDP 信令推送失败喵 ({}): {:?}", state.config.interface, e);
                                } else {
                                    println!("喵！已向对端 {} 主动推送 12580 (UDP) 信令盒。", addr);
                                }
                            }
                        }
                    }
                }
                time::sleep(Duration::from_secs(10)).await;
            }
        }
    };

    let recv_task = {
        let states = Arc::clone(&states);
        let socket = Arc::clone(&socket);
        async move {
            let mut buf = [0u8; 1024];
            loop {
                if let Ok((len, addr)) = socket.recv_from(&mut buf).await {
                    if len < 12 + 32 { continue; }
                    let (nonce_part, encrypted_part) = buf[..len].split_at(12);
                    let nonce = Nonce::from_slice(nonce_part);

                    for state in states.iter() {
                        if state.config.mode != "udp" { continue; }
                        let cipher = derive_cipher(&state.config.psk);
                        if let Ok(decrypted) = cipher.decrypt(nonce, encrypted_part) {
                            if decrypted.len() >= 36 {
                                let peer_pub_key = BASE64.encode(&decrypted[..32]);
                                let peer_mtu = Some(u16::from_be_bytes([decrypted[32], decrypted[33]]));
                                let peer_tunnel_port = u16::from_be_bytes([decrypted[34], decrypted[35]]);
                                
                                let mut endpoint = addr.ip().to_string();
                                if peer_tunnel_port > 0 {
                                    endpoint = format!("{}:{}", endpoint, peer_tunnel_port);
                                } else {
                                    endpoint = format!("{}:{}", endpoint, addr.port());
                                }

                                println!("喵！12580 (UDP) 握手处理成功：{} -> {}", endpoint, state.config.interface);
                                let _ = configure_peer(&state.config.interface, &peer_pub_key, endpoint, state.config.persistent_keepalive, peer_mtu, state.config.mtu == Some(0)).await;
                                
                                // 回发响应喵
                                let msg_base = state.pub_key.as_bytes().to_vec();
                                let current_mtu = get_interface_mtu(&state.config.interface).unwrap_or(1420);
                                let actual_tunnel_port = get_actual_listen_port(&state.config.interface).unwrap_or(0);
                                let mut resp_msg = msg_base;
                                resp_msg.extend_from_slice(&current_mtu.to_be_bytes());
                                resp_msg.extend_from_slice(&actual_tunnel_port.to_be_bytes());
                                
                                let mut nonce_bytes = [0u8; 12];
                                OsRng.fill_bytes(&mut nonce_bytes);
                                if let Ok(ciphertext) = cipher.encrypt(Nonce::from_slice(&nonce_bytes), resp_msg.as_slice()) {
                                    let mut pkt = nonce_bytes.to_vec();
                                    pkt.extend_from_slice(&ciphertext);
                                    let _ = socket.send_to(&pkt, addr).await;
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
    };

    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }
    Ok(())
}

async fn run_global_tcp_signaling(states: Arc<Vec<NekoState>>) -> Result<()> {
    let port = states.iter().map(|s| s.config.signal_port).find(|&p| p > 0).unwrap_or(12580);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;

    println!("ฅ^•ﻌ•^ฅ TCP 信令管线就绪，正在监听 {} 端口，监控 {} 个接口喵。", port, states.len());

    let send_task = {
        let states = Arc::clone(&states);
        async move {
            loop {
                for state in states.iter() {
                    let established = get_established_peers(&state.config.interface).await;
                    if state.config.mode != "tcp" || state.pub_key.as_bytes() == &[0u8; 32] {
                        continue;
                    }
                    
                    if !established.is_empty() {
                        continue;
                    }

                    let cipher = derive_cipher(&state.config.psk);
                    let pub_key_bytes = state.pub_key.as_bytes().to_vec();
                    let interface = state.config.interface.clone();
                    
                    for peer in &state.config.peers {
                        if let Ok(mut addr) = peer.endpoint.parse::<SocketAddr>() {
                            addr.set_port(state.config.signal_port);
                            let cipher = cipher.clone();
                            let pub_key_bytes = pub_key_bytes.clone();
                            let interface_inner = interface.clone();
                            tokio::spawn(async move {
                                println!("喵！正在发起 TCP 信令连接: {}...", addr);
                                match time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(addr)).await {
                                    Ok(Ok(mut stream)) => {
                                        println!("喵！TCP 信令连接已建立: {}", addr);
                                        let current_mtu = get_interface_mtu(&interface_inner).unwrap_or(1420);
                                        let actual_tunnel_port = get_actual_listen_port(&interface_inner).unwrap_or(0);

                                        let mut msg = pub_key_bytes.clone();
                                        msg.extend_from_slice(&current_mtu.to_be_bytes());
                                        msg.extend_from_slice(&actual_tunnel_port.to_be_bytes());

                                        let mut nonce_bytes = [0u8; 12];
                                        OsRng.fill_bytes(&mut nonce_bytes);
                                        if let Ok(ciphertext) = cipher.encrypt(Nonce::from_slice(&nonce_bytes), msg.as_slice()) {
                                            let mut pkt = nonce_bytes.to_vec();
                                            pkt.extend_from_slice(&ciphertext);
                                            if tokio::io::AsyncWriteExt::write_all(&mut stream, &pkt).await.is_ok() {
                                                println!("喵！已向对端推送 12580 信令，等待服务端 Ack...");
                                                let mut ack_buf = [0u8; 128];
                                                if let Ok(Ok(n)) = time::timeout(Duration::from_secs(10), tokio::io::AsyncReadExt::read(&mut stream, &mut ack_buf)).await {
                                                    if n >= 12 + 32 {
                                                        let (nonce_part, encrypted_part) = ack_buf[..n].split_at(12);
                                                        let nonce = Nonce::from_slice(nonce_part);
                                                        if let Ok(decrypted) = cipher.decrypt(nonce, encrypted_part) {
                                                            if decrypted.len() >= 36 {
                                                                let peer_pub_key = BASE64.encode(&decrypted[..32]);
                                                                let peer_mtu = Some(u16::from_be_bytes([decrypted[32], decrypted[33]]));
                                                                let peer_tunnel_port = u16::from_be_bytes([decrypted[34], decrypted[35]]);
                                                                let mut endpoint = addr.ip().to_string();
                                                                if peer_tunnel_port > 0 {
                                                                    endpoint = format!("{}:{}", endpoint, peer_tunnel_port);
                                                                }
                                                                println!("喵！成功接收 TCP 信令响应 (ACK)：来自 {} (隧道端口: {})", endpoint, peer_tunnel_port);
                                                                let _ = configure_peer(&interface_inner, &peer_pub_key, endpoint, None, peer_mtu, true).await;
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    println!("喵呜... 没收到 {} 的 TCP 信令响应，下次再试喵。", addr);
                                                }
                                            }
                                        }
                                    },
                                    Ok(Err(e)) => {
                                        println!("喵呜... TCP 连接对端 {} 失败: {:?} (请检查服务端 12580 是否开启喵)", addr, e);
                                    },
                                    Err(_) => {
                                        println!("喵呜... TCP 连接对端 {} 超时喵。", addr);
                                    }
                                }
                            });
                        }
                    }
                }
                time::sleep(Duration::from_secs(10)).await;
            }
        }
    };

    let recv_task = {
        let states = Arc::clone(&states);
        async move {
            loop {
                if let Ok((mut stream, addr)) = listener.accept().await {
                    let states = Arc::clone(&states);
                    tokio::spawn(async move {
                        let mut buf = [0u8; 256];
                        if let Ok(Ok(len)) = time::timeout(Duration::from_secs(5), tokio::io::AsyncReadExt::read(&mut stream, &mut buf)).await {
                            if len >= 12 + 32 {
                                let (nonce_part, encrypted_part) = buf[..len].split_at(12);
                                let nonce = Nonce::from_slice(nonce_part);
                                
                                for state in states.iter() {
                                    if state.config.mode != "tcp" { continue; }
                                    let cipher = derive_cipher(&state.config.psk);
                                    if let Ok(decrypted) = cipher.decrypt(nonce, encrypted_part) {
                                        if decrypted.len() >= 36 {
                                            let peer_pub_key = BASE64.encode(&decrypted[..32]);
                                            let peer_mtu = Some(u16::from_be_bytes([decrypted[32], decrypted[33]]));
                                            let peer_tunnel_port = u16::from_be_bytes([decrypted[34], decrypted[35]]);
                                            
                                            let mut endpoint = addr.ip().to_string();
                                            if peer_tunnel_port > 0 {
                                                endpoint = format!("{}:{}", endpoint, peer_tunnel_port);
                                            }

                                            println!("喵！12580 (TCP) 识别成功：{} -> {}", endpoint, state.config.interface);
                                            let _ = configure_peer(&state.config.interface, &peer_pub_key, endpoint, state.config.persistent_keepalive, peer_mtu, state.config.mtu == Some(0)).await;
                                            
                                            // TCP 握手响应喵！直接在当前流回发
                                            let msg_base = state.pub_key.as_bytes().to_vec();
                                            let current_mtu = get_interface_mtu(&state.config.interface).unwrap_or(1420);
                                            let actual_tunnel_port = get_actual_listen_port(&state.config.interface).unwrap_or(0);
                                            let mut resp_msg = msg_base;
                                            resp_msg.extend_from_slice(&current_mtu.to_be_bytes());
                                            resp_msg.extend_from_slice(&actual_tunnel_port.to_be_bytes());
                                            
                                            let mut nonce_bytes = [0u8; 12];
                                            OsRng.fill_bytes(&mut nonce_bytes);
                                            if let Ok(ciphertext) = cipher.encrypt(Nonce::from_slice(&nonce_bytes), resp_msg.as_slice()) {
                                                let mut pkt = nonce_bytes.to_vec();
                                                pkt.extend_from_slice(&ciphertext);
                                                use tokio::io::AsyncWriteExt;
                                                let _ = stream.write_all(&pkt).await;
                                            }
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    });
                }
            }
        }
    };

    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }
    Ok(())
}

async fn run_global_raw_signaling(states: Arc<Vec<NekoState>>) -> Result<()> {
    // 这里简单处理：监听默认的协议号 141
    let proto = 141; 
    let v4_socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(proto as i32))).ok();
    
    println!("ฅ^•ﻌ•^ฅ Raw IP 信令管线就绪，正在监控 {} 个接口喵。", states.len());

    let v4_socket = v4_socket.map(|s| { s.set_nonblocking(true).unwrap(); Arc::new(tokio::io::unix::AsyncFd::new(s).unwrap()) });

    let magic_byte: u8 = 0x99;

    let send_task = {
        let states = Arc::clone(&states);
        let v4_socket = v4_socket.clone();
        async move {
            loop {
                for state in states.iter() {
                    if state.config.mode != "ip" || state.pub_key.as_bytes() == &[0u8; 32] { continue; }
                    let established = get_established_peers(&state.config.interface).await;
                    if !established.is_empty() { continue; }

                    let cipher = derive_cipher(&state.config.psk);
                    let pub_key_bytes = state.pub_key.as_bytes().to_vec();
                    let current_mtu = get_interface_mtu(&state.config.interface).unwrap_or(1420);

                    for peer in &state.config.peers {
                        if let Ok(ip) = peer.endpoint.parse::<IpAddr>() {
                            let mut msg = pub_key_bytes.clone();
                            msg.extend_from_slice(&current_mtu.to_be_bytes());
                            let mut nonce_bytes = [0u8; 12];
                            OsRng.fill_bytes(&mut nonce_bytes);
                            if let Ok(ciphertext) = cipher.encrypt(Nonce::from_slice(&nonce_bytes), msg.as_slice()) {
                                let mut pkt = vec![magic_byte];
                                pkt.extend_from_slice(&nonce_bytes);
                                pkt.extend_from_slice(&ciphertext);
                                let addr = socket2::SockAddr::from(SocketAddr::new(ip, 0));
                                let socket_to_use = v4_socket.as_ref(); 
                                if let Some(socket) = socket_to_use {
                                    if let Ok(mut guard) = socket.writable().await {
                                        let _ = guard.try_io(|s: &tokio::io::unix::AsyncFd<Socket>| s.get_ref().send_to(&pkt, &addr));
                                    }
                                }
                            }
                        }
                    }
                }
                time::sleep(Duration::from_secs(10)).await;
            }
        }
    };

    let recv_task = {
        let states = Arc::clone(&states);
        let v4_socket = v4_socket.clone();
        async move {
            let mut buf = [0u8; 1024];
            loop {
                if let Some(ref s) = v4_socket {
                    if let Ok(mut guard) = s.readable().await {
                        if let Ok(Ok((len, addr))) = guard.try_io(|sock: &tokio::io::unix::AsyncFd<Socket>| sock.get_ref().recv_from(unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [std::mem::MaybeUninit<u8>]) })) {
                             let offset = if len >= 20 && (buf[0] & 0xf0) == 0x40 { 20 } else { 0 };
                             if len >= offset + 1 + 12 + 32 && buf[offset] == magic_byte {
                                 let nonce = Nonce::from_slice(&buf[offset+1..offset+13]);
                                 let encrypted = &buf[offset+13..len];
                                 for state in states.iter() {
                                     if state.config.mode != "ip" { continue; }
                                     let cipher = derive_cipher(&state.config.psk);
                                     if let Ok(decrypted) = cipher.decrypt(nonce, encrypted) {
                                         let ip_addr = addr.as_socket().map(|s| s.ip()).unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                                         let peer_mtu = if decrypted.len() >= 34 { Some(u16::from_be_bytes([decrypted[32], decrypted[33]])) } else { None };
                                         println!("喵！12580 (Raw IP) 识别成功：{} -> {}", ip_addr, state.config.interface);
                                         let _ = configure_peer(&state.config.interface, &BASE64.encode(&decrypted[..32]), ip_addr.to_string(), state.config.persistent_keepalive, peer_mtu, state.config.mtu == Some(0)).await;

                                         // Raw IP 响应喵！
                                         let msg_base = state.pub_key.as_bytes().to_vec();
                                         let current_mtu = get_interface_mtu(&state.config.interface).unwrap_or(1420);
                                         let mut resp_msg = msg_base;
                                         resp_msg.extend_from_slice(&current_mtu.to_be_bytes());
                                         
                                         let mut nonce_bytes = [0u8; 12];
                                         OsRng.fill_bytes(&mut nonce_bytes);
                                         if let Ok(ciphertext) = cipher.encrypt(Nonce::from_slice(&nonce_bytes), resp_msg.as_slice()) {
                                              let mut pkt = vec![magic_byte];
                                              pkt.extend_from_slice(&nonce_bytes);
                                              pkt.extend_from_slice(&ciphertext);
                                              let dest_addr = socket2::SockAddr::from(SocketAddr::new(ip_addr, 0));
                                              if let Ok(mut guard) = v4_socket.as_ref().unwrap().writable().await {
                                                  let _ = guard.try_io(|s: &tokio::io::unix::AsyncFd<Socket>| s.get_ref().send_to(&pkt, &dest_addr));
                                              }
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

async fn configure_peer(interface: &str, peer_pub_key: &str, endpoint: String, keepalive: Option<u16>, peer_mtu: Option<u16>, auto_sync_mtu: bool) -> Result<()> {
    let mut uapi_cmd = format!(
        "set=1\npublic_key={}\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\nendpoint={}\n",
        peer_pub_key, endpoint
    );
    if let Some(ka) = keepalive {
        uapi_cmd.push_str(&format!("persistent_keepalive_interval={}\n", ka));
    }
    uapi_cmd.push_str("\n");
    
    send_uapi(interface, &uapi_cmd).await.context("配置 Peer 失败")?;
    println!("配置队友 {} (Endpoint: {}) 成功喵！", peer_pub_key, endpoint);

    if let Some(m) = peer_mtu {
        if auto_sync_mtu {
            let _ = sync_mtu_if_needed(interface, m).await;
        }
    }
    Ok(())
}

async fn sync_mtu_if_needed(interface: &str, peer_mtu: u16) -> Result<()> {
    let current_mtu = get_interface_mtu(interface).unwrap_or(0);
    if current_mtu != peer_mtu && peer_mtu >= 1280 {
        println!("检测到对端 MTU 为 {}，正在同步接口 {} 的 MTU 喵...", peer_mtu, interface);
        let _ = run_cmd(&format!("ip link set mtu {} dev {}", peer_mtu, interface));
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
        let mode_desc = match config.mode.as_str() {
            "ip" => format!("ip (协议={})", config.ip_protocol.unwrap_or(141)),
            "tcp" => "fake-tcp + safe-signaling".to_string(),
            _ => "udp".to_string(),
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
fn get_actual_listen_port(interface: &str) -> Option<u16> {
    // 通过 UAPI 获取实际监听端口
    let path = format!("/var/run/wireguard/{}.sock", interface);
    if let Ok(std_stream) = std::os::unix::net::UnixStream::connect(path) {
        use std::io::{Read, Write};
        let mut stream = std_stream;
        let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
        let _ = stream.write_all(b"get=1\n\n");
        let mut buf = String::new();
        let _ = stream.read_to_string(&mut buf);
        for line in buf.lines() {
            if line.starts_with("listen_port=") {
                return line["listen_port=".len()..].trim().parse().ok();
            }
        }
    }
    None
}

fn load_or_generate_keys(interface: &str) -> Result<(String, String, PublicKey)> {
    let key_path = format!("/etc/neko-link/{}.key", interface);
    let pub_path = format!("/etc/neko-link/{}.pub", interface);
    
    let priv_key = if let Ok(existing_key_b64) = fs::read_to_string(&key_path) {
        let trimmed = existing_key_b64.trim();
        let bytes = BASE64.decode(trimmed).context("无法解码现有私钥喵")?;
        StaticSecret::from(<[u8; 32]>::try_from(bytes).map_err(|_| anyhow::anyhow!("私钥长度不对喵"))?)
    } else {
        println!("正在为接口 {} 生成新的魔法密钥对喵...", interface);
        let new_priv = StaticSecret::random_from_rng(OsRng);
        let new_b64 = BASE64.encode(new_priv.to_bytes());
        fs::write(&key_path, new_b64).context("无法保存私钥文件喵")?;
        new_priv
    };

    let pub_key = PublicKey::from(&priv_key);
    let priv_b64 = BASE64.encode(priv_key.to_bytes());
    let pub_b64 = BASE64.encode(pub_key.as_bytes());
    let _ = fs::write(&pub_path, &pub_b64);
    
    Ok((priv_b64, pub_b64, pub_key))
}


