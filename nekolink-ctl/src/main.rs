use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::net::{IpAddr, SocketAddr};
use std::fs;
use std::process::Command;
use std::time::Duration;
use tokio::time;
use anyhow::{Context, Result};
use rand_core::{OsRng, RngCore};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use socket2::{Domain, Protocol, Socket, Type};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PeerConfig {
    endpoint: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct GlobalConfig {
    #[serde(default = "default_signal_port")]
    pub signal_port: u16,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self { signal_port: 12580 }
    }
}

static PEER_CACHE: OnceLock<Mutex<HashMap<(String, String), String>>> = OnceLock::new();
static CONFIG_MUTEX: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
static SIDE_CARS: OnceLock<tokio::sync::Mutex<HashMap<(String, String), tokio::process::Child>>> = OnceLock::new();
static PROBED_MTU_CACHE: OnceLock<tokio::sync::Mutex<HashMap<String, (u16, std::time::Instant)>>> = OnceLock::new();

async fn get_auto_mtu(endpoint: &str, mode: &str) -> u16 {
    let mut cache = PROBED_MTU_CACHE.get_or_init(|| tokio::sync::Mutex::new(HashMap::new())).lock().await;

    if let Some((mtu, timestamp)) = cache.get(endpoint) {
        if timestamp.elapsed() < Duration::from_secs(3600) {
            return *mtu;
        }
    }

    // 执行探测喵
    let host = if endpoint.contains(':') {
        endpoint.split(':').next().unwrap()
    } else {
        endpoint
    };

    let pmtu = if mode == "tcp" {
        match perform_tcp_mtu_probe(host).await {
            Ok(val) => val,
            Err(_) => perform_mtu_probe(host).await.unwrap_or(1500)
        }
    } else {
        perform_mtu_probe(host).await.unwrap_or(1500)
    };

    let overhead = match mode {
        "ip" => 52,
        "tcp" => 84,
        _ => 60,
    };

    let recommended = pmtu - overhead;
    cache.insert(endpoint.to_string(), (recommended, std::time::Instant::now()));
    recommended
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
    listen_port: Option<u16>,
    #[serde(default)]
    auto_route: bool,
    pub persistent_keepalive: Option<u16>,
    pub mtu: Option<u16>,
    #[serde(default)]
    pub clamp_mss: bool,
    /// TCP 模式下，Phantun 的远端数据端口（默认 4567）喵
    #[serde(default = "default_tcp_data_port")]
    pub tcp_data_port: u16,
}

fn default_tcp_data_port() -> u16 {
    4567
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

    let mut global_config = GlobalConfig::default();
    let global_path = format!("{}/global.json", config_dir);
    if fs::metadata(&global_path).is_ok() {
        if let Ok(content) = fs::read_to_string(&global_path) {
            if let Ok(conf) = serde_json::from_str::<GlobalConfig>(&content) {
                global_config = conf;
                println!("喵！成功加载全局配置：信令端口 = {}", global_config.signal_port);
            }
        }
    }

    let mut configs = vec![];
    for entry in glob::glob(&format!("{}/*.json", config_dir))? {
        let path = entry?;
        if path.file_name().and_then(|n| n.to_str()) == Some("global.json") { continue; }
        
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
    let signal_port = global_config.signal_port;
    tokio::spawn(async move {
        println!("ฅ^•ﻌ•^ฅ 全局信令中枢计划启用端口：{}", signal_port);
        
        println!("ฅ^•ﻌ•^ฅ 全局信令中枢：UDP 管线启动...");
        let s1 = Arc::clone(&signaling_states);
        tokio::spawn(async move { if let Err(e) = run_global_udp_signaling(s1, signal_port).await { eprintln!("UDP 信令管线异常退出喵: {:?}", e); } });

        println!("ฅ^•ﻌ•^ฅ 全局信令中枢：TCP 管线启动...");
        let s2 = Arc::clone(&signaling_states);
        tokio::spawn(async move { if let Err(e) = run_global_tcp_signaling(s2, signal_port).await { eprintln!("TCP 信令管线异常退出喵: {:?}", e); } });

        // 收集所有 Raw IP 使用的协议号喵
        let mut raw_protos = std::collections::HashSet::new();
        for s in signaling_states.iter() {
            if s.config.mode == "ip" {
                if let Some(p) = s.config.ip_protocol {
                    raw_protos.insert(p);
                } else {
                    raw_protos.insert(141); // 默认协议号
                }
            }
        }

        for proto in raw_protos {
            println!("ฅ^•ﻌ•^ฅ 全局信令中枢：Raw IP (协议 {}) 管线启动...", proto);
            let s3 = Arc::clone(&signaling_states);
            tokio::spawn(async move { if let Err(e) = run_global_raw_signaling(s3, proto).await { eprintln!("Raw IP (协议 {}) 信令管线异常退出喵: {:?}", proto, e); } });
        }
    });

    let mut handles = vec![];
    for state in states.iter() {
        let state_clone = state.clone();
        let handle = tokio::spawn(async move {
            loop {
                let state_inner = state_clone.clone();
                if let Err(e) = run_instance(state_inner).await {
                    eprintln!("实例 {} 运行出错喵: {:?}。正在尝试重启...", state_clone.config.interface, e);
                } else {
                    println!("实例 {} 已退出喵。正在尝试重启...", state_clone.config.interface);
                }
                time::sleep(Duration::from_secs(5)).await;
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
    cmd.env("WG_LOG_LEVEL", "info");
    cmd.arg("--disable-drop-privileges");
    cmd.kill_on_drop(true); // 重点：ctl 退出时一定要带走 cli 喵！
    if config.mode == "ip" {
        if let Some(proto) = config.ip_protocol {
            cmd.arg("--ip-protocol").arg(proto.to_string());
        }
    }
    
    // 强制设置 MTU，默认 1420 喵
    // 特殊：如果 config.mtu 为 0 (自动同步)，启动时先用 1420 喵
    let mtu = match config.mtu {
        Some(0) => 1420,
        Some(val) => val,
        None => 1420,
    };
    
    let mut child = cmd.spawn().context("启动 nekolink-cli 失败")?;

    // 3. 配置接口与私钥 (UAPI 方式)
    {
        let locker = CONFIG_MUTEX.get_or_init(|| tokio::sync::Mutex::new(()));
        let _guard = locker.lock().await;

        // 等待接口创建喵，500ms 通常足够了
        time::sleep(Duration::from_millis(500)).await;

        let mut uapi_cmd = format!("set=1\nprivate_key={}\n", state.priv_b64);
        if let Some(port) = config.listen_port {
            uapi_cmd.push_str(&format!("listen_port={}\n", port));
        }
        uapi_cmd.push('\n');

        send_uapi(&config.interface, &uapi_cmd).await.context("配置私钥失败")?;
    }

    println!("正在启用网卡 {} 喵...", config.interface);
    run_cmd(&format!("ip link set up dev {}", config.interface)).context("启用网卡失败")?;
    
    println!("正在配置 IP 地址 {} 到 {}...", config.local_address, config.interface);
    let _ = run_cmd(&format!("ip addr del {} dev {} 2>/dev/null", config.local_address, config.interface));
    run_cmd(&format!("ip addr add {} dev {}", config.local_address, config.interface)).context("添加 IP 失败")?;

    println!("正在设置 MTU {} 到 {}...", mtu, config.interface);
    run_cmd(&format!("ip link set mtu {} dev {}", mtu, config.interface)).context("设置 MTU 失败")?;

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
    
    // TCP 模式：自动启动 udp2raw 组件喵（比 Phantun 更简单，无需 TUN 接口）
    let mut udp2raw_server_child: Option<tokio::process::Child> = None;
    if config.mode == "tcp" {
        // 判断是服务端还是客户端：服务端 = peers 为空 或 所有 peers 的 endpoint 都为空
        let is_server = config.peers.is_empty() || config.peers.iter().all(|p| p.endpoint.is_empty());
        
        if is_server {
            println!("喵！检测到 TCP 服务端模式，正在自动启动 udp2raw...");
            
            // 获取 WireGuard 监听端口
            let wg_port = get_actual_listen_port(&config.interface).unwrap_or(51820);
            let local_wg = format!("127.0.0.1:{}", wg_port);
            
            // 使用配置的端口，如果为 0 则默认 4567 喵
            let effective_port = if config.tcp_data_port > 0 { config.tcp_data_port } else { 4567 };
            let listen_addr = format!("0.0.0.0:{}", effective_port);
            
            // 使用 PSK 的前 16 字符作为 udp2raw 密码喵
            let udp2raw_key = if config.psk.len() >= 16 { &config.psk[..16] } else { &config.psk };

            // 检查系统是否有 iptables 喵
            let has_iptables = check_command_exists("iptables");
            let mut cmd = tokio::process::Command::new("udp2raw");
            cmd.arg("-s")  // 服务端模式
               .arg("-l").arg(&listen_addr)
               .arg("-r").arg(&local_wg)
               .arg("-k").arg(udp2raw_key)
               .arg("--raw-mode").arg("faketcp")
               .kill_on_drop(true);

            if has_iptables {
                cmd.arg("-a"); // 如果有 iptables，继续使用自动模式喵
            } else {
                // 如果没有 iptables，我们手动用 nftables 挡一下喵
                let _ = setup_udp2raw_nft_rules(effective_port).await;
            }
            
            let server_child = cmd.spawn();
            
            match server_child {
                Ok(child) => {
                    println!("喵！udp2raw 服务端已启动：监听 TCP {} -> 转发到 {}", effective_port, local_wg);
                    if !has_iptables {
                        println!("💡 提示：检测到系统中缺少 iptables，已为您自动配置 nftables 拦截规则喵！");
                    }
                    udp2raw_server_child = Some(child);
                }
                Err(e) => {
                    eprintln!("喵呜... 无法启动 udp2raw: {:?}", e);
                    // 如果启动失败，清理一下 nft 规则（如果加了的话）
                    if !has_iptables { let _ = cleanup_udp2raw_nft_rules().await; }
                }
            }
        } else {
            println!("喵！检测到 TCP 客户端模式，侧车将在信令握手时自动启动喵。");
        }
    }
    
    // 监控进程
    let _ = child.wait().await;

    // 清理 udp2raw 服务端进程
    if let Some(mut srv) = udp2raw_server_child {
        println!("正在关闭 udp2raw 喵...");
        let _ = srv.kill().await;
    }

    println!("正在清理接口 {} 喵...", config.interface);
    if config.clamp_mss {
        let table_name = format!("nekolink_mss_{}", config.interface);
        let _ = run_cmd(&format!("nft delete table inet {} 2>/dev/null", table_name));
    }
    let _ = run_cmd(&format!("ip link del {} 2>/dev/null", config.interface));
    
    // 清理 udp2raw 的 nftables 规则喵
    let _ = cleanup_udp2raw_nft_rules().await;

    Ok(())
}


async fn run_global_udp_signaling(states: Arc<Vec<NekoState>>, signal_port: u16) -> Result<()> {
    // 全局绑定
    let std_socket = std::net::UdpSocket::bind(format!("0.0.0.0:{}", signal_port))?;
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
                    for peer in &state.config.peers {
                        let current_mtu = if state.config.mtu == Some(0) {
                            get_auto_mtu(&peer.endpoint, &state.config.mode).await
                        } else {
                            get_interface_mtu(&state.config.interface).unwrap_or(1420)
                        };

                        let addr_opt = if let Ok(mut sa) = peer.endpoint.parse::<SocketAddr>() {
                            sa.set_port(signal_port);
                            Some(sa)
                        } else if let Ok(ip) = peer.endpoint.parse::<IpAddr>() {
                            Some(SocketAddr::new(ip, signal_port))
                        } else {
                            None
                        };

                        if let Some(addr) = addr_opt {
                            let actual_tunnel_port = get_actual_listen_port(&state.config.interface).unwrap_or(0);
                            let mut msg = msg_base.clone();
                            msg.extend_from_slice(&current_mtu.to_be_bytes());
                            msg.extend_from_slice(&actual_tunnel_port.to_be_bytes());
                            // UDP 模式不需要 Phantun 端口喵

                            let mut nonce_bytes = [0u8; 12];
                            OsRng.fill_bytes(&mut nonce_bytes);
                            if let Ok(ciphertext) = cipher.encrypt(Nonce::from_slice(&nonce_bytes), msg.as_slice()) {
                                let mut pkt = nonce_bytes.to_vec();
                                pkt.extend_from_slice(&ciphertext);
                                if let Err(e) = socket.send_to(&pkt, addr).await {
                                    eprintln!("UDP 信令推送失败喵 ({}): {:?}", state.config.interface, e);
                                } else {
                                    println!("喵！已向对端 {} 主动推送 {} (UDP) 信令盒。", addr, signal_port);
                                }
                            }
                        }
                    }
                }
                time::sleep(Duration::from_secs(5)).await;
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
                                // UDP 模式不使用 Phantun 端口喵
                                
                                if peer_tunnel_port == 0 && state.config.mode != "ip" {
                                    continue;
                                }

                                let mut endpoint = addr.ip().to_string();
                                if peer_tunnel_port > 0 {
                                    endpoint = format!("{}:{}", endpoint, peer_tunnel_port);
                                }

                                println!("喵！12580 (UDP) 握手处理成功：{} -> {}", endpoint, state.config.interface);
                                // UDP 模式不使用 Phantun，直接配置 peer 喵
                                let _ = configure_peer(&state.config.interface, &peer_pub_key, endpoint, state.config.persistent_keepalive, peer_mtu, state.config.mtu == Some(0), &state.config.mode, 0, &state.config.psk).await;
                                
                                // 回回响应喵（UDP 模式不包含 Phantun 端口）
                                let msg_base = state.pub_key.as_bytes().to_vec();
                                let current_mtu = if state.config.mtu == Some(0) {
                                    get_auto_mtu(&addr.ip().to_string(), &state.config.mode).await
                                } else {
                                    get_interface_mtu(&state.config.interface).unwrap_or(1420)
                                };
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

async fn run_global_tcp_signaling(states: Arc<Vec<NekoState>>, signal_port: u16) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", signal_port)).await?;

    println!("ฅ^•ﻌ•^ฅ TCP 信令管线就绪，正在监听 {} 端口，监控 {} 个接口喵。", signal_port, states.len());

    let send_task = {
        let states = Arc::clone(&states);
        async move {
            loop {
                for state in states.iter() {
                    let established = get_established_peers(&state.config.interface).await;
                    if (state.config.mode != "tcp" && state.config.mode != "ip") || state.pub_key.as_bytes() == &[0u8; 32] {
                        continue;
                    }
                    
                    if !established.is_empty() {
                        continue;
                    }

                    let cipher = derive_cipher(&state.config.psk);
                    let pub_key_bytes = state.pub_key.as_bytes().to_vec();
                    let interface = state.config.interface.clone();
                    
                    for peer in &state.config.peers {
                        let addr_opt = if let Ok(mut sa) = peer.endpoint.parse::<SocketAddr>() {
                            sa.set_port(signal_port);
                            Some(sa)
                        } else if let Ok(ip) = peer.endpoint.parse::<IpAddr>() {
                            Some(SocketAddr::new(ip, signal_port))
                        } else {
                            None
                        };

                        if let Some(addr) = addr_opt {
                            let cipher = cipher.clone();
                            let pub_key_bytes = pub_key_bytes.clone();
                            let interface_inner = interface.clone();
                            let is_raw_ip_mode = state.config.mode == "ip";
                            let psk_inner = state.config.psk.clone();
                            let auto_mtu_enabled = state.config.mtu == Some(0);
                            
                            tokio::spawn(async move {
                                println!("喵！正在发起 TCP 信令连接: {}...", addr);
                                match time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(addr)).await {
                                    Ok(Ok(mut stream)) => {
                                        println!("喵！TCP 信令连接已建立: {}", addr);
                                        let current_mtu = if is_raw_ip_mode {
                                            if auto_mtu_enabled { get_auto_mtu(&addr.ip().to_string(), "ip").await } else { get_interface_mtu(&interface_inner).unwrap_or(1420) }
                                        } else {
                                            if auto_mtu_enabled { get_auto_mtu(&addr.ip().to_string(), "tcp").await } else { get_interface_mtu(&interface_inner).unwrap_or(1420) }
                                        };
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
                                                                match time::timeout(Duration::from_secs(10), tokio::io::AsyncReadExt::read(&mut stream, &mut ack_buf)).await {
                                                                    Ok(Ok(n)) if n >= 12 + 32 => {
                                                                        let (nonce_part, encrypted_part) = ack_buf[..n].split_at(12);
                                                                        let nonce = Nonce::from_slice(nonce_part);
                                                                        if let Ok(decrypted) = cipher.decrypt(nonce, encrypted_part) {
                                                                            if decrypted.len() >= 36 {
                                                                                let peer_pub_key = BASE64.encode(&decrypted[..32]);
                                                                                let peer_mtu = Some(u16::from_be_bytes([decrypted[32], decrypted[33]]));
                                                                                let peer_tunnel_port = u16::from_be_bytes([decrypted[34], decrypted[35]]);
                                                                                // 扩展：提取对端的 Phantun 数据端口喵
                                                                                let peer_phantun_port = if decrypted.len() >= 38 {
                                                                                    u16::from_be_bytes([decrypted[36], decrypted[37]])
                                                                                } else {
                                                                                    4567 // 默认端口
                                                                                };
                                                                                if peer_tunnel_port == 0 && !is_raw_ip_mode {
                                                                                    println!("喵呜... 收到来自 {} 的 ACK，但隧道端口为 0，忽略喵。", addr);
                                                                                    return;
                                                                                }

                                                                                let mut endpoint = addr.ip().to_string();
                                                                                if peer_tunnel_port > 0 {
                                                                                    endpoint = format!("{}:{}", endpoint, peer_tunnel_port);
                                                                                }
                                                                                println!("喵！成功接收 TCP 信令响应 (ACK)：来自 {} (隧道端口: {}, Phantun端口: {})", endpoint, peer_tunnel_port, peer_phantun_port);
                                                                                let _ = configure_peer(&interface_inner, &peer_pub_key, endpoint, None, peer_mtu, true, "tcp", peer_phantun_port, &psk_inner).await;
                                                                            }
                                                                        } else {
                                                                            println!("喵呜... 无法解密来自 {} 的 TCP ACK，PSK 匹配吗喵？", addr);
                                                                        }
                                                                    },
                                                                    Ok(Ok(n)) => println!("喵呜... 来自 {} 的 TCP ACK 长度不足: {} 字节喵。", addr, n),
                                                                    Ok(Err(e)) => println!("喵呜... 读取来自 {} 的 TCP ACK 出错: {:?} 喵。", addr, e),
                                                                    Err(_) => println!("喵呜... 等待来自 {} 的 TCP ACK 超时 10 秒喵。", addr),
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
                time::sleep(Duration::from_secs(5)).await;
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
                                    if state.config.mode != "tcp" && state.config.mode != "ip" { continue; }
                                    let cipher = derive_cipher(&state.config.psk);
                                    if let Ok(decrypted) = cipher.decrypt(nonce, encrypted_part) {
                                        if decrypted.len() >= 36 {
                                            let peer_pub_key = BASE64.encode(&decrypted[..32]);
                                            let peer_mtu = Some(u16::from_be_bytes([decrypted[32], decrypted[33]]));
                                            let peer_tunnel_port = u16::from_be_bytes([decrypted[34], decrypted[35]]);
                                            // 扩展：提取对端的 Phantun 数据端口喵
                                            let peer_phantun_port = if decrypted.len() >= 38 {
                                                u16::from_be_bytes([decrypted[36], decrypted[37]])
                                            } else {
                                                0
                                            };
                                            
                                            if peer_tunnel_port == 0 && state.config.mode != "ip" {
                                                continue;
                                            }
                                            let mut endpoint = addr.ip().to_string();
                                            if peer_tunnel_port > 0 {
                                                endpoint = format!("{}:{}", endpoint, peer_tunnel_port);
                                            }

                                            println!("喵！12580 (TCP) 识别成功：{} -> {} (Phantun端口: {})", endpoint, state.config.interface, peer_phantun_port);
                                            // 使用对端的 Phantun 端口（如果协商到的话）
                                            let effective_phantun_port = if peer_phantun_port > 0 { peer_phantun_port } else { state.config.tcp_data_port };
                                            let _ = configure_peer(&state.config.interface, &peer_pub_key, endpoint, state.config.persistent_keepalive, peer_mtu, state.config.mtu == Some(0), &state.config.mode, effective_phantun_port, &state.config.psk).await;
                                            
                                            // TCP 握手响应喵！直接在当前流回发
                                            let msg_base = state.pub_key.as_bytes().to_vec();
                                            let current_mtu = if state.config.mtu == Some(0) { 
                                                get_auto_mtu(&addr.ip().to_string(), &state.config.mode).await 
                                            } else { 
                                                get_interface_mtu(&state.config.interface).unwrap_or(1420) 
                                            };
                                            let actual_tunnel_port = get_actual_listen_port(&state.config.interface).unwrap_or(0);
                                            let mut resp_msg = msg_base;
                                            resp_msg.extend_from_slice(&current_mtu.to_be_bytes());
                                            resp_msg.extend_from_slice(&actual_tunnel_port.to_be_bytes());
                                            // 扩展：添加 Phantun 数据端口喵
                                            resp_msg.extend_from_slice(&state.config.tcp_data_port.to_be_bytes());
                                            
                                            let mut nonce_bytes = [0u8; 12];
                                            OsRng.fill_bytes(&mut nonce_bytes);
                                            if let Ok(ciphertext) = cipher.encrypt(Nonce::from_slice(&nonce_bytes), resp_msg.as_slice()) {
                                                let mut pkt = nonce_bytes.to_vec();
                                                pkt.extend_from_slice(&ciphertext);
                                                use tokio::io::AsyncWriteExt;
                                                let _ = stream.write_all(&pkt).await;
                                                let _ = stream.flush().await;
                                                println!("喵！已向对端 {} 回发 ACK 完成喵。", addr);
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

async fn run_global_raw_signaling(states: Arc<Vec<NekoState>>, proto: u8) -> Result<()> {
    let v4_socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(proto as i32))).ok();
    
    let v4_socket = v4_socket.map(|s| { s.set_nonblocking(true).unwrap(); Arc::new(tokio::io::unix::AsyncFd::new(s).unwrap()) });

    let magic_byte: u8 = 0x99;

    let send_task = {
        let states = Arc::clone(&states);
        let v4_socket = v4_socket.clone();
        async move {
            loop {
                for state in states.iter() {
                    let st_proto = state.config.ip_protocol.unwrap_or(141);
                    if state.config.mode != "ip" || st_proto != proto || state.pub_key.as_bytes() == &[0u8; 32] { continue; }
                    let established = get_established_peers(&state.config.interface).await;
                    if !established.is_empty() { continue; }

                    let cipher = derive_cipher(&state.config.psk);
                    let pub_key_bytes = state.pub_key.as_bytes().to_vec();
                    for peer in &state.config.peers {
                        let current_mtu = if state.config.mtu == Some(0) {
                            get_auto_mtu(&peer.endpoint, "ip").await
                        } else {
                            get_interface_mtu(&state.config.interface).unwrap_or(1420)
                        };
                        let ip_opt = if let Ok(ip) = peer.endpoint.parse::<IpAddr>() {
                            Some(ip)
                        } else if let Ok(sa) = peer.endpoint.parse::<SocketAddr>() {
                            Some(sa.ip())
                        } else {
                            None
                        };

                        if let Some(ip) = ip_opt {
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
                time::sleep(Duration::from_secs(5)).await;
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
                                     let st_proto = state.config.ip_protocol.unwrap_or(141);
                                     if state.config.mode != "ip" || st_proto != proto { continue; }
                                     let cipher = derive_cipher(&state.config.psk);
                                     if let Ok(decrypted) = cipher.decrypt(nonce, encrypted) {
                                         let ip_addr = addr.as_socket().map(|s| s.ip()).unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                                         let peer_mtu = if decrypted.len() >= 34 { Some(u16::from_be_bytes([decrypted[32], decrypted[33]])) } else { None };
                                         println!("喵！12580 (Raw IP) 识别成功：{} -> {}", ip_addr, state.config.interface);
                                         let _ = configure_peer(&state.config.interface, &BASE64.encode(&decrypted[..32]), ip_addr.to_string(), state.config.persistent_keepalive, peer_mtu, state.config.mtu == Some(0), "ip", 0, &state.config.psk).await;

                                         // Raw IP 响应喵！
                                         let msg_base = state.pub_key.as_bytes().to_vec();
                                         let current_mtu = if state.config.mtu == Some(0) {
                                             get_auto_mtu(&ip_addr.to_string(), "ip").await
                                         } else {
                                             get_interface_mtu(&state.config.interface).unwrap_or(1420)
                                         };
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
                time::sleep(Duration::from_secs(5)).await;
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

// udp2raw 使用 -a 参数自动管理 iptables 规则，无需手动配置 nftables 喵


async fn configure_peer(interface: &str, peer_pub_key: &str, mut endpoint: String, keepalive: Option<u16>, peer_mtu: Option<u16>, auto_sync_mtu: bool, mode: &str, tcp_data_port: u16, psk: &str) -> Result<()> {
    // 保存原始探测地址喵（防止 TCP 模式下被 127.0.0.1 覆盖）
    let probe_address = endpoint.clone();
    
    // 处理 TCP 模式下的侧车逻辑喵
    if mode == "tcp" {
        let sidecar_key = (interface.to_string(), peer_pub_key.to_string());
        let mut sidecars = SIDE_CARS.get_or_init(|| tokio::sync::Mutex::new(HashMap::new())).lock().await;

        // 如果已经有侧车且 Endpoint 没变，直接复用喵
        let mut need_new_sidecar = true;
        let mut local_port = 0;

        if let Some(_) = sidecars.get(&sidecar_key) {
             // 检查缓存的 Endpoint 喵
             let cache_mutex = PEER_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
             let cache = cache_mutex.lock().unwrap();
             if let Some(old_ep) = cache.get(&sidecar_key) {
                 if old_ep.starts_with("127.0.0.1:") {
                      // 已经是一个本地中转了喵
                      need_new_sidecar = false;
                      local_port = old_ep[10..].parse().unwrap_or(0);
                 }
             }
        }

        if need_new_sidecar {
            // 先清理旧侧车喵
            if let Some(mut old_child) = sidecars.remove(&sidecar_key) {
                let _ = old_child.kill().await;
            }

            // 解析远端 IP（endpoint 格式可能是 IP:PORT 或纯 IP）
            let remote_ip = endpoint.split(':').next().unwrap_or(&endpoint);
            // 使用协商的 tcp_data_port，如果为 0 则使用默认 4567 喵
            let effective_port = if tcp_data_port > 0 { tcp_data_port } else { 4567 };
            let remote_addr = format!("{}:{}", remote_ip, effective_port);

            // 寻找一个闲置的本地 UDP 端口（简单起见，从 40000 开始随机抽一个喵）
            local_port = (OsRng.next_u32() % 10000 + 40000) as u16;
            let local_udp = format!("127.0.0.1:{}", local_port);
            
            // 使用 PSK 前 16 字符作为 udp2raw 密码喵（与服务端保持一致）
            let udp2raw_key = if psk.len() >= 16 { &psk[..16] } else { psk };
            
            println!("喵！正在为队友 {} 启动 udp2raw 侧车：{} <-> {} (TCP 数据端口: {})", peer_pub_key, local_udp, remote_addr, effective_port);
            
            // 检查系统是否有 iptables 喵
            let has_iptables = check_command_exists("iptables");
            let mut cmd = tokio::process::Command::new("udp2raw");
            cmd.arg("-c")  // 客户端模式
               .arg("-l").arg(&local_udp)
               .arg("-r").arg(&remote_addr)
               .arg("-k").arg(udp2raw_key)
               .arg("--raw-mode").arg("faketcp")
               .kill_on_drop(true);

            if has_iptables {
                cmd.arg("-a"); // 如果有 iptables，继续使用自动模式喵
            } else {
                // 如果没有 iptables，手动拦截来自对端 TCP 端口的包喵
                // 客户端需要拦截源端口为 effective_port 的包喵
                println!("喵！检测到缺少 iptables，客户端将手动配置 nftables 拦截来自对端端口 {} 的回包喵...", effective_port);
                let _ = std::process::Command::new("nft")
                    .arg("add").arg("table").arg("inet").arg("nekolink_udp2raw")
                    .status();
                let _ = std::process::Command::new("nft")
                    .args(&[
                        "add", "chain", "inet", "nekolink_udp2raw", "input", "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}"
                    ])
                    .status();
                let _ = std::process::Command::new("nft")
                    .args(&[
                        "insert", "rule", "inet", "nekolink_udp2raw", "input", "tcp", "sport", &effective_port.to_string(), "drop"
                    ])
                    .status();
            }

            // 启动 udp2raw 客户端 喵！
            let child = cmd.spawn()?;
            
            sidecars.insert(sidecar_key, child);
            endpoint = local_udp;
        } else {
            endpoint = format!("127.0.0.1:{}", local_port);
        }
    }

    let locker = CONFIG_MUTEX.get_or_init(|| tokio::sync::Mutex::new(()));
    let _guard = locker.lock().await;

    let key = (interface.to_string(), peer_pub_key.to_string());
    {
        let cache_mutex = PEER_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        let cache = cache_mutex.lock().unwrap();
        if let Some(old_ep) = cache.get(&key) {
            if old_ep == &endpoint {
                return Ok(());
            }
            println!("检测到接口 {} 的队友 {} Endpoint 变更: {} -> {}喵！", interface, peer_pub_key, old_ep, endpoint);
        } else {
            println!("首次识别接口 {} 的队友 {}: {}喵！", interface, peer_pub_key, endpoint);
        }
    }

    // 幂等保护：先删除旧 Peer 再添加喵
    let remove_cmd = format!("set=1\npublic_key={}\nremove=true\n\n", peer_pub_key);
    let _ = send_uapi(interface, &remove_cmd).await; 

    let mut uapi_cmd = format!(
        "set=1\npublic_key={}\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\nendpoint={}\n",
        peer_pub_key, endpoint
    );
    if let Some(ka) = keepalive {
        uapi_cmd.push_str(&format!("persistent_keepalive_interval={}\n", ka));
    }
    uapi_cmd.push_str("\n");
    
    send_uapi(interface, &uapi_cmd).await.context("配置 Peer 失败")?;
    
    // 更新缓存
    {
        let cache_mutex = PEER_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        let mut cache = cache_mutex.lock().unwrap();
        cache.insert(key, endpoint.clone());
    }

    println!("配置队友 {} (Endpoint: {}) 成功喵！", peer_pub_key, endpoint);

    if let Some(m) = peer_mtu {
        if auto_sync_mtu {
            let probed_mtu = Some(get_auto_mtu(&probe_address, mode).await);
            let _ = sync_mtu_if_needed(interface, m, probed_mtu).await;
        }
    }
    Ok(())
}

async fn sync_mtu_if_needed(interface: &str, peer_mtu: u16, probed_mtu: Option<u16>) -> Result<()> {
    let current_mtu = get_interface_mtu(interface).unwrap_or(1420);
    
    let target_mtu = if let Some(p) = probed_mtu {
        // 全自动协商模式喵：取我方探测值和对方建议值的最小值
        u16::min(p, peer_mtu)
    } else {
        // 半自动模式喵：直接同步对方的值
        peer_mtu
    };

    if current_mtu != target_mtu && target_mtu >= 1280 {
        println!("接口 {} MTU 协商收敛中：[我方探测 {}] vs [对方建议 {}] -> 最终选用 {}喵！", interface, probed_mtu.unwrap_or(0), peer_mtu, target_mtu);
        let _ = run_cmd(&format!("ip link set mtu {} dev {}", target_mtu, interface));
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
        if path.file_name().and_then(|n| n.to_str()) == Some("global.json") { continue; }
        
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
                println!("UAPI 运行状态：");
                for line in info.lines() {
                    let line = line.trim();
                    if line.is_empty() { continue; }
                    let parts: Vec<&str> = line.splitn(2, '=').collect();
                    if parts.len() == 2 {
                        let (k, v) = (parts[0], parts[1]);
                        match k {
                            "protocol" => println!("  传输协议: {}", v),
                            "ip_protocol" => println!("  IP 协议号: {}", v),
                            "listen_port" => println!("  监听端口: {}", v),
                            "own_public_key" => println!("  本地公钥: {}", v),
                            "public_key" => println!("  对端公钥: {}", v),
                            "endpoint" => println!("  对端端点: {}", v),
                            "rx_bytes" => println!("  接收流量: {} Bytes", v),
                            "tx_bytes" => println!("  发送流量: {} Bytes", v),
                            "last_handshake_time_sec" => {
                                if let Ok(sec) = v.parse::<u64>() {
                                    if sec > 0 {
                                        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                                        println!("  最近握手: {} 秒前", now.saturating_sub(sec));
                                    } else {
                                        println!("  最近握手: 尚未完成握手喵");
                                    }
                                }
                            }
                            "persistent_keepalive_interval" => println!("  保活间隔: {} 秒", v),
                            "allowed_ip" => println!("  允许路由: {}", v),
                            _ => println!("  {}: {}", k, v),
                        }
                    }
                }
            },
            Err(e) => {
                println!("UAPI 状态: 离线喵 (可能服务未启动) 错误: {:?}", e);
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
    let mut stream = time::timeout(Duration::from_secs(2), tokio::net::UnixStream::connect(path)).await
        .map_err(|_| anyhow::anyhow!("连接 UAPI Socket 超时喵 (2s)"))?
        .context("无法连接到 UAPI Socket")?;
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

    // 针对 TCP 模式尝试使用真 TCP 探测，否则回退到 ICMP
    let pmtu = if mode == "tcp" {
        match perform_tcp_mtu_probe(host).await {
            Ok(val) => {
                println!("喵！成功通过 TCP 握手探测到路径 MTU 为 {}。", val);
                val
            },
            Err(_) => {
                println!("TCP 探测受限喵... 回退到 ICMP 二分法探测。");
                perform_mtu_probe(host).await.unwrap_or(1500)
            }
        }
    } else {
        perform_mtu_probe(host).await.unwrap_or(1500)
    };

    // 精准开销分析喵：
    // IP: 52 (IP 20 + WG 32)
    // UDP: 60 (IP 20 + UDP 8 + WG 32)
    // TCP (udp2raw): 84 (IP 20 + TCP 20 + udp2raw 12 + WG 32)
    let overhead = match mode {
        "ip" => 52,
        "tcp" => 84,
        _ => 60, // udp
    };

    let recommended = pmtu - overhead;
    println!("探测完成：PMTU={}，建议 MTU={} (模式: {}) 喵！", pmtu, recommended, mode);
    println!("RECOMMENDED_MTU={}", recommended);

    Ok(())
}

async fn perform_tcp_mtu_probe(host: &str) -> Result<u16> {
    use std::os::unix::io::AsRawFd;
    
    // 尝试连接对端的信令端口 (默认 12580)
    let addr = format!("{}:12580", host);
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    
    // 设置非阻塞和超时
    socket.set_nonblocking(true)?;
    
    // 异步连接
    let addr_sock: SocketAddr = addr.parse().unwrap_or("0.0.0.0:12580".parse().unwrap());
    let _ = socket.connect(&addr_sock.into());
    
    // 等待一小会儿确保路径被探测喵
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    // 在 Linux 下读取 IP_MTU 选项喵
    // libc::IP_MTU 的值是 14
    let mut mtu: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    
    let res = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MTU,
            &mut mtu as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    
    if res == 0 && mtu > 0 {
        Ok(mtu as u16)
    } else {
        Err(anyhow::anyhow!("无法获取 TCP MTU"))
    }
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

fn check_command_exists(cmd: &str) -> bool {
    std::process::Command::new(cmd)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

async fn setup_udp2raw_nft_rules(port: u16) -> Result<()> {
    println!("喵！检测到缺少 iptables，执行 nftables 备选预案：手动拦截端口 {}...", port);
    
    // 创建一个专用的表喵
    let _ = std::process::Command::new("nft")
        .arg("add").arg("table").arg("inet").arg("nekolink_udp2raw")
        .status();
        
    // 创建链并添加拦截规则喵
    // udp2raw 需要拦截目标端口的 TCP 包，防止内核回复 RST 喵
    let status = std::process::Command::new("nft")
        .args(&[
            "add", "chain", "inet", "nekolink_udp2raw", "input", "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}"
        ])
        .status();

    if let Ok(s) = status {
        if s.success() {
            let _ = std::process::Command::new("nft")
                .args(&[
                    "insert", "rule", "inet", "nekolink_udp2raw", "input", "tcp", "dport", &port.to_string(), "drop"
                ])
                .status();
            println!("喵！nftables 拦截规则已生效喵！");
        }
    }
    
    Ok(())
}

async fn cleanup_udp2raw_nft_rules() -> Result<()> {
    println!("喵！正在清理 nftables 拦截规则...");
    let _ = std::process::Command::new("nft")
        .arg("delete").arg("table").arg("inet").arg("nekolink_udp2raw")
        .status();
    Ok(())
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


