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
use tokio_util::sync::CancellationToken;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};

struct InstanceHandle {
    state: NekoState,
    token: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PeerConfig {
    /// 对端的 Endpoint 地址（IP:Port 或纯 IP）
    #[serde(default)]
    endpoint: String,
    /// WireGuard 兼容模式：对端的公钥（Base64 编码）
    #[serde(default)]
    public_key: Option<String>,
    /// WireGuard 兼容模式：隧道层预共享密钥（Base64 编码，与 NekoLink 的 psk 不同）
    #[serde(default)]
    preshared_key: Option<String>,
    /// WireGuard 兼容模式：允许的 IP 列表（如 "10.0.0.0/24, 192.168.1.0/24"）
    #[serde(default)]
    allowed_ips: Option<String>,
    /// 单独为此 Peer 设置的 Keepalive（覆盖全局设置）
    #[serde(default)]
    persistent_keepalive: Option<u16>,
    /// 对端服务器的信令端口(客户端用,覆盖接口级和全局配置)喵
    #[serde(skip_serializing_if = "Option::is_none")]
    signal_port: Option<u16>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct GlobalConfig {
    #[serde(default = "default_signal_port")]
    pub signal_port: u16,
    /// 全局 Loopback 接口名称喵
    pub loopback_interface: Option<String>,
    /// 全局 Loopback 接口地址喵
    pub loopback_address: Option<String>,
    /// 设备唯一标识 ID 喵
    pub device_id: Option<String>,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self { 
            signal_port: 12580,
            loopback_interface: None,
            loopback_address: None,
            device_id: None,
        }
    }
}

static PEER_CACHE: OnceLock<Mutex<HashMap<(String, String), String>>> = OnceLock::new();
static CONFIG_MUTEX: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

static PROBED_MTU_CACHE: OnceLock<tokio::sync::Mutex<HashMap<String, (u16, std::time::Instant)>>> = OnceLock::new();
static DNS_CACHE: OnceLock<tokio::sync::Mutex<HashMap<String, (IpAddr, std::time::Instant)>>> = OnceLock::new();

async fn resolve_dns(host: &str, interface: Option<&str>, prefer_ipv6: bool) -> Result<IpAddr> {
    {
        let cache_mutex = DNS_CACHE.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()));
        let cache = cache_mutex.lock().await;
        if let Some((ip, timestamp)) = cache.get(host) {
            if timestamp.elapsed() < Duration::from_secs(300) {
                return Ok(*ip);
            }
        }
    }

    let addr = if let Some(iface) = interface {
        // 使用隧道接口进行可信 DNS 解析 (Google DNS 8.8.8.8) 喵
        match resolve_via_tunnel(host, iface).await {
            Ok(ip) => ip,
            Err(_e) => {
                // tracing::warn!("可信 DNS 解析失败,降级回系统解析: {:?}", _e);
                resolve_with_preference(host, prefer_ipv6).await?
            }
        }
    } else {
        // 没有指定接口,直接使用系统解析喵
        resolve_with_preference(host, prefer_ipv6).await?
    };

    {
        let mut cache = DNS_CACHE.get_or_init(|| tokio::sync::Mutex::new(HashMap::new())).lock().await;
        cache.insert(host.to_string(), (addr, std::time::Instant::now()));
    }
    
    Ok(addr)
}

/// 根据 IPv6 优先级偏好解析主机名喵
async fn resolve_with_preference(host: &str, prefer_ipv6: bool) -> Result<IpAddr> {
    let addrs: Vec<IpAddr> = tokio::net::lookup_host(format!("{}:0", host))
        .await?
        .map(|addr| addr.ip())
        .collect();
    
    if addrs.is_empty() {
        return Err(anyhow::anyhow!("DNS 解析结果为空喵"));
    }
    
    if prefer_ipv6 {
        // 优先返回 IPv6
        addrs.iter().find(|ip| ip.is_ipv6()).copied()
            .or_else(|| addrs.first().copied())
            .ok_or_else(|| anyhow::anyhow!("未找到合适的 IP 地址喵"))
    } else {
        // 优先返回 IPv4
        addrs.iter().find(|ip| ip.is_ipv4()).copied()
            .or_else(|| addrs.first().copied())
            .ok_or_else(|| anyhow::anyhow!("未找到合适的 IP 地址喵"))
    }
}

// 手动构造 DNS 查询包并通过隧道接口发送喵
async fn resolve_via_tunnel(host: &str, interface: &str) -> Result<IpAddr> {
    use hickory_proto::op::{Message, Query, ResponseCode};
    use hickory_proto::rr::{Name, RecordType, RData};
    use std::str::FromStr;

    // 1. 尝试解析为 A 记录 (IPv4)
    let name = Name::from_str(host).map_err(|_| anyhow::anyhow!("Invalid hostname"))?;
    if !name.is_fqdn() {
        // 如果不是 FQDN，可能需要 append search domain，这里简化处理只查一次
        // name.append_domain(...) 
    }
    
    // 构造查询
    let query = Query::query(name.clone(), RecordType::A);
    let mut msg = Message::new();
    msg.add_query(query);
    msg.set_recursion_desired(true);
    let msg_bytes = msg.to_vec()?;

    // 绑定到隧道接口
    let socket = connect_via_interface_udp(interface, None).await?;
    
    // 发送给 8.8.8.8:53
    let target = "8.8.8.8:53".parse::<SocketAddr>().unwrap();
    socket.send_to(&msg_bytes, target).await?;

    // 接收响应
    let mut buf = [0u8; 4096];
    let (len, _src) = time::timeout(Duration::from_secs(3), socket.recv_from(&mut buf)).await??;
    
    let resp = Message::from_vec(&buf[..len])?;
    if resp.response_code() != ResponseCode::NoError {
        return Err(anyhow::anyhow!("DNS query failed: {:?}", resp.response_code()));
    }

    // 提取 IP
    for answer in resp.answers() {
        if let Some(RData::A(ip)) = answer.data() {
            return Ok(IpAddr::V4(ip.0));
        }
    }

    Err(anyhow::anyhow!("No A record found via tunnel"))
}

/// 统一的 endpoint 解析函数,支持 IP、域名和带端口的地址喵
async fn resolve_endpoint_with_port(endpoint: &str, port: u16, prefer_ipv6: bool) -> Result<SocketAddr> {
    if let Ok(mut sa) = endpoint.parse::<SocketAddr>() {
        // 已经是 IP:Port 格式,替换端口喵
        sa.set_port(port);
        Ok(sa)
    } else if let Ok(ip) = endpoint.parse::<IpAddr>() {
        // 纯 IP 地址喵
        Ok(SocketAddr::new(ip, port))
    } else {
        // 作为域名解析喵
        let ip = resolve_dns(endpoint, None, prefer_ipv6).await?;
        Ok(SocketAddr::new(ip, port))
    }
}


async fn get_auto_mtu(endpoint: &str, mode: &str) -> u16 {
    let mut cache = PROBED_MTU_CACHE.get_or_init(|| tokio::sync::Mutex::new(HashMap::new())).lock().await;

    if let Some((mtu, timestamp)) = cache.get(endpoint) {
        if timestamp.elapsed() < Duration::from_secs(3600) {
            return *mtu;
        }
    }

    // 执行探测喵
    let (host, _port) = if let Ok(addr) = endpoint.parse::<SocketAddr>() {
        (addr.ip().to_string(), addr.port())
    } else if endpoint.contains(':') {
        let parts: Vec<&str> = endpoint.rsplitn(2, ':').collect();
        if parts.len() == 2 {
            (parts[1].trim_start_matches('[').trim_end_matches(']').to_string(), parts[0].parse().unwrap_or(0))
        } else {
            (endpoint.to_string(), 0)
        }
    } else {
        (endpoint.to_string(), 0)
    };

    let pmtu = if mode == "tcp" || mode == "mullvad-tcp" {
        match perform_tcp_mtu_probe(&host).await {
            Ok(val) => val,
            Err(_) => perform_mtu_probe(&host).await.unwrap_or(1500)
        }
    } else {
        perform_mtu_probe(&host).await.unwrap_or(1500)
    };

    // 检测是否为 IPv6 地址喵（IPv6 头比 IPv4 大 20 字节）
    let is_ipv6 = host.contains(':') || host.parse::<std::net::Ipv6Addr>().is_ok();
    let ip_header_size: u16 = if is_ipv6 { 40 } else { 20 };

    let recommended = match mode {
        "ip" => pmtu - (ip_header_size + 32),                       // IP + WG
        "tcp" => pmtu - (ip_header_size + 20 + 2 + 32),             // IP + TCP + 2 bytes framing + WG
        "mullvad-tcp" => pmtu - (ip_header_size + 20 + 2 + 32),     // IP + TCP + 2 bytes framing + WG
        "fake-tcp" => pmtu - (ip_header_size + 20 + 12 + 20 + 32),  // udp2raw 大约 12-20 字节额外开销，保守算 84 喵
        _ => pmtu - (ip_header_size + 8 + 32),                      // IP + UDP + WG
    };
    
    // 如果是 udp2raw (fake-tcp)，开销非常大，特殊处理下喵
    let recommended = if mode == "fake-tcp" {
        pmtu - 84 // 参考 CHANGELOG 里的 84 字节修正喵
    } else {
        recommended
    };

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
    /// NekoLink 信令通道的预共享密钥（用于自动交换公钥）
    psk: String,
    peers: Vec<PeerConfig>,
    listen_port: Option<u16>,
    #[serde(default)]
    auto_route: bool,
    pub persistent_keepalive: Option<u16>,
    pub mtu: Option<u16>,
    #[serde(default)]
    pub clamp_mss: bool,
    /// Mullvad TCP 模式下，远端绑定的物理端口（默认 12581）喵
    #[serde(default = "default_tcp_data_port")]
    pub mullvad_tcp_port: u16,
    /// WireGuard 原生兼容模式：禁用信令通道，使用配置文件中的公钥
    #[serde(default)]
    pub native_wg_compat: bool,
    /// 导入模式下的私钥（Base64 编码，可选）
    #[serde(default)]
    pub private_key: Option<String>,
    /// 是否开启多队列（默认关闭以提升兼容性喵）
    #[serde(default)]
    pub use_multi_queue: bool,
    /// 本地 SOCKS5 代理端口喵
    #[serde(default)]
    pub socks5_port: Option<u16>,
    /// 是否开启 UDP GRO 接收卸载（默认开启，若遇到性能问题可关闭喵）
    #[serde(default = "default_true")]
    pub enable_udp_gro: bool,
    /// 接口级信令端口(可选,覆盖全局配置)喵
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_port: Option<u16>,
    /// 是否优先使用 IPv6(默认 false,优先 IPv4)喵
    #[serde(default)]
    pub prefer_ipv6: bool,
    /// 是否在本地 127.0.0.1 监听 SOCKS5 (默认 true) 喵
    #[serde(default = "default_true")]
    pub socks5_listen_local: bool,
    /// 是否在全局 Loopback 接口监听 SOCKS5 (默认 false) 喵
    #[serde(default)]
    pub socks5_listen_loopback: bool,
    /// 显式指定的 SOCKS5 绑定 IP（开启同端口多 IP 监听的关键喵！）
    #[serde(default)]
    pub socks5_bind_addr: Option<String>,
}

fn default_true() -> bool { true }

fn default_tcp_data_port() -> u16 {
    12581
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
    // 存储客户端模式下的 Mullvad sidecar 进程喵
    client_sidecar: Arc<parking_lot::Mutex<Option<tokio::process::Child>>>,
    // 全局配置引用喵
    global_config: GlobalConfig,
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
            "reload" => {
                let pid_path = "/var/run/nekolink-ctl.pid";
                if let Ok(pid_str) = fs::read_to_string(pid_path) {
                    if let Ok(pid) = pid_str.trim().parse::<i32>() {
                        use nix::sys::signal::{kill, Signal};
                        use nix::unistd::Pid;
                        if kill(Pid::from_raw(pid), Signal::SIGHUP).is_ok() {
                            println!("喵！已向主进程 (PID: {}) 发送重载信号。", pid);
                            return Ok(());
                        }
                    }
                }
                eprintln!("喵呜... 找不到运行中的 NekoLink 主进程，请检查服务是否已启动喵。");
                std::process::exit(1);
            }
            _ => {
                eprintln!("喵？不支持的指令: '{}'。如果您想启动服务，请不要带参数喵。", args[1]);
                std::process::exit(1);
            }
        }
    }

    println!("ฅ^•ﻌ•^ctl NekoLink 控制平面启动中...");
    
    // 初始化日志系统喵
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    // 记录 PID 喵
    let pid = std::process::id();
    if let Err(e) = fs::write("/var/run/nekolink-ctl.pid", pid.to_string()) {
        eprintln!("警告：无法写入 PID 文件喵: {:?}", e);
    }

    let config_dir = "/etc/neko-link";
    if !std::path::Path::new(config_dir).exists() {
        fs::create_dir_all(config_dir).context("无法创建配置目录")?;
    }

    let load_configs = || -> Result<(GlobalConfig, Vec<NekoConfig>)> {
        let mut global_config = GlobalConfig::default();
        let global_path = format!("{}/global.json", config_dir);
        if fs::metadata(&global_path).is_ok() {
            if let Ok(content) = fs::read_to_string(&global_path) {
                if let Ok(conf) = serde_json::from_str::<GlobalConfig>(&content) {
                    global_config = conf;
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
        Ok((global_config, configs))
    };

    let (mut current_global, initial_configs) = load_configs()?;
    println!("喵！成功加载初始配置，发现 {} 个接口喵。", initial_configs.len());
    
    // 初始化全局 Loopback 接口喵
    if let Err(e) = setup_loopback_interface(&current_global).await {
        eprintln!("警告：设置全局 Loopback 接口失败喵: {:?}", e);
    }

    let active_instances: Arc<tokio::sync::RwLock<HashMap<String, InstanceHandle>>> = Arc::new(tokio::sync::RwLock::new(HashMap::new()));
    
    // 信号监听喵
    use tokio::signal::unix::{signal, SignalKind};
    let mut sighup = signal(SignalKind::hangup())?;
    
    // 全局取消令牌，用于信令管理器在端口变更时重启喵
    let signaling_token = Arc::new(Mutex::new(CancellationToken::new()));

    // 内部函数：启动信令管理器喵
    let start_signaling_tasks = |global: GlobalConfig, instances: Arc<tokio::sync::RwLock<HashMap<String, InstanceHandle>>>, token: CancellationToken| {
        tokio::spawn(async move {
            let mut port_to_use = global.signal_port;
            
            // 检查是否需要固定监听端口喵 (即是否存在服务端模式的接口)
            let has_server = {
                let lock = instances.read().await;
                lock.values().any(|h| {
                    let config = &h.state.config;
                    config.peers.is_empty() || config.peers.iter().all(|p| p.endpoint.is_empty())
                })
            };

            if !has_server {
                println!("ฅ^•ﻌ•^ฅ 检测到当前仅作为客户端运行，信令监听将使用随机端口喵。");
                port_to_use = 0;
            } else {
                println!("ฅ^•ﻌ•^ฅ 全局信令中枢计划启用端口：{}", port_to_use);
            }

            tokio::select! {
                _ = token.cancelled() => {
                    println!("ฅ^•ﻌ•^ฅ 全局信令中枢：正在因重载而停止端口 {} 的管线喵。", global.signal_port);
                }
                _ = async {
                    let i1 = Arc::clone(&instances);
                    let t1 = token.clone();
                    tokio::spawn(async move { if let Err(e) = run_global_udp_signaling_dynamic(i1, port_to_use, t1).await { eprintln!("UDP 信令管线异常退出喵: {:?}", e); } });

                    println!("ฅ^•ﻌ•^ฅ 全局信令中枢：TCP 管线启动...");
                    let i2 = Arc::clone(&instances);
                    let t2 = token.clone();
                    tokio::spawn(async move { if let Err(e) = run_global_tcp_signaling_dynamic(i2, port_to_use, t2).await { eprintln!("TCP 信令管线异常退出喵: {:?}", e); } });

                    // 收集所有 Raw IP 使用的协议号并启动喵
                    // 注意：这里简化处理，只在信令启动时扫描一次协议号，或者可以后续动态扫描喵
                    let raw_protos = {
                        let lock = instances.read().await;
                        let mut set = std::collections::HashSet::new();
                        for inst in lock.values() {
                            if inst.state.config.mode == "ip" {
                                set.insert(inst.state.config.ip_protocol.unwrap_or(141));
                            }
                        }
                        set
                    };

                    for proto in raw_protos {
                        println!("ฅ^•ﻌ•^ฅ 全局信令中枢：Raw IP (协议 {}) 管线启动...", proto);
                        let i3 = Arc::clone(&instances);
                        let t3 = token.clone();
                        tokio::spawn(async move { if let Err(e) = run_global_raw_signaling_dynamic(i3, proto, t3).await { eprintln!("Raw IP (协议 {}) 信令管线异常退出喵: {:?}", proto, e); } });
                    }
                    
                    // 挂起保持此线程运行喵
                    std::future::pending::<()>().await;
                } => {}
            }
        });
    };

    // 初始启动逻辑喵
    {
        let mut instances = active_instances.write().await;
        for config in initial_configs {
            let iface = config.interface.clone();
            let (priv_b64, pub_key) = if let Some(pk) = &config.private_key {
                let bytes = decode_base64(pk).context("无法解码配置中的私钥喵")?;
                let priv_key = StaticSecret::from(<[u8; 32]>::try_from(bytes).map_err(|_| anyhow::anyhow!("私钥长度不对喵"))?);
                let pub_key = PublicKey::from(&priv_key);
                (pk.clone(), pub_key)
            } else {
                let (p_b64, _, p_k) = load_or_generate_keys(&iface)?;
                (p_b64, p_k)
            };
            let state = NekoState { config, priv_b64, pub_key, client_sidecar: Arc::new(parking_lot::Mutex::new(None)), global_config: current_global.clone() };
            let token = CancellationToken::new();
            let token_clone = token.clone();
            let state_clone = state.clone();
            
            let task = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = token_clone.cancelled() => break,
                        res = run_instance(state_clone.clone(), token_clone.clone()) => {
                            if let Err(e) = res {
                                eprintln!("实例 {} 出错喵: {:?}。5秒后重启...", state_clone.config.interface, e);
                            }
                            tokio::select! {
                                _ = token_clone.cancelled() => break,
                                _ = time::sleep(Duration::from_secs(5)) => {}
                            }
                        }
                    }
                }
                println!("实例 {} 已彻底停止喵。", state_clone.config.interface);
            });
            
            instances.insert(iface, InstanceHandle { state, token, task });
        }
        
        // 初始启动信令喵
        let token = CancellationToken::new();
        start_signaling_tasks(current_global.clone(), Arc::clone(&active_instances), token.clone());
        *signaling_token.lock().unwrap() = token;
    }

    println!("ฅ^•ﻌ•^ฅ NekoLink 已进入长效监听模式，支持 SIGHUP 热重载喵！");

    // 服务主循环，等待热重载信号喵
    loop {
        sighup.recv().await;
        println!("\nฅ^•ﻌ•^ฅ 接收到 SIGHUP 信号，正在施展热重载魔法...");
        
        match load_configs() {
            Ok((new_global, new_configs)) => {
                // 1. 检查全局信令端口是否变更喵
                if new_global.signal_port != current_global.signal_port {
                    println!("喵！检测到信令端口变更 {} -> {}", current_global.signal_port, new_global.signal_port);
                    signaling_token.lock().unwrap().cancel();
                    let new_token = CancellationToken::new();
                    start_signaling_tasks(new_global.clone(), Arc::clone(&active_instances), new_token.clone());
                    *signaling_token.lock().unwrap() = new_token;
                    current_global = new_global.clone();
                }

                // 检查 Loopback 配置变更喵
                if new_global.loopback_interface != current_global.loopback_interface || new_global.loopback_address != current_global.loopback_address {
                    println!("喵！检测到全局 Loopback 配置变更，正在重新魔法化...");
                    if let Err(e) = setup_loopback_interface(&new_global).await {
                        eprintln!("警告：重新设置 Loopback 接口失败喵: {:?}", e);
                    }
                    current_global = new_global.clone();
                }

                // 2. 更新接口喵
                let mut instances = active_instances.write().await;
                let mut next_instances = HashMap::new();
                
                // 处理新配置和待更新配置喵
                for config in new_configs {
                    let iface = config.interface.clone();
                    
                    let should_restart = if let Some(old_h) = instances.get(&iface) {
                        // 简单对比 JSON 序列化结果来判断是否有变化喵
                        serde_json::to_string(&old_h.state.config).unwrap() != serde_json::to_string(&config).unwrap()
                    } else {
                        true // 新接口
                    };

                    if should_restart {
                        if let Some(old_h) = instances.remove(&iface) {
                            println!("喵！检测到配置变更，正在重启接口 {}...", iface);
                            old_h.token.cancel();
                            let _ = old_h.task.await; // 等待旧任务彻底结束喵
                        } else {
                            println!("喵！检测到新接口 {}，正在启动...", iface);
                        }
                        
                        let (priv_b64, pub_key) = if let Some(pk) = &config.private_key {
                            match decode_base64(pk) {
                                Ok(bytes) => {
                                    if let Ok(bytes_32) = <[u8; 32]>::try_from(bytes) {
                                        let priv_key = StaticSecret::from(bytes_32);
                                        let pub_key = PublicKey::from(&priv_key);
                                        (pk.clone(), pub_key)
                                    } else {
                                        let (p_b64, _, p_k) = load_or_generate_keys(&iface).unwrap_or_else(|_| (String::new(), String::new(), PublicKey::from([0u8; 32])));
                                        (p_b64, p_k)
                                    }
                                }
                                Err(_) => {
                                     let (p_b64, _, p_k) = load_or_generate_keys(&iface).unwrap_or_else(|_| (String::new(), String::new(), PublicKey::from([0u8; 32])));
                                     (p_b64, p_k)
                                }
                            }
                        } else {
                            let (p_b64, _, p_k) = load_or_generate_keys(&iface).unwrap_or_else(|_| (String::new(), String::new(), PublicKey::from([0u8; 32])));
                            (p_b64, p_k)
                        };

                        let state = NekoState { config: config.clone(), priv_b64, pub_key, client_sidecar: Arc::new(parking_lot::Mutex::new(None)), global_config: new_global.clone() };
                        let token = CancellationToken::new();
                        let token_clone = token.clone();
                        let state_clone = state.clone();
                        
                        let task = tokio::spawn(async move {
                                loop {
                                    tokio::select! {
                                        _ = token_clone.cancelled() => break,
                                        res = run_instance(state_clone.clone(), token_clone.clone()) => {
                                            if let Err(e) = res {
                                                eprintln!("实例 {} 出错喵: {:?}。5秒后重启...", state_clone.config.interface, e);
                                            }
                                            tokio::select! {
                                                _ = token_clone.cancelled() => break,
                                                _ = time::sleep(Duration::from_secs(5)) => {}
                                            }
                                        }
                                    }
                                }
                        });
                        next_instances.insert(iface, InstanceHandle { state, token, task });
                    } else {
                        // 保持原样喵
                        if let Some(old_h) = instances.remove(&iface) {
                            next_instances.insert(iface, old_h);
                        }
                    }
                }

                // 3. 清理已删除的接口喵
                for (iface, old_h) in instances.drain() {
                    println!("喵！检测到接口 {} 已从配置中移除，正在停止...", iface);
                    old_h.token.cancel();
                    // 显式清理全局状态喵，防止残留缓存或进程影响后续同名接口的创建
                    let iface_clone = iface.clone();
                    tokio::spawn(async move {
                        cleanup_interface_state(&iface_clone).await;
                    });
                }
                
                *instances = next_instances;
                println!("ฅ^•ﻌ•^ctl 热重载魔法施展完成！目前运行 {} 个接口喵。", instances.len());
            }
            Err(e) => {
                eprintln!("喵呜... 热重载加载配置失败: {:?}", e);
            }
        }
    }
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
        if let Some(stripped) = line.strip_prefix("errno=") {
            let errno: i32 = stripped.trim().parse()?;
            if errno != 0 {
                return Err(anyhow::anyhow!("UAPI 返回错误: {}", errno));
            }
            break;
        }
        line.clear();
    }
    Ok(())
}

async fn run_instance(state: NekoState, token: CancellationToken) -> Result<()> {
    let config = &state.config;
    println!("正在启动接口 {} 喵...", config.interface);

    println!("使用公钥: {} 喵！", state.pub_key_b64());

    // 2. 状态预清理：强制删除旧接口、清理缓存、杀死残留侧车喵
    cleanup_interface_state(&config.interface).await;
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
        if !config.use_multi_queue {
            cmd.arg("--disable-multi-queue");
        }
    }
    if !config.enable_udp_gro {
        cmd.arg("--disable-udp-gro");
    }
    if config.mode == "tcp" || config.mode == "mullvad-tcp" {
        cmd.arg("--tcp");
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

        // 转换私钥格式（Base64 -> Hex for UAPI）
        let priv_hex = base64_to_hex(&state.priv_b64);
        let mut uapi_cmd = format!("set=1\nprivate_key={}\n", priv_hex);
        if let Some(port) = config.listen_port {
            uapi_cmd.push_str(&format!("listen_port={}\n", port));
        }
        uapi_cmd.push('\n');

        send_uapi(&config.interface, &uapi_cmd).await.context("配置私钥失败")?;
    }

    println!("正在设置 MTU {} 到 {}...", mtu, config.interface);
    run_cmd(&format!("ip link set mtu {} dev {}", mtu, config.interface)).context("设置 MTU 失败")?;

    println!("正在开启网卡 {} 的多播 (Multicast) 魔法喵...", config.interface);
    if let Err(e) = run_cmd(&format!("ip link set dev {} multicast on", config.interface)) {
        eprintln!("警告：开启多播失败喵（部分环境可能不支持）: {:?}", e);
    }

    println!("正在启用网卡 {} 喵...", config.interface);
    run_cmd(&format!("ip link set up dev {}", config.interface)).context("启用网卡失败")?;
    
    // 支持多个地址（逗号分隔），同时配置 IPv4 和 IPv6 喵
    let addresses: Vec<&str> = config.local_address.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    for addr in &addresses {
        println!("正在配置 IP 地址 {} 到 {}...", addr, config.interface);
        let _ = run_cmd(&format!("ip addr del {} dev {} 2>/dev/null", addr, config.interface));
        if let Err(e) = run_cmd(&format!("ip addr add {} dev {}", addr, config.interface)) {
            eprintln!("喵呜... 添加地址 {} 失败: {:?}", addr, e);
        }
    }

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
    
    // WireGuard 兼容模式：直接从配置文件配置 Peers，不等待信令喵
    if config.native_wg_compat {
        println!("喵！检测到 WireGuard 原生兼容模式，正在直接配置 Peers...");
        for peer in &config.peers {
            if let Some(ref pub_key) = peer.public_key {
                let allowed_ips = peer.allowed_ips.as_deref().unwrap_or("0.0.0.0/0, ::/0");
                let keepalive = peer.persistent_keepalive.or(config.persistent_keepalive);
                
                // 转换公钥格式（Base64 -> Hex for UAPI）
                let pub_key_hex = base64_to_hex(pub_key);
                
                let mut uapi_cmd = format!(
                    "set=1\npublic_key={}\n",
                    pub_key_hex
                );
                
                // 配置允许的 IP
                for ip in allowed_ips.split(',').map(|s| s.trim()) {
                    if !ip.is_empty() {
                        uapi_cmd.push_str(&format!("allowed_ip={}\n", ip));
                    }
                }
                
                // 配置 Endpoint
                // 配置 Endpoint (支持域名解析喵)
                if !peer.endpoint.is_empty() {
                    let resolved_endpoint = if let Ok(mut addrs) = tokio::net::lookup_host(&peer.endpoint).await {
                        if let Some(addr) = addrs.next() {
                            addr.to_string()
                        } else {
                            peer.endpoint.clone()
                        }
                    } else {
                        peer.endpoint.clone()
                    };
                    uapi_cmd.push_str(&format!("endpoint={}\n", resolved_endpoint));
                }
                
                // 配置 Keepalive
                if let Some(ka) = keepalive {
                    uapi_cmd.push_str(&format!("persistent_keepalive_interval={}\n", ka));
                }
                
                // 配置 PresharedKey（隧道层加密，与 NekoLink 的 psk 不同）
                if let Some(ref psk) = peer.preshared_key {
                    let psk_hex = base64_to_hex(psk);
                    uapi_cmd.push_str(&format!("preshared_key={}\n", psk_hex));
                }
                
                uapi_cmd.push('\n');
                
                match send_uapi(&config.interface, &uapi_cmd).await {
                    Ok(_) => println!("喵！成功配置 Peer: {} (Endpoint: {})", pub_key, peer.endpoint),
                    Err(e) => eprintln!("喵呜... 配置 Peer {} 失败: {:?}", pub_key, e),
                }
            } else {
                println!("喵？跳过没有公钥的 Peer (endpoint: {})", peer.endpoint);
            }
        }
        println!("喵！WireGuard 兼容模式配置完成，共配置了 {} 个 Peer。", config.peers.len());
    }
    
    // Mullvad TCP 模式：启动服务端侧车 tcp2udp 喵
    let mut mullvad_sidecar: Option<tokio::process::Child> = None;
    if config.mode == "mullvad-tcp" {
        let is_server = config.peers.is_empty() || config.peers.iter().all(|p| p.endpoint.is_empty());
        
        if is_server {
            let wg_port = get_actual_listen_port(&config.interface).unwrap_or(51820);
            let effective_port = config.mullvad_tcp_port;
            
            println!("喵！检测到 Mullvad TCP 服务端模式，正在启动 tcp2udp...");
            let mut cmd = tokio::process::Command::new("tcp2udp");
            cmd.arg("--tcp-listen").arg(format!("0.0.0.0:{}", effective_port))
               .arg("--udp-forward").arg(format!("127.0.0.1:{}", wg_port))
               .kill_on_drop(true);
            
            match cmd.spawn() {
                Ok(child) => {
                    println!("喵！tcp2udp 已启动：监听 TCP {} -> 转发到 UDP 127.0.0.1:{}", effective_port, wg_port);
                    mullvad_sidecar = Some(child);
                }
                Err(e) => eprintln!("喵呜... 无法启动 tcp2udp: {:?}", e),
            }
        }
        // 客户端模式：udp2tcp 将由 NekoState.client_sidecar 在 configure_peer 中启动和管理喵
    }
    
    // 启动 SOCKS5 代理服务喵
    let mut socks5_task: Option<(tokio::task::JoinHandle<Result<()>>, CancellationToken)> = None;
    if let Some(_s5_port) = config.socks5_port {
        let _iface = config.interface.clone();
        let s5_token = CancellationToken::new();
        let s5_token_clone = s5_token.clone();
        
        // 尝试解析本地隧道 IP 用于绑定喵 (Source IP Binding)
        let local_ip = config.local_address.split('/').next().and_then(|s| s.parse::<IpAddr>().ok());
        
        let state_clone = state.clone();
        let task = tokio::spawn(async move {
            if let Err(e) = run_socks5_server(state_clone.clone(), s5_token_clone, local_ip).await {
                eprintln!("ฅ^•ﻌ•^ctl SOCKS5 服务 ({}) 启动失败喵: {:?}", state_clone.config.interface, e);
                return Err(e);
            }
            Ok(())
        });
        socks5_task = Some((task, s5_token));
    }
    
    // 监控进程与取消信号喵
    tokio::select! {
        _ = child.wait() => {
            println!("nekolink-cli 进程已退出喵。");
        }
        _ = token.cancelled() => {
            println!("接收到中转停止信号，正在关闭接口 {} 喵...", config.interface);
            let _ = child.kill().await;
        }
    }

    // 清理 SOCKS5 任务喵
    if let Some((task, s5_token)) = socks5_task {
        s5_token.cancel();
        let _ = task.await;
    }

    // 清理 Mullvad 侧车
    if let Some(mut srv) = mullvad_sidecar {
        println!("正在关闭 Mullvad TCP 侧车喵...");
        let _ = srv.kill().await;
    }

    println!("正在清理接口 {} 喵...", config.interface);
    if config.clamp_mss {
        let table_name = format!("nekolink_mss_{}", config.interface);
        let _ = run_cmd(&format!("nft delete table inet {} 2>/dev/null", table_name));
    }
    let _ = run_cmd(&format!("ip link del {} 2>/dev/null", config.interface));
    
    // (此处原为清理 udp2raw 规则的代码喵)

    Ok(())
}

async fn run_socks5_server(state: NekoState, token: CancellationToken, local_ip: Option<IpAddr>) -> Result<()> {
    let config = &state.config;
    let global = &state.global_config;
    let mut listen_addrs = Vec::new();

    // 1. 检查是否有精准绑定地址喵 (支持逗号分隔多个 IP)
    if let Some(ref bind_addr_str) = config.socks5_bind_addr {
        let addr_list: Vec<&str> = bind_addr_str.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
        for ip_str in addr_list {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                listen_addrs.push(SocketAddr::new(ip, config.socks5_port.unwrap()));
            } else {
                eprintln!("警告：接口 {} 的 socks5_bind_addr 部分 '{}' 解析失败喵。", config.interface, ip_str);
            }
        }
    } else {
        // 2. 默认兼容逻辑：本地监听 + 环回池监听
        if config.socks5_listen_local {
            listen_addrs.push(SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), config.socks5_port.unwrap()));
        }

        if config.socks5_listen_loopback {
            if let Some(ref loopback_addrs) = global.loopback_address {
                let addr_list: Vec<&str> = loopback_addrs.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
                for addr_str in addr_list {
                    let ip_str = addr_str.split('/').next().unwrap();
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        listen_addrs.push(SocketAddr::new(ip, config.socks5_port.unwrap()));
                    }
                }
            }
        }
    }

    if listen_addrs.is_empty() {
        println!("警告：接口 {} 的 SOCKS5 服务未配置任何监听地址，跳过启动喵。", config.interface);
        return Ok(());
    }

    let mut listeners = Vec::new();
    for addr in listen_addrs {
        match TcpListener::bind(addr).await {
            Ok(l) => {
                println!("ฅ^•ﻌ•^ctl SOCKS5 代理监听中：{} -> {} (出口绑定: {:?}) 喵。", addr, config.interface, local_ip);
                listeners.push(l);
            },
            Err(e) => eprintln!("警告：连接网口 {} 失败，无法绑定 SOCKS5 监听地址 {}: {:?} 喵。", config.interface, addr, e),
        }
    }

    if listeners.is_empty() {
        return Err(anyhow::anyhow!("所有 SOCKS5 监听地址均绑定失败喵"));
    }

    loop {
        let mut futures = Vec::new();
        for l in &listeners {
            futures.push(Box::pin(l.accept()));
        }

        tokio::select! {
            _ = token.cancelled() => break,
            (res, _index, _remaining) = futures::future::select_all(futures) => {
                if let Ok((mut client_stream, peer_addr)) = res {
                    let iface = config.interface.clone();
                    let l_ip = local_ip;
                    tokio::spawn(async move {
                        if let Err(e) = handle_socks5(&iface, &mut client_stream, l_ip).await {
                             tracing::debug!("SOCKS5 处理异常 (来自 {}): {:?} 喵", peer_addr, e);
                        }
                    });
                }
            }
        }
    }
    println!("ฅ^•ﻌ•^ctl SOCKS5 代理 ({}) 已关闭喵。", config.interface);
    Ok(())
}

async fn handle_socks5(interface: &str, client: &mut TcpStream, local_ip: Option<IpAddr>) -> Result<()> {
    let _ = client.set_nodelay(true); // 提升交互响应速度喵
    let mut buf = [0u8; 512];
    
    // 1. Handshake
    client.read_exact(&mut buf[..2]).await?;
    if buf[0] != 0x05 { return Err(anyhow::anyhow!("Not SOCKS5")); }
    let nmethods = buf[1] as usize;
    client.read_exact(&mut buf[..nmethods]).await?;
    client.write_all(&[0x05, 0x00]).await?; // No auth

    // 2. Request
    client.read_exact(&mut buf[..4]).await?;
    let cmd = buf[1];
    
    if cmd == 0x01 { // CONNECT
        let target_addr: String = match buf[3] {
            0x01 => { // IPv4
                client.read_exact(&mut buf[..4]).await?;
                let ip = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                client.read_exact(&mut buf[..2]).await?;
                let port = u16::from_be_bytes([buf[0], buf[1]]);
                format!("{}:{}", ip, port)
            }
            0x03 => { // Domain
                client.read_exact(&mut buf[..1]).await?;
                let len = buf[0] as usize;
                client.read_exact(&mut buf[..len]).await?;
                let domain = String::from_utf8_lossy(&buf[..len]).to_string();
                client.read_exact(&mut buf[..2]).await?;
                let port = u16::from_be_bytes([buf[0], buf[1]]);
                format!("{}:{}", domain, port)
            }
            0x04 => { // IPv6
                 client.read_exact(&mut buf[..16]).await?;
                 let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&buf[..16]).unwrap());
                 client.read_exact(&mut buf[..2]).await?;
                 let port = u16::from_be_bytes([buf[0], buf[1]]);
                 format!("[{}]:{}", ip, port)
            }
            _ => return Err(anyhow::anyhow!("Unsupported address type")),
        };

        // 3. Connect to target through interface
        let mut target_stream = match connect_via_interface(interface, &target_addr, local_ip).await {
            Ok(s) => {
                // SOCKS5 响应: 成功
                client.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                s
            }
            Err(_e) => {
                // SOCKS5 响应: 失败
                let _ = client.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                return Err(anyhow::anyhow!("Connect failed to {}: {:?}", target_addr, _e));
            }
        };

        // 4. Relay
        let _ = copy_bidirectional(client, &mut target_stream).await;
    } else if cmd == 0x03 { // UDP ASSOCIATE
        // 绑定一个用于中转的 UDP 端口喵
        let relay_socket = UdpSocket::bind("127.0.0.1:0").await?;
        let relay_port = relay_socket.local_addr()?.port();
        
        // 解析客户端可能提供的源地址（通常忽略，但由于协议要求需要读取喵）
        let _source_addr: String = match buf[3] {
            0x01 => { client.read_exact(&mut buf[..6]).await?; "ipv4".into() }
            0x03 => { client.read_exact(&mut buf[..1]).await?; let len = buf[0] as usize; client.read_exact(&mut buf[..len+2]).await?; "domain".into() }
            0x04 => { client.read_exact(&mut buf[..18]).await?; "ipv6".into() }
            _ => return Err(anyhow::anyhow!("Unsupported address type for UDP Associate")),
        };

        // 响应客户端：服务端监听的 UDP 端口喵
        client.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, (relay_port >> 8) as u8, (relay_port & 0xFF) as u8]).await?;

        // 开启 UDP 中转逻辑喵
        let tunnel_socket = connect_via_interface_udp(interface, local_ip).await?;
        let mut client_relay_buf = [0u8; 2048];
        let mut tunnel_relay_buf = [0u8; 2048];
        let mut client_udp_addr: Option<SocketAddr> = None;

        loop {
            tokio::select! {
                // TCP 连接关闭信号喵
                n = client.read(&mut buf) => {
                    if n.is_err() || n.unwrap() == 0 { break; }
                }
                // 从客户端接收 UDP 数据并剥离头发往隧道喵
                Ok((n, addr)) = relay_socket.recv_from(&mut client_relay_buf) => {
                    if client_udp_addr.is_none() { client_udp_addr = Some(addr); }
                    if Some(addr) == client_udp_addr {
                        if let Ok((header_len, target_addr)) = parse_socks5_udp_header(&client_relay_buf[..n], interface).await {
                            let _ = tunnel_socket.send_to(&client_relay_buf[header_len..n], target_addr).await;
                        }
                    }
                }
                // 从隧道接收 UDP 数据并封装头发回客户端喵
                Ok((n, addr)) = tunnel_socket.recv_from(&mut tunnel_relay_buf) => {
                    if let Some(c_addr) = client_udp_addr {
                        let mut resp = Vec::with_capacity(n + 32);
                        append_socks5_udp_header(&mut resp, addr);
                        resp.extend_from_slice(&tunnel_relay_buf[..n]);
                        let _ = relay_socket.send_to(&resp, c_addr).await;
                    }
                }
            }
        }
    } else {
        return Err(anyhow::anyhow!("Only CONNECT and UDP ASSOCIATE supported"));
    }
    
    Ok(())
}

async fn parse_socks5_udp_header(buf: &[u8], interface: &str) -> Result<(usize, SocketAddr)> {
    if buf.len() < 4 { return Err(anyhow::anyhow!("UDP header too short")); }
    if buf[2] != 0x00 { return Err(anyhow::anyhow!("Fragments not supported")); }
    
    let atyp = buf[3];
    match atyp {
        0x01 => { // IPv4
            if buf.len() < 10 { return Err(anyhow::anyhow!("UDP header too short for IPv4")); }
            let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            Ok((10, SocketAddr::new(IpAddr::V4(ip), port)))
        }
        0x03 => { // Domain
            let len = buf[4] as usize;
            if buf.len() < 5 + len + 2 { return Err(anyhow::anyhow!("UDP header too short for Domain")); }
            let domain = String::from_utf8_lossy(&buf[5..5+len]).to_string();
            let port = u16::from_be_bytes([buf[5+len], buf[5+len+1]]);
            // 异步解析 DNS 喵 (使用可信隧道解析)
            let ip = resolve_dns(&domain, Some(interface), false).await?;
            Ok((5 + len + 2, SocketAddr::new(ip, port)))
        }
        0x04 => { // IPv6
            if buf.len() < 22 { return Err(anyhow::anyhow!("UDP header too short for IPv6")); }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&buf[4..20]);
            let ip = std::net::Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            Ok((22, SocketAddr::new(IpAddr::V6(ip), port)))
        }
        _ => Err(anyhow::anyhow!("Unsupported address type in UDP header")),
    }
}

fn append_socks5_udp_header(buf: &mut Vec<u8>, addr: SocketAddr) {
    buf.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV + FRAG
    match addr {
        SocketAddr::V4(v4) => {
            buf.push(0x01); // ATYP IPv4
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            buf.push(0x04); // ATYP IPv6
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
}

async fn connect_via_interface(interface: &str, target: &str, local_ip: Option<IpAddr>) -> Result<TcpStream> {
    // 异步 DNS 解析喵
    let (host, port_str) = target.rsplit_once(':').ok_or(anyhow::anyhow!("不合法的目标地址: {}", target))?;
    let port: u16 = port_str.parse()?;
    
    let ip = if let Ok(parsed_ip) = host.parse::<IpAddr>() {
        parsed_ip
    } else {
        // TCP 模式下也使用可信解析喵
        resolve_dns(host, Some(interface), false).await?
    };
    let addr = SocketAddr::new(ip, port);
    
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    
    // Bind to device (SO_BINDTODEVICE)
    socket.bind_device(Some(interface.as_bytes()))?;
    
    // 如果指定了本地 IP，则进行显式绑定喵
    if let Some(lip) = local_ip {
        if (lip.is_ipv4() && addr.is_ipv4()) || (lip.is_ipv6() && addr.is_ipv6()) {
            let bind_addr: SocketAddr = SocketAddr::new(lip, 0);
            let _ = socket.bind(&bind_addr.into());
        }
    }

    socket.set_nodelay(true)?; // 降低小包延迟喵
    socket.set_tcp_keepalive(&socket2::TcpKeepalive::new().with_time(Duration::from_secs(60)))?; // 开启 Keepalive 防止死连接喵
    socket.set_nonblocking(true)?;
    
    match socket.connect(&addr.into()) {
        Ok(_) => {},
        Err(e) => {
            if e.raw_os_error() != Some(libc::EINPROGRESS) {
                return Err(e.into());
            }
        }
    }
    
    let stream = TcpStream::from_std(socket.into())?;
    
    // 增加连接超时机制 (10秒)，防止被墙时无限等待喵
    if time::timeout(Duration::from_secs(10), stream.writable()).await.is_err() {
        return Err(anyhow::anyhow!("连接超时喵 (可能是被阻断或网络不通)"));
    }
    
    if let Some(e) = stream.take_error()? {
        return Err(e.into());
    }
    Ok(stream)
}

async fn connect_via_interface_udp(interface: &str, local_ip: Option<IpAddr>) -> Result<UdpSocket> {
    let domain = if local_ip.map_or(true, |ip| ip.is_ipv4()) { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    
    // Bind to device (SO_BINDTODEVICE)
    socket.bind_device(Some(interface.as_bytes()))?;
    
    // 如果指定了本地 IP，则进行显式绑定喵
    if let Some(lip) = local_ip {
        let bind_addr: SocketAddr = SocketAddr::new(lip, 0);
        let _ = socket.bind(&bind_addr.into());
    }

    socket.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(socket.into())?)
}


async fn run_global_udp_signaling_dynamic(instances: Arc<tokio::sync::RwLock<HashMap<String, InstanceHandle>>>, signal_port: u16, token: CancellationToken) -> Result<()> {
    // 全局绑定
    let std_socket = std::net::UdpSocket::bind(format!("0.0.0.0:{}", signal_port))?;
    std_socket.set_nonblocking(true)?;
    let socket = Arc::new(tokio::net::UdpSocket::from_std(std_socket)?);

    let send_task = {
        let instances = Arc::clone(&instances);
        let socket = Arc::clone(&socket);
        async move {
            loop {
                // 快照当前实例列表喵
                let current_states: Vec<NekoState> = {
                    let lock = instances.read().await;
                    lock.values().map(|h| h.state.clone()).collect()
                };

                for state in current_states {
                    // 跳过非 UDP 模式、空公钥、以及 WireGuard 兼容模式的接口喵
                    if state.config.mode != "udp" || state.pub_key.as_bytes() == &[0u8; 32] || state.config.native_wg_compat { continue; }
                    
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

                        // 端口优先级: peer > interface > global 喵
                        let target_port = peer.signal_port
                            .or(state.config.signal_port)
                            .unwrap_or(state.global_config.signal_port);

                        // 使用统一的endpoint解析函数喵
                        let addr_opt = match resolve_endpoint_with_port(
                            &peer.endpoint,
                            target_port,
                            state.config.prefer_ipv6
                        ).await {
                            Ok(addr) => Some(addr),
                            Err(e) => {
                                eprintln!("警告喵: 无法解析 endpoint {}: {:?}", peer.endpoint, e);
                                None
                            }
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
                                    // println!("喵！已向对端 {} 主动推送 {} (UDP) 信令盒。", addr, signal_port);
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
        let instances = Arc::clone(&instances);
        let socket = Arc::clone(&socket);
        async move {
            let mut buf = [0u8; 1024];
            loop {
                if let Ok((len, addr)) = socket.recv_from(&mut buf).await {
                    if len < 12 + 32 { continue; }
                    let (nonce_part, encrypted_part) = buf[..len].split_at(12);
                    let nonce = Nonce::from_slice(nonce_part);

                    let current_states: Vec<NekoState> = {
                        let lock = instances.read().await;
                        lock.values().map(|h| h.state.clone()).collect()
                    };

                    for state in current_states {
                        // 跳过非 UDP 模式和 WireGuard 兼容模式的接口喵
                        if state.config.mode != "udp" || state.config.native_wg_compat { continue; }
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
                                let _ = configure_peer(&state.config.interface, &peer_pub_key, endpoint, state.config.persistent_keepalive, peer_mtu, state.config.mtu == Some(0), &state.config.mode, 0, &state.config.psk, Some(state.client_sidecar.clone())).await;
                                
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
        _ = token.cancelled() => {},
        _ = send_task => {},
        _ = recv_task => {},
    }
    Ok(())
}

async fn run_global_tcp_signaling_dynamic(instances: Arc<tokio::sync::RwLock<HashMap<String, InstanceHandle>>>, signal_port: u16, token: CancellationToken) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", signal_port)).await?;
    let bound_port = listener.local_addr()?.port();
    if signal_port == 0 {
        println!("ฅ^•ﻌ•^ฅ TCP 信令管线就绪，已绑定到随机端口 {} 喵。", bound_port);
    } else {
        println!("ฅ^•ﻌ•^ฅ TCP 信令管线就绪，正在监听 {} 端口喵。", bound_port);
    }

    println!("ฅ^•ﻌ•^ฅ TCP 信令管线就绪，正在监听 {} 端口喵。", signal_port);

    let send_task = {
        let instances = Arc::clone(&instances);
        async move {
            loop {
                let current_states: Vec<NekoState> = {
                    let lock = instances.read().await;
                    lock.values().map(|h| h.state.clone()).collect()
                };

                for state in current_states {
                    let established = get_established_peers(&state.config.interface).await;
                    // 跳过空公钥、以及 WireGuard 兼容模式的接口喵
                    if state.pub_key.as_bytes() == &[0u8; 32] || state.config.native_wg_compat {
                        continue;
                    }
                    // 仅处理 TCP 相关模式喵
                    if state.config.mode != "tcp" && state.config.mode != "mullvad-tcp" {
                        continue;
                    }
                    
                    if !established.is_empty() {
                        continue;
                    }

                    let cipher = derive_cipher(&state.config.psk);
                    let pub_key_bytes = state.pub_key.as_bytes().to_vec();
                    let interface = state.config.interface.clone();
                    
                    for peer in &state.config.peers {
                        // 端口优先级: peer > interface > global 喵
                        let target_port = peer.signal_port
                            .or(state.config.signal_port)
                            .unwrap_or(state.global_config.signal_port);

                        // 使用统一的endpoint解析函数喵
                        let addr_opt = match resolve_endpoint_with_port(
                            &peer.endpoint,
                            target_port,
                            state.config.prefer_ipv6
                        ).await {
                            Ok(addr) => Some(addr),
                            Err(e) => {
                                eprintln!("警告喵: TCP 无法解析 endpoint {}: {:?}", peer.endpoint, e);
                                None
                            }
                        };

                        if let Some(addr) = addr_opt {
                            let cipher = cipher.clone();
                            let pub_key_bytes = pub_key_bytes.clone();
                            let interface_inner = interface.clone();
                            let is_raw_ip_mode = state.config.mode == "ip";
                            let mode_inner = state.config.mode.clone();
                            let psk_inner = state.config.psk.clone();
                            let auto_mtu_enabled = state.config.mtu == Some(0);
                            let local_tcp_data_port = state.config.mullvad_tcp_port;
                            let client_sidecar_clone = state.client_sidecar.clone();
                            
                            tokio::spawn(async move {
                                // println!("喵！正在发起 TCP 信令连接: {}...", addr);
                                match time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(addr)).await {
                                    Ok(Ok(mut stream)) => {
                                        // println!("喵！TCP 信令连接已建立: {}", addr);
                                        let current_mtu = if is_raw_ip_mode {
                                            if auto_mtu_enabled { get_auto_mtu(&addr.ip().to_string(), "ip").await } else { get_interface_mtu(&interface_inner).unwrap_or(1420) }
                                        } else {
                                            if auto_mtu_enabled { get_auto_mtu(&addr.ip().to_string(), "tcp").await } else { get_interface_mtu(&interface_inner).unwrap_or(1420) }
                                        };
                                        let actual_tunnel_port = if mode_inner == "mullvad-tcp" { local_tcp_data_port } else { get_actual_listen_port(&interface_inner).unwrap_or(0) };

                                        let mut msg = pub_key_bytes.clone();
                                        msg.extend_from_slice(&current_mtu.to_be_bytes());
                                        msg.extend_from_slice(&actual_tunnel_port.to_be_bytes());
                                        
                                        // 原本的 Fake-TCP 端口逻辑已移除喵

                                        let mut nonce_bytes = [0u8; 12];
                                        OsRng.fill_bytes(&mut nonce_bytes);
                                        if let Ok(ciphertext) = cipher.encrypt(Nonce::from_slice(&nonce_bytes), msg.as_slice()) {
                                            let mut pkt = nonce_bytes.to_vec();
                                            pkt.extend_from_slice(&ciphertext);
                                            if tokio::io::AsyncWriteExt::write_all(&mut stream, &pkt).await.is_ok() {
                                                // println!("喵！已向对端推送 12580 信令，等待服务端 Ack...");
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
                                                                                 
                                                                                 // 识别下层端口信息喵
                                                                                 let _peer_lower_port = 0;

                                                                                 if peer_tunnel_port == 0 && !is_raw_ip_mode {
                                                                                     return;
                                                                                 }

                                                                                 let mut endpoint = addr.ip().to_string();
                                                                                 if peer_tunnel_port > 0 {
                                                                                     endpoint = format!("{}:{}", endpoint, peer_tunnel_port);
                                                                                 }
                                                                                 
                                                                                 println!("喵！成功接收 TCP 信令响应 (ACK)：来自 {} (传输模式: {})", endpoint, mode_inner);
                                                                                 
                                                                                 let _ = configure_peer(&interface_inner, &peer_pub_key, endpoint, None, peer_mtu, true, &mode_inner, 0, &psk_inner, Some(client_sidecar_clone)).await;
                                                                            }
                                                                        }
                                                                    },
                                                                    _ => {}
                                                                }
                                            }
                                        }
                                    },
                                    _ => {}
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
        let instances = Arc::clone(&instances);
        async move {
            loop {
                if let Ok((mut stream, addr)) = listener.accept().await {
                    let instances = Arc::clone(&instances);
                    tokio::spawn(async move {
                        let mut buf = [0u8; 256];
                        if let Ok(Ok(len)) = time::timeout(Duration::from_secs(5), tokio::io::AsyncReadExt::read(&mut stream, &mut buf)).await {
                            if len >= 12 + 32 {
                                let (nonce_part, encrypted_part) = buf[..len].split_at(12);
                                let nonce = Nonce::from_slice(nonce_part);
                                
                                let current_states: Vec<NekoState> = {
                                    let lock = instances.read().await;
                                    lock.values().map(|h| h.state.clone()).collect()
                                };

                                for state in current_states {
                                    // 跳过非 TCP 模式和 WireGuard 兼容模式的接口喵
                                    if state.config.mode != "tcp" && state.config.mode != "mullvad-tcp" || state.config.native_wg_compat { continue; }
                                    let cipher = derive_cipher(&state.config.psk);
                                    if let Ok(decrypted) = cipher.decrypt(nonce, encrypted_part) {
                                        if decrypted.len() >= 36 {
                                             let peer_pub_key = BASE64.encode(&decrypted[..32]);
                                             let peer_mtu = Some(u16::from_be_bytes([decrypted[32], decrypted[33]]));
                                             let peer_tunnel_port = u16::from_be_bytes([decrypted[34], decrypted[35]]);
                                             
                                             let _peer_lower_port = 0;
                                            
                                            if peer_tunnel_port == 0 && state.config.mode != "ip" {
                                                continue;
                                            }
                                            let mut endpoint = addr.ip().to_string();
                                            if peer_tunnel_port > 0 {
                                                endpoint = format!("{}:{}", endpoint, peer_tunnel_port);
                                            }

                                            println!("喵！12580 (TCP) 识别成功：{} -> {} (传输模式: {})", endpoint, state.config.interface, state.config.mode);
                                            // 使用对端的下层端口（如果协商到的话）
                                            let _ = configure_peer(&state.config.interface, &peer_pub_key, endpoint, state.config.persistent_keepalive, peer_mtu, state.config.mtu == Some(0), &state.config.mode, 0, &state.config.psk, Some(state.client_sidecar.clone())).await;
                                            
                                            // TCP 握手响应喵！直接在当前流回发
                                            let msg_base = state.pub_key.as_bytes().to_vec();
                                            let current_mtu = if state.config.mtu == Some(0) { 
                                                get_auto_mtu(&addr.ip().to_string(), &state.config.mode).await 
                                            } else { 
                                                get_interface_mtu(&state.config.interface).unwrap_or(1420) 
                                            };
                                             let actual_tunnel_port = if state.config.mode == "mullvad-tcp" { state.config.mullvad_tcp_port } else { get_actual_listen_port(&state.config.interface).unwrap_or(0) };
                                             let mut resp_msg = msg_base;
                                             resp_msg.extend_from_slice(&current_mtu.to_be_bytes());
                                             resp_msg.extend_from_slice(&actual_tunnel_port.to_be_bytes());
                                             
                                             // 原本的 Fake-TCP 端口逻辑已移除喵
                                            
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
        _ = token.cancelled() => {},
        _ = send_task => {},
        _ = recv_task => {},
    }
    Ok(())
}

async fn run_global_raw_signaling_dynamic(instances: Arc<tokio::sync::RwLock<HashMap<String, InstanceHandle>>>, proto: u8, token: CancellationToken) -> Result<()> {
    let v4_socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(proto as i32))).ok();
    
    let v4_socket = v4_socket.map(|s| { s.set_nonblocking(true).unwrap(); Arc::new(tokio::io::unix::AsyncFd::new(s).unwrap()) });

    let magic_byte: u8 = 0x99;

    let send_task = {
        let instances = Arc::clone(&instances);
        let v4_socket = v4_socket.clone();
        async move {
            loop {
                // 快照当前实例列表喵
                let current_states: Vec<NekoState> = {
                    let lock = instances.read().await;
                    lock.values().map(|h| h.state.clone()).collect()
                };

                for state in current_states {
                    let st_proto = state.config.ip_protocol.unwrap_or(141);
                    // 跳过非 Raw IP 模式、协议不匹配、空公钥、以及 WireGuard 兼容模式的接口喵
                    if state.config.mode != "ip" || st_proto != proto || state.pub_key.as_bytes() == &[0u8; 32] || state.config.native_wg_compat { continue; }
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
                            // 使用统一的DNS解析函数喵
                            match resolve_dns(&peer.endpoint, None, state.config.prefer_ipv6).await {
                                Ok(ip) => Some(ip),
                                Err(e) => {
                                    eprintln!("警告喵: Raw IP 模式无法解析 {}: {:?}", peer.endpoint, e);
                                    None
                                }
                            }
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
        let instances = Arc::clone(&instances);
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

                                 let current_states: Vec<NekoState> = {
                                     let lock = instances.read().await;
                                     lock.values().map(|h| h.state.clone()).collect()
                                 };

                                 for state in current_states {
                                     let st_proto = state.config.ip_protocol.unwrap_or(141);
                                     // 跳过非 Raw IP 模式、协议不匹配、以及 WireGuard 兼容模式的接口喵
                                     if state.config.mode != "ip" || st_proto != proto || state.config.native_wg_compat { continue; }
                                     let cipher = derive_cipher(&state.config.psk);
                                     if let Ok(decrypted) = cipher.decrypt(nonce, encrypted) {
                                         let ip_addr = addr.as_socket().map(|s| s.ip()).unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                                         let peer_mtu = if decrypted.len() >= 34 { Some(u16::from_be_bytes([decrypted[32], decrypted[33]])) } else { None };
                                         println!("喵！12580 (Raw IP) 识别成功：{} -> {}", ip_addr, state.config.interface);
                                         let _ = configure_peer(&state.config.interface, &BASE64.encode(&decrypted[..32]), ip_addr.to_string(), state.config.persistent_keepalive, peer_mtu, state.config.mtu == Some(0), "ip", 0, &state.config.psk, Some(state.client_sidecar.clone())).await;
 
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
        _ = token.cancelled() => {},
        _ = send_task => {},
        _ = recv_task => {},
    }
    Ok(())
}

/// 将 Base64 编码的密钥转换为 Hex 格式（UAPI 需要）喵
fn decode_base64(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if let Ok(b) = BASE64.decode(s) {
        return Ok(b);
    }
    // 如果标准解码失败，尝试智能纠正填充符（Padding）喵
    let mut padded = s.to_string();
    padded = padded.trim_end_matches('=').to_string();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    BASE64.decode(&padded).context("Base64 格式无效，即便尝试补齐填充后依然无法解码喵")
}

fn base64_to_hex(b64: &str) -> String {
    match decode_base64(b64) {
        Ok(bytes) => bytes.iter().map(|b| format!("{:02x}", b)).collect(),
        Err(_) => b64.to_string(), // 如果解码失败，保持原样喵
    }
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

// 原 udp2raw 逻辑已由 Mullvad TCP 侧车方案替代喵


async fn configure_peer(interface: &str, peer_pub_key: &str, mut endpoint: String, keepalive: Option<u16>, peer_mtu: Option<u16>, auto_sync_mtu: bool, mode: &str, _tcp_data_port: u16, _psk: &str, client_sidecar: Option<Arc<parking_lot::Mutex<Option<tokio::process::Child>>>>) -> Result<()> {
    // 尝试解析域名端点喵
    if !endpoint.is_empty() {
        let resolved = if let Ok(mut addrs) = tokio::net::lookup_host(&endpoint).await {
            addrs.next().map(|a| a.to_string())
        } else {
            None
        };
        if let Some(r) = resolved {
            endpoint = r;
        }
    }
    // 保存原始探测地址喵（防止被 127.0.0.1 覆盖后无法探测 PMTU）
    let probe_address_orig = endpoint.clone();
    
    // Mullvad TCP 模式特殊处理喵
    if mode == "mullvad-tcp" && !endpoint.is_empty() && !endpoint.starts_with("127.0.0.1") {
        let wg_port = get_actual_listen_port(interface).unwrap_or(51820);
        let bridge_port = wg_port + 1;
        let remote_addr = endpoint.clone();
        
        // 确保 udp2tcp 正在运行并连向对端喵
        println!("喵！正在建立 Mullvad TCP 桥接: 127.0.0.1:{} -> {}", bridge_port, remote_addr);
        
        let mut cmd = tokio::process::Command::new("udp2tcp");
        cmd.arg("--udp-listen").arg(format!("127.0.0.1:{}", bridge_port))
           .arg("--tcp-forward").arg(&remote_addr)
           .kill_on_drop(true);
        
        // 如果提供了 client_sidecar，就将进程句柄存储起来喵
        if let Some(sidecar_ref) = client_sidecar {
            match cmd.spawn() {
                Ok(child) => {
                    println!("喵！udp2tcp 进程已启动并托管 (PID: {:?})", child.id());
                    *sidecar_ref.lock() = Some(child);
                }
                Err(e) => eprintln!("喵呜... 无法启动 udp2tcp: {:?}", e),
            }
        }
        // 服务端不会提供 client_sidecar，因此不会启动 udp2tcp 喵
        
        // 修改 WireGuard 的 Endpoint 为本地网桥喵
        endpoint = format!("127.0.0.1:{}", bridge_port);
    }

    let probe_address = if endpoint.starts_with("127.0.0.1") { probe_address_orig } else { endpoint.clone() };


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

    // 转换公钥格式（Base64 -> Hex for UAPI）
    let peer_pub_key_hex = base64_to_hex(peer_pub_key);

    // 幂等保护：先删除旧 Peer 再添加喵
    let remove_cmd = format!("set=1\npublic_key={}\nremove=true\n\n", peer_pub_key_hex);
    let _ = send_uapi(interface, &remove_cmd).await; 

    let mut uapi_cmd = format!(
        "set=1\npublic_key={}\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\nendpoint={}\n",
        peer_pub_key_hex, endpoint
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
        // 智能同步逻辑喵：
        // 1. 如果开启了 auto_sync_mtu (MTU=0)，则必须同步喵。
        // 2. 如果没开启，但对端建议的值比我当前的 MTU 小，为了稳定性，我也应该“偷偷”同步一下喵（向下兼容逻辑）。
        let current_mtu = get_interface_mtu(interface).unwrap_or(1420);
        let should_sync = auto_sync_mtu || m < current_mtu;
        
        if should_sync {
            let probed_mtu = if auto_sync_mtu { Some(get_auto_mtu(&probe_address, mode).await) } else { None };
            let _ = sync_mtu_if_needed(interface, m, probed_mtu).await;
        }
    }
    Ok(())
}

async fn sync_mtu_if_needed(interface: &str, peer_mtu: u16, probed_mtu: Option<u16>) -> Result<()> {
    let current_mtu = get_interface_mtu(interface).unwrap_or(1420);
    
    let target_mtu = if let Some(p) = probed_mtu {
        // 全自动协商模式喵：取我方探测值和对方建议值的最小值
        let converged = u16::min(p, peer_mtu);
        println!("喵！MTU 协商判定: [我方探测 {}] vs [对方建议 {}] -> 计算收敛值为 {}。", p, peer_mtu, converged);
        converged
    } else {
        // 半自动模式喵：直接同步对方的值
        peer_mtu
    };

    if target_mtu < 1280 {
        // TCP/IP 最小 MTU 是 1280 喵，不能再低了
        return Ok(());
    }

    if current_mtu != target_mtu {
        println!("ฅ^•ﻌ•^ฅ 接口 {} 执行 MTU 魔法校准：{} -> {} (协商自队友建议)", interface, current_mtu, target_mtu);
        let _ = run_cmd(&format!("ip link set mtu {} dev {}", target_mtu, interface));
    } else {
        // println!("喵！接口 {} 的 MTU 已经是 {} 了，无需改动。", interface, current_mtu);
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

async fn cleanup_interface_state(interface: &str) {
    // 1. 清理 PEER_CACHE 喵
    if let Some(cache_mutex) = PEER_CACHE.get() {
        let mut cache = cache_mutex.lock().unwrap();
        cache.retain(|(iface, _), _| iface != interface);
    }


    
    // 3. 清理 PROBED_MTU_CACHE 喵 (由于 MTU 缓存是以 Endpoint 为 Key 的，目前不需要按接口清理，
    // 但是考虑到热重载可能有网络变动，保持它一段时间自动过期即可喵)
}

fn run_cmd(cmd: &str) -> Result<()> {
    let status = Command::new("sh").arg("-c").arg(cmd).status()?;
    if !status.success() {
        return Err(anyhow::anyhow!("命令失败: {}", cmd));
    }
    Ok(())
}

async fn setup_loopback_interface(global_config: &GlobalConfig) -> Result<()> {
    if let Some(ref iface) = global_config.loopback_interface {
        println!("ฅ^•ﻌ•^ctl 正在设置全局 Loopback 接口 {} 喵...", iface);
        
        // 如果接口不存在则创建 (dummy 类型)
        let check_exists = Command::new("ip").arg("link").arg("show").arg(iface).status();
        if check_exists.is_err() || !check_exists.unwrap().success() {
            println!("正在创建 dummy 接口 {} 喵...", iface);
            run_cmd(&format!("ip link add {} type dummy", iface))?;
        }
        
        // 设置为 up
        run_cmd(&format!("ip link set {} up", iface))?;

        // 设置设备 ID 到接口别名喵 (alias)
        if let Some(ref id) = global_config.device_id {
            println!("正在将设备 ID '{}' 绑定到接口别名喵...", id);
            run_cmd(&format!("ip link set dev {} alias \"DeviceID:{}\"", iface, id))?;
        }
        
        // 配置地址
        if let Some(ref addresses) = global_config.loopback_address {
            let addr_list: Vec<&str> = addresses.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
            for addr in addr_list {
                println!("正在配置地址 {} 到 {} 喵...", addr, iface);
                // 尝试先清理旧地址，忽略错误
                let _ = run_cmd(&format!("ip addr del {} dev {} 2>/dev/null", addr, iface));
                if let Err(e) = run_cmd(&format!("ip addr add {} dev {}", addr, iface)) {
                    eprintln!("警告：无法添加地址 {} 到 {}: {:?}", addr, iface, e);
                }
            }
        }
        println!("ฅ^•ﻌ•^ctl Loopback 接口 {} 设置完成喵！", iface);
    }
    Ok(())
}
async fn show_status() -> Result<()> {
    let config_dir = "/etc/neko-link";
    let mut global_config = GlobalConfig::default();
    let global_path = format!("{}/global.json", config_dir);
    if let Ok(content) = fs::read_to_string(&global_path) {
        if let Ok(conf) = serde_json::from_str::<GlobalConfig>(&content) {
            global_config = conf;
        }
    }

    println!("ฅ^•ﻌ•^ฅ NekoLink 状态报告：\n");
    if let Some(ref did) = global_config.device_id {
        println!("【 全局设备 ID: {} 】喵！", did);
    }
    if let Some(ref lif) = global_config.loopback_interface {
        let addr = global_config.loopback_address.as_deref().unwrap_or("未配置地址");
        println!("【 全局 Loopback: {} ({}) 】喵！", lif, addr);
    }
    println!();
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
            "tcp" => "tcp (native signaling)".to_string(),
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
    let pmtu = if mode == "tcp" || mode == "mullvad-tcp" {
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
    // Mullvad TCP: 74 (IP 20 + TCP 20 + framing 2 + WG 32)
    let overhead = match mode {
        "ip" => 20, // IPv4 Header
        "tcp" => 20 + 20 + 2, // IP + TCP + 2 bytes framing
        _ => 20 + 8, // IP + UDP
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

async fn perform_udp_mtu_probe(host: &str, port: u16) -> Result<u16> {
    use std::os::unix::io::AsRawFd;
    
    // 尝试使用 UDP socket 探测 PMTU（适用于 NAT 映射端口场景）喵
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    
    // 设置 IP_MTU_DISCOVER 为 IP_PMTUDISC_DO（强制路径 MTU 探测）喵
    // IP_PMTUDISC_DO = 2
    let pmtudisc_do: libc::c_int = 2;
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            &pmtudisc_do as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
    
    // 连接到目标地址（对于 UDP 这只是设置默认目标）喵
    let addr: SocketAddr = format!("{}:{}", host, port).parse()
        .unwrap_or_else(|_| format!("{}:12580", host).parse().unwrap());
    let _ = socket.connect(&addr.into());
    
    // 发送一个小包来触发路径 MTU 探测喵
    let probe_data = [0u8; 8];
    let _ = socket.send(&probe_data);
    
    // 等待一小会儿让内核更新 MTU 缓存喵
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // 读取 IP_MTU 喵
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
        Err(anyhow::anyhow!("无法获取 UDP MTU"))
    }
}

async fn perform_mtu_probe(host: &str) -> Result<u16> {
    // 首先尝试使用 UDP 探测（适用于 NAT 环境）喵
    // 使用信令端口 12580 作为默认探测目标
    if let Ok(mtu) = perform_udp_mtu_probe(host, 12580).await {
        if mtu >= 576 && mtu <= 1500 {
            println!("喵！通过 UDP 套接字成功探测到 PMTU: {}", mtu);
            return Ok(mtu);
        }
    }
    
    // 如果 UDP 探测失败，回退到 ICMP ping 二分法喵
    println!("UDP MTU 探测受限喵，回退到 ICMP 二分法探测...");
    
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

// check_command_exists 原本用于 udp2raw，现已移除喵

// (原 setup_udp2raw_nft_rules 和 cleanup_udp2raw_nft_rules 已移除喵)
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


