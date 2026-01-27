use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::{SocketAddr, UdpSocket};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use x25519_dalek::{PublicKey, StaticSecret};

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
        let config: NekoConfig = serde_json::from_str(&config_str)?;

        let handle = tokio::spawn(async move {
            if let Err(e) = run_instance(config).await {
                eprintln!("实例运行时出错: {:?}", e);
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
    
    // 我们需要把私钥传给 nekolink-cli
    // 通常 boringtun-cli 通过 UAPI 设置。我们这里为了简单，先启动，后续通过 wg 命令配置。
    let mut child = cmd.spawn().context("启动 nekolink-cli 失败")?;

    // 等待接口创建
    time::sleep(Duration::from_secs(2)).await;

    // 3. 配置接口与私钥
    // 写入临时私钥文件
    let key_file = format!("/tmp/neko_{}.key", config.interface);
    fs::write(&key_file, &priv_b64)?;

    run_cmd(&format!("wg set {} private-key {}", config.interface, key_file))?;
    if let Some(port) = config.listen_port {
        run_cmd(&format!("wg set {} listen-port {}", config.interface, port))?;
    }
    run_cmd(&format!("ip addr add {} dev {}", config.local_address, config.interface))?;
    run_cmd(&format!("ip link set up dev {}", config.interface))?;

    // 如果开启了 auto_route，则添加默认路由（实验性，谨慎使用喵）
    if config.auto_route {
        println!("警告喵：正在尝试配置系统路由表...");
        // 这里的逻辑可以以后完善，目前遵循用户“不操作系统路由表”的默认行为喵
    }
    
    let _ = fs::remove_file(key_file);

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
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", state.config.signal_port))?;
    socket.set_nonblocking(true)?;
    let socket = Arc::new(tokio::net::UdpSocket::from_std(socket)?);

    let mut psk_bytes = [0u8; 32];
    let salt = b"NekoLink_Magic_Salt";
    // 简单的派生 key 逻辑
    let mut hasher = blake2::Blake2s256::new();
    use blake2::Digest;
    hasher.update(state.config.psk.as_bytes());
    hasher.update(salt);
    let derived_key = hasher.finalize();
    psk_bytes.copy_from_slice(&derived_key);

    let cipher = ChaCha20Poly1305::new(&psk_bytes.into());


    // 定时向外广播/发送自己的公钥
    let send_task = {
        let config = state.config.clone();
        let socket = Arc::clone(&socket);
        let cipher = cipher.clone();
        let pub_key_bytes = state.pub_key.as_bytes().to_vec();
        async move {
            loop {
                for peer in &config.peers {
                    let mut nonce_bytes = [0u8; 12];
                    OsRng.fill_bytes(&mut nonce_bytes);
                    let nonce = Nonce::from_slice(&nonce_bytes);

                    if let Ok(ciphertext) = cipher.encrypt(nonce, pub_key_bytes.as_slice()) {
                        let mut pkt = nonce_bytes.to_vec();
                        pkt.extend_from_slice(&ciphertext);
                        let _ = socket.send_to(&pkt, &peer.endpoint).await;
                    }
                }
                time::sleep(Duration::from_secs(10)).await;
            }
        }
    };

    // 接收任务
    let recv_task = {
        let socket = Arc::clone(&socket);
        let interface = state.config.interface.clone();
        async move {
            let mut known_peers = std::collections::HashSet::new();
            loop {
                let mut buf = [0u8; 1024];
                if let Ok((len, addr)) = socket.recv_from(&mut buf).await {
                    if len < 12 + 16 {
                        continue;
                    }
                    let (nonce_part, encrypted_part) = buf[..len].split_at(12);
                    let nonce = Nonce::from_slice(nonce_part);
                    if let Ok(decrypted) = cipher.decrypt(nonce, encrypted_part) {
                        if decrypted.len() == 32 {
                            let peer_pub_key = BASE64.encode(&decrypted);
                            if !known_peers.contains(&peer_pub_key) {
                                println!("喵！发现新队友: {} 来自 {}", peer_pub_key, addr);
                                // 配置 WireGuard 队友
                                if let Ok(_) = configure_peer(&interface, &peer_pub_key, &addr) {
                                    known_peers.insert(peer_pub_key);
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

fn configure_peer(interface: &str, peer_pub_key: &str, addr: &SocketAddr) -> Result<()> {
    // 假设 WireGuard 端口比信令端口大 1 或者你可以自定义。这里简单起见，如果 mode=ip 则不需要对端端口。
    // 如果是 UDP 模式，通常加密流量和信令流量在不同端口。
    // 我们这里假设对端启动的是 WireGuard 标准监听端口。
    
    // 这里是一个简化的逻辑：将对端加入状态机
    run_cmd(&format!("wg set {} peer {} allowed-ips 0.0.0.0/0,::/0 endpoint {}", interface, peer_pub_key, addr))?;
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
