# NekoLink 🐱 (Go-EtherTunnel)

一个极简、高性能的二层 (Layer 2) VPN，使用 Golang 编写。
它旨在提供一个安全、抗干扰且能够最大化利用带宽的虚拟以太网隧道。

## ✨ 核心特性 (Features)

*   **Pure IP 虚拟化 (L3)**: 抛弃了复杂的二层以太网头，直接在 IP 层进行数据传输。彻底解决 L2 带来的广播风暴和兼容性问题，让 ping 和路由更加稳定。
*   **智能 MSS 钳制 (Smart MSS Clamping)**: **(New!)** 内置 `nftables` 自动化策略，在隧道建立时自动修正 TCP MSS。完美解决 **PPPoE**、**IPv6 PMTU** 黑洞导致的网页打不开问题，无需手动调整 MTU。
*   **VoLTE 级 QoS 优化 (VoLTE Priority)**: **(New!)** 自动将 IPv6 数据包标记为 `0xB8` (DSCP 46 / EF)，模拟 VoLTE 语音流量。在移动网络 (4G/5G) 下可获得运营商级的高优先级转发，大幅降低抖动。
*   **路由协议感知 (Routing Aware)**: **(New!)** 支持 OSPF / RIP 等组播路由协议。服务端采用 Hub-and-Spoke 模式智能分发组播包，让您可以直接在隧道上运行动态路由协议。
*   **Layer 3 虚拟化 (WireGuard-TUN)**: 基于官方 `wireguard/tun` 库，支持多队列和 GSO/GRO，提供目前 Go 生态中最顶级的 TUN 读写性能。
*   **批处理传输 (UDP/IPv4 Batching)**: 引入 `x/net/ipv4` 的 `ReadBatch` 技术，一次系统调用处理一组数据包，极大降低高吞吐下的 CPU 中断和损耗。
*   **调试监控系统 (Debug Mode)**: 支持通过 `-debug` 参数开启详细的包追踪日志，实时洞察数据包在隧道中的流转状态。
*   **无感知代理 (Transparent Proxy)**: **(New!)** 客户端支持开启本地 SOCKS5 代理 (如 `127.0.0.1:1080`)。该代理的所有出站流量会自动绑定到 VPN 接口发送，无需配置系统全局路由，极大方便浏览器/TG等程序单独使用 VPN。
*   **现代加密**: 全程使用 ChaCha20-Poly1305 (IETF) 进行加密和完整性校验，安全无忧。

## 🛠️ 快速开始 (Quick Start)

### 1. 环境准备 (Prerequisites)

*   **OS**: Linux (支持 nftables)
*   **Tools**: `nftables` (必须安装，用于 MSS 修复)
*   **Go**: 1.24+ (可使用 `setup_go.sh` 自动配置)

```bash
# Ubuntu/Debian
sudo apt install nftables git

# Arch Linux
sudo pacman -S nftables git
```

### 2. 编译 (Build)

```bash
git clone https://github.com/yourname/go-ethertunnel.git
cd go-ethertunnel
./setup_go.sh  # 自动配置 Go 环境并拉取依赖
go build -o vpn main.go
```

### 3. 配置 (Configuration)

创建 `config.json` 文件：

```json
{
  "server_addr": "1.2.3.4",        // 服务端 IP (Client 填 Server IP, Server 可填 [::])
  "protocol": "udp",               // "udp"(推荐), "tcp", "raw"
  "ip_protocol_num": 233,          // Raw 模式下的协议号
  "base_port": 9000,               // UDP 起始端口 / TCP 监听端口
  "port_count": 4,                 //并发通道数量 (建议 4-8)
  "key": "your-secret-key-32-chars-needed!!", // 32字节密钥
  "local_addr": "10.0.0.1/24",     // 虚拟网卡 IP
  "mode": "server",                // "server" 或 "client"
  "interface_name": "tap0",        // 自定义网卡名称
  "mtu": 1280,                     // 推荐 1280 (IPv6安全值) 或 1400 (搭配自动MSS)
  "socks_bind": "127.0.0.1:1080"   // (可选) 开启本地 SOCKS5 代理，流量将自动强制走 VPN
}
```

### 4. 运行 (Run)

```bash
# 服务端
sudo ./vpn -c config.json

# 客户端
sudo ./vpn -c client_config.json
```

## 🧪 进阶玩法 (Advanced)

### 动态路由 OSPF
由于 NekoLink 现在支持组播转发，您可以直接配置 OSPF：

```bash
# 在 config.json 中配置好两端的 IP，例如 10.0.0.1 和 10.0.0.2

# 启动 OSPF (以 Bird 或 FRR 为例)
protocol ospf {
    area 0 {
        interface "tap0" {
            type ptmp; # 推荐点对多点模式
            hello 10;
        };
    };
}
```

### 开启 Raw Socket 隐身模式
如果你的服务器在公网（非 NAT 后），可以将 `protocol` 设置为 `raw`。
这样程序将直接通过 IP 协议号 233 通信，不使用任何 TCP/UDP 端口，传统的端口扫描将无法发现此服务。

### 5. 安装为系统服务 (Systemd Service)

使用 `install_service.sh` 脚本将 **NekoLink** 安装到系统：

```bash
sudo ./install_service.sh
```

- **二进制位置**: `/usr/local/bin/neko-link`
- **配置文件**: `/etc/neko-link/config.json`
- **服务名称**: `neko-link.service`

```bash
sudo systemctl start neko-link
sudo systemctl status neko-link
```

### 6. 升级 (Upgrade)

在代码目录下执行升级脚本，它会自动拉取最新代码并重新编译重启服务：

```bash
./update.sh
```

### 7. 如何验证是否真的走了 Raw 协议？(Verification)

您可以使用 `tcpdump` 抓包来验证流量是否真的通过了自定义协议号 (233) 传输，而不是伪装成了 UDP/TCP。

在服务器或客户端执行：
```bash
# 假设您的物理网卡是 eth0 (请根据实际情况修改)
# 抓取协议号为 233 的包
sudo tcpdump -n -i eth0 proto 233
```

- **成功**: 屏幕上疯狂滚动 `IP 1.2.3.4 > 5.6.7.8: ip-proto-233 1400`，说明这是货真价实的 Raw IP 通讯！
- **失败**: 没有任何输出，但 VPN 能通？那说明您可能还在跑 UDP 模式，请检查配置文件。

### 8. TCP 模式与防火墙穿透 (TCP Mode & Optimization)
如果您的网络环境封锁了 UDP (如某些公司内网或校园网)，可以将 `protocol` 设置为 `tcp`。

NekoLink 的 TCP 模式已针对隧道场景进行了深度优化：
*   **TCP_NODELAY**: 禁用 Nagle 算法，确保操作无延迟。
*   **KeepAlive**: 30秒心跳保活，断线即刻重连。
*   **Large Buffer**: 4MB 读写缓冲区，跑满千兆带宽无压力。

只需将配置改为：
```json
"protocol": "tcp",
"base_port": 443  // 伪装成 HTTPS 流量效果更佳
```

### 9. 高阶用法 (Advanced Usage)

#### 9.1 多实例运行 (Multi-Instance)
NekoLink 支持在一个进程中同时运行多个 VPN 实例（混合 Client 和 Server 均可）。
只需将 `config.json` 的内容改为 **数组 `[]`** 格式即可：

```json
[
  {
    "interface_name": "neko0",
    "mode": "server",
    ...
  },
  {
    "interface_name": "neko1",
    "mode": "client",
    ...
  }
]
```
这样您就可以在一个配置文件里管理无数条隧道，互不干扰！

#### 7.2 多用户服务端 (Multi-User Server)
NekoLink 的服务端采用 **智能动态学习** 机制。
*   **服务端**: 只需要配置一份。
*   **客户端**: 可以有 N 个。只需给每个客户端配置不同的 `local_addr` (例如 `10.0.0.2`, `10.0.0.3`...)。
*   **连接**: 当客户端发送数据包时，服务端会自动记录该 IP 对应的物理地址。支持点对多点 (Point-to-Multipoint) 拓扑。
