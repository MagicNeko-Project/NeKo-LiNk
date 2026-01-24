# NekoLink 🐱 (Go-EtherTunnel)

一个极简、高性能的二层 (Layer 2) VPN，使用 Golang 编写。
它旨在提供一个安全、抗干扰且能够最大化利用带宽的虚拟以太网隧道。

## ✨ 核心特性 (Features)

*   **v6.0 Next-Gen QUIC Revolution**: 全面拥抱 QUIC 协议 (基于 HTTP/3 底层)，内置 Google BBR 拥塞控制，彻底解决 UDP 丢包、乱序和卡顿。
*   **Pure IP 虚拟化 (L3)**: 抛弃了复杂的二层以太网头，直接在 IP 层进行数据传输。彻底解决 L2 带来的广播风暴和兼容性问题，让 ping 和路由更加稳定。
*   **计数器 Nonce 加密 (Counter Nonce)**: **(New!)** 使用原子计数器生成 Nonce，避免每包调用 `crypto/rand` 的系统调用开销，性能提升 20-30%。
*   **零拷贝缓冲池 (Zero-Copy Buffer Pool)**: **(New!)** 全链路使用 `sync.Pool` 复用内存，减少 GC 压力，降低延迟抖动。
*   **智能 MSS 钳制 (Smart MSS Clamping)**: 内置 `nftables` 自动化策略，在隧道建立时自动修正 TCP MSS。完美解决 **PPPoE**、**IPv6 PMTU** 黑洞导致的网页打不开问题，无需手动调整 MTU。
*   **VoLTE 级 QoS 优化 (VoLTE Priority)**: 自动将 IPv6 数据包标记为 `0xB8` (DSCP 46 / EF)，模拟 VoLTE 语音流量。在移动网络 (4G/5G) 下可获得运营商级的高优先级转发，大幅降低抖动。
*   **路由协议感知 (Routing Aware)**: 支持 OSPF / RIP 等组播路由协议。服务端采用 Hub-and-Spoke 模式智能分发组播包，让您可以直接在隧道上运行动态路由协议。
*   **Layer 3 虚拟化 (WireGuard-TUN)**: 基于官方 `wireguard/tun` 库，支持多队列和 GSO/GRO，提供目前 Go 生态中最顶级的 TUN 读写性能。
*   **批处理传输 (UDP/IPv4 Batching)**: 引入 `x/net/ipv4` 的 `ReadBatch` 技术，一次系统调用处理一组数据包，极大降低高吞吐下的 CPU 中断和损耗。
*   **调试监控系统 (Debug Mode)**: 支持通过 `-debug` 参数开启详细的包追踪日志，实时洞察数据包在隧道中的流转状态。
*   **现代加密**: 使用 QUIC 内置的 **TLS 1.3** 进行银行级加密与身份验证，更安全，更高效。

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
  "server_addr": "1.2.3.4",        // 服务端 IP
  "protocol": "quic",              // "quic" (推荐), "udp", "tcp", 或 "raw"
  "ip_protocol_num": 233,          // Raw 模式下的协议号
  "base_port": 9000,               // UDP/QUIC 监听端口
  "key": "your-secret-key-32-chars-needed!!", // 32字节密钥 (用于 TLS PSK)
  "local_addr": "10.0.0.1/24",     // 虚拟网卡 IP
  "mode": "server",                // "server" 或 "client"
  "interface_name": "tap0",        // 自定义网卡名称
  "mtu": 1280                      // 推荐 1280
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

### 7. 高阶用法 (Advanced Usage)

#### 7.1 多实例运行 (Multi-Instance)
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
