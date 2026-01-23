# NekoLink 🐱 (Go-EtherTunnel)

一个极简、高性能的二层 (Layer 2) VPN，使用 Golang 编写。
它旨在提供一个安全、抗干扰且能够最大化利用带宽的虚拟以太网隧道。

## ✨ 特性 (Features)

*   **Layer 3 虚拟化 (WireGuard-TUN)**: 基于官方 `wireguard/tun` 库，支持多队列和 GSO/GRO，提供目前 Go 生态中最顶级的 TUN 读写性能。
*   **批处理传输 (UDP/IPv4 Batching)**: 引入 `x/net/ipv4` 的 `ReadBatch` 技术，一次系统调用处理一组数据包，极大降低高吞吐下的 CPU 中断和损耗。
*   **零拷贝加速 (Zero-Copy)**: 全链路数据包尽可能减少内存分配，配合 `sync.Pool` 智能缓冲池，即使 10Gbps 流量也能从容应对。
*   **现代加密**: 全程使用 ChaCha20-Poly1305 (IETF) 进行加密和完整性校验，安全无忧。
*   **IPv6 Ready**: 完美支持 IPv6 (隧道内与隧道外)。

## 🛠️ 快速开始 (Quick Start)

### 1. 编译 (Build)

需要 Go 1.24+ 环境。

```bash
git clone https://github.com/yourname/go-ethertunnel.git
cd go-ethertunnel
go mod tidy
go build -o vpn main.go
```

### 2. 配置 (Configuration)

创建 `config.json` 文件：

```json
{
  "server_addr": "1.2.3.4",        // 服务端 IP (Client 填 Server IP, Server 可填 [::])
  "protocol": "udp",               // "udp" 或 "raw"
  "ip_protocol_num": 233,          // Raw 模式下的协议号
  "base_port": 9000,               // UDP 起始端口
  "port_count": 4,                 //并发通道数量 (建议 4-8)
  "key": "your-secret-key-32-chars-needed!!", // 32字节密钥
  "local_addr": "10.0.0.1/24",     // 虚拟网卡 IP
  "mode": "server",                // "server" 或 "client"
  "interface_name": "tap0",        // 自定义网卡名称
  "mtu": 1400
}
```

### 3. 运行 (Run)

```bash
# 服务端
sudo ./vpn -c config.json

# 客户端
sudo ./vpn -c client_config.json
```

## 🧪 进阶玩法 (Advanced)

### 开启 Raw Socket 隐身模式
如果你的服务器在公网（非 NAT 后），可以将 `protocol` 设置为 `raw`。
这样程序将直接通过 IP 协议号 233 通信，不使用任何 TCP/UDP 端口，传统的端口扫描将无法发现此服务。

### OSPF / 组播支持
由于是二层隧道，你可以直接在 `tap0` 接口上运行 OSPF 或 BGP：

```bash
# 这里是其它的路由软件配置示例
interface tap0
 ip ospf area 0
```

### 4. 安装为系统服务 (Systemd Service)

如果需要开机自启或后台长期运行，可以使用一键安装脚本：

### 4. 安装为系统服务 (Systemd Service)

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

### 5. 升级 (Upgrade)

在代码目录下执行升级脚本，它会自动拉取最新代码并重新编译重启服务：

### 6. 如何验证是否真的走了 Raw 协议？(Verification)

您可以使用 `tcpdump` 抓包来验证流量是否真的通过了自定义协议号 (233) 传输，而不是伪装成了 UDP/TCP。

在服务器或客户端执行：
```bash
# 假设您的物理网卡是 eth0 (请根据实际情况修改)
# 抓取协议号为 233 的包
sudo tcpdump -n -i eth0 proto 233
```

- **成功**: 屏幕上疯狂滚动 `IP 1.2.3.4 > 5.6.7.8: ip-proto-233 1400`，说明这是货真价实的 Raw IP 通讯！
- **失败**: 没有任何输出，但 VPN 能通？那说明您可能还在跑 UDP 模式，请检查配置文件。

### 7. 高阶用法 (Advanced Usage)

#### 7.1 多实例运行 (Multi-Instance)
NekoLink 支持在一个进程中同时运行多个 VPN 实例（混合 Client 和 Server 均可）。
只需将 `config.json` 的内容改为 **数组 `[]`** 格式即可：

```json
[
  {
    "interface_name": "neko0",
    "mode": "server",
    "base_port": 9000,
    "local_addr": "10.0.0.1/24"
  },
  {
    "interface_name": "neko1",
    "mode": "client",
    "server_ip": "1.2.3.4",
    "server_port": 10000,
    "local_addr": "192.168.1.2/24"
  }
]
```
这样您就可以在一个配置文件里管理无数条隧道，互不干扰！

#### 7.2 多用户服务端 (Multi-User Server)
NekoLink 的服务端采用 **智能动态学习** 机制。
*   **服务端**: 只需要配置一份。
*   **客户端**: 可以有 N 个。只需给每个客户端配置不同的 `local_addr` (例如 `10.0.0.2`, `10.0.0.3`...)。
*   **连接**: 当客户端发送数据包时，服务端会自动记录该 IP 对应的物理地址。支持点对多点 (Point-to-Multipoint) 拓扑。
