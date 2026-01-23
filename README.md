# NekoLink 🐱 (Go-EtherTunnel)

一个极简、高性能的二层 (Layer 2) VPN，使用 Golang 编写。
它旨在提供一个安全、抗干扰且能够最大化利用带宽的虚拟以太网隧道。

## ✨ 特性 (Features)

*   **Layer 2 虚拟化**: 基于 TAP 设备，构建虚拟以太网。这意味着你可以在隧道内运行 ARP, DHCP, OSPF, IPv6 等任何二层协议。
*   **双模传输 (Dual Mode)**:
    *   `UDP` 模式: 标准兼容模式，适合 NAT 环境。
    *   `Raw IP` 模式: 使用自定义 IP 协议号 (默认 233)，无视端口封锁，拥有极高的隐蔽性。
*   **多通道负载均衡 (Multi-Channel Balancing)**: 自动同时使用多个端口/通道进行并发传输，叠加带宽并利用多核 CPU 性能。
*   **现代加密**: 全程使用 ChaCha20-Poly1305 (IETF) 进行加密和完整性校验，安全无忧。
*   **IPv6 Ready**: 完美支持 IPv6 (隧道内与隧道外)。

## 🛠️ 快速开始 (Quick Start)

### 1. 编译 (Build)

需要 Go 1.19+ 环境。

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

```bash
sudo ./update.sh
```
