# NekoLink 🐱 (Shadow WireGuard Edition)

一个为极端环境设计的、全自动、高隐蔽性、基于 eBPF 的 Layer 3 加密隧道。
现在的 NekoLink 将官方 `wireguard-go` 的安全性与 eBPF/XDP 带来的巅峰性能完美结合，为您提供最智能的隧道体验。

## ✨ 幻影模式高级特性 (wg-raw V2.1)

*   **真正的“零配置”体验**: 在 `wg-raw` 模式下，NekoLink 会在加密握手中自动完成公钥交换。主人您只需两端设置相同的 `key` (密码) 和 `local_addr`，其余密钥对配对工作由猫咪自动完成喵~
*   **TCP 伪装层 (Protocol Disguise)**: 开启 `use_tcp: true` 后，VPN 流量将被包裹在仿真度极高的 TCP 报头中（包含 Seq/Ack 模拟及 PSH-ACK 标志）。即使是具备深度包检测 (DPI) 的防火墙，也会将其视为正常的长连接流量。
*   **二层 (L2) 灵魂注入**: `raw` 协议支持完整的以太网帧透传，让 ARP、DHCP 完美越过隧道。

## 🛠️ 快速开始

### 1. 编译 (Go 1.24+)
```bash
./setup_go.sh && ./.go/bin/go build -o neko-link .
```

### 2. 幻影模式 (WG-Phantom) 示例配置
```json
{
  "version": "v2.1",
  "interface_name": "tox-phantom",
  "mode": "client",
  "protocol": "wg-raw",
  "key": "myaespassword",      // 共享加密密码
  "peer_addr": "1.2.3.4",      // [重要] 远端服务端公网 IP (Client必填)
  "peer_port": 23333,          // [重要] 远端监听端口 (与服务端 listen_port 对齐)
  "parent_interface": "eth0",  // eBPF 挂载的目标物理网卡
  "wg_interface": "tox0",      // 系统中看到的 WG 网卡名
  "local_addr": "10.0.0.2/24", // 隧道内网 IP
  "use_tcp": true,             // 开启仿真 TCP 伪装
  "mtu": 1380
}
```

### 3. 高级配置字段
| 字段名 | 作用 |
| :--- | :--- |
| `parent_interface` | **物理入口**。eBPF 程序会挂载在这个网卡上捕获流量。 |
| `wg_interface` | **WireGuard 逻辑网卡**。在系统中看到的 VPN 设备名。 |
| `app_interface` | **Raw 模式对端**。在传统 Raw 模式下连接 APP 侧的 Veth 名。 |
| `ip_protocol_num` | **伪装 IP 协议号**。默认 250，可改为 6 (TCP) 等。 |

## 📥 安装与升级
- **一键安装服务**: `sudo ./install_service.sh`
- **一键调试**: `sudo bash debug.sh` (实时查看加解密流水线状态)
- **V2 配置极致升级**: `./neko-link -migrate -c config.json`
  - 程序会自动在 `/etc/neko-link/config.v2.json` 生成 V2 标准配置文件。
  - **智能探测**: 下次启动时，若存在 `config.v2.json`，程序将**自动锁定该文件**并跳过旧的 `config.json`。
  - **协议自适应**: V2 格式仅包含您当前协议所需的必要字段，拒绝配置臃肿喵~

---
主人，快来体验这由 eBPF 驱动的、极致丝滑的“影子隧道”世界吧喵！(≧∇≦)/🐾
