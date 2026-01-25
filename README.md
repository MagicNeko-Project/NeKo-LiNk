# NekoLink 🐱 (Shadow WireGuard Edition)

一个为极端环境设计的、全自动、高隐蔽性的 Layer 3 加密隧道。
现在的 NekoLink 将官方 `wireguard-go` 的安全性与自定义 Raw Socket 传输的隐蔽性完美结合，为您提供最智能的隧道体验。

## ✨ 核心特性

*   **Shadow WireGuard (wg-raw)**: 官方 WireGuard 内核，但**不走 UDP**。流量被巧妙地封装在自定义 IP 协议号（如 233）或 **TCP 伪装协议**中，彻底规避针对 WireGuard 协议特征的识别。
*   **TCP 协议头伪装**: 当选择 `protocol: "tcp"` 时，流量将自动包裹一层真实的 TCP 协议头（包含 Seq/Ack/PSH-ACK 标志），在防火墙看来就是正常的 TCP 流量，具有极强的穿透性。
*   **全自动“零配置”握手**: 彻底告别繁琐的密钥对生成与手工 Peer 配置！只需在两端设置相同的 `key` (密码)，NekoLink 会通过私有的 `0xFE` 握手协议自动交换临时密钥并配置隧道。
*   **传送门接管 (Shadowing)**: 所有的流量接管对 WireGuard 工具完全透明。外部 `wg` 工具看到的 Endpoint 始终是 `127.0.0.1`，而真实的物理传输由 NekoLink 在底层通过劫持逻辑无感完成。
*   **Phantom Mode (幻影模式)**: 在 `wg-raw` 协议下，NekoLink 启用极速 AF_XDP 模式直接挂载物理网卡 (`eth0`)。系统不再创建任何虚拟 Tun/Tap 设备，彻底隐形！它像幽灵一样只捕获特定的 VPN 加密包，性能损耗近乎为零。
*   **NAT-T 全程穿透**: 面对严苛的 NAT 环境，可选开启 UDP 封装模式，让自定义协议流量像普通 UDP 包一样滑过路由器，兼顾隐蔽性与兼容性。
*   **自进化配置逻辑**: 内置 `-migrate` 智能引擎。无论是升级旧版配置、优化 MTU 还是更新命名规范，程序都能在启动瞬间自动识别并写回优化结果，无需人工干预。
*   **性能怪兽**: 继承了 v6.0 以来的全链路 `sync.Pool` 内存复用、多队列 TUN 读写支持，提供在 Go 生态中顶级的吞吐性能与超低延迟。

## 🛠️ 快速开始

### 1. 编译
```bash
git clone https://github.com/yourname/go-ethertunnel.git
cd go-ethertunnel
./setup_go.sh  # 自动配置 Go 环境
go build -o neko-link main.go structs.go wg_bind.go
```

### 2. 配置 (config.json)
最简配置，只需填一个密码：

```json
{
  "mode": "server",           // server 或 client
  "listen_addr": "0.0.0.0",   // 服务端监听
  "peer_addr": "1.2.3.4",     // 客户端目标 (client 必填)
  "key": "myaespassword",     // 共享密码，保持一致即可
  "protocol": "wg-raw",       // 开启 Shadow WireGuard 模式
  "local_addr": "10.0.0.1/24",// 隧道内部 IP
  "mtu": 1400                 // 推荐 1400
}
```

### 3. 运行
```bash
# 服务端
sudo ./neko-link -c config.json

# 客户端
sudo ./neko-link -c client_config.json
```

## 🧪 进阶玩法

### 自动配置文件优化
如果您是从旧版本升级，直接运行：
```bash
./neko-link -migrate -c config.json
```
程序会自动将旧的协议映射到 `wg-raw`，并将旧的字段名（如 `server_ip`）升级为新的规范命名。

### 自定义协议号伪装
在配置中设置 `ip_protocol_num`:
- 设置为 `6`：流量在 IP 层看起来像 TCP (仅限非 NAT 且能接受非标 TCP 头的情况)。
- 设置为 `200+`: 避开所有标准协议号，走纯净的私有 IP 通道。

## 📥 安装与升级
- **一键安装服务**: `sudo ./install_service.sh`
- **一键升级并优化**: `sudo ./update.sh` (会自动完成编译、更新二进制及配置平滑迁移)

---
主人，快来体验这属于“影子 WireGuard”的纯净世界吧喵！(≦∇≦)/🐾
