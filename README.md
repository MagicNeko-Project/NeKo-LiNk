# NekoLink: High-Performance Stealth Magic Tunnel ฅ^•ﻌ•^ฅ

![NekoLink Banner](./banner.png)

**NekoLink** 是一个高性能、隐蔽且智能的隧道系统，基于高度定制的 [WireGuard®](https://www.wireguard.com/) 协议实现。它继承了 WireGuard 的极速体验，同时引入了独特的“魔法”特性，助你轻松穿越复杂的网络环境。

**NekoLink** is a high-performance, stealthy, and intelligent tunnel system based on a highly customized [WireGuard®](https://www.wireguard.com/) protocol implementation. It inherits the extreme speed of WireGuard while adding unique "magic" features to help you navigate complex network environments with ease.

---

## 🌟 核心特性 / Core Features

### 🚀 Custom IP Protocol (Raw IP Mode)
打破 UDP (协议号 17) 的限制与封锁！你可以使用 1 到 255 之间的任意 IP 协议号进行通信。在此模式下，**NekoLink 是 100% 无 UDP 特征的**，甚至密钥交换也通过 Raw IP 进行。防火墙根本不知道发生了什么！

Break free from UDP (Protocol 17) throttling and identification! You can communicate directly using any IP protocol number between 1 and 255. In this mode, **NekoLink is 100% UDP-free**, as even the signaling/key-exchange is performed over Raw IP. Firewalls won't even know what hit them!

### 🧦 Built-in SOCKS5 Proxy
**内建 SOCKS5 代理**: 客户端自带本地 SOCKS5 服务端，支持只代理特定浏览器的流量，无需修改系统全局路由。
[点击查看使用指南 / View SOCKS5 Guide](docs/SOCKS5_GUIDE_CN.md)

### 🎭 Fake-TCP Stealth Mode
终极渗透魔法！通过将所有流量伪装成合法的 TCP 数据包（包含完整的三次握手模拟和状态管理），你的数据流在网络监控者眼中就像普通的网页浏览一样。

The ultimate penetration magic! By masquerading all traffic as legitimate TCP packets (including full handshake simulation and state management), your data flows appear like regular web browsing to network monitors.



### 🤝 Automated Key Exchange
无需手动复制粘贴冗长的公钥。只要预共享密钥 (PSK) 匹配，NekoLink 就能通过加密信令通道自动交换 WireGuard 公钥。

No more manually copying and pasting long public keys. As long as the Pre-Shared Keys (PSK) match, NekoLink will automatically exchange WireGuard public keys via an encrypted signaling channel.

---

## 🏗️ 架构 / Architecture

1.  **nekolink-core**: 核心引擎库，支持 Raw IP、UDP GRO 和高性能事件循环。
2.  **nekolink-cli**: 用于加密解密的命令行工具。
3.  **nekolink-ctl**: 智能控制平面，管理配置、密钥生成、信令和隧道生命周期。
4.  **neko-link.sh**: 你的交互式配置向导。

---

## 🛠️ 安装 / Installation

运行项目根目录下的通用安装脚本：
Run the universal installation script from the project root:

```bash
chmod +x install.sh
sudo ./install.sh
```

### ⛵ 平滑升级 / Smooth Update

```bash
chmod +x update.sh
sudo ./update.sh
```

---

## 📖 快速开始 / Quick Start

### 1. 交互式设置 (推荐)
### 1. Interactive Setup (Recommended)

Simply run / 只需运行:
```bash
nekolink
```

按照向导选择角色（服务端/客户端）、传输模式（IP/UDP/TCP）和协议号即可。
Follow the prompts to choose your role (Server/Client), transmission mode (IP/UDP/TCP), and protocol number.

### 2. 管理隧道 / Manage Tunnels

```bash
# Start / 启动
sudo systemctl start nekolink

# Stop / 停止
sudo systemctl stop nekolink

# Logs / 查看日志
journalctl -u nekolink -f
```

---

## 📜 更新日志 / Changelog

详见 [docs/CHANGELOG.md](docs/CHANGELOG.md)。
See [docs/CHANGELOG.md](docs/CHANGELOG.md) for details.



---

## 📜 声明与致谢 / Acknowledgments

**特别鸣谢 / Special Thanks**:
- **Jason A. Donenfeld**: WireGuard 协议的发明者。
- **Cloudflare**: [BoringTun](https://github.com/cloudflare/boringtun) 开源项目的贡献者，NekoLink 的核心基于此项目。
- **Mullvad VPN**: [GotaTun](https://github.com/mullvad/gotatun) 项目的贡献者，其优秀的性能优化思路深受启发。

## 📜 许可 / License

基于 [3-Clause BSD License](./LICENSE.md) 发布。
Released under the [3-Clause BSD License](./LICENSE.md).

*WireGuard® is a registered trademark of Jason A. Donenfeld. NekoLink is not affiliated with or endorsed by Jason A. Donenfeld.*
