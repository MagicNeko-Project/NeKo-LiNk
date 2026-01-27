# NekoLink：高性能隐蔽式魔法隧道 ฅ^•ﻌ•^ฅ

![NekoLink Banner](./banner.png)

**NekoLink** 是一个基于 [WireGuard®](https://www.wireguard.com/) 协议深度定制的高性能、隐蔽且智能的隧道系统。它不仅继承了 WireGuard 的极致速度，还加入了猫娘特有的“魔法”，让你在复杂的网络环境中如鱼得水喵！

---

## 🌟 核心特性 (Core Features)

- **🚀 自定义 IP 协议 (Raw IP Mode)**: 摆脱 UDP (Protocol 17) 的频率限制与识别！你可以直接使用 1 到 255 之间的任意 IP 协议号进行通讯。防火墙？它根本看不懂喵！
- **🤝 自动公钥交换 (Auto Key Exchange)**: 再也不用手动复制粘贴长长的公钥了。只要两端预共享密钥 (PSK) 一致，猫娘就会通过加密信令通道自动帮你把公钥换好喵。
- **🎮 交互式配置助手 (`neko-link`)**: 傻瓜式操作，引导你一步步配置服务端或客户端，自动生成 JSON 配置文件喵。
- **🛡️ 路由安全保护 (Table=off)**: 默认不操作系统路由表，防止因为 `0.0.0.0/0` 这种野心勃勃的配置导致你跟服务器彻底断连，安全感拉满喵。
- **🦀 全 Rust 实现**: 从核心驱动到控制平面，全部使用 Rust 编写，内存安全且性能炸裂喵。

---

## 🏗️ 架构组成

1. **nekolink-core**: 核心驱动库，包含对 Raw IP 协议的支持喵。
2. **nekolink-cli**: 命令行工具，负责具体的隧道加解密。
3. **nekolink-ctl**: 智能控制平面，自动读取配置、生成密钥、启动信令交换并拉起隧道喵。
4. **neko-link.sh**: 你的专属引导猫娘，负责交互式生成配置。

---

## 🛠️ 快速安装 (Installation)

在项目根目录下运行安装脚本，一键搞定编译与安装：

```bash
chmod +x install.sh
sudo ./install.sh
```

> [!NOTE]
> 安装脚本会自动将二进制文件和管理脚本放入 `/usr/local/bin`，并为它们设置必要的 Network Capabilities 权限喵。

---

## 📖 使用指南 (Usage)

### 1. 交互式配置 (推荐)
只需输入以下指令，然后根据猫娘的提示操作即可：
```bash
neko-link
```
在这个过程中，你可以选择节点角色（服务端/客户端）、传输模式（IP 或 UDP）、协议号、内网 IP 等。

### 2. 管理隧道
配置完成后，启动控制平面：
```bash
sudo nekolink-ctl
```
猫娘会自动扫描 `/etc/neko-link/*.json` 下的所有配置并并行启动它们喵！

---

## 📝 配置文件详解

如果你想手动编辑配置文件（位于 `/etc/neko-link/*.json`），可以参考以下格式：

```json
{
  "interface": "nekotun0",
  "mode": "ip",
  "ip_protocol": 141,
  "listen_port": null,
  "auto_route": false,
  "local_address": "10.0.0.1/24",
  "psk": "猫娘的秘密密钥",
  "peers": [
    { "endpoint": "对端公网IP:5678" }
  ],
  "signal_port": 5678
}
```

| 参数 | 说明 | 建议喵 |
| :--- | :--- | :--- |
| `interface` | 虚拟网卡接口名称 | 默认为 `nekotun0` |
| `mode` | 传输模式：`ip` (Raw IP) 或 `udp` | 推荐使用 `ip` 模式绕过限制 |
| `ip_protocol`| Raw IP 模式下的协议号 | 建议选择 143-252 之间的数字喵 |
| `listen_port` | UDP 模式下的监听端口 | `ip` 模式下设为 `null` 即可 |
| `auto_route` | 是否自动修改系统路由表 | 默认 `false` 以防断连 (类似 Table=off) |
| `local_address`| 隧道内部的私网 IP | 例如 `10.0.0.1/24` |
| `psk` | 自动信令交换的预共享密钥 | 两端必须严格一致喵！ |
| `signal_port` | **信令端口** (UDP) | 哪怕是 `ip` 模式，初始握手也需要这个传统的 UDP 端口喵 |

---

## ⚠️ 注意事项

1. **防火墙配置**：请务必在机器的防护墙中同时开放你选定的 `ip_protocol` 号以及 `signal_port` (UDP 端口) 喵。
2. **运行权限**：接口操作需要较高权限，建议使用 `sudo` 运行管理工具喵。

---

## 📜 声明与权属

- **基于原项目修改**：本项目是基于官方 [Boringtun](https://github.com/cloudflare/boringtun) (by Cloudflare) 深度定制与二次开发的喵。感谢原作者们的优秀工作！
- **开源协议**：本项目沿用 [3-Clause BSD License](./LICENSE.md)。
- **商标声明**：WireGuard® 是 Jason A. Donenfeld 的注册商标。NekoLink 与其无官方合作关系。

---

祝主人的网络旅程像猫娘一样轻盈敏捷喵！( ⸝⸝•ᴗ•⸝⸝ )੭⁾⁾
