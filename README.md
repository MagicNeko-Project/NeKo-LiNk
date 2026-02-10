# NekoLink：高性能隐蔽式魔法隧道 ฅ^•ﻌ•^ฅ

![NekoLink Banner](./banner.png)

**NekoLink** 是一个基于 [WireGuard®](https://www.wireguard.com/) 协议深度定制的高性能、隐蔽且智能的隧道系统。它不仅继承了 WireGuard 的极致速度，还加入了猫娘特有的“魔法”，让你在复杂的网络环境中如鱼得水喵！

---

## 🌟 核心特性 (Core Features)

- **🚀 自定义 IP 协议 (Raw IP Mode)**: 摆脱 UDP (Protocol 17) 的频率限制与识别！你可以直接使用 1 到 255 之间的任意 IP 协议号进行通讯。在这个模式下，**NekoLink 实现 100% 纯净 IP 传输，连信令交换也复用 Raw IP，彻底告别 UDP 端口喵**！
- **🎭 Fake-TCP 模式 (Fake-TCP Mode)**: 侧车魔法！通过调用侧车组件 [udp2raw](https://github.com/wangyu-/udp2raw-multi)，将流量伪装成标准 TCP 流。在 `fake-tcp` 模式下，猫娘会自动为你打理一切喵。
- **🔌 原生 TCP 模式 (Native TCP Mode)**: 极致性能！基于 [udp-over-tcp](https://github.com/mullvad/udp-over-tcp) 协议实现的内置 TCP 驱动。在 `tcp` 模式下提供极低的延迟与零依赖的极简体验喵！
- **🤝 双向自动公钥交换 (Auto Key Exchange)**: 再也不用手动复制粘贴长长的公钥了。只要两端预共享密钥 (PSK) 一致，猫娘就会通过加密信令通道自动发现队友并交换公钥喵。即使是一端主动发起的连接，另一端也能自动配置回程信令，实现双向连通喵。
- **🎮 交互式配置助手 (`neko-link`)**: 傻瓜式操作，引导你一步步配置服务端或客户端，自动生成 JSON 配置文件喵。
- **🛡️ 路由安全保护 (Table=off)**: 默认不操作系统路由表，防止因为 `0.0.0.0/0` 这种野心勃勃的配置导致你跟服务器彻底断连，安全感拉满喵。
- **🧦 本地 SOCKS5 服务端**: 支持在客户端开启本地 SOCKS5 代理服务，强制绑定 `127.0.0.1`，实现安全的分应用代理，无需修改全局路由喵！
- **💤 智能信令停机 (Smart Halt)**: 为了极智隐蔽，隧道连接成功后，信令交换会自动永久进入深度休眠，不产生任何多余特征包。配合 Keepalive 魔法，连接稳如磐石喵！
- **🕸️ P2P 全网状 Mesh 模式**: 真正的去中心化喵！开启 `mesh_mode` 后，NekoLink 节点间会自动发现并建立全连接，不再依赖单一中心，构建坚固的网状网络喵。
- **🌉 二层透明桥接 (TAP Mode)**: 像交换机一样工作喵！支持创建 TAP (Layer 2) 设备，实现以太网帧的透明转发。配合自动 MAC 学习引擎，轻松构建跨地域的二层局域网喵！
- **⚖️ 全网 MTU 动态协商**: 告别手动配置喵！在 Mesh 或自动 MTU 模式下，猫娘会自动探测并同步所有邻居的最低 MTU 值，确保全网通讯顺滑无阻喵。
- **📡 多端口并发信令**: 强大的监听能力喵！控制面支持同时在多个端口或协议号上监听信令，让你在复杂的网络环境下更容易连接到小伙伴喵。
- **🦀 全 Rust 实现**: 从核心驱动到控制平面，全部使用 Rust 编写，内存安全且性能炸裂喵。
- **� 多上游 & 独立协议支持 (Multi-UP & Per-Peer Mode)**: 灵活变身喵！现在一个接口可以同时连接多个上游节点，并且可以为**每个对端独立配置传输模式**（如对端 A 用 Raw IP，对端 B 用 UDP，对端 C 用 TCP）。再复杂的拓扑也能轻松 Hold 住喵！
- **🛰️ 自适应 MTU 探测**: 自动识别物理链路的 PMTU，并为隧道推荐最佳 MTU 值，告别手动尝试喵！
- **🧦 强化版 SOCKS5 联动**: 基于信令的智能联动。在 Mesh 模式下自动移除 `127.0.0.1` 监听，转而绑定至 NekoLink 接口 IP，实现更安全的网络隔离喵。

---

## 🕸️ Neko-Mesh：去中心化全网状魔法 ฅ^•ﻌ•^ฅ

**NekoLink Mesh** 是 3.4.1 版本重点强化的黑科技！它能让你的节点不再孤军奋战喵。

### 🌈 为什么需要 Mesh？
传统的隧道通常是“点对点”或“星型”结构。一旦中心节点倒下，全网都会瘫痪喵。而开启 `mesh_mode` 后：
- **自动邻居发现**：只需给出一个共同的 PSK，节点间会通过信令魔法自动交换公钥并建立连接。
- **全网状连接**：节点 A 连接 B，B 连接 C，A 也会自动发现并连接 C，构建坚固的 P2P 网络。
- **动态路由同步**：配合 `auto_route`，数据包会自动在最优路径上飞翔喵。

### 🏮 快速开启 Mesh
在配置文件中将 `mesh_mode` 设为 `true` 即可：
```json
{
  "interface": "nekotun0",
  "mesh_mode": true,
  "psk": "共同的魔法暗号",
  ...
}
```
结合 **3.4.1** 引入的 `rename` 与 `delete` 功能，管理大规模 Mesh 节点集群也将变得优雅而从容喵！

---

## 🏗️ 架构组成

1. **nekolink-core**: 核心驱动库，包含对 Raw IP 协议的支持喵。
2. **nekolink-cli**: 命令行工具，负责具体的隧道加解密。
3. **nekolink-ctl**: 智能控制平面，自动读取配置、分派侧车辅助插件、启动信令交换并拉起隧道喵。
4. **nekolink-tcp**: 包含增强版的辅助插件集喵。
5. **neko-link.sh**: 你的专属引导猫娘，负责交互式生成配置。

---

## 🛠️ 快速安装 (Installation)

在项目根目录下运行安装脚本，一键搞定编译与安装：

```bash
chmod +x install.sh
sudo ./install.sh
```
> [!NOTE]
> 现在的安装脚本会全自动完成 **编译 -> 打包 -> apt 安装** 的整套流程。这种方式比手动拷贝更安全，且能被系统完美追踪喵！

### ⛵ 平滑升级 (Update)
如果主人已经安装过 NekoLink，可以使用专门的升级脚本来平滑更新，它会自动帮你处理残留进程并拉取最新代码喵：
```bash
chmod +x update.sh
sudo ./update.sh
```

> [!TIP]
> 升级脚本会温柔地保留你在 `/etc/neko-link/` 下的所有配置，请放心使用喵！

---

## 📖 使用指南 (Usage)

### 1. 交互式配置 (推荐)
只需输入以下指令，然后根据猫娘的提示操作即可：
```bash
nekolink
```
在这个过程中，你可以选择节点角色（服务端/客户端）、传输模式（IP 或 UDP）、协议号、内网 IP 等。

### 2. 管理隧道 (Management)
配置完成后，你可以使用 systemd 来管理隧道服务：

```bash
# 启动服务
sudo systemctl start nekolink

# 停止服务
sudo systemctl stop nekolink

# 查看实时日志
journalctl -u nekolink -f

# 设置/取消开机自启
sudo systemctl enable/disable nekolink
```

也会你可以直接运行 `nekolink-ctl` 进行前台调试喵。控制面会自动扫描 `/etc/neko-link/*.json` 下的所有配置并并行启动它们喵！

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
  "mesh_mode": true,
  "mtu": 0,
  "psk": "猫娘的秘密密钥",
  "peers": [
    { "endpoint": "上游IP1:12580", "mode": "ip" },
    { "endpoint": "上游IP2:12580", "mode": "udp" }
  ],
  "signal_port": 12580
}
```

| 参数 | 说明 | 建议喵 |
| :--- | :--- | :--- |
| `interface` | 虚拟网卡接口名称 | 默认为 `nekotun0` |
| `mode` | 全局默认数据模式：`ip`, `udp`, `mullvad-tcp`。 | 性能：`ip` > `tcp` |
| `peers` | **对端清单 (重要喵！)**。现在支持配置多个对端。 | 示例：`{"endpoint": "1.2.3.4", "mode": "ip"}` |
| `peers[*].mode` | **对端独立传输模式**。可选 `ip`, `udp`, `rawip` 或 `mullvad-tcp`。留空则跟随全局 `mode`。 | **3.4.0 新特性喵！** |
| `socks5_port` | **本地 SOCKS5 监听端口**。开启后提供安全代理服务喵。 | 例如 `1080` |
| `socks5_listen_local` | 是否在 `127.0.0.1` 监听 (默认 `true`)。 | 建议保持 `true` 喵 |
| `socks5_listen_loopback` | 是否在**全局环回接口**的 IP 上监听 (默认 `false`)。 | 用于容器/局域网共享喵 |
| `persistent_keepalive` | **Keepalive 持续活动魔法间隔** (单位：秒)。保持穿透与连接稳如磐石。 | 推荐设为 `25` |
| `mtu` | **隧道接口 MTU**。设为 `0` 则启用自适应探测喵。 | 推荐 `1420` 或 `0` 喵 |
| `signal_port` | **加密信令端口** (仅服务端需固定)。客户端模式下会自动使用随机端口。 | 默认 `12580` 喵 |

---

## ⚠️ 注意事项

1. **防火墙配置**：请务必在机器的防护墙中同时开放你选定的 `ip_protocol` 号以及 `signal_port` (UDP 端口) 喵。
2. **运行权限**：接口操作需要较高权限，建议使用 `sudo` 运行管理工具喵。

---

## 🧦 SOCKS5 代理魔法 (Advanced Proxy)

NekoLink 内置了高性能 SOCKS5 服务端，配合 **3.4.1** 新增的环回接口管理，功能极其强大喵：

- **快速使用**: 在配置中加入 `"socks5_port": 1080` 后，本地即可通过 `127.0.0.1:1080` 上网喵。
- **内部共享与容器支持**: 开启 **全局 Loopback 接口** 后，你可以设置 `"socks5_listen_loopback": true`，让容器或虚拟机直接通过环回 IP 使用代理喵。
- **双向独立开关**: 支持独立控制在 `127.0.0.1` 和环回接口 IP 上启停监听，安全满分喵。

---

## 🔍 如何验证 IP 模式是否生效？

主人可以使用 `tcpdump` 咒语来观察物理网卡上的流量。

假设主人的物理网卡是 `eth0`，设置的 `ip_protocol` 是 `141`：

```bash
# 在服务端或客户端运行，抓取指定协议号的包
sudo tcpdump -i eth0 proto 141 -n -v
```

**如果连接成功，主人会看到：**
- 物理网卡上出现了大量协议号为 `141` 的包。
- 没有任何 UDP 端口被使用（除非主人用的是 `udp` 模式）。
- `ip link show nekotun0` 显示 MTU 为 `1420`。

这就证明魔法生效了喵！ฅ^•ﻌ•^ฅ

---

## 📜 声明与权属

- **基于原项目修改**：本项目是基于官方 [Boringtun](https://github.com/cloudflare/boringtun) (by Cloudflare) 深度定制与二次开发的喵。感谢原作者们的优秀工作！
- **开源协议**：本项目沿用 [3-Clause BSD License](./LICENSE.md)。
- [架构方案](docs/ARCHITECTURE.md)
- [设计分析与作用详解](docs/DESIGN_ANALYSIS_CN.md) ฅ^•ﻌ•^ฅ
- [自动化发布指南](docs/CI_CD_GUIDE.md) (GitHub Actions)
- **商标声明**：WireGuard® 是 Jason A. Donenfeld 的注册商标。NekoLink 与其无官方合作关系。

---

祝主人的网络旅程像猫娘一样轻盈敏捷喵！( ⸝⸝•ᴗ•⸝⸝ )੭⁾⁾
