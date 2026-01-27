# NekoLink：高性能隐蔽式魔法隧道 ฅ^•ﻌ•^ฅ

![NekoLink Banner](./banner.png)

**NekoLink** 是一个基于 [WireGuard®](https://www.wireguard.com/) 协议深度定制的高性能、隐蔽且智能的隧道系统。它不仅继承了 WireGuard 的极致速度，还加入了猫娘特有的“魔法”，让你在复杂的网络环境中如鱼得水喵！

---

## 🌟 核心特性 (Core Features)

- **🚀 自定义 IP 协议 (Raw IP Mode)**: 摆脱 UDP (Protocol 17) 的频率限制与识别！你可以直接使用 1 到 255 之间的任意 IP 协议号进行通讯。在这个模式下，**NekoLink 实现 100% 纯净 IP 传输，连信令交换也复用 Raw IP，彻底告别 UDP 端口喵**！
- **🤝 双向自动公钥交换 (Auto Key Exchange)**: 再也不用手动复制粘贴长长的公钥了。只要两端预共享密钥 (PSK) 一致，猫娘就会通过加密信令通道自动发现队友并交换公钥喵。即使是一端主动发起的连接，另一端也能自动配置回程信令，实现双向连通喵。
- **🎮 交互式配置助手 (`neko-link`)**: 傻瓜式操作，引导你一步步配置服务端或客户端，自动生成 JSON 配置文件喵。
- **🛡️ 路由安全保护 (Table=off)**: 默认不操作系统路由表，防止因为 `0.0.0.0/0` 这种野心勃勃的配置导致你跟服务器彻底断连，安全感拉满喵。
- **💤 智能信令停机 (Smart Halt)**: 为了极智隐蔽，隧道连接成功后，信令交换会自动永久进入深度休眠，不产生任何多余特征包。配合 Keepalive 魔法，连接稳如磐石喵！
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
| `mode` | `ip` (使用 Raw IP) 或 `udp` (标准模式)。这是**数据传输与信令交换**使用的协议喵。 | 推荐使用 `ip` 模式绕过限制 |
| `ip_protocol` | 当模式为 `ip` 时指定的协议号。 | 建议选择 143 到 252 之间的数字。 |
| `listen_port` | 当模式为 `udp` 时，指定 WireGuard 的监听端口（默认 51820）。在 `ip` 模式下该选项会被忽略喵。 | `ip` 模式下设为 `null` 即可 |
| `auto_route` | `true` 或 `false` (默认 `false`)。当设置为 `false` 时，即使 `AllowedIPs` 是 `0.0.0.0/0`，猫娘也**不会**自动修改系统的路由表。这能防止因为路由冲突导致你的机器彻底断网，就像 `wg-quick` 的 `Table=off` 配置一样安全喵！ | 默认 `false` 以防断连 (类似 Table=off) |
| `local_address` | 隧道内网 IP。 | 例如 `10.0.0.1/24` |
| `psk` | 用于自动交换公钥的预共享密钥（必须两端一致）。这是魔法的源泉喵！ | 两端必须严格一致喵！ |
| `peers` | 对端信息。在 `ip` 模式下，只需填入对端的 **公网 IP** (如 `1.2.3.4`)，猫娘会通过 Raw IP 直接通讯，实现 **100% 纯净隐藏，彻底告别 UDP 端口喵**！ | 例如 `{"endpoint": "1.2.3.4"}` |
| `persistent_keepalive` | **Keepalive 持续活动魔法间隔** (单位：秒)。开启后 WireGuard 会定期发送极小的心跳包以维持穿透与连接状态喵。配合智能信令停机使用效果更佳喵！ | 推荐设为 `25` |
| `mtu` | **隧道接口 MTU**。如果未指定，默认会自动设为 `1420` 喵。 | 推荐 `1420` (标准物理层 1500 - 80) |
| `signal_port` | **加密信令端口** (仅用于 `udp` 模式，默认为 5678)。在 `ip` 模式下，这个选项会被猫娘温柔地完全忽略喵！ | `ip` 模式下完全无需 UDP 端口喵 |

---

## ⚠️ 注意事项

1. **防火墙配置**：请务必在机器的防护墙中同时开放你选定的 `ip_protocol` 号以及 `signal_port` (UDP 端口) 喵。
2. **运行权限**：接口操作需要较高权限，建议使用 `sudo` 运行管理工具喵。

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
- **商标声明**：WireGuard® 是 Jason A. Donenfeld 的注册商标。NekoLink 与其无官方合作关系。

---

祝主人的网络旅程像猫娘一样轻盈敏捷喵！( ⸝⸝•ᴗ•⸝⸝ )੭⁾⁾
