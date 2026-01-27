# NekoLink：你的自定义魔法隧道 ฅ^•ﻌ•^ฅ

NekoLink 是一个高性能、隐蔽且智能的隧道系统。它由三部分组成：核心驱动、命令行工具和自动化控制平面。

## 核心特性

- **自定义 IP 协议**: 摆脱 UDP (Protocol 17) 的限制，直接使用任意 IP 协议号通讯。
- **自动密钥交换**: 只要 PSK 对得上，猫娘就会帮你自动交换公钥，无需手动配置对端公钥。
- **全 Rust 实现**: 极致的性能与安全性喵！

## 快速安装

在项目根目录下运行安装脚本：
```bash
chmod +x install.sh
./install.sh
```
这会将 `nekolink-cli` 和 `nekolink-ctl` 安装到你的系统路径喵。

## 配置文件指南

请在 `/etc/neko-link/` 下创建 JSON 配置文件。文件名可以随意，例如 `home.json`：

```json
{
  "interface": "nekotun0",
  "mode": "ip", 
  "ip_protocol": 141,
  "local_address": "10.0.0.1/24",
  "psk": "猫娘的秘密密钥",
  "peers": [
    {
      "endpoint": "对端公网IP:5678"
    }
  ],
  "signal_port": 5678
}
```

### 参数说明：
- `interface`: 虚拟网卡名称。
- `mode`: `ip` (使用 Raw IP) 或 `udp` (标准模式)。这是**数据传输**使用的协议喵。
- `ip_protocol`: 当模式为 `ip` 时指定的协议号。
    - **建议喵**：你可以选择 143 到 252 之间的数字。
- `listen_port`: 当模式为 `udp` 时，指定 WireGuard 的监听端口（默认 51820）。在 `ip` 模式下该选项会被忽略喵。
- `auto_route`: `true` 或 `false` (默认 `false`)。
    - **安全提示喵**：当设置为 `false` 时，即使 `AllowedIPs` 是 `0.0.0.0/0`，猫娘也**不会**自动修改系统的路由表。这能防止因为路由冲突导致你的机器彻底断网，就像 `wg-quick` 的 `Table=off` 配置一样安全喵！
- `local_address`: 隧道内网 IP。
- `psk`: 用于自动交换公钥的预共享密钥（必须两端一致）。这是魔法的源泉喵！
- `peers`: 对端信息，目前只需填入对端的信令地址喵。
- `signal_port`: **加密信令端口**，默认为 5678。
    - **注意喵**：这个端口是 `nekolink-ctl` 用来自动交换公钥的。即使你数据模式选了 `ip` 协议，这个信令交换依然需要通过 UDP 5678 端口（或者你自定义的端口）进行“握手”喵！

## 运行喵

启动控制平面，它会自动管理所有隧道：
```bash
nekolink-ctl
```

## 注意事项

1. **防火墙**: 记得放行 `signal_port` (UDP) 以及你选择的 `ip_protocol` 喵。
2. **权限**: `install.sh` 已经处理好了权限，通常不需要以 root 运行，但由于涉及网卡操作，建议还是使用 `sudo nekolink-ctl` 喵。

祝你的网络之旅像猫娘一样轻盈喵！( ⸝⸝•ᴗ•⸝⸝ )੭⁾⁾
