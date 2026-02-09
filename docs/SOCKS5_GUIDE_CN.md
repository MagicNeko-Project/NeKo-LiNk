# NekoLink SOCKS5 服务端使用指南 ฅ^•ﻌ•^ctl

欢迎使用 NekoLink 的 SOCKS5 魔法通道！这个功能允许主人在不改变系统全局路由的情况下，让特定的应用程序（如浏览器、Telegram 等）通过 NekoLink 隧道上网喵。

---

## 🛡️ 安全第一：本地限定原则

> [!WARNING]
> **重要安全性说明**：
> NekoLink 的 SOCKS5 服务端默认**绑定在 `127.0.0.1`**（本地地址）。
> 
> 现在主人还可以通过 **全局 Loopback 接口** 来实现更强大的功能：
> 1. **内部共享**：例如给 Docker 容器、虚拟机使用。
> 2. **多 IP 绑定**：支持同时绑定多个 IPv4 和 IPv6 地址。
> 3. **安全隔离**：主人可以精确控制 SOCKS5 在哪些接口上开启监听喵！

---

## 🛠️ 如何开启 SOCKS5 魔法？

只需要在你的配置文件（通常在 `/etc/neko-link/*.json`）中添加一行 `socks5_port` 即可喵：

### 1. 修改配置文件
打开你的接口配置文件，加入端口号（例如 `1080`）：

{
  "interface": "nekotun0",
  "mode": "ip",
  "socks5_port": 1080,
  "socks5_listen_local": true,
  "socks5_listen_loopback": true,
  ...
}
```

### 2. 配置全局 Loopback 接口 (可选)
如果主人想跨设备/容器共享，可以在 `global.json` 中配置：
```json
{
  "signal_port": 12580,
  "loopback_interface": "nekolo0",
  "loopback_address": "172.16.0.1/24, fd00::1/64"
}
```
这样 SOCKS5 就会同时出现在 `127.0.0.1:1080` 和 `172.16.0.1:1080` 了喵！

### 3. 重载配置
修改完成后，让猫娘重新加载一下配置：
```bash
sudo nekolink-ctl reload
```

---

## 🎮 如何使用这个代理？

配置完成后，主人的电脑上就会有一个运行在 `127.0.0.1:1080` 的 SOCKS5 代理了喵！

### 浏览器使用 (推荐)
1. 安装 **SwitchyOmega** 插件。
2. 创建一个新情景模式，类型选择 **代理服务器**。
3. 协议选择 **SOCKS5**，代理服务器填写 `127.0.0.1`，端口填写你设置的数字（如 `1080`）。
4. 点击“应用选项”，然后切换到该情景模式即可喵！

### 命令行测试
主人可以用下面这个咒语来验证是否生效：
```bash
curl --socks5-hostname 127.0.0.1:1080 https://www.google.com
```

---

## 🚀 进阶：UDP 支持 (UDP ASSOCIATE)

现在的 SOCKS5 魔法已经原生支持 **UDP** 转发了喵！
1. 像 **Telegram** 这样的桌面客户端，开启 SOCKS5 后可以自动使用 UDP 进行更流畅的通话。
2. 只要您的软件支持 SOCKS5 UDP，它就能无缝地穿过隧道。
3. 请注意，UDP 转发对网络要求较高，请确保您的网络环境稳定喵。

---

## 📖 SOCKS5 知识百科

### 什么是 SOCKS5 喵？
SOCKS5 是一种通用代理协议，不仅可以转发网页 (HTTP)，还能转发各种 TCP/UDP 流量（如游戏、邮件、信令等）。它就像一个全能的“直通管道”，不改动数据内容，只负责在客户端和目标服务端之间高效搬运喵。

### 📡 关于 DNS 解析：SOCKS5 vs SOCKS5h
主人可能会听到 `socks5h` 这个词，它其实标志着 **DNS 解析在哪做**：

1. **普通模式 (SOCKS5)**：客户端在本地查询域名 IP，然后让代理去连那个 IP。
   - *风险*：如果主人的本地 DNS 环境不干净，可能还没连上代理就解析失败了喵 (DNS 泄漏)。
2. **远程解析模式 (SOCKS5h)**：客户端把域名直接发给代理，由代理在服务器端进行解析。
   - *优势*：完全无视本地 DNS 干扰，更安全、更准确喵。

> [!TIP]
> **魔法提示**：NekoLink 的 SOCKS5 服务**原生支持远程解析**喵！在 SwitchyOmega 等软件中选择“由代理服务器进行域名解析”即可自动启用 SOCKS5h 模式喵。

---

## 🏎️ 骨灰级性能优化：内核调优指南

当主人的 SOCKS5 服务需要承载成百上千的并发连接时，Linux 默认的内核参数可能会成为瓶颈。
猫娘为您准备了一份 **“赛车手专用”** 的调优清单，建议在 `/etc/sysctl.conf` 中添加以下内容喵：

```ini
# 1. 开启 TCP BBR 拥塞控制 (Google 黑科技，大幅提升弱网速度)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# 2. 增加 TCP 连接队列长度 (防止突发流量把连接挤爆)
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535

# 3. 扩大端口范围 & 允许端口复用 (解决 TIME_WAIT 耗尽端口问题)
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_tw_reuse = 1

# 4. 增大文件句柄上限 (防止 "Too many open files" 报错)
fs.file-max = 1000000
# 注意：还需要同步修改 /etc/security/limits.conf 中的 nofile 限制喵

# 5. 调整 TCP 缓冲区 (让大水管跑得更欢)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 16384 16777216
```

修改完成后，执行 `sudo sysctl -p` 即可生效喵！

---

## ❓ 常见问题

**Q: 为什么我设置了 `0.0.0.0` 却还是不能从外网连？**
A: 为了主人的安全，猫娘不允许随便暴露到公网喵！请使用 `socks5_listen_loopback` 配合指定的虚拟接口地址来进行受限的共享喵。

**Q: SOCKS5 模式下还要设置系统路由吗？**
A: 完全不需要喵！你可以把 `auto_route` 设为 `false`，这样只有手动设置了代理的软件才会走隧道，其他流量正常走本地网络，互不干扰喵！

---

祝主人使用愉快喵！如果遇到问题，随时召唤我哦喵！( ⸝⸝•ᴗ•⸝⸝ )੭⁾⁾
