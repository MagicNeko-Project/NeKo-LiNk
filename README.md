# NekoLink 🐱 (Shadow WireGuard Edition)

一个为极端环境设计的、全自动、高隐蔽性、基于 eBPF 的 Layer 3 加密隧道。
现在的 NekoLink 将官方 `wireguard-go` 的安全性与 eBPF/XDP 带来的巅峰性能完美结合，为您提供最智能的隧道体验。

## ✨ 核心特性

*   **Shadow WireGuard (wg-raw)**: 官方 WireGuard 内核，但**不走 UDP**。流量被巧妙地封装在自定义 IP 协议号或 **TCP 伪装协议**中。
*   **eBPF / 幻影模式 (Phantom Mode)**: 采用 Linux 最前沿的 **eBPF/XDP** 技术，直接在物理网卡驱动层捕获和重定向流量。系统甚至不再需要虚拟网卡，彻底隐身！
*   **多核加速流水线**: 深度优化的“单生产者-多消费者”模型，支持多核并行加解密，即使在 10Gbps 负载下也能保持低延迟。
*   **全链路内存复用**: 引入自适应 `sync.Pool` 内存池，全链路几乎零内存分配，极大降低了垃圾回收 (GC) 对网络延迟的影响。
*   **自进化配置引擎**: 内置 `-migrate` 模式，自动识别旧版配置并平滑升级至最新架构，支持物理接口自动探测。

## 🧠 eBPF 技术深度解析 (黑科技揭秘)

NekoLink 的核心威力源自对 **eBPF (Extended Berkeley Packet Filter)** 的深度运用：

1.  **XDP (eXpress Data Path)**:
    传统的网络处理需要经过 Linux 内核协议栈的层层剥离，开销巨大。NekoLink 在物理网卡接收数据的**第一个瞬间（驱动入口）**就插入了 eBPF 程序。这使得我们可以直接在内核层决定某个包的去向，无需经过繁重的协议栈处理。

2.  **AF_XDP (Address Family XDP)**:
    我们通过 `AF_XDP` 专用套接字建立了“内核与用户态的极速直连通道”。流量通过 **Zero-copy (零拷贝)** 或 **Copy mode** 直接从网卡 DMA 传输到 NekoLink 的处理流水线，规避了传统 Socket 调用中昂贵的 context switch 成本。

3.  **BPF Maps 自注册**:
    程序启动时会动态编译并向内核加载 XDP 程序，并利用 **BPF Map** 进行实时的“身份登记”。只有符合我们加密协议特征的“暗号包”才会被重定向到用户态，其余流量依然由操作系统原本的协议栈处理，互不干扰，安全无感。

## 🛠️ 快速开始

### 1. 编译 (需要安装 Go 1.24+)
```bash
./setup_go.sh  # 一键配置猫咪生产线
./.go/bin/go build -o neko-link .
```

### 2. 配置 (config.json) 参考
```json
{
  "interface_name": "neko0",   // 您心仪的逻辑接口名 (15字符以内)
  "mode": "server",            // 角色: server 或 client
  "local_addr": "10.0.0.1/24", // 隧道内网 IP
  "key": "myaespassword",      // 共享密码 (喵呜~)
  "protocol": "wg-raw",        // 核心协议: wg-raw (Shadow WG)
  "parent_interface": "eth0",  // [重要] 真实的物理网卡名
  "listen_port": 23333,        // 外部通讯端口
  "wg_port": 51820,            // 内部 WireGuard 端口 (通常不用改)
  "mtu": 1400                  // 为保证兼容性建议 1380~1400
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
- **V1.5 配置升级**: `./neko-link -migrate -c config.json`
  - 程序会读取旧配置，并生成一个纯净的 `config.json.v15`。
  - **新特性**: V1.5 格式会根据您选择的 `protocol` 自动过滤字段。例如 `wg-raw` 模式将不再显示 `local_addr` 等无关字段，让配置更专注、更清爽喵~

---
主人，快来体验这由 eBPF 驱动的、极致丝滑的“影子隧道”世界吧喵！(≧∇≦)/🐾
