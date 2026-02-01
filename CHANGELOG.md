# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v2.5.1 (2026-02-01)
- 🐛 **修复**：解决 `udp2raw` 在缺少 `iptables` 环境（如 Debian 12）下启动失败的问题。
- ✨ **改进**：支持自动检测 `iptables`，若缺失则自动通过 `nftables` (nft) 接管 TCP 拦截规则。
- 🧹 **改进**：增加退出时对应的 `nftables` 规则自动清理逻辑。

- 🎉 **重大更新：从 Phantun 迁移到 udp2raw**！
    - **更简单的集成**: udp2raw 使用 raw socket，无需 TUN 接口，避免了 IP 冲突问题
    - **更少的依赖**: 无需 nftables 手动配置，udp2raw 使用 `-a` 参数自动管理 iptables 规则
    - **更好的兼容性**: udp2raw 是成熟稳定的 C++ 项目，支持 FakeTCP/ICMP/UDP 多种伪装模式
    - **自动下载**: `install.sh` 会自动下载对应架构的 udp2raw 二进制

## v2.4.8 (2026-02-01)
- 喵喵！**信令协议增强 + 配置向导优化**：
    - **配置向导增强**: 新增全局信令端口设置选项（菜单选项 8）
    - **分离输入**: 客户端配置时，服务端 IP 和信令端口分开输入，更加清晰
    - **Phantun 端口自动协商**: TCP 模式不再需要手动指定端口，通过信令交换自动协商
    - **信令协议扩展**: 包格式从 36 字节扩展为 38 字节，新增 Phantun 数据端口字段

## v2.4.7 (2026-02-01)
- 喵喵！**TCP 模式极简化体验**，一键开启 Fake-TCP 隧道：
    - **服务端全自动**: 只需配置 `"mode": "tcp"` + 空 peers，`phantun-server` 会自动启动喵！
    - **客户端全自动**: 配置 peers.endpoint 后，`phantun-client` 侧车会在信令握手时自动启动。
    - **零配置负担**: 不再需要手动运行任何 Phantun 命令，一切由 `nekolink-ctl` 统一调度。

## v2.4.6 (2026-01-31)
- 喵呜！**Phantun 联动完善修复**，解决了 v2.4.5 发现的集成问题：
    - **二进制部署**: `phantun-client` 和 `phantun-server` 现已纳入 deb 安装包，并自动设置 `CAP_NET_ADMIN` 能力。
    - **nftables 自动配置**: 启动 TCP 侧车时会自动配置所需的 NAT/MASQUERADE 规则，无需手动干预喵。
    - **端口分离**: 新增 `tcp_data_port` 配置项（默认 4567），区分信令端口（12580）和 Phantun 数据端口。
    - **全局信令端口遵守**: TCP/UDP 模式均遵守 `/etc/neko-link/global.json` 中的 `signal_port` 配置。

## v2.4.5 (2026-01-30)
- 喵呜！实现了 **Fake-TCP 插件化重构**，引入 Phantun 作为侧车插件：
    - **核心解耦**: 将复杂的 TCP 模拟协议栈从 `nekolink-core` 中完全剥离，核心层回归原生 UDP/IP 性能。
    - **自动侧车管理**: `nekolink-ctl` 现在能自动调度 `phantun-client` 进程，为 TCP 模式的队友自动建立中转站。
    - **现代化适配**: 深度修复了 Phantun 源码与最新版 `nix`, `tokio`, `bytes` 库的兼容性问题。
    - **全量构建**: 支持工作区全量一键编译，插件与主程序完美合流喵！

- 喵呜！重构了全局信令架构，锁定端口为 **12580** (一按我帮您) ฅ^•ﻌ•^ฅ：
    - **单端口多隧道共享**: 现在一个 12580 端口就能识别并分发所有隧道的握手包，不再需要每个隧道占用不同端口。
    - **数据端口自动协商**: 12580 仅作为控制平面，实际的数据隧道端口会自动通过信令交换并协商，支持监听端口设置为 `0`（自动分配）。
- 更新了 `nekolink.sh` 交互配置助手，全面对齐 12580 默认值与自动协商逻辑。
- 增加了 `get_actual_listen_port` 机制，实时感知底层网卡分配的真实端口。

- 喵呜！信令系统现在会根据传输模式**自动切换协议**：
    - `tcp` 模式改用真 TCP 信令，完美穿透 NAT 环境喵！
    - `ip` 模式维持 Raw IP 传输，追求极致隐蔽。
    - `udp` 模式维持 UDP 传输，兼容性拉满。
- 修复了 `nekolink-ctl` 在 NAT 环境下无法完成握手的问题。

## v2.4.1 (2026-01-28)
- 喵呜！新增了 **MTU 动态同步机制**，服务端可自动跟随客户端的 MTU。
- 在 `nekolink.sh` 中增加了 `Auto Sync` 模式选项。

## v2.4.0 (2026-01-28)
- 喵喵！新增了 **自适应 MTU 探测机制**，自动识别链路 PMTU。
- 在 `nekolink-ctl` 中添加 `mtu-probe` 命令。
- 在 `nekolink.sh` 助手创建配置时自动推荐最佳 MTU 值。
- [x] 验证并集成 <!-- id: 27 -->
    - [x] 联调验证 MTU 同步效果 <!-- id: 28 -->
    - [x] 更新 `nekolink.sh` 给用户提供 "auto MTU" 选项 <!-- id: 29 -->
    - [x] 统一并更新版本号为 2.4.1 <!-- id: 30 -->

## v2.3.0 (2026-01-27)

### 新增功能 (Added)
- **全内置 Fake-TCP 模式**: 在 `nekolink-core` 中实现了完整的伪造 TCP 协议栈喵！支持完整的 TCP 握手模拟与数据封包，让隧道流量在复杂的网络防火墙下也能如履平地。
- **命令行 Fake-TCP 支持**: 为 `nekolink-cli` 增加了 `--fake-tcp` 开关，让高手们能手动开启伪装模式喵。
- **控制平面 TCP 适配**: `nekolink-ctl` 现在能解析 `"mode": "tcp"` 并自动下发所有底层配置，让 TCP 模式像 UDP 一样平滑喵。
- **交互脚本 3.0**: `nekolink` 交互菜单新增“TCP 伪装模式”选项，极地下配置门槛喵。

## [2.2.0] - 2026-01-28

### 新增功能 (Added)
- **交互式配置修改**: 现在的 `nekolink` 命令支持直接修改现有的配置文件了喵！无需删除再重建，魔法调整更方便。
- **安全加固 (PR 453)**: 合并了来自上游 BoringTun 的 PR 453，升级了所有核心加密依赖（aead, chacha20poly1305 等）以消除已知漏洞，并引入了全新的协议模糊测试与安全集成测试。

## [2.1.0] - 2026-01-28

### 新增功能 (Added)
- **Debian 打包支持**: 新增 `install.sh --package` 命令，支持一键构建适用于 Debian 12+ 的 `.deb` 安装包喵。
- **CI/CD 自动化**: 新增 GitHub Actions 工作流，每次推送代码自动构建并发布 Debian 安装包。
- **状态显示优化**: 在 IP 模式下，UAPI 状态现在会准确显示 `protocol=协议号`，修复了之前错误显示为 `listen_port` 的问题喵。
- **命名规范化**: 统一了命令前缀。主管理脚本为 `nekolink` (支持交互式菜单与命令转发)，守护进程为 `nekolink-cli`，控制器为 `nekolink-ctl`。
- **平滑迁移脚本**: 新增 `migrate.sh` 魔法脚本，支持从手动安装一键平滑迁移至 .deb 包管理模式，自动清理冲突文件并保留配置喵。
- **IPv6 优先级增强**: 在使用 Raw IP 传输 IPv6 信令时，自动设置 Traffic Class (DSCP) 为 `0xE0` (CS7)，确保连接质量。
- **TCP MSS 自动修复**: 集成 `nftables` 实现 MSS Clamping，解决 MTU 导致的网页加载问题。

### 优化改进 (Improved)
- **命名规范化**: 二进制文件统一更名为 `nekolink`, `nekolink-cli`, `nekolink-ctl`。
- **生命周期管理**: 强化了控制平面与隧道的“共命”关系，服务停止时自动回收所有虚拟网卡与进程喵。
- **交互式配置**: 完善了 `nekolink` 脚本 (原 `neko-link`)，支持更多高级网络选项。

### 修复 (Fixed)
- **修复 TUN 接口坏态错误**: 解决了交互式脚本中的参数转发 typo 导致的 `File descriptor in bad state (EBADFD)` 错误喵。
- **强化 CLI 健壮性**: 加强了 `nekolink-ctl` 的参数校验逻辑，防止因误输入指令导致启动冗余冲突实例喵。

## [2.0.0] - 2026-01-27

### 新增功能 (Added)
- **100% UDP-Free IP 模式**: 实现了完全基于 Raw IP 的数据与信令传输，彻底摆脱 UDP 协议限制。
- **智能信令停机 (Smart Halt)**: 隧道建立成功后信令交换自动进入休眠，极大降低流量特征喵。
- **密钥持久化**: 自动保存本地公私钥对，确保重启后 Peer 信息的一致性。
- **基础 UAPI 支持**: 实现了基于 Unix Socket 的控制接口，不再依赖外部 `wg` 命令。

## [0.7.0] - 2026-01-09

### Changes

- Breaking: make `noise::Tunn::new` infallible
- Upgrade vulnerable dependencies: ring, x25519-dalek
- Fix a compilation error on freebsd
- Fix incorrect socket type in `device::Peer::connect_endpoint`