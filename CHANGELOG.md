# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.7.5] - 2026-02-02

### Added
- **接口级热重载魔法**：实现了基于 `SIGHUP` 信号的零停机配置更新，支持不重启进程的情况下更新隧道。
- **nekolink-ctl reload**：新增专门的重载指令，通过信号机制触发表内实例的差异对比与增量更新。
- **优雅任务调度**：引入 `CancellationToken` 与 `JoinHandle` 异步等待机制，确保旧实例资源（特别是 `udp2raw` 侧车与 `iptables` 规则）被彻底清理后再启动新实例。
- **脚本交互升级**：`nekolink.sh` (v2.7.5) 现在集成了热重载选项，并会在修改配置后智能提示主人重载喵。

- **信令协议严苛隔离**：修复了 RawIP 模式接口在 TCP 信令管道中被误识别的问题。
- **WireGuard 兼容模式满血复活**：修复了兼容模式下 UAPI 密钥格式不匹配及域名解析失效的问题。
- **架构级重构**：内部状态管理由静态 `Vec` 全面升级为动态 `HashMap` + `RwLock` 架构，满足高并发下的读写分离。
- **信令自适应级联**：全局信令端口或 Raw IP 协议列表变更时，UDP/TCP/RawIP 三大信令管道会自动侦测并执行级联式平滑重启。

## [2.7.0] - 2026-02-02

### Fixed
- **传输模式完全隔离**：修复了 RawIP 模式错误启动 `udp2raw` 侧车的问题，现在 TCP/UDP/RawIP 三种模式完全独立互不干扰。
- **IPv6 MTU 计算**：修正了 IPv6 隧道的 MTU 开销计算（IPv6 头 40 字节 vs IPv4 头 20 字节）。
- **TCP 信令端口协商**：修复了 `tcp_data_port` 配置为 0 时，信令中发送 0 而非默认 4567 的问题。
- **模式参数传递**：修复了收到 TCP 信令 ACK 后，`configure_peer` 被硬编码传入 `"tcp"` 的 bug。

### Changed
- 代码版本升级至 2.7.0，统一所有子项目版本号。

---

## [2.6.0] - 2026-02-01

### Added
- **全自动 MTU 协商魔法**：当 MTU 设置为 `0` 时，两端会自动通过信令交换探测到的 PMTU。
- **智能收敛算法**：自动选取双端探测值的最小值作为最终接口 MTU，彻底解决“木桶效应”导致的数据包分片问题。
- **高级设置菜单**：在 `nekolink.sh` 中新增“高级设置”分级菜单，支持批量开启全自动 MTU 协商。
- **探测缓存机制**：引入 PMTU 探测结果缓存，避免频繁探测带来的性能损耗。

### Fixed
- 修正了 `udp2raw` (FakeTCP) 模式下的精准开销计算（从 72 修正为 84 字节）。
- 解决了 TCP 信令握手中并发任务导致的生命周期借用冲突问题。

## [2.5.1] - 2026-02-01

### Added
- 支持自动检测 `iptables` 指令是否存在。
- 引入 `nftables` (nft) 备选方案，在缺少 `iptables` 的环境下（如 Debian 12）自动接管 TCP 拦截规则。
- 增加程序退出时自动清理 `nftables` 拦截表和规则的逻辑。

### Fixed
- 修复 `udp2raw` 在缺少 `iptables` 环境下启动失败并产生僵尸进程的问题。

## [2.5.0] - 2026-02-01

### Added
- 集成 `udp2raw` 作为新的 Fake-TCP 传输插件，支持更为稳定的 Raw TCP 伪装。
- `install.sh` 现在能自动根据系统架构（amd64/arm64）下载并打包 `udp2raw` 二进制。
- 支持使用 PSK 的前 16 位字符作为 `udp2raw` 的鉴权密钥。

### Removed
- 删除了 `phantun` 相关的子项目及其编译依赖。
- 移除了不再使用的 `phantun` nftables 手动配置逻辑。

### Changed
- 将 TCP 模式的底层传输从 Phantun 迁移至 udp2raw，大幅提升 NAT 穿透成功率与稳定性。

## [2.4.8] - 2026-02-01

### Added
- `nekolink.sh` 配置助手新增全局信令端口（signal_port）设置菜单（选项 8）。
- 客户端配置向导现在支持将服务端 IP 与对端信令端口分开输入。

### Changed
- 扩展信令报文格式，从 36 字节增加至 38 字节，新增 2 字节用于协商 Fake-TCP 数据端口。
- TCP 模式下的数据端口现在完全实现自动协商，用户无需手动填写的端口默认为 `0`（自动）。

## [2.4.7] - 2026-02-01

### Added
- 实现 Fake-TCP 模式全自动侧车生命周期管理。
- 服务端模式下检测到 `tcp` 模式时自动拉起伪装服务。
- 客户端在信令连接成功后自动根据协商结果启动伪装客户端。

## [2.4.6] - 2026-01-31

### Added
- 将 `phantun-client` 与 `phantun-server` 预编译二进制纳入 `.deb` 包。
- 自动为插件二进制设置 `CAP_NET_ADMIN` 能力，允许非 root（受限）环境下运行相关网络操作。
- `nekolink-ctl` 现在能自动生成配套的 nftables NAT/MASQUERADE 规则。

### Changed
- 新增 `tcp_data_port` 配置项，允许用户在自动协商失效时手动锁定伪装端口（默认 4567）。

## [2.4.5] - 2026-01-30

### Added
- **Fake-TCP 插件化架构**：引入外部侧车插件机制，解耦核心加密逻辑与伪装传输层。
- 实现单信令端口（12580）多隧道共享机制，大幅节省公网暴露端口。
- 增加 `get_actual_listen_port` 机制，支持通过 UAPI 感知底层随机分配的真实监听端口。

### Changed
- 信令传输现在会根据 `mode` 自动切换底层协议：`tcp` 模式使用真 TCP 连接，`udp` 使用原生 UDP，`ip` 使用 Raw IP。

### Fixed
- 修复了在多层 NAT 环境下，UDP 信令无法打洞导致无法正常握手的问题。

## [2.4.1] - 2026-01-28

### Added
- 增加服务端自动同步客户端 MTU 的响应机制。
- `nekolink.sh` 中增加 `Auto Sync` 配置开关。

## [2.4.0] - 2026-01-28

### Added
- **自适应 MTU 探测**：集成 `mtu-probe` 命令，通过二进制搜索算法自动寻找最佳 PMTU 值。
- 配置向导在创建隧道时会自动推荐探测到的 MTU 值。

## [2.3.0] - 2026-01-27

### Added
- 在 `nekolink-core` 中直接集成了初步的 Fake-TCP 协议栈模拟。
- `nekolink-cli` 增加 `--fake-tcp` 原型控制开关。
- 交互脚本 3.0：新增“TCP 伪装模式”创建选项。

## [2.2.0] - 2026-01-28

### Added
- **配置文件就地修改**：允许通过 `nekolink` 脚本直接加载并编辑已有的 JSON 配置。
- 安全加固：升级核心加密库依赖，消除已知漏洞。

## [2.1.0] - 2026-01-28

### Added
- Debian 官方打包支持（一键生成 `.deb` 文件）。
- 建立 GitHub Actions CI/CD 自动构建流。
- 集成 `nftables` 实现全自动 TCP MSS Clamping，解决跨网访问网页卡死的顽疾。
- 新增 `migrate.sh` 平滑迁移脚本。

### Fixed
- 修复了 `nekolink.sh` 中因参数未引用导致的变量名拼写错误（EBADFD错误）。

## [2.0.0] - 2026-01-27

### Added
- **100% UDP-Free IP 模式**：通过原生 Raw IP (Protocol 51/115 等) 传输数据。
- 智能信令休眠机制（Smart Halt）：握手成功后控制面自动进入低功耗休眠，减少指纹暴露。

## [0.7.0] - 2026-01-09

### Changed
- BREAKING: `noise::Tunn::new` 变更为 infallible（不可失败）。

### Fixed
- 升级有漏洞的依赖项：ring, x25519-dalek。
- 修复 FreeBSD 平台下的编译错误。
- 修复 `device::Peer::connect_endpoint` 中错误的套接字类型。

[2.5.1]: https://github.com/MagicNeko-Project/NeKo-LiNk/compare/v2.5.0...v2.5.1
[2.5.0]: https://github.com/MagicNeko-Project/NeKo-LiNk/compare/v2.4.8...v2.5.0
[2.4.8]: https://github.com/MagicNeko-Project/NeKo-LiNk/compare/v2.4.7...v2.4.8
[2.4.7]: https://github.com/MagicNeko-Project/NeKo-LiNk/compare/v2.4.6...v2.4.7
[2.4.6]: https://github.com/MagicNeko-Project/NeKo-LiNk/compare/v2.4.5...v2.4.6
[2.4.5]: https://github.com/MagicNeko-Project/NeKo-LiNk/compare/v2.4.1...v2.4.5
[2.4.1]: https://github.com/MagicNeko-Project/NeKo-LiNk/compare/v2.4.0...v2.4.1
[2.4.0]: https://github.com/MagicNeko-Project/NeKo-LiNk/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/MagicNeko-Project/NeKo-LiNk/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/MagicNeko-Project/NeKo-LiNk/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/MagicNeko-Project/NeKo-LiNk/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/MagicNeko-Project/NeKo-LiNk/compare/v0.7.0...v2.0.0
[0.7.0]: https://github.com/MagicNeko-Project/NeKo-LiNk/releases/tag/v0.7.0