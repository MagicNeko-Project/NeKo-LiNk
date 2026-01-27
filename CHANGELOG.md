# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-01-28

### 新增功能 (Added)
- **Debian 打包支持**: 新增 `install.sh --package` 命令，支持一键构建适用于 Debian 12+ 的 `.deb` 安装包喵。
- **CI/CD 自动化**: 新增 GitHub Actions 工作流，每次推送代码自动构建并发布 Debian 安装包。
- **状态显示优化**: 在 IP 模式下，UAPI 状态现在会准确显示 `protocol=协议号`，修复了之前错误显示为 `listen_port` 的问题喵。
- **Systemd 深度集成**: 管理脚本 `neko-link` 的启动逻辑全面转向 `systemctl restart`，管理服务更加规范。
- **平滑迁移脚本**: 新增 `migrate.sh` 魔法脚本，支持从手动安装一键平滑迁移至 .deb 包管理模式，自动清理冲突文件并保留配置喵。
- **IPv6 优先级增强**: 在使用 Raw IP 传输 IPv6 信令时，自动设置 Traffic Class (DSCP) 为 `0xE0` (CS7)，确保连接质量。
- **TCP MSS 自动修复**: 集成 `nftables` 实现 MSS Clamping，解决 MTU 导致的网页加载问题。

### 优化改进 (Improved)
- **命名规范化**: 二进制文件统一更名为 `nekolink`, `nekolink-cli`, `nekolink-ctl`。
- **生命周期管理**: 强化了控制平面与隧道的“共命”关系，服务停止时自动回收所有虚拟网卡与进程喵。
- **交互式配置**: 完善了 `neko-link` 脚本，支持更多高级网络选项。

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