# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2026-01-27

### 新增功能 (Added)
- **Debian 打包支持**: 新增 `install.sh --package` 命令，支持一键构建适用于 Debian 12+ 的 `.deb` 安装包。
- **CI/CD 自动化**: 新增 GitHub Actions 工作流，每次推送代码自动构建并发布 Debian 安装包。
- **Raw IP 纯净模式**: 实现了完全基于 Raw IP 的信令传输，移除所有对 UDP 的依赖 (UDP-free)，增强隐蔽性。
- **IPv6 优先级增强**: 在 IPv6 Raw IP 模式下，自动设置 Traffic Class 为 `0xE0` (CS7)，确保信令享有最高网络优先级。
- **TCP MSS 自动修复**: 集成 `nftables` 实现 MSS Clamping，解决 MTU 导致的网页加载问题 (可在 `neko-link` 中开启)。
- **智能信令与 Keepalive**: 
    - 隧道建立后信令进程自动进入“永久休眠”模式，不再产生背景噪音。
    - 支持 WireGuard 原生 Keepalive 心跳包，保持 NAT 会话活跃。
- **交互式管理脚本**: `neko-link` 脚本全面升级，支持 MSS、Keepalive、MTU 等高级选项的交互式配置。
- **多架构支持**: 完善了对 IPv4/IPv6 双栈的检测与支持。

### 优化改进 (Improved)
- **命名规范化**: 二进制文件重命名为 `nekolink` (Core), `nekolink-cli` (Daemon), `nekolink-ctl` (Controller)。
- **生命周期管理**: 强化了控制平面与隧道的绑定，服务停止时自动清理虚拟网卡与残留进程。
- **安装体验**: 修复了 `Text file busy` 错误，优化了 systemd 服务配置。
- **构建系统**: 解决了 `futures` 依赖冲突，移除了不必要的构建依赖。

### 修复 (Fixed)
- 修复了 `nekolink-cli` 权限切换可能导致的启动失败问题。
- 修复了信令接收端逻辑，解决潜在的丢包与握手延迟。

## [0.7.0] - 2026-01-09

### Changes

- Breaking: make `noise::Tunn::new` infallible
- Upgrade vulnerable dependencies: ring, x25519-dalek
- Fix a compilation error on freebsd
- Fix incorrect socket type in `device::Peer::connect_endpoint`