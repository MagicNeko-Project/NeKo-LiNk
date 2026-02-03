# NekoLink 架构设计文档

版本: 3.0.0

## 1. 核心设计理念

NekoLink 是一个专注于 **极致性能** 和 **跨平台移植性** 的 WireGuard 协议实现。与原版 BoringTun 或其他 Rust 实现（如 GotaTun）相比，NekoLink 采用了独特的多线程同步事件循环架构，旨在最大化利用多核 CPU 性能并减少任务切换开销。

### 1.1 核心特性
- **多线程模型 (N-Threads)**: 不同于 Tokio 的工作窃取 (Work-stealing) 模式，NekoLink 采用 "Run-to-Completion" 的多线程模型。每个线程绑定一个独立的 Epoll/Kqueue 实例，独占处理分配给它的任务，无锁竞争。
- **纯粹的 Event Loop**: 摒弃了复杂的异步运行时 (Async Runtime)，直接通过 `libc` 封装底层的 `epoll` (Linux/Android) 或 `kqueue` (macOS/iOS)。
- **零内存分配 (Zero-Allocation)**: 数据平面中的所有缓冲区（接收、发送、中间状态）均在启动时预分配。运行时实现了真正的零 GC、零动态内存分配。
- **原始系统调用**: 直接使用 `recvmmsg` / `sendmmsg` 等高级系统调用，绕过标准库的开销。

---

## 2. 线程模型对比：为什么不使用 Tokio？

| 特性 | NekoLink (Current) | GotaTun / Tokio | 决策理由 |
| :--- | :--- | :--- | :--- |
| **调度方式** | 操作系统原生线程调度 | 用户态协程调度 (Green Threads) | 对于网络密集型 I/O，OS 调度更“硬”，更能抵抗 CPU 抖动。 |
| **上下文切换** | 较低 (仅系统调用时) | 极低 (协程切换) | 虽然协程切换快，但复杂的 Runtime 会引入额外的 Overhead。 |
| **任务隔离** | 强 (线程间完全隔离) | 弱 (任务可能阻塞整个 Runtime) | 弱网环境下，单一任务的阻塞不应影响其他任务。 |
| **GRO/GSO** | 手动控制 (精细化) | 依赖 Runtime 或 OS | NekoLink 手动实现的用户态切片 (Segmentation) 比通用实现更高效。 |

---

## 3. 数据流处理 (Data Plane)

### 3.1 接收路径 (RX Path)
1.  **Syscall**: 线程调用 `recvmmsg`，一次性从内核拉取 **64 个** 数据包。
2.  **GRO Processing**:
    - 检查 `cmsg` 辅助数据。
    - 如果发现 `UDP_GRO` 标记，根据 `segment_size` 在用户态进行零拷贝切片。
    - 将一个大包虚拟化为多个小包处理。
3.  **Decryption**: ChaCha20-Poly1305 解密（多线程并行）。
4.  **Routing**: 查表决定路由到 TUN 设备还是丢弃。
5.  **TUN Write**: 写入 TUN 设备（支持多队列）。

### 3.2 发送路径 (TX Path)
1.  **TUN Read**: 从 TUN 设备读取 IP 包。
2.  **Encryption**: ChaCha20-Poly1305 加密。
3.  **Batching**:
    - 加密后的包**不立即发送**。
    - 而是填充到 `ThreadData` 的 `send_batch_bufs` 队列中。
4.  **Syscall**:
    - 当队列满 (64个) 或当前 Event Loop 周期结束时。
    - 调用 `sendmmsg` 一次性刷入内核。

---

## 4. 跨平台支持

- **Linux / Android**: 完整支持，启用 `recvmmsg`, `sendmmsg`, `UDP_GRO`。
- **macOS / iOS**: 支持，使用 `kqueue`，暂不支持 GRO (内核限制)。
- **Windows**: 基础支持 (实验性)。
