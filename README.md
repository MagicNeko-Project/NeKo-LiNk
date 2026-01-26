# Neko-Link (Rust Version) 🐾

喵！欢迎来到 **Neko-Link** 的 Rust 重制版！✨
这是一个高性能、低延迟的网络隧道工具，专门为了让你的网络连接像猫咪一样灵敏而生！🚀

## ✨ 新特性 (Rust vs Go)

比起原来的 Go 版本，Rust 版本可是有了超多进化哦！💪

### 1. 🚀 性能大爆发 (GRO/GSO)
我们学会了新的魔法！
- **GSO (Generic Segmentation Offload)**: 发送数据时，我们会把一大块数据 (64KB) 直接交给网卡，让它自己去切片。这样 CPU 就不容易累啦！
- **GRO (Generic Receive Offload)**: 接收数据时，我们会把好多小包包拼成一个大包再处理。减少了好多系统调用，吞吐量蹭蹭涨！📈

### 2. 🛡️ 内存更安全 (Buffer Pool)
我们也更懂事了，学会了 **Buffer Pool** (内存池) 技术。不再乱丢垃圾 (GC)，而是乖乖地复用内存，运行起来又稳又快！

### 3. ⚡ 黑科技 AF_XDP (实验性)
这是最厉害的！我们可以直接和网卡驱动说话 (eBPF)，绕过慢吞吞的操作系统内核。
*注：如果环境不支持，我会乖乖降级到普通模式，不用担心罢工哦！*

## 🛠️ 如何食用

### 环境要求
- Linux (Debian 12 推荐) 🐧
- Rust 1.70+ (如果需要自己编译) 🦀

### 一键安装环境 (Debian 12)
```bash
sudo ./scripts/install_rust_env.sh
```

### 快速迁移 (从 Go 版本)
如果你之前在用 Go 版本，别担心，我准备了搬家脚本！📦
```bash
sudo ./scripts/migrate_go_to_rust.sh
```
它会自动备份旧文件，把新家布置好，然后无缝切换！

### 日常维护
- **更新**: `sudo ./scripts/update_rust.sh`
- **体检**: `sudo ./scripts/debug_rust.sh`

## 📝 配置文件
配置文件 `config.json` 和以前几乎一模一样哦！
不过现在不仅支持 `raw` 协议，未来还会支持 `udp` 哦 (画饼中...) 🍪

```json
{
  "mode": "server", 
  "protocol": "raw", 
  "interface_name": "neko0",
  "mtu": 1400
}
```

## ⚠️ 注意事项
- **无公网 IP?**: 如果没有公网 IP，Raw 模式可能连不上哦。请期待后续的 UDP 模式！
- **权限**: 因为要操作网卡，请务必用 `root` 或者 `sudo` 运行我！

---
Made with ❤️ and Rust by MagicNeko Project. 
有问题记得来找我玩哦！喵~ 🐾
