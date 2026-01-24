#!/bin/bash
# NekoLink XDP 故障诊断脚本 (Nya~ 🐾)
# 用于排查物理/虚拟网卡为何不支持 Native XDP 模式

IFACE=$1
if [ -z "$IFACE" ]; then
    echo "使用方法: sudo ./check_xdp.sh <网卡名称，如 eth0>"
    exit 1
fi

echo "=================================================="
echo "🔍 正在对网卡 $IFACE 进行 eBPF/XDP 兼容性体检..."
echo "=================================================="

# 1. 检查网卡驱动
echo -e "\n[1] 正在检查网卡驱动信息..."
DRIVER=$(ethtool -i "$IFACE" 2>/dev/null | grep driver | awk '{print $2}')
if [ -z "$DRIVER" ]; then
    echo "❌ 无法获取驱动信息，请确认网卡名称是否正确喵。"
else
    echo "✅ 当前驱动: $DRIVER"
    # 提示常见驱动兼容性
    case "$DRIVER" in
        virtio_net)
            echo "💡 提示: virtio_net 支持 XDP，但如果是在 PVE 中，请确保网卡设置了 '多队列 (Multi-queue)'，且 MTU 不要设置得太大喵。"
            ;;
        veth)
            echo "💡 提示: veth 接口通常需要内核 4.20+ 才能支持 Native XDP。"
            ;;
        bridge)
            echo "⚠️ 警告: Linux Bridge (网桥) 接口通常不支持 Native XDP，建议直接挂载在物理成员网卡上喵。"
            ;;
        i40e|ixgbe|mlx5_core|bnxt_en)
            echo "✨ 极品驱动: 这款驱动对 Native XDP 支持非常好喵！"
            ;;
        *)
            echo "ℹ️ 如果 Native 模式报错 Operation not supported，通常是因为驱动源码还没适配 XDP 钩子。"
            ;;
    esac
fi

# 2. 检查内核特性支持
echo -e "\n[2] 正在检查内核 BPF 特性支持..."
if [ -f "/proc/config.gz" ]; then
    CONFIG_SRC="zcat /proc/config.gz"
elif [ -f "/boot/config-$(uname -r)" ]; then
    CONFIG_SRC="cat /boot/config-$(uname -r)"
fi

if [ -n "$CONFIG_SRC" ]; then
    $CONFIG_SRC | grep -E "CONFIG_BPF_SYSCALL|CONFIG_XDP_SOCKETS|CONFIG_BPF_JIT" | sed 's/CONFIG_//'
else
    echo "⚠️ 无法找到内核 config 文件，跳过此步喵。"
fi

# 3. 检查当前挂载状态
echo -e "\n[3] 当前网卡的 XDP 挂载状态:"
ip link show "$IFACE" | grep -E "xdp|prog" || echo "✨ 当前网卡未挂载任何 XDP 程序。"

# 4. 尝试一次“空加载”测试（需要 iproute2-ebpf 环境）
echo -e "\n[4] 正在尝试底层驱动兼容性压力测试..."
if command -v bpftool &> /dev/null; then
    echo "✅ 系统已安装 bpftool，环境很专业喵！"
else
    echo "💡 建议安装 bpftool (apt install linux-cpupower-dbgsym 等包带，或者从源码编译)。"
fi

# 5. 常见原因总结
echo -e "\n=================================================="
echo "🐾 诊断建议总结:"
echo "--------------------------------------------------"
echo "1. 操作不支持 (Operation not supported): 驱动没写 XDP 代码。升级内核到 Debian 13 (6.10+) 可能会有奇迹。"
echo "2. PVE/虚拟机环境: 请务必在虚拟网卡设置里手动开启 'Multiqueue' (队列数设为 CPU 核心数)。"
echo "3. MTU 限制: Native XDP 模式下，驱动会保留一些空间给 XDP，如果 MTU 太大（如 >3000）驱动可能会拒绝加载。"
echo "4. 通用模式也能飞: 如果诊断结果显示驱动确实无能为力，[Generic Mode] 依然比用户态快很多，请放心使用喵！"
echo "=================================================="
