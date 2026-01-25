#!/bin/bash

# NekoLink System Tuning Script 🚀
# 解决高吞吐下的 "No Buffer Space Available" 和内核级丢包问题

# 注意: 在 LXC 容器中，大多数 sysctl 是只读的。
# 如果执行报错，请联系宿主机管理员调整，或忽略非关键优化。

echo "Applying kernel optimizations..."

# 1. 增加 UDP/IP 接收和发送缓冲区 (关键！)
# 默认通常只有 200KB，跑 300Mbps 瞬间就溢出了。
# 调整为 25MB
sysctl -w net.core.rmem_max=26214400
sysctl -w net.core.rmem_default=26214400
sysctl -w net.core.wmem_max=26214400
sysctl -w net.core.wmem_default=26214400

# 2. 增加网络设备积压队列 (Backlog)
# 防止网卡中断处理不过来导致丢包
sysctl -w net.core.netdev_max_backlog=10000

# 3. 启用 BBR (有助于 TCP 性能，虽然 NekoLink 是 UDP，但对隧道内的流量有帮助)
sysctl -w net.ipv4.tcp_congestion_control=bbr

# 4. 其它优化
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.udp_rmem_min=16384
sysctl -w net.ipv4.udp_wmem_min=16384

echo "---------------------------------------------"
echo "Optimization Done!"
echo "Please restart NekoLink to apply socket buffer changes:"
echo "  sudo systemctl restart neko-link"
echo "---------------------------------------------"
