#!/bin/bash

SERVICE_NAME="neko-link"

echo "=== Neko-Link (Rust) 诊断工具 🐾 ==="
echo "Time: $(date)"
echo "-----------------------------------"

# 1. 服务状态
echo "[1] 服务状态 (Systemd)"
systemctl status $SERVICE_NAME --no-pager
echo ""

# 2. 进程状态
echo "[2] 进程信息"
pgrep -a neko-link
echo ""

# 3. 日志 (最后 20 行)
echo "[3] 最近日志"
journalctl -u $SERVICE_NAME -n 20 --no-pager
echo ""

# 4. 网络接口
echo "[4] 网络接口状态"
ip addr show neko0 2>/dev/null || echo "neko0 interface not found"
ip addr show neko0_app 2>/dev/null || echo "neko0_app interface not found"
echo ""

# 5. Ethtool 状态 (检查 Offload)
echo "[5] Offload 状态 (neko0)"
ethtool -k neko0 2>/dev/null | grep -E "tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload" || echo "ethtool failed"
echo ""

# 6. 连通性测试 (假设对端 IP 是 192.168.200.1 或 .2)
# 从 config.json 读取 peer_addr 太复杂，这里做简单的猜测 ping
echo "[6] 连通性测试 (Ping)"
for ip in 192.168.200.1 192.168.200.2; do
    echo "Pinging $ip ..."
    ping -c 3 -W 1 $ip || echo "Failed to ping $ip"
done

echo "=== 诊断结束 ==="
