#!/bin/bash
echo "=== Neko-Link Log Monitor 🐾 ==="
echo "Press Ctrl+C to exit..."
echo ""

# 使用 journalctl 跟踪日志
# -u: 指定服务
# -f: Follow mode
# -n: 显示最近 50 行
journalctl -u neko-link -f -n 50 --output cat
