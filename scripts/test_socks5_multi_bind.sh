#!/bin/bash
# SOCKS5 多地址绑定验证脚本喵 v1.0

# 准备测试目录
mkdir -p /etc/neko-link

# 确保 127.0.0.2 可用喵
ip addr add 127.0.0.2/8 dev lo 2>/dev/null || true

# 创建配置：单个接口监听两个 IP
cat > /etc/neko-link/testMulti.json << EOF
{
    "interface": "neko-testMulti",
    "mode": "udp",
    "local_address": "10.0.3.1/24",
    "psk": "test_psk",
    "peers": [],
    "socks5_port": 10801,
    "socks5_bind_addr": "127.0.0.1, 127.0.0.2"
}
EOF

echo "正在启动 nekolink-ctl 进行多地址绑定测试喵..."

export PATH="$(pwd)/target/debug:$PATH"

# 启动 ctl (后台运行)
./target/debug/nekolink-ctl &>/tmp/neko-multi-test.log &
CTL_PID=$!

sleep 3

echo "--- 监听状态检查 ---"
ss -tln | grep 10801

count=$(ss -tln | grep 10801 | wc -l)
if [ $count -eq 2 ]; then
    echo -e "\n\033[0;32m🎉 成功喵！单个隧道已经同时监听在两个 IP 上了！\033[0m"
else
    echo -e "\n\033[0;31m❌ 失败喵... 监听数量不正确 (预期 2，实际 $count)。\033[0m"
    cat /tmp/neko-multi-test.log
fi

# 清理
kill $CTL_PID 2>/dev/null || true
pkill -f nekolink-cli || true
rm /etc/neko-link/testMulti.json 2>/dev/null || true
