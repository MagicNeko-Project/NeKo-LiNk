#!/bin/bash
# SOCKS5 兼容性验证脚本喵 v1.0

# 准备测试目录
mkdir -p /tmp/neko-socks5-test
mkdir -p /etc/neko-link

# 确保 127.0.0.2 可用喵
ip addr add 127.0.0.2/8 dev lo 2>/dev/null || true

# 创建配置 A
cat > /etc/neko-link/testA.json << EOF
{
    "interface": "neko-testA",
    "mode": "udp",
    "local_address": "10.0.1.1/24",
    "psk": "test_psk",
    "peers": [],
    "socks5_port": 10800,
    "socks5_bind_addr": "127.0.0.1"
}
EOF

# 创建配置 B (同端口 10800，但地址是 127.0.0.2)
cat > /etc/neko-link/testB.json << EOF
{
    "interface": "neko-testB",
    "mode": "udp",
    "local_address": "10.0.2.1/24",
    "psk": "test_psk",
    "peers": [],
    "socks5_port": 10800,
    "socks5_bind_addr": "127.0.0.2"
}
EOF

echo "正在启动 nekolink-ctl 进行冲突兼容性测试喵..."

# 设置 PATH 确保 ctl 能找到刚编译的 cli
export PATH="$(pwd)/target/debug:$PATH"

# 启动 ctl (后台运行)
./target/debug/nekolink-ctl &>/tmp/neko-ctl-test.log &
CTL_PID=$!

sleep 3

echo "--- 监听状态检查 ---"
ss -tln | grep 10800

if [ $(ss -tln | grep 10800 | wc -l) -eq 2 ]; then
    echo -e "\n\033[0;32m🎉 成功喵！两个隧道都在 10800 端口共存了，且绑定在不同 IP！\033[0m"
else
    echo -e "\n\033[0;31m❌ 失败喵... 监听数量不正确。\033[0m"
    cat /tmp/neko-ctl-test.log
fi

# 清理
kill $CTL_PID 2>/dev/null || true
pkill -f nekolink-cli || true
rm /etc/neko-link/testA.json /etc/neko-link/testB.json 2>/dev/null || true
