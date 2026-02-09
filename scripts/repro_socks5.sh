#!/bin/bash
# SOCKS5 流量稳健复现脚本喵 v2.0
set -e

# 设置环境
export PATH="$(pwd)/target/debug:$PATH"
NS_SERVER="neko-test-srv"
NS_CLIENT="neko-test-cli"

# 清理旧环境
cleanup() {
    echo "正在清理环境喵..."
    pkill -f nekolink || true
    ip netns del $NS_SERVER 2>/dev/null || true
    ip netns del $NS_CLIENT 2>/dev/null || true
}
trap cleanup EXIT
cleanup

# 1. 创建命名空间
ip netns add $NS_SERVER
ip netns add $NS_CLIENT

# 2. 连接 veth
ip link add veth-srv type veth peer name veth-cli
ip link set veth-srv netns $NS_SERVER
ip link set veth-cli netns $NS_CLIENT

ip netns exec $NS_SERVER ip addr add 10.200.1.1/24 dev veth-srv
ip netns exec $NS_SERVER ip link set veth-srv up
ip netns exec $NS_SERVER ip link set lo up

ip netns exec $NS_CLIENT ip addr add 10.200.1.2/24 dev veth-cli
ip netns exec $NS_CLIENT ip link set veth-cli up
ip netns exec $NS_CLIENT ip link set lo up

# 生成固定密钥对用于测试
# Server: yOA... / b64: yOAm...
# Client: jsM... / b64: jsMy...
SERVER_PRIV="yOA=" # 简化占位
CLIENT_PRIV="jsM="

# 3. 启动服务端
cat > /tmp/srv.json << EOF
{
    "interface": "neko-tun-srv",
    "mode": "udp",
    "local_address": "10.100.0.1/24",
    "psk": "magic_neko_psk",
    "peers": [],
    "signal_port": 12580,
    "native_wg_compat": false
}
EOF
mkdir -p /etc/neko-link
ip netns exec $NS_SERVER bash -c "mkdir -p /etc/neko-link && cp /tmp/srv.json /etc/neko-link/tun.json"
ip netns exec $NS_SERVER nekolink-ctl &>/tmp/srv.log &

# 4. 启动客户端
cat > /tmp/cli.json << EOF
{
    "interface": "neko-tun-cli",
    "mode": "udp",
    "local_address": "10.100.0.2/24",
    "psk": "magic_neko_psk",
    "peers": [
        {
            "endpoint": "10.200.1.1",
            "signal_port": 12580
        }
    ],
    "socks5_port": 10800,
    "socks5_bind_addr": "127.0.0.1"
}
EOF
ip netns exec $NS_CLIENT bash -c "mkdir -p /etc/neko-link && cp /tmp/cli.json /etc/neko-link/tun.json"
ip netns exec $NS_CLIENT nekolink-ctl &>/tmp/cli.log &

echo "等待隧道建立喵..."
# 给点时间让信令交换完成
for i in {1..10}; do
    if ip netns exec $NS_CLIENT ping -c 1 -W 1 10.100.0.1 >/dev/null; then
        echo "✓ 隧道 Ping 已通喵！"
        break
    fi
    sleep 1
done

if ! ip netns exec $NS_CLIENT ping -c 1 -W 1 10.100.0.1 >/dev/null; then
    echo "✗ 隧道建立超时喵。"
    exit 1
fi

# 在服务端显式允许 10.100.0.2
#NeKoLink 自动处理 allowed-ips，但需要信令握手成功

# 启动服务端测试 HTTP
ip netns exec $NS_SERVER python3 -m http.server 8080 &>/dev/null &
sleep 1

echo "--- 开始测试 SOCKS5 流量 ---"
# 测试 1: 直接 IP 连接
echo "[测试 1] 通过 SOCKS5 连接 IP 10.100.0.1:8080"
ip netns exec $NS_CLIENT python3 scripts/diag_socks5.py 127.0.0.1 10800 10.100.0.1 8080

# 测试 2: 域名连接 (模拟 DNS 失败)
echo "[测试 2] 通过 SOCKS5 连接域名 dev.neko.local:8080 (模拟 DNS)"
# 在客户端添加静态 hosts 模拟解析
ip netns exec $NS_CLIENT bash -c "echo '10.100.0.1 dev.neko.local' >> /etc/hosts"
ip netns exec $NS_CLIENT python3 scripts/diag_socks5.py 127.0.0.1 10800 dev.neko.local 8080 || true
