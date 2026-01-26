#!/bin/bash
# NekoLink Verification Script (Robust Version)

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}>>> 深度清理旧环境...${NC}"
pkill neko-link || true
pkill iperf3 || true
ip netns del ns_server 2>/dev/null || true
ip netns del ns_client 2>/dev/null || true

echo -e "${GREEN}>>> 准备测试场...${NC}"
ip netns add ns_server
ip netns add ns_client
ip link add v_srv type veth peer name v_cli
ip link set v_srv netns ns_server
ip link set v_cli netns ns_client
ip netns exec ns_server ip addr add 10.0.0.1/24 dev v_srv
ip netns exec ns_server ip link set v_srv up
ip netns exec ns_server ip link set lo up
ip netns exec ns_client ip addr add 10.0.0.2/24 dev v_cli
ip netns exec ns_client ip link set v_cli up
ip netns exec ns_client ip link set lo up

# 生成配置
cat > raw_server_test.json <<EOF
{
    "interface_name": "nekos0",
    "app_interface": "nekos0_app",
    "mode": "server",
    "local_addr": "192.168.200.1/24",
    "key": "TEST_KEY_123",
    "protocol": "raw",
    "listen_addr": "10.0.0.1",
    "listen_port": 0,
    "mtu": 1200,
    "debug": true
}
EOF

cat > raw_client_test.json <<EOF
{
    "interface_name": "nekoc0",
    "app_interface": "nekoc0_app",
    "mode": "client",
    "local_addr": "192.168.200.2/24",
    "key": "TEST_KEY_123",
    "protocol": "raw",
    "mtu": 1200,
    "peer_addr": "10.0.0.1",
    "debug": true
}
EOF

echo -e "${GREEN}>>> 启动 NekoLink (Release Mode)...${NC}"
# Use absolute path to ensure binary is found
BIN="./target/release/neko-link"
ip netns exec ns_server $BIN -c raw_server_test.json > /tmp/neko_server.log 2>&1 &
PID_S=$!
ip netns exec ns_client $BIN -c raw_client_test.json > /tmp/neko_client.log 2>&1 &
PID_C=$!

echo "等待隧道建立 (8s)..."
sleep 8

echo -e "${GREEN}>>> 测试隧道连通性 (Ping)...${NC}"
if ip netns exec ns_client ping -c 5 192.168.200.1; then
    echo -e "${GREEN}>>> Ping 测试通过！${NC}"
else
    echo -e "${RED}>>> Ping 测试失败！${NC}"
fi

echo -e "${GREEN}>>> 开启 5201 端口性能测试 (iperf3)...${NC}"
ip netns exec ns_server iperf3 -s -D > /dev/null 2>&1
sleep 2
ip netns exec ns_client iperf3 -c 192.168.200.1 -t 10

echo -e "${GREEN}>>> 测试完成喵！日志已保存在 /tmp/neko_{server,client}.log${NC}"
echo -e "${GREEN}>>> 请手动运行 pkill neko-link 清理环境喵。${NC}"
