#!/bin/bash
set -e

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 必须以 root 运行
if [ "$EUID" -ne 0 ]; then 
    echo "请使用 root 权限运行 (sudo)"
    exit 1
fi

echo -e "${GREEN}>>> 准备测试环境 (Network Namespaces)...${NC}"

# 1. 清理旧环境
ip netns del ns_server 2>/dev/null || true
ip netns del ns_client 2>/dev/null || true

# 2. 创建命名空间
ip netns add ns_server
ip netns add ns_client

# 3. 创建 veth pair (模拟物理链路)
ip link add v_srv type veth peer name v_cli

# 4. 将接口移动到命名空间
ip link set v_srv netns ns_server
ip link set v_cli netns ns_client

# 5. 配置 IP (模拟公网 IP)
# Server: 10.0.0.1
ip netns exec ns_server ip addr add 10.0.0.1/24 dev v_srv
ip netns exec ns_server ip link set v_srv up
ip netns exec ns_server ip link set lo up

# Client: 10.0.0.2
ip netns exec ns_client ip addr add 10.0.0.2/24 dev v_cli
ip netns exec ns_client ip link set v_cli up
ip netns exec ns_client ip link set lo up

# 测试物理连通性
echo -e "${GREEN}>>> 测试物理链路连通性...${NC}"
ip netns exec ns_client ping -c 1 10.0.0.1 >/dev/null || { echo -e "${RED}物理链路不通！${NC}"; exit 1; }
echo "物理链路正常 (Client -> Server)"

# 6. 生成配置文件
echo -e "${GREEN}>>> 生成测试配置...${NC}"

# Server Config
cat > raw_server_test.json <<EOF
{
    "interface_name": "nekos0",
    "mode": "server",
    "local_addr_v4": "192.168.200.1/24",
    "key": "TEST_KEY_123",
    "protocol": "raw",
    "listen_addr": "10.0.0.1",
    "listen_port": 0,
    "mtu": 1400,
    "debug": true
}
EOF

# Client Config
cat > raw_client_test.json <<EOF
{
    "interface_name": "nekoc0",
    "mode": "client",
    "local_addr_v4": "192.168.200.2/24",
    "key": "TEST_KEY_123",
    "protocol": "raw",
    "mtu": 1400,
    "peer_addr": "10.0.0.1",
    "debug": true
}
EOF

echo -e "${GREEN}>>> 启动 NekoLink...${NC}"

# 启动 Server
ip netns exec ns_server sh -c "ulimit -l unlimited && ./neko-link -c raw_server_test.json" > server.log 2>&1 &
PID_S=$!
echo "Server PID: $PID_S"

# 启动 Client
ip netns exec ns_client sh -c "ulimit -l unlimited && ./neko-link -c raw_client_test.json" > client.log 2>&1 &
PID_C=$!
echo "Client PID: $PID_C"

sleep 3

echo -e "${GREEN}>>> 检查隧道连通性...${NC}"

# Client Ping Server Tunnel IP
if ip netns exec ns_client ping -c 3 192.168.200.1; then
    echo -e "${GREEN}>>> 测试成功: Client 可以 Ping 通 Server (Tunnel)! 喵！${NC}"
else
    echo -e "${RED}>>> 测试失败: 无法 Ping 通隧道。${NC}"
    echo "Server Log:"
    cat server.log
    echo "Client Log:"
    cat client.log
fi

# Cleanup
echo -e "${GREEN}>>> 清理环境...${NC}"
kill $PID_S 2>/dev/null || true
kill $PID_C 2>/dev/null || true
ip netns del ns_server
ip netns del ns_client
rm raw_server_test.json raw_client_test.json server.log client.log
