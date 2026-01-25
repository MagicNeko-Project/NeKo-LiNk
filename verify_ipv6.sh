#!/bin/bash
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo "Run as root"
    exit 1
fi

echo -e "${GREEN}>>> Setup Network Namespaces...${NC}"

ip netns del ns_server 2>/dev/null || true
ip netns del ns_client 2>/dev/null || true

ip netns add ns_server
ip netns add ns_client

ip link add v_srv type veth peer name v_cli

ip link set v_srv netns ns_server
ip link set v_cli netns ns_client

# Config IP (Physical) - Keep transport IPv4 to isolate tunnel IPv6 test.
ip netns exec ns_server ip addr add 10.0.0.1/24 dev v_srv
ip netns exec ns_server ip link set v_srv up
ip netns exec ns_server ip link set lo up

ip netns exec ns_client ip addr add 10.0.0.2/24 dev v_cli
ip netns exec ns_client ip link set v_cli up
ip netns exec ns_client ip link set lo up

echo -e "${GREEN}>>> Check Physical Link...${NC}"
ip netns exec ns_client ping -c 1 10.0.0.1 >/dev/null || { echo -e "${RED}Physical link down!${NC}"; exit 1; }

echo -e "${GREEN}>>> Generate Config...${NC}"

# Server Config (IPv6 Tunnel Address)
cat > raw_server_v6.json <<EOF
{
    "interface_name": "nekos0",
    "mode": "server",
    "local_addr_v6": "fd00::1/64",
    "key": "TEST_KEY_123",
    "protocol": "raw",
    "listen_addr": "10.0.0.1",
    "listen_port": 0,
    "mtu": 1400,
    "debug": true
}
EOF

# Client Config
cat > raw_client_v6.json <<EOF
{
    "interface_name": "nekoc0",
    "mode": "client",
    "local_addr_v6": "fd00::2/64",
    "key": "TEST_KEY_123",
    "protocol": "raw",
    "mtu": 1400,
    "peer_addr": "10.0.0.1",
    "debug": true
}
EOF

echo -e "${GREEN}>>> Start NekoLink...${NC}"

ip netns exec ns_server sh -c "ulimit -l unlimited; ./neko-link -c raw_server_v6.json" > server_v6.log 2>&1 &
PID_S=$!

ip netns exec ns_client sh -c "ulimit -l unlimited; ./neko-link -c raw_client_v6.json" > client_v6.log 2>&1 &
PID_C=$!

sleep 5

echo -e "${GREEN}>>> Check IPv6 Tunnel Connectivity...${NC}"

if ip netns exec ns_client ping6 -c 3 fd00::1; then
    echo -e "${GREEN}>>> SUCCESS: Client can Ping6 Server (Tunnel)! 喵！${NC}"
else
    echo -e "${RED}>>> FAILED: IPv6 Ping failed.${NC}"
    echo "Server Log:"
    cat server_v6.log
    echo "Client Log:"
    cat client_v6.log
    exit 1
fi

echo -e "${GREEN}>>> Cleanup...${NC}"
kill $PID_S 2>/dev/null || true
kill $PID_C 2>/dev/null || true
ip netns del ns_server
ip netns del ns_client
rm raw_server_v6.json raw_client_v6.json server_v6.log client_v6.log
