#!/bin/bash
if [ "$EUID" -ne 0 ]; then echo "请使用 root 权限运行 (sudo)"; exit 1; fi

CONFIG_FILE="config.json"

if [ ! -f "$CONFIG_FILE" ]; then
    echo ">>> 生成服务端配置..."
    
    RAND_KEY=$(openssl rand -hex 32)
    
    cat > "$CONFIG_FILE" <<EOF
[
  {
    "mode": "server",
    "protocol": "wg-raw",
    "interface_name": "eth0",
    "listen_addr": "0.0.0.0",
    "listen_port": 23333,
    "wg_port": 51820,
    "ip_protocol_num": 233,
    "local_addr": "10.0.0.1/24",
    "key": "$RAND_KEY",
    "mtu": 1400,
    "comment": "Mode 3 (Phantom): InterfaceName 是物理网卡(eth0)，wg_port 是内核 WG 端口(127.0.0.1)"
  }
]
EOF
    echo "配置已生成 (Key: $RAND_KEY)"
    exit 0
fi

echo ">>> 启动 NekoLink (Server)..."
./neko-link -c "$CONFIG_FILE"
