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
    "ip_protocol_num": 233,
    "local_addr": "10.0.0.1/24",
    "server_addr": "0.0.0.0",
    "key": "$RAND_KEY",
    "interface_name": "neko0",
    "mtu": 1400
  }
]
EOF
    echo "配置已生成 (Key: $RAND_KEY)"
    exit 0
fi

echo ">>> 启动 NekoLink (Server)..."
./neko-link -c "$CONFIG_FILE"
