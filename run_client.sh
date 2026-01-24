#!/bin/bash
if [ "$EUID" -ne 0 ]; then echo "请使用 root 权限运行 (sudo)"; exit 1; fi

CONFIG_FILE="client_config.json"

if [ ! -f "$CONFIG_FILE" ]; then
    echo ">>> 生成客户端配置..."
    
    cat > "$CONFIG_FILE" <<EOF
[
  {
    "mode": "client",
    "protocol": "wg-raw",
    "peer_addr": "1.2.3.4",
    "peer_port": 23333,
    "ip_protocol_num": 233,
    "local_addr": "10.0.0.2/24",
    "key": "PASSWORD_HERE",
    "interface_name": "neko0",
    "mtu": 1400,
    "wg_port": 51820
  }
]
EOF
    echo "配置已生成！请编辑 key 和 server_ip。"
    exit 0
fi

echo ">>> 启动 NekoLink (Client)..."
./neko-link -c "$CONFIG_FILE"
