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
    "interface_name": "eth0",
    "peer_addr": "1.2.3.4",
    "peer_port": 23333,
    "wg_port": 51820,
    "ip_protocol_num": 233,
    "local_addr": "10.0.0.2/24",
    "key": "YOUR_PRIVATE_KEY",
    "mtu": 1400,
    "comment": "Mode 3 (Phantom): interface_name 填物理网卡(eth0)。NekoLink 不创建虚接口，直接劫持eth0。"
  }
]
EOF
    echo "配置已生成！请编辑 key 和 server_ip。"
    exit 0
fi

echo ">>> 启动 NekoLink (Client)..."
./neko-link -c "$CONFIG_FILE"
