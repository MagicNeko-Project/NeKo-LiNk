#!/bin/bash
if [ "$EUID" -ne 0 ]; then echo "Root required"; exit 1; fi

# 为了让用户看到新配置，备份旧的 (如果存在切不含 protocol 字段)
if [ -f "config.json" ]; then
    if ! grep -q "protocol" config.json; then
        echo "发现旧配置，备份为 config.json.bak 并生成新配置..."
        mv config.json config.json.bak
    fi
fi

if [ ! -f "config.json" ]; then
    cat > config.json <<EOF
{
  "server_addr": "[::]",
  "protocol": "udp",
  "ip_protocol_num": 233,
  "base_port": 9000,
  "port_count": 4,
  "key": "change-this-to-a-secure-key-32-chars-exact!",
  "local_addr": "10.0.0.1/24",
  "mode": "server",
  "interface_name": "tap0",
  "mtu": 1400
}
EOF
fi

echo "启动 VPN Server..."
./vpn -c config.json
