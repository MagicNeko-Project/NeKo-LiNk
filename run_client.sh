#!/bin/bash
if [ "$EUID" -ne 0 ]; then echo "Root required"; exit 1; fi

if [ -f "client_config.json" ]; then
    if ! grep -q "protocol" client_config.json; then
        echo "发现旧配置，备份为 client_config.json.bak 并生成新配置..."
        mv client_config.json client_config.json.bak
    fi
fi

if [ ! -f "client_config.json" ]; then
    cat > client_config.json <<EOF
{
  "server_addr": "1.2.3.4",
  "protocol": "udp",
  "ip_protocol_num": 233,
  "base_port": 9000,
  "port_count": 4,
  "key": "change-this-to-a-secure-key-32-chars-exact!",
  "local_addr": "10.0.0.2/24",
  "mode": "client",
  "interface_name": "tap0",
  "mtu": 1400
}
EOF
fi

echo "启动 VPN Client..."
./vpn -c client_config.json
