#!/bin/bash
if [ "$EUID" -ne 0 ]; then echo "请使用 root 权限运行 (sudo)"; exit 1; fi

CONFIG_FILE="config.json"

# 检查 config.json 是否存在
if [ ! -f "$CONFIG_FILE" ]; then
    echo ">>> 未发现配置文件，生成默认配置..."
    
    # Generate random key
    RAND_KEY=$(openssl rand -hex 32)
    
    cat > "$CONFIG_FILE" <<EOF
{
  "server_addr": "[::]",
  "protocol": "udp",
  "ip_protocol_num": 233,
  "base_port": 9000,
  "port_count": 4,
  "key": "$RAND_KEY",
  "local_addr": "10.0.0.1/24",
  "mode": "server",
  "interface_name": "tap0",
  "mtu": 1400
}
EOF
    echo -e "\033[0;32m配置文件 config.json 已生成！\033[0m"
    echo -e "已为您自动生成随机密钥: \033[0;33m$RAND_KEY\033[0m"
    echo "-----------------------------------------------------"
    echo "请检查该文件，确认端口和 IP 设置无误。"
    echo "确认无误后，请再次运行 ./run_server.sh 启动服务。"
    echo "-----------------------------------------------------"
    exit 0
fi

# Run
echo ">>> 正在启动 VPN Server..."
./vpn -c "$CONFIG_FILE"
