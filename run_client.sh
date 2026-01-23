#!/bin/bash
if [ "$EUID" -ne 0 ]; then echo "请使用 root 权限运行 (sudo)"; exit 1; fi

CONFIG_FILE="client_config.json"

if [ ! -f "$CONFIG_FILE" ]; then
    echo ">>> 未发现客户端配置，生成默认模版..."
    
    cat > "$CONFIG_FILE" <<EOF
{
  "server_addr": "1.2.3.4",
  "protocol": "udp",
  "ip_protocol_num": 233,
  "base_port": 9000,
  "port_count": 4,
  "key": "PLEASE_COPY_KEY_FROM_SERVER_CONFIG",
  "local_addr": "10.0.0.2/24",
  "mode": "client",
  "interface_name": "tap0",
  "mtu": 1400
}
EOF
    echo -e "\033[0;32m配置文件 client_config.json 已生成！\033[0m"
    echo "-----------------------------------------------------"
    echo "请务必编辑该文件："
    echo "1. 修改 'server_addr' 为服务端的真实 IP。"
    echo "2. 修改 'key' 为服务端生成的随机密钥。"
    echo "-----------------------------------------------------"
    echo "修改完成后，请再次运行 ./run_client.sh 启动连接。"
    exit 0
fi

# Check for placeholder
if grep -q "PLEASE_COPY_KEY_FROM_SERVER_CONFIG" "$CONFIG_FILE"; then
    echo -e "\033[0;31m错误：未设置密钥！\033[0m"
    echo "请编辑 $CONFIG_FILE，填入正确的 Server Key。"
    exit 1
fi

if grep -q "1.2.3.4" "$CONFIG_FILE"; then
    echo -e "\033[0;33m警告：Server IP 似乎仍是默认的 1.2.3.4，确认要连接吗？(3秒后继续)\033[0m"
    sleep 3
fi

echo ">>> 正在启动 VPN Client..."
./vpn -c "$CONFIG_FILE"
