#!/bin/bash
# install_service.sh - NekoLink 一键安装脚本 (Systemd)

if [ "$EUID" -ne 0 ]; then echo "请使用 root 权限 (sudo)"; exit 1; fi

APP_NAME="neko-link"
BIN_NAME="neko-link"
CONF_DIR="/etc/neko-link"
BIN_DIR="/usr/local/bin"

# 检查依赖
if ! command -v clang &> /dev/null; then
    echo "错误: 未找到 clang 编译器。"
    echo "请先运行依赖安装脚本: sudo bash setup_go.sh"
    exit 1
fi

echo ">>> 正在编译 $APP_NAME (使用 Make)..."
# Check env
if [ ! -f ".go/bin/go" ] && ! command -v go &> /dev/null; then
    echo ">>> 检测到缺失 Go 环境，正在初始化..."
    bash setup_go.sh
fi
make
if [ $? -ne 0 ]; then echo "编译失败"; exit 1; fi

echo ">>> 安装二进制文件到 $BIN_DIR ..."
cp $BIN_NAME $BIN_DIR/
chmod +x $BIN_DIR/$BIN_NAME

echo ">>> 创建配置目录 $CONF_DIR ..."
mkdir -p $CONF_DIR

# 询问是 Server 还是 Client
echo "请选择安装模式:"
echo "1) 服务端 (Server)"
echo "2) 客户端 (Client)"
echo "3) 取消"
read -p "请输入 [1/2]: " choice

CFG_SRC=""
if [ "$choice" == "1" ]; then
    CFG_SRC="config.json"
    if [ ! -f "$CFG_SRC" ]; then
        echo "当前目录无 $CFG_SRC，是否生成默认服务端配置？(y/n)"
        read -p "> " gen_cfg
        if [ "$gen_cfg" == "y" ]; then
             echo "是否开启现代科技加速 (AF_XDP)? (y/N)"
             read -p "> " use_xdp
             USE_XDP_VAL="false"
             PHY_IFACE=""
             if [ "$use_xdp" == "y" ] || [ "$use_xdp" == "Y" ]; then
                USE_XDP_VAL="true"
                echo "请输入物理网卡名称 (例如 eth0):"
                read -p "> " PHY_IFACE
                if [ -z "$PHY_IFACE" ]; then PHY_IFACE="eth0"; fi
             fi

             RAND_KEY=$(openssl rand -hex 32)
             cat > config.json <<EOF
[
  {
    "mode": "server",
    "protocol": "udp",
    "use_xdp": $USE_XDP_VAL,
    "xdp_device": "$PHY_IFACE",
    "interface_name": "neko0",
    "local_addr": "10.0.0.1/24",
    "server_addr": "0.0.0.0",
    "base_port": 9000,
    "port_count": 4,
    "key": "$RAND_KEY",
    "mtu": 1400
  }
]
EOF
             echo "已生成默认配置 (Key: $RAND_KEY)"
        else
            echo "错误：找不到配置文件。"; exit 1
        fi
    fi
    SERVICE_DESC="NekoLink VPN Server"
elif [ "$choice" == "2" ]; then
    CFG_SRC="client_config.json"
    if [ ! -f "$CFG_SRC" ]; then
         echo "警告：当前目录找不到 $CFG_SRC，安装后请务必去 $CONF_DIR/config.json 手动配置！"
         
         # 同样的 XDP 询问逻辑
         echo "是否开启现代科技加速 (AF_XDP)? (y/N)"
         read -p "> " use_xdp
         USE_XDP_VAL="false"
         PHY_IFACE=""
         if [ "$use_xdp" == "y" ] || [ "$use_xdp" == "Y" ]; then
            USE_XDP_VAL="true"
            echo "请输入物理网卡名称 (例如 eth0):"
            read -p "> " PHY_IFACE
            if [ -z "$PHY_IFACE" ]; then PHY_IFACE="eth0"; fi
         fi

         cat > client_config.json <<EOF
[
  {
    "mode": "client",
    "protocol": "udp",
    "use_xdp": $USE_XDP_VAL,
    "xdp_device": "$PHY_IFACE",
    "interface_name": "neko0",
    "local_addr": "10.0.0.2/24",
    "server_ip": "1.2.3.4",
    "server_port": 9000,
    "base_port": 9000,
    "port_count": 4,
    "key": "FILL_ME",
    "socks_bind": "127.0.0.1:1080",
    "mtu": 1400
  }
]
EOF
    fi
    SERVICE_DESC="NekoLink VPN Client"
else
    echo "已取消。"
    exit 0
fi

# 复制配置文件
echo ">>> 安装配置文件到 $CONF_DIR/config.json ..."
cp $CFG_SRC $CONF_DIR/config.json
chmod 600 $CONF_DIR/config.json

# 创建 Systemd Unit
# 注意：我们不再指定 -c 参数，让程序自己去读 /etc/neko-link/config.json 或默认值
# 为了稳妥，我们显式指定配置文件路径
cat > /etc/systemd/system/${APP_NAME}.service <<EOF
[Unit]
Description=$SERVICE_DESC
After=network.target

[Service]
Type=simple
ExecStart=$BIN_DIR/$BIN_NAME -c $CONF_DIR/config.json
Restart=always
RestartSec=5
User=root
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

echo ">>> 重新加载 Systemd..."
systemctl daemon-reload
systemctl enable ${APP_NAME}

echo "-----------------------------------------------------"
echo "✅ NekoLink 安装成功！(Nya~)"
echo "无法抗拒的连接已经建立在: $CONF_DIR/config.json"
echo ""
echo "启动服务: systemctl start $APP_NAME"
echo "停止服务: systemctl stop $APP_NAME"
echo "查看状态: systemctl status $APP_NAME"
echo "-----------------------------------------------------"
