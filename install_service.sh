#!/bin/bash
# install_service.sh - NekoLink 一键安装脚本 (Systemd)

if [ "$EUID" -ne 0 ]; then echo "请使用 root 权限 (sudo)"; exit 1; fi

APP_NAME="neko-link"
BIN_NAME="neko-link"
CONF_DIR="/etc/neko-link"
BIN_DIR="/usr/local/bin"

echo ">>> 正在编译 $APP_NAME ..."
# Detect Local Go
GO_CMD="./.go/bin/go"
if [ ! -f "$GO_CMD" ]; then GO_CMD="go"; fi

$GO_CMD build -o $BIN_NAME .
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
    TARGET_CONF="$CONF_DIR/server.json"
    
    # Check if we need to generate
    if [ ! -f "$TARGET_CONF" ]; then
        echo "当前目录无 server.json，是否生成默认服务端配置？(y/n)"
        read -p "> " gen_cfg
        if [ "$gen_cfg" == "y" ]; then
             RAND_KEY=$(openssl rand -hex 32)
             cat > "$TARGET_CONF" <<EOF
[
  {
    "server_addr": "[::]",
    "protocol": "wg-raw",
    "ip_protocol_num": 233,
    "key": "$RAND_KEY",
    "local_addr": "10.0.0.1/24",
    "mode": "server",
    "interface_name": "neko0",
    "mtu": 1400
  }
]
EOF
            echo "已生成默认配置 (Key: $RAND_KEY) -> $TARGET_CONF"
        else
            if [ -f "config.json" ]; then
                cp config.json "$TARGET_CONF"
                echo "使用了当前目录的 config.json"
            else
                 echo "未生成配置。安装后请手动创建 $TARGET_CONF"
            fi
        fi
    fi
    SERVICE_DESC="NekoLink VPN Server"
    
elif [ "$choice" == "2" ]; then
    TARGET_CONF="$CONF_DIR/client.json"
    
    if [ ! -f "$TARGET_CONF" ]; then
         echo "生成默认客户端配置模板..."
         cat > "$TARGET_CONF" <<EOF
[
  {
    "server_addr": "1.2.3.4",
    "protocol": "wg-raw",
    "ip_protocol_num": 233,
    "key": "FILL_ME",
    "local_addr": "10.0.0.2/24",
    "mode": "client",
    "interface_name": "eth0",
    "mtu": 1400,
    "wg_port": 51820
  }
]
EOF
        echo "已生成: $TARGET_CONF (请记得修改 ip 和 key)"
    fi
    SERVICE_DESC="NekoLink VPN Client"
else
    echo "已取消。"
    exit 0
fi

chmod 600 "$TARGET_CONF"

# 创建 Systemd Unit
# 使用目录作为配置源，支持多文件加载
CONF_ARG="$CONF_DIR"

cat > /etc/systemd/system/${APP_NAME}.service <<EOF
[Unit]
Description=$SERVICE_DESC
After=network.target

[Service]
Type=simple
ExecStart=$BIN_DIR/$BIN_NAME -c $CONF_ARG
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
