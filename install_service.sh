#!/bin/bash
# install_service.sh - 一键安装为 Systemd 服务

if [ "$EUID" -ne 0 ]; then echo "请使用 root 权限 (sudo)"; exit 1; fi

INSTALL_DIR="/opt/vpn"
BIN_NAME="vpn"
SERVICE_NAME="vpn"

echo ">>> 正在编译..."
go build -o $BIN_NAME main.go
if [ $? -ne 0 ]; then echo "编译失败"; exit 1; fi

echo ">>> 安装到 $INSTALL_DIR ..."
mkdir -p $INSTALL_DIR
cp $BIN_NAME $INSTALL_DIR/

# 询问是 Server 还是 Client
echo "请选择安装模式:"
echo "1) 服务端 (Server) - 使用 config.json"
echo "2) 客户端 (Client) - 使用 client_config.json"
echo "3) 取消"
read -p "请输入 [1/2]: " choice

CFG_SRC=""
if [ "$choice" == "1" ]; then
    if [ ! -f "config.json" ]; then
        echo "错误: 当前目录下找不到 config.json，请先运行 run_server.sh 生成并配置好！"
        exit 1
    fi
    CFG_SRC="config.json"
    SERVICE_DESC="Go-EtherTunnel VPN Server"
elif [ "$choice" == "2" ]; then
    if [ ! -f "client_config.json" ]; then
        echo "错误: 当前目录下找不到 client_config.json，请先运行 run_client.sh 生成并配置好！"
        exit 1
    fi
    CFG_SRC="client_config.json"
    SERVICE_DESC="Go-EtherTunnel VPN Client"
else
    echo "已取消。"
    exit 0
fi

# 复制配置文件
cp $CFG_SRC $INSTALL_DIR/config.json
echo "配置已复制到 $INSTALL_DIR/config.json"

# 创建 Systemd Unit
cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=$SERVICE_DESC
After=network.target

[Service]
Type=simple
WORKDIR=$INSTALL_DIR
ExecStart=$INSTALL_DIR/$BIN_NAME -c config.json
Restart=always
RestartSec=5
User=root
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

echo ">>> 重新加载 Systemd..."
systemctl daemon-reload
systemctl enable ${SERVICE_NAME}

echo "-----------------------------------------------------"
echo "✅ 安装成功！"
echo "启动服务: systemctl start ${SERVICE_NAME}"
echo "停止服务: systemctl stop ${SERVICE_NAME}"
echo "查看状态: systemctl status ${SERVICE_NAME}"
echo "-----------------------------------------------------"
