#!/bin/bash
# NekoLink Debug Helper (Nya~ 🐾)
# 一键停止服务、重编译、前台运行并打印详细日志。

if [ "$EUID" -ne 0 ]; then echo -e "\033[0;31m请使用 root 权限 (sudo) 运行我喵！\033[0m"; exit 1; fi

SERVICE_NAME="neko-link"
APP_BIN="./neko-link"

echo ">>> [Debug] 正在尝试停止系统服务 $SERVICE_NAME ..."
systemctl stop $SERVICE_NAME 2>/dev/null

echo ">>> [Debug] 正在清理旧的编译产物..."
rm -f $APP_BIN

echo ">>> [Debug] 正在确认 Go 环境..."
GO_CMD="./.go/bin/go"
if [ ! -f "$GO_CMD" ]; then
    echo ">>> [Debug] 未发现本地 Go，尝试使用系统 Go..."
    GO_CMD="go"
fi

echo ">>> [Debug] 正在重新编译 (使用 $($GO_CMD version))..."
$GO_CMD build -o $APP_BIN .
if [ $? -ne 0 ]; then
    echo -e "\033[0;31m❌ 编译失败了，请检查代码喵！\033[0m"
    exit 1
fi

echo ">>> [Debug] 正在自动优化配置文件..."
$APP_BIN -migrate -c "$CONF"

# 查找配置
CONF="/etc/neko-link/config.json"
if [ ! -f "$CONF" ]; then
    if [ -f "config.json" ]; then
        CONF="config.json"
    else
        echo -e "\033[0;31m❌ 找不到配置文件喵！(请在 /etc/neko-link/ 或当前目录准备好 config.json)\033[0m"
        exit 1
    fi
fi

echo -e "\033[0;32m>>> [Debug] NekoLink 启动！(配置路径: $CONF)\033[0m"
echo ">>> (温馨提示: 按下 Ctrl+C 就可以停止调试啦喵~)"
echo "---------------------------------------------------"

# 运行并强制刷新日志，默认开启调试模式 (如果 main.go 支持该参数)
$APP_BIN -c "$CONF" -debug
