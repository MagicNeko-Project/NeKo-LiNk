#!/bin/bash
# NekoLink 升级脚本

if [ "$EUID" -ne 0 ]; then echo "请使用 root 权限 (sudo)"; exit 1; fi

SERVICE_NAME="neko-link"
BIN_NAME="neko-link"
BIN_DIR="/usr/local/bin"

echo ">>> 正在拉取最新代码..."
git pull
if [ $? -ne 0 ]; then echo "Git pull 失败，请检查网络或仓库状态"; exit 1; fi

# 编译新版本 (优先使用本地 Go)
GO="./.go/bin/go"
if [ ! -f "$GO" ]; then GO="go"; fi

echo ">>> 正在编译新版本 (使用 $($GO version))..."
$GO mod tidy
$GO build -o $BIN_NAME main.go
if [ $? -ne 0 ]; then echo "编译失败"; exit 1; fi

echo ">>> 停止当前服务..."
systemctl stop $SERVICE_NAME

echo ">>> 更新二进制文件..."
cp $BIN_NAME $BIN_DIR/
chmod +x $BIN_DIR/$BIN_NAME

echo ">>> 重启服务..."
systemctl start $SERVICE_NAME
systemctl status $SERVICE_NAME --no-pager

echo "-----------------------------------------------------"
echo "✅ NekoLink 升级完成！"
echo "-----------------------------------------------------"
