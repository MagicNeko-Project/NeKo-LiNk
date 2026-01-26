#!/bin/bash
set -e

SERVICE_NAME="neko-link"
INSTALL_PATH="/usr/local/bin/neko-link"

echo ">>> 更新 Neko-Link (Rust)..."

# 1. 拉取代码
echo "Pulling latest code..."
git pull

# 2. 编译
echo "Building release binary..."
export RUSTFLAGS="-C target-cpu=native"
cargo build --release

# 3. 停止服务
echo "Stopping service..."
systemctl stop $SERVICE_NAME

# 4. 替换二进制
echo "Updating binary..."
cp target/release/neko-link "$INSTALL_PATH"
chmod +x "$INSTALL_PATH"

# 5. 更新 Systemd 配置
SERVICE_FILE="neko-link.service"
if [ -f "$SERVICE_FILE" ]; then
    echo "Updating systemd service file..."
    cp "$SERVICE_FILE" "/etc/systemd/system/$SERVICE_FILE"
    systemctl daemon-reload
fi

# 6. 重启
echo "Restarting service..."
systemctl start $SERVICE_NAME
systemctl status $SERVICE_NAME --no-pager

echo ">>> 更新完成! 喵! 🐾"
