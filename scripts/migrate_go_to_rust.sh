#!/bin/bash
set -e

# Configuration
SERVICE_NAME="neko-link"
GO_BIN_PATH="/usr/local/bin/neko-link"
RUST_BIN_PATH="$(pwd)/target/release/neko-link"
BACKUP_DIR="/root/neko-link-backup-$(date +%Y%m%d%H%M%S)"
CONFIG_DIR="/etc/neko-link"

echo ">>> 开始迁移 Neko-Link (Go -> Rust)..."

# 1. 检查 Rust 二进制是否已编译
if [ ! -f "$RUST_BIN_PATH" ]; then
    echo "Rust binary not found at $RUST_BIN_PATH. Compiling..."
    export RUSTFLAGS="-C target-cpu=native"
    cargo build --release
fi

# 2. 停止服务
echo "Stopping existing service..."
systemctl stop $SERVICE_NAME || true

# 3. 备份
echo "Backing up legacy files to $BACKUP_DIR..."
mkdir -p $BACKUP_DIR
if [ -f "$GO_BIN_PATH" ]; then
    cp "$GO_BIN_PATH" "$BACKUP_DIR/neko-link.go"
fi
if [ -d "$CONFIG_DIR" ]; then
    cp -r "$CONFIG_DIR" "$BACKUP_DIR/config"
fi

# 4. 安装 Rust 版本
echo "Installing Rust binary..."
cp "$RUST_BIN_PATH" "$GO_BIN_PATH"
chmod +x "$GO_BIN_PATH"

# 5. 更新 Systemd 配置 (如有必要)
# Rust 版本参数与 Go 版本基本兼容，但建议检查 config.json
# Rust 版本会自动适配旧版 config.json 结构 (config.rs 中的 parse_legacy)

# 6. 重启服务
echo "Restarting service..."
systemctl start $SERVICE_NAME
systemctl status $SERVICE_NAME --no-pager

echo ">>> 迁移完成! 喵! 🐾"
