#!/bin/bash
if [ "$EUID" -ne 0 ]; then echo "请使用 root 权限运行 (sudo)"; exit 1; fi

CONFIG_FILE="raw_server.json"

if [ ! -f "$CONFIG_FILE" ]; then
    # Try /etc/neko-link/raw_server.json
    if [ -f "/etc/neko-link/raw_server.json" ]; then
        CONFIG_FILE="/etc/neko-link/raw_server.json"
    else
        echo ">>> 未找到配置文件，正在尝试自动生成..."
        ./neko-link -init -type raw
        if [ -f "/etc/neko-link/config.json" ]; then
             mv /etc/neko-link/config.json /etc/neko-link/raw_server.json
             CONFIG_FILE="/etc/neko-link/raw_server.json"
        elif [ -f "config.json" ]; then
             mv config.json raw_server.json
             CONFIG_FILE="raw_server.json"
        else
            echo ">>> 生成失败，请手动检查。"
            exit 1
        fi
        echo ">>> 已生成默认配置 ($CONFIG_FILE)，请编辑后重新运行！"
        echo ">>> 编辑命令: nano $CONFIG_FILE"
        exit 0
    fi
fi

echo ">>> 启动 NekoLink Raw Server..."
./neko-link -c "$CONFIG_FILE"
