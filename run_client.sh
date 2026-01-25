#!/bin/bash
if [ "$EUID" -ne 0 ]; then echo "请使用 root 权限运行 (sudo)"; exit 1; fi

CONFIG_FILE="client_config.json"

if [ ! -f "$CONFIG_FILE" ]; then
    echo ">>> 未找到配置文件 '$CONFIG_FILE'，正在尝试自动生成..."
    
    ./neko-link -init -type client
    
    if [ -f "/etc/neko-link/config.json" ]; then
        echo ">>> 配置已生成到 /etc/neko-link/config.json。"
        echo ">>> 为了作为客户端运行，建议将其复制为 $CONFIG_FILE 或直接使用。"
        # Logic adjustment for client script preference
        CONFIG_FILE="/etc/neko-link/config.json"
    elif [ -f "config.json" ]; then
        mv config.json $CONFIG_FILE
        echo ">>> 已生成默认客户端配置: $CONFIG_FILE"
    else
        echo ">>> 生成失败。"
        exit 1
    fi
    
    echo ">>> 请务必编辑配置文件填写服务器地址！"
    echo ">>> 编辑命令: nano $CONFIG_FILE"
    exit 0
fi

echo ">>> 启动 NekoLink (Client)..."
./neko-link -c "$CONFIG_FILE"
