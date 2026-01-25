#!/bin/bash
if [ "$EUID" -ne 0 ]; then echo "请使用 root 权限运行 (sudo)"; exit 1; fi

# 优先使用 /etc/neko-link 目录 (如果存在且非空)
if [ -d "/etc/neko-link" ] && [ "$(ls -A /etc/neko-link)" ]; then
    CONFIG_PATH="/etc/neko-link"
else
    # 简单的本地回退
    if [ -f "config.json" ]; then
        CONFIG_PATH="config.json"
    else
        # 都不存在，初始化到全局目录
        echo ">>> 未找到有效配置，正在初始化服务端配置..."
        ./neko-link -init -type server
        CONFIG_PATH="/etc/neko-link"
        echo ">>> 已生成默认配置到 $CONFIG_PATH，请编辑后重试。"
        exit 0
    fi
fi

echo ">>> 启动 NekoLink (Server) [Config: $CONFIG_PATH]..."
./neko-link -c "$CONFIG_PATH"
