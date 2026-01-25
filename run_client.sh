#!/bin/bash
if [ "$EUID" -ne 0 ]; then echo "请使用 root 权限运行 (sudo)"; exit 1; fi

# 优先使用本地 client_config.json (因为客户端可能在同一台机跑多个实例)
if [ -f "client_config.json" ]; then
    CONFIG_PATH="client_config.json"
elif [ -d "/etc/neko-link" ] && [ "$(ls -A /etc/neko-link)" ]; then
    CONFIG_PATH="/etc/neko-link"
else
    # 都不存在，初始化
    echo ">>> 未找到配置，正在初始化客户端配置..."
    ./neko-link -init -type client
    
    # 检查生成在了哪里
    if [ -f "/etc/neko-link/config.json" ]; then
        # 把它重命名为 client.json 以便区分
        mv /etc/neko-link/config.json /etc/neko-link/client.json
        CONFIG_PATH="/etc/neko-link"
    else
        echo ">>> 生成位置未知，请手动检查。"
        exit 1
    fi
    echo ">>> 已生成配置到 /etc/neko-link/client.json，请编辑后重试。"
    exit 0
fi

echo ">>> 启动 NekoLink (Client) [Config: $CONFIG_PATH]..."
./neko-link -c "$CONFIG_PATH"
