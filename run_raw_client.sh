#!/bin/bash
if [ "$EUID" -ne 0 ]; then echo "请使用 root 权限运行 (sudo)"; exit 1; fi

CONFIG_FILE="raw_client.json"

if [ ! -f "$CONFIG_FILE" ]; then
    echo ">>> 未找到配置文件 '$CONFIG_FILE'，正在尝试自动生成..."
    
    ./neko-link -init -type raw
    
    if [ -f "/etc/neko-link/config.json" ]; then
        mv /etc/neko-link/config.json /etc/neko-link/raw_client.json
        CONFIG_FILE="/etc/neko-link/raw_client.json"
        
        echo ">>> 配置已生成到 $CONFIG_FILE"
    elif [ -f "config.json" ]; then
        mv config.json raw_client.json
        CONFIG_FILE="raw_client.json"
        echo ">>> 已生成默认客户端配置: $CONFIG_FILE"
    else
        echo ">>> 生成失败。"
        exit 1
    fi
    
    # Modify default raw config (which is server-like) to client mode
    # Simple sed to switch mode if possible, or just prompt user.
    # Raw mode structure is confusing in code: "Mode: server" but "PeerAddr" set. 
    # Actually raw mode is symmetric. It just needs Remote IP.
    
    echo ">>> 请务必编辑配置文件填写对端地址 (peer_addr)！"
    echo ">>> 注意：Raw 模式是对等的，两端都需要填对方 IP。"
    echo ">>> 编辑命令: nano $CONFIG_FILE"
    exit 0
fi

echo ">>> 启动 NekoLink Raw Client..."
./neko-link -c "$CONFIG_FILE"
