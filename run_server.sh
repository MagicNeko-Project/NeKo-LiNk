#!/bin/bash
if [ "$EUID" -ne 0 ]; then echo "请使用 root 权限运行 (sudo)"; exit 1; fi

CONFIG_FILE="config.json"

if [ ! -f "$CONFIG_FILE" ]; then
    echo ">>> 错误: 未找到配置文件 '$CONFIG_FILE'"
    echo ">>> 请将 config.example.json 复制为 $CONFIG_FILE 并根据其中的说明修改配置。"
    exit 1
fi

echo ">>> 启动 NekoLink (Server)..."
./neko-link -c "$CONFIG_FILE"
