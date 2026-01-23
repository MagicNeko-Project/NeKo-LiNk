#!/bin/bash

# 颜色定义
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}>>> 开始安装 Go 语言环境...${NC}"

# Check if Go is already installed
if command -v go &> /dev/null; then
    echo -e "${GREEN}>>> Go 已经安装: $(go version)${NC}"
else
    echo "Go 未找到，正在尝试自动安装..."
    
    # Try apt first (Debian/Ubuntu)
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y golang
    elif command -v yum &> /dev/null; then
        sudo yum install -y golang
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y golang
    elif command -v apk &> /dev/null; then
        sudo apk add go
    else
        echo "无法自动安装 Go，请手动安装后重试。"
        exit 1
    fi
fi

echo -e "${GREEN}>>> 初始化项目依赖...${NC}"
if [ ! -f "go.mod" ]; then
    go mod init vpn
fi

echo -e "${GREEN}>>> 下载依赖库 (water, crypto)...${NC}"
go get github.com/songgao/water
go get golang.org/x/crypto/chacha20poly1305
go get golang.org/x/net/ipv6

echo -e "${GREEN}>>> 环境准备完成！${NC}"
