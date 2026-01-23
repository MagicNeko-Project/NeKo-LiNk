#!/bin/bash

# 颜色定义
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}>>> 开始安装 Go 语言环境...${NC}"

# Check local Go installation
if [ -d ".go" ] && [ -f ".go/bin/go" ]; then
    GO_VERSION=$(./.go/bin/go version | awk '{print $3}' | sed 's/go//')
    echo -e "${GREEN}>>> 本地 Go 版本: $GO_VERSION${NC}"
else
    echo "本地 Go 未找到，正在安装 Go 1.22 到 ./.go 目录..."
    wget -q https://golang.google.cn/dl/go1.22.5.linux-amd64.tar.gz -O /tmp/go.tar.gz
    # Extract to temp dir then move to .go
    mkdir -p .go_tmp
    tar -C .go_tmp -xzf /tmp/go.tar.gz
    mv .go_tmp/go/* .go/ 2>/dev/null || mv .go_tmp/go .go
    rm -rf .go_tmp
    echo -e "${GREEN}>>> Go 已安装: $(./.go/bin/go version)${NC}"
fi

# 配置国内代理
go env -w GOPROXY=https://goproxy.cn,direct

# 安装 eBPF 编译依赖
echo -e "${GREEN}>>> 安装 eBPF 编译工具链...${NC}"
if command -v apt-get &> /dev/null; then
    sudo apt-get update
    sudo apt-get install -y clang llvm libelf-dev libbpf-dev gcc-multilib make linux-headers-$(uname -r)
elif command -v yum &> /dev/null; then
    sudo yum install -y clang llvm libelf-devel libbpf-devel make kernel-headers
elif command -v dnf &> /dev/null; then
    sudo dnf install -y clang llvm libelf-devel libbpf-devel make kernel-headers
elif command -v apk &> /dev/null; then
    sudo apk add clang llvm libelf-dev libbpf-dev make linux-headers
fi

echo -e "${GREEN}>>> 初始化项目依赖...${NC}"
if [ ! -f "go.mod" ]; then
    go mod init vpn
fi

echo -e "${GREEN}>>> 这里的 go get 已废弃，编译时会自动 tidy...${NC}"

echo -e "${GREEN}>>> 环境准备完成！${NC}"
