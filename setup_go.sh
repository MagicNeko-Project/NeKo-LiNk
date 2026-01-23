#!/bin/bash

# 颜色定义
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}>>> 开始安装 Go 语言环境...${NC}"

# Check if Go is already installed and new enough
if command -v go &> /dev/null; then
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    GO_MAJOR=$(echo $GO_VERSION | cut -d. -f1)
    GO_MINOR=$(echo $GO_VERSION | cut -d. -f2)
    if [ "$GO_MAJOR" -ge 1 ] && [ "$GO_MINOR" -ge 21 ]; then
        echo -e "${GREEN}>>> Go 版本足够新: $(go version)${NC}"
    else
        echo "Go 版本太旧 ($GO_VERSION)，需要 1.21+。正在升级..."
        rm -rf /usr/local/go
        wget -q https://golang.google.cn/dl/go1.22.5.linux-amd64.tar.gz -O /tmp/go.tar.gz
        tar -C /usr/local -xzf /tmp/go.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
        echo -e "${GREEN}>>> Go 已升级到 $(go version)${NC}"
    fi
else
    echo "Go 未找到，正在安装 Go 1.22..."
    wget -q https://golang.google.cn/dl/go1.22.5.linux-amd64.tar.gz -O /tmp/go.tar.gz
    tar -C /usr/local -xzf /tmp/go.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    echo -e "${GREEN}>>> Go 已安装: $(go version)${NC}"
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

echo -e "${GREEN}>>> 下载依赖库 (water, crypto)...${NC}"
# 使用 tidy 自动管理，更加稳健
go mod tidy
go get github.com/songgao/water
go get golang.org/x/crypto/chacha20poly1305
go get golang.org/x/net/ipv6

echo -e "${GREEN}>>> 环境准备完成！${NC}"
