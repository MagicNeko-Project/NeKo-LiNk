#!/bin/bash
# setup_go.sh - NekoLink 自动化环境配置脚本 (Go + 依赖)

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

GO_VERSION="1.24.0"
LOCAL_GO_DIR="$(pwd)/.go"
ARCH=$(uname -m)

# 1. 安装系统依赖 (nftables, git)
echo -e "${GREEN}>>> [1/3] 检查并安装系统依赖...${NC}"
install_deps() {
    if command -v apt &> /dev/null; then
        sudo apt update
        sudo apt install -y nftables git curl tar
    elif command -v pacman &> /dev/null; then
        sudo pacman -Syu --noconfirm nftables git curl tar
    elif command -v yum &> /dev/null; then
        sudo yum install -y nftables git curl tar
    else
        echo -e "${RED}⚠️ 未检测到常见包管理器，请手动安装: nftables git curl${NC}"
    fi
}
install_deps

# 2. 配置 Go 环境
# 架构映射
case $ARCH in
    x86_64) GO_ARCH="amd64" ;;
    aarch64) GO_ARCH="arm64" ;;
    armv7l) GO_ARCH="armv6l" ;;
    *) echo -e "${RED}不支持的架构: $ARCH${NC}"; exit 1 ;;
esac

echo -e "${GREEN}>>> [2/3] 正在为 NekoLink 配置本地 Go 环境 ($GO_VERSION)...${NC}"

# 创建本地 Go 目录
if [ -d "$LOCAL_GO_DIR" ]; then
    INSTALLED_VER=$($LOCAL_GO_DIR/bin/go version 2>/dev/null)
    if [[ "$INSTALLED_VER" == *"$GO_VERSION"* ]]; then
        echo -e "${GREEN}>>> 本地 Go 版本已是最新 ($GO_VERSION)，跳过下载。${NC}"
    else
        echo -e "${GREEN}>>> 检测到旧版本/损坏，准备更新...${NC}"
        rm -rf "$LOCAL_GO_DIR"
    fi
fi

if [ ! -d "$LOCAL_GO_DIR" ]; then
    mkdir -p "$LOCAL_GO_DIR"
    # 下载 Go 压缩包
    GO_TAR="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
    URL="https://golang.google.cn/dl/${GO_TAR}" # 优先使用国内镜像
    
    echo -e ">>> 正在下载: $URL"
    curl -L "$URL" -o "/tmp/${GO_TAR}"
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}下载失败，请检查网络连接！${NC}"
        exit 1
    fi
    
    # 解压到本地目录
    echo -e ">>> 正在解压到 $LOCAL_GO_DIR ..."
    tar -C "$LOCAL_GO_DIR" -xzf "/tmp/${GO_TAR}" --strip-components=1
    rm "/tmp/${GO_TAR}"
fi

# 验证安装
export PATH="$LOCAL_GO_DIR/bin:$PATH"
if command -v go &> /dev/null; then
    echo -e "${GREEN}>>> 本地 Go 环境就绪: $(go version)${NC}"
else
    echo -e "${RED}>>> 配置失败，请检查安装路径。${NC}"
    exit 1
fi

# 3. 同步依赖
echo -e "${GREEN}>>> [3/3] 正在同步 Go 项目依赖...${NC}"
go mod tidy

echo -e "${GREEN}-------------------------------------------------------${NC}"
echo -e "${GREEN}✅ 环境配置完成！(Nya~)${NC}"
echo -e "请使用以下命令编译:"
echo -e "  ${GREEN}go build -o vpn main.go${NC}"
echo -e "${GREEN}-------------------------------------------------------${NC}"
