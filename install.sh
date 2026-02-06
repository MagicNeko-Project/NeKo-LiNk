#!/bin/bash
# NekoLink 自动化安装魔法脚本 ฅ^•ﻌ•^ฅ
set -e

# 提升权限
if [ "$EUID" -ne 0 ]; then
  echo "请使用 sudo 运行此安装脚本喵！"
  exit 1
fi

echo "正在准备通过 Debian 包管理系统安装 NekoLink..."

# 0. Mullvad udp-over-tcp 魔法准备
PINK='\033[1;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${PINK}正在检查 Mullvad udp-over-tcp 组件...${NC}"

if ! command -v udp2tcp &> /dev/null || ! command -v tcp2udp &> /dev/null; then
    echo -e "${CYAN}发现缺少 Mullvad 组件，正在开始自动化编译安装仪式...${NC}"
    
    # 安装必要依赖
    if ! command -v cargo &> /dev/null || ! command -v git &> /dev/null; then
        echo -e "${CYAN}正在补充编译依赖 (cargo, git)...${NC}"
        apt-get update && apt-get install -y cargo git
    fi

    TEMP_DIR=$(mktemp -d)
    echo -e "${CYAN}正在下载源码到 $TEMP_DIR ...${NC}"
    git clone https://github.com/mullvad/udp-over-tcp.git "$TEMP_DIR"
    
    cd "$TEMP_DIR"
    echo -e "${CYAN}正在进行魔法编译 (Release 模式)...${NC}"
    cargo build --release
    
    echo -e "${CYAN}正在将组件安置到 /usr/local/bin ...${NC}"
    cp target/release/udp2tcp /usr/local/bin/
    cp target/release/tcp2udp /usr/local/bin/
    
    cd - > /dev/null
    rm -rf "$TEMP_DIR"
    echo -e "${PINK}Mullvad 组件安装完成喵！${NC}"
else
    echo -e "${PINK}Mullvad 组件已就绪，跳过编译喵。${NC}"
fi

# 1. 编译项目 (Rust 魔法时间)
echo "正在注入 Rust 灵力进行编译喵..."
cargo build --release --workspace --exclude nekolink-android

# 2. 生成 Debian 魔法包
echo "正在塑造 .deb 安装包喵..."
chmod +x scripts/build_deb.sh
./scripts/build_deb.sh

# 3. 寻找生成的包 (从全局 VERSION 文件读取)
VERSION=$(cat VERSION)
DEB_FILE=$(ls NekoLink_${VERSION}_*.deb 2>/dev/null | head -n 1)

if [ -z "$DEB_FILE" ]; then
    echo "喵？！找不到生成的 .deb 文件，请检查编译日志喵。"
    exit 1
fi

# 4. 这里的魔法重点：使用 apt 安装本地生成的包
# 它会自动处理依赖，并让系统正式接管文件管理喵！
echo "正在通过 apt 执行转生仪式：$DEB_FILE 喵！"
apt install -y --reinstall ./"$DEB_FILE"

# 5. 清理现场
echo "正在清理临时构建产物喵..."
rm -f ./*.deb
systemctl daemon-reload

# 6. 询问是否重启服务
if systemctl is-active --quiet nekolink; then
    echo ""
    read -p "主人，检测到 NekoLink 正在运行，是否现在重启它来应用新魔法喵？(y/n, 默认 n): " confirm_restart
    if [ "$confirm_restart" == "y" ]; then
        systemctl restart nekolink
        echo "服务已重启喵！(〃'▽'〃)"
    else
        echo "好的喵，主人记得稍后手动重启服务来生效哦。"
    fi
fi

echo ""
echo "===================================================="
echo "✨ NekoLink 安装成功！(๑•̀ㅂ•́)و✧ ✨"
echo "===================================================="
echo "1. 主人可以使用 'nekolink' 指令启动交互式配置助手喵。"
echo "2. 服务关键指令："
echo "   sudo systemctl start/stop/restart nekolink"
echo "3. 您的所有配置文件请放在 /etc/neko-link/ 喵。"
echo "===================================================="
