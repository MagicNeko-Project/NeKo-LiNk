#!/bin/bash
# NekoLink 智能升级/修复脚本 ฅ^•ﻌ•^ฅ

set -e

PINK='\033[1;35m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${PINK}ฅ^•ﻌ•^ฅ 欢迎使用 NekoLink 魔法升级助理！${NC}"

# 检查权限
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}喵？为了替换系统组件，请使用 sudo 运行我喵！${NC}"
  exit 1
fi

# 1. 更新源代码
echo -e "\n${CYAN}[1/5] 正在从星辰大海采集最新的魔法代码 (Git Pull)...${NC}"
if [ -d ".git" ]; then
    git fetch origin
    git reset --hard origin/rust-wireguard-rawtunnel
else
    echo -e "${RED}警告：当前目录不是一个有效的 Git 仓库，跳过拉取更新喵。${NC}"
fi

# 2. 编译新核心
echo -e "\n${CYAN}[2/5] 正在熔炼全新的核心组件 (Cargo Build)...${NC}"
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}喵呜！没找到 Cargo，升级失败！请先安装 Rust 环境喵。${NC}"
    exit 1
fi
cargo build --release

# 3. 生成并安装 Debian 魔法包
echo -e "\n${CYAN}[3/5] 正在塑造并应用全新的 Debian 魔法包...${NC}"
VERSION=$(cat VERSION)
chmod +x scripts/build_deb.sh
./scripts/build_deb.sh

DEB_FILE=$(ls NekoLink_${VERSION}_*.deb 2>/dev/null | head -n 1)
if [ -z "$DEB_FILE" ]; then
    echo -e "${RED}喵？！找不到生成的 .deb 文件，请检查编译日志喵。${NC}"
    exit 1
fi

echo -e "${PINK}正在通过 apt 执行转生仪式：$DEB_FILE 喵！${NC}"
apt install -y --reinstall ./"$DEB_FILE"

# 4. 清理现场
echo -e "\n${CYAN}[4/5] 正在清理临时产物喵...${NC}"
rm -f ./*.deb
systemctl daemon-reload

# 5. 询问是否重启服务
echo -e "\n${CYAN}[5/5] 魔法升级包已安装完成喵！${NC}"
if systemctl is-active --quiet nekolink; then
    read -p "主人，检测到 NekoLink 正在运行，是否现在重启它来应用新魔法喵？(y/n, 默认 n): " confirm_restart
    if [ "$confirm_restart" == "y" ]; then
        systemctl restart nekolink
        echo -e "${PINK}服务已重启喵！(〃'▽'〃)${NC}"
    else
        echo -e "${CYAN}好的喵，主人记得稍后手动重启服务来生效哦。${NC}"
    fi
else
    echo -e "${CYAN}服务当前未运行，输入 'systemctl start nekolink' 即可启动新版魔法喵！${NC}"
fi

echo -e "\n${PINK}✨ 升级成功喵！✨${NC}"
echo -e "原有的配置文件 (/etc/neko-link/) 已被温柔地保留。您可以运行 'nekolink' 指令启动交互式助手喵！"
