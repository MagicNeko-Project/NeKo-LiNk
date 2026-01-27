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

# 1. 清理旧势力
echo -e "\n${CYAN}[1/6] 正在驱散旧的魔法能量（停止并清理遗留进程/服务）...${NC}"
# 先温柔地停止服务，防止 Text file busy 喵
sudo systemctl stop nekolink || true
sudo pkill -9 nekolink-ctl || true
sudo pkill -9 nekolink-cli || true
# 预防性清理原始 boringtun 命名残留
sudo pkill -9 boringtun-cli || true

# 清理旧版 neko-link.service (防止与新版 nekolink.service 冲突喵)
if [ -f /etc/systemd/system/neko-link.service ]; then
    echo -e "${CYAN}发现旧版 neko-link.service，正在强制驱逐喵...${NC}"
    sudo systemctl stop neko-link.service || true
    sudo systemctl disable neko-link.service || true
    sudo rm -f /etc/systemd/system/neko-link.service
    sudo systemctl daemon-reload
fi

# 2. 更新源代码
echo -e "\n${CYAN}[2/5] 正在从星辰大海采集最新的魔法代码 (Git Pull)...${NC}"
if [ -d ".git" ]; then
    git fetch origin
    git reset --hard origin/rust-wireguard-rawtunnel
else
    echo -e "${RED}警告：当前目录不是一个有效的 Git 仓库，跳过拉取更新喵。${NC}"
fi

# 3. 编译新核心
echo -e "\n${CYAN}[3/5] 正在熔炼全新的核心组件 (Cargo Build)...${NC}"
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}喵呜！没找到 Cargo，升级失败！请先安装 Rust 环境喵。${NC}"
    exit 1
fi
cargo build --release

# 4. 生成并安装 Debian 魔法包
echo -e "\n${CYAN}[4/5] 正在塑造并应用全新的 Debian 魔法包...${NC}"
VERSION="2.4.1"
chmod +x scripts/build_deb.sh
./scripts/build_deb.sh

DEB_FILE=$(ls NekoLink_${VERSION}_*.deb 2>/dev/null | head -n 1)
if [ -z "$DEB_FILE" ]; then
    echo -e "${RED}喵？！找不到生成的 .deb 文件，请检查编译日志喵。${NC}"
    exit 1
fi

echo -e "${PINK}正在通过 apt 执行转生仪式：$DEB_FILE 喵！${NC}"
apt install -y --reinstall ./"$DEB_FILE"

# 5. 清理现场并重启
echo -e "\n${CYAN}[5/5] 正在重载并重启 NekoLink 服务...${NC}"
rm -f ./*.deb
systemctl daemon-reload

if systemctl is-active --quiet nekolink; then
    systemctl restart nekolink
    echo -e "${PINK}服务已自动重启喵！${NC}"
else
    echo -e "${CYAN}服务当前未运行，输入 'systemctl start nekolink' 即可启动喵！${NC}"
fi

echo -e "\n${PINK}✨ 升级成功喵！✨${NC}"
echo -e "原有的配置文件 (/etc/neko-link/) 已被温柔地保留。您可以运行 'nekolink' 指令启动交互式助手喵！"
