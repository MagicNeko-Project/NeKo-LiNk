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
sudo pkill nekolink-ctl || true
sudo pkill nekolink-cli || true
# 预防性清理原始 boringtun 命名残留
sudo pkill boringtun-cli || true

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

# 4. 覆盖安装
echo -e "\n${CYAN}[4/6] 正在注入全新的魔法二进制文件...${NC}"
cp target/release/nekolink-cli /usr/local/bin/
cp target/release/nekolink-ctl /usr/local/bin/
cp neko-link.sh /usr/local/bin/neko-link
cp nekolink.service /etc/systemd/system/
chmod +x /usr/local/bin/neko-link


# 5. 重新赋予特权
echo -e "\n${CYAN}[5/6] 正在为新核心注入超级权能 (SetCap)...${NC}"
setcap cap_net_admin,cap_net_raw+epi /usr/local/bin/nekolink-cli
setcap cap_net_admin,cap_net_raw+epi /usr/local/bin/nekolink-ctl

# 6. 重启服务
echo -e "\n${CYAN}[6/6] 正在重载并重启 NekoLink 服务...${NC}"
systemctl daemon-reload
if systemctl is-active --quiet nekolink; then
    systemctl restart nekolink
    echo -e "${PINK}服务已自动重启喵！${NC}"
else
    echo -e "${CYAN}服务当前未运行，输入 'systemctl start nekolink' 即可启动喵！${NC}"
fi

echo -e "\n${PINK}✨ 升级成功喵！✨${NC}"
echo -e "原有的配置文件 (/etc/neko-link/) 已被温柔地保留。你可以使用 'journalctl -u nekolink -f' 查看实时日志喵！"
