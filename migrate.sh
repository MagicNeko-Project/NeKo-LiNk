#!/bin/bash
# NekoLink 迁移至 .deb 安装包管理魔法脚本 ฅ^•ﻌ•^ฅ
set -e

VERSION="2.1.0"

# 提升权限
if [ "$EUID" -ne 0 ]; then
  echo "请使用 sudo 运行此迁移脚本喵！"
  exit 1
fi

echo "正在准备将 NekoLink 从手动安装迁移至 Debian 包管理系统..."

# 1. 停止并禁用旧版服务
echo "正在清理旧版服务残留喵..."
systemctl stop nekolink 2>/dev/null || true
systemctl disable nekolink 2>/dev/null || true
pkill -9 nekolink-ctl 2>/dev/null || true
pkill -9 nekolink-cli 2>/dev/null || true

# 2. 移除旧版手动安装的文件 (防止冲突)
echo "正在移除旧版手动二进制文件喵..."
rm -f /usr/local/bin/nekolink-cli
rm -f /usr/local/bin/nekolink-ctl
rm -f /usr/local/bin/neko-link
rm -f /etc/systemd/system/nekolink.service
systemctl daemon-reload

# 3. 确保配置目录安全
echo "您的配置目录 /etc/neko-link/ 将被保留喵。"
mkdir -p /etc/neko-link

# 4. 构建最新的 Debian 包
echo "正在召唤 NekoLink v$VERSION Debian 魔法包喵 (这可能需要一点时间编译)..."
# 确保在项目根目录运行
if [ ! -f "install.sh" ]; then
    echo "喵？找不到 install.sh，请确保在 NekoLink 项目根目录下运行此脚本喵。"
    exit 1
fi

chmod +x install.sh
./install.sh --package

# 5. 寻找并安装生成的 .deb 包
DEB_FILE=$(ls NekoLink_${VERSION}_*.deb 2>/dev/null | head -n 1)
if [ -f "$DEB_FILE" ]; then
    echo "发现安装包: $DEB_FILE，正在执行转生仪式...喵！"
    dpkg -i "$DEB_FILE"
else
    echo "喵？！找不到生成的 .deb 文件。请检查上面的编译日志是否有错喵。"
    exit 1
fi

echo ""
echo "===================================================="
echo "✨ 迁移成功！(๑•̀ㅂ•́)و✧ ✨"
echo "===================================================="
echo "1. NekoLink 现在已由 Debian 包管理器接管。"
echo "2. 您的配置在 /etc/neko-link/ 中安然无恙。"
echo "3. 您可以使用 'sudo systemctl start nekolink' 启动服务喵。"
echo "4. 将来只需下载新的 .deb 并 dpkg -i 即可无缝升级喵！"
echo "===================================================="
