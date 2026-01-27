#!/bin/bash
# NekoLink 自动化安装魔法脚本 ฅ^•ﻌ•^ฅ
set -e

# 提升权限
if [ "$EUID" -ne 0 ]; then
  echo "请使用 sudo 运行此安装脚本喵！"
  exit 1
fi

echo "正在准备通过 Debian 包管理系统安装 NekoLink..."

# 1. 编译项目 (Rust 魔法时间)
echo "正在注入 Rust 灵力进行编译喵..."
cargo build --release

# 2. 生成 Debian 魔法包
echo "正在塑造 .deb 安装包喵..."
chmod +x scripts/build_deb.sh
./scripts/build_deb.sh

# 3. 寻找生成的包
VERSION="2.1.0"
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

echo ""
echo "===================================================="
echo "✨ NekoLink 安装成功！(๑•̀ㅂ•́)و✧ ✨"
echo "===================================================="
echo "1. 主人可以使用 'nekolink' 指令启动交互式配置助手喵。"
echo "2. 服务已由 Systemd 接管，配置好后运行："
echo "   sudo systemctl start nekolink"
echo "3. 您的所有配置文件请放在 /etc/neko-link/ 喵。"
echo "===================================================="
