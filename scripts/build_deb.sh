#!/bin/bash
# NekoLink Debian 打包魔法脚本 ฅ^•ﻌ•^ฅ
set -e

VERSION="2.4.0"
ARCH=$(dpkg --print-architecture)
PKG_NAME="nekolink"
BUILD_DIR="build_deb_tmp"

echo "正在为架构 $ARCH 准备打包 NekoLink $VERSION..."

# 1. 清理并创建目录结构
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/DEBIAN"
mkdir -p "$BUILD_DIR/usr/local/bin"
mkdir -p "$BUILD_DIR/etc/systemd/system"
mkdir -p "$BUILD_DIR/etc/neko-link"

# 2. 准备 control 文件
cat > "$BUILD_DIR/DEBIAN/control" <<EOF
Package: $PKG_NAME
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Depends: libc6, systemd
Maintainer: MagicNeko Project <icecat@catio.network>
Description: NekoLink Intelligent Tunnel Control Plane - High performance & stealthy tunnel based on customized WireGuard protocol.
EOF

# 3. 准备 postinst (安装后脚本)
cat > "$BUILD_DIR/DEBIAN/postinst" <<EOF
#!/bin/sh
set -e
setcap cap_net_admin,cap_net_raw+epi /usr/local/bin/nekolink-cli
setcap cap_net_admin,cap_net_raw+epi /usr/local/bin/nekolink-ctl
systemctl daemon-reload
echo "NekoLink 安装完成喵！配置文件请放在 /etc/neko-link/ 喵。"
exit 0
EOF
chmod 755 "$BUILD_DIR/DEBIAN/postinst"

# 4. 拷贝文件
# 假设已经编译好了
if [ ! -f "target/release/nekolink-cli" ] || [ ! -f "target/release/nekolink-ctl" ]; then
    echo "喵？找不到二进制文件，请先运行 cargo build --release 喵！"
    exit 1
fi

cp target/release/nekolink-cli "$BUILD_DIR/usr/local/bin/"
cp target/release/nekolink-ctl "$BUILD_DIR/usr/local/bin/"
cp nekolink.sh "$BUILD_DIR/usr/local/bin/nekolink"
chmod +x "$BUILD_DIR/usr/local/bin/nekolink"
cp nekolink.service "$BUILD_DIR/etc/systemd/system/"

# 5. 打包
dpkg-deb --build "$BUILD_DIR" "NekoLink_${VERSION}_${ARCH}.deb"

echo "打包成功喵！文件: NekoLink_${VERSION}_${ARCH}.deb"
rm -rf "$BUILD_DIR"
