#!/bin/bash
# NekoLink Debian 打包魔法脚本 ฅ^•ﻌ•^ฅ
set -e

VERSION=$(cat VERSION)
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
mkdir -p "$BUILD_DIR/usr/local/share/nekolink"

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
# udp2raw 需要 root 或 CAP_NET_RAW 权限
if [ -f /usr/local/bin/udp2raw ]; then
    setcap cap_net_admin,cap_net_raw+epi /usr/local/bin/udp2raw
fi
systemctl daemon-reload
echo "NekoLink 安装完成喵！配置文件请放在 /etc/neko-link/ 喵。"
exit 0
EOF
chmod 755 "$BUILD_DIR/DEBIAN/postinst"

# 4. 拷贝文件
# 假设已经编译好了
if [ ! -f "target/release/nekolink-cli" ] || [ ! -f "target/release/nekolink-ctl" ]; then
    echo "喵？找不到主二进制文件，请先运行 cargo build --release 喵！"
    exit 1
fi

cp target/release/nekolink-cli "$BUILD_DIR/usr/local/bin/"
cp target/release/nekolink-ctl "$BUILD_DIR/usr/local/bin/"

# 5. 下载或使用现有的 udp2raw 二进制
UDP2RAW_PATH="$BUILD_DIR/usr/local/bin/udp2raw"
if [ -f "/usr/local/bin/udp2raw" ]; then
    echo "发现系统已安装 udp2raw，复用喵..."
    cp /usr/local/bin/udp2raw "$UDP2RAW_PATH"
elif [ -f "udp2raw" ]; then
    echo "发现本地 udp2raw，复用喵..."
    cp udp2raw "$UDP2RAW_PATH"
else
    echo "正在下载 udp2raw 喵..."
    # 根据架构下载对应的二进制
    case "$ARCH" in
        amd64|x86_64)
            UDP2RAW_URL="https://github.com/wangyu-/udp2raw/releases/download/20230206.0/udp2raw_binaries.tar.gz"
            ;;
        arm64|aarch64)
            UDP2RAW_URL="https://github.com/wangyu-/udp2raw/releases/download/20230206.0/udp2raw_binaries.tar.gz"
            ;;
        *)
            echo "喵？不支持的架构 $ARCH，请手动安装 udp2raw 喵！"
            # 创建一个占位符脚本
            echo '#!/bin/sh' > "$UDP2RAW_PATH"
            echo 'echo "请手动安装 udp2raw: https://github.com/wangyu-/udp2raw"' >> "$UDP2RAW_PATH"
            chmod +x "$UDP2RAW_PATH"
            ;;
    esac
    
    if [ -n "$UDP2RAW_URL" ]; then
        # 下载并解压
        TMP_TAR="/tmp/udp2raw_binaries.tar.gz"
        curl -L -o "$TMP_TAR" "$UDP2RAW_URL" || wget -O "$TMP_TAR" "$UDP2RAW_URL"
        TMP_DIR="/tmp/udp2raw_extract"
        mkdir -p "$TMP_DIR"
        tar -xzf "$TMP_TAR" -C "$TMP_DIR"
        # 根据架构选择对应二进制
        if [ "$ARCH" = "amd64" ] || [ "$ARCH" = "x86_64" ]; then
            cp "$TMP_DIR/udp2raw_amd64" "$UDP2RAW_PATH"
        elif [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then
            cp "$TMP_DIR/udp2raw_arm" "$UDP2RAW_PATH"
        fi
        chmod +x "$UDP2RAW_PATH"
        rm -rf "$TMP_DIR" "$TMP_TAR"
    fi
fi

cp nekolink.sh "$BUILD_DIR/usr/local/bin/nekolink"
chmod +x "$BUILD_DIR/usr/local/bin/nekolink"
cp nekolink.service "$BUILD_DIR/etc/systemd/system/"
cp VERSION "$BUILD_DIR/usr/local/share/nekolink/"

# 6. 打包 (显式输出到项目根目录喵)
OUTPUT_FILE="NekoLink_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$BUILD_DIR" "$OUTPUT_FILE"

echo "打包成功喵！文件: NekoLink_${VERSION}_${ARCH}.deb"
rm -rf "$BUILD_DIR"
