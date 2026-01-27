#!/bin/bash
# NekoLink 全自动安装脚本 ฅ^•ﻌ•^ฅ

set -e

echo "正在准备安装 NekoLink..."

# 0. 清理遗留配置 (Legacy Cleanup)
echo "正在检查并清理旧版遗留配置..."
# 清理可能存在的旧版 neko-link.service (注意：新版统一使用 nekolink.service)
if [ -f /etc/systemd/system/neko-link.service ]; then
    echo "发现旧版 neko-link.service，正在移除喵..."
    sudo systemctl stop neko-link.service || true
    sudo systemctl disable neko-link.service || true
    sudo rm -f /etc/systemd/system/neko-link.service
    sudo systemctl daemon-reload
fi

# 1. 编译
cargo build --release

# 2. 安装二进制文件与管理脚本
sudo cp target/release/nekolink-cli /usr/local/bin/
sudo cp target/release/nekolink-ctl /usr/local/bin/
sudo cp neko-link.sh /usr/local/bin/neko-link
sudo chmod +x /usr/local/bin/neko-link

# 3. 赋予权限
sudo setcap cap_net_admin,cap_net_raw+epi /usr/local/bin/nekolink-cli
sudo setcap cap_net_admin,cap_net_raw+epi /usr/local/bin/nekolink-ctl

# 4. 创建配置目录
sudo mkdir -p /etc/neko-link

# 5. 安装 systemd 服务
echo "正在配置 systemd 服务..."
sudo cp nekolink.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable nekolink

echo "安装成功喵！"
echo "请在 /etc/neko-link/ 创建你的 .json 配置文件，然后运行 'sudo systemctl start nekolink' 启动魔法喵！"
echo "也可以直接运行 'nekolink-ctl' 进行前台调试喵。"
