#!/bin/bash
# NekoLink 全自动安装脚本 ฅ^•ﻌ•^ฅ

set -e

echo "正在准备安装 NekoLink..."

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
