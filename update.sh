#!/bin/bash
# NekoLink 升级脚本

if [ "$EUID" -ne 0 ]; then echo "请使用 root 权限 (sudo)"; exit 1; fi

SERVICE_NAME="neko-link"
BIN_NAME="neko-link"
BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/neko-link"

# 配置迁移函数：将老格式 {} 转换为新格式 [{}]，并添加 XDP 字段
migrate_config() {
    local cfg_file="$CONF_DIR/config.json"
    
    if [ ! -f "$cfg_file" ]; then
        echo ">>> 未发现配置文件，跳过迁移"
        return 0
    fi
    
    # 检查是否安装了 jq
    if ! command -v jq &> /dev/null; then
        echo ">>> 提示: 安装 jq 可启用配置自动迁移 (apt install jq)"
        return 0
    fi
    
    # 检测是否为老格式（单对象而非数组）
    if jq -e 'type == "object"' "$cfg_file" > /dev/null 2>&1; then
        echo ">>> 检测到老版本配置格式，正在迁移..."
        
        # 备份老配置
        cp "$cfg_file" "$cfg_file.bak.$(date +%Y%m%d%H%M%S)"
        echo "    ✓ 已备份老配置"
        
        # 转换为数组格式，添加 XDP 默认字段，移除废弃字段
        jq '[
            . + {
                "use_xdp": (.use_xdp // false),
                "xdp_device": (.xdp_device // ""),
                "interface_name": (.interface_name // "neko0")
            }
        ]' "$cfg_file.bak."* 2>/dev/null | head -1 > "$cfg_file.tmp" && mv "$cfg_file.tmp" "$cfg_file"
        
        if [ $? -eq 0 ]; then
            echo "    ✓ 配置已升级为新格式 (Nya~)"
        else
            echo "    ✗ 迁移失败，已保留原配置"
        fi
    else
        echo ">>> 配置格式已是最新版本"
    fi
}

echo ">>> 正在拉取最新代码..."
git pull
if [ $? -ne 0 ]; then echo "Git pull 失败，请检查网络或仓库状态"; exit 1; fi

echo ">>> 正在编译新版本 (使用 Make)..."
make
if [ $? -ne 0 ]; then echo "编译失败"; exit 1; fi

echo ">>> 停止当前服务..."
systemctl stop $SERVICE_NAME

echo ">>> 检查并迁移配置文件..."
migrate_config

echo ">>> 更新二进制文件..."
cp $BIN_NAME $BIN_DIR/
chmod +x $BIN_DIR/$BIN_NAME

echo ">>> 重启服务..."
systemctl start $SERVICE_NAME
systemctl status $SERVICE_NAME --no-pager

echo "-----------------------------------------------------"
echo "✅ NekoLink 升级完成！"
echo "-----------------------------------------------------"
