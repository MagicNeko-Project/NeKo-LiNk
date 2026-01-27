#!/bin/bash
# NekoLink 交互式配置助手 ฅ^•ﻌ•^ฅ

set -e

# 颜色定义
PINK='\033[1;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${PINK}ฅ^•ﻌ•^ฅ 欢迎使用 NekoLink 交互式配置助手！${NC}"

if [ "$EUID" -ne 0 ]; then
  echo "请使用 sudo 运行此脚本喵！"
  exit 1
fi

CONFIG_DIR="/etc/neko-link"
mkdir -p "$CONFIG_DIR"

function show_menu() {
    echo -e "${CYAN}请选择操作：${NC}"
    echo "1. 创建新配置文件 (Node Config)"
    echo "2. 启动 NekoLink (nekolink-ctl)"
    echo "3. 查看运行状态 (Status)"
    echo "4. 查看配置文件列表"
    echo "5. 退出"
    read -p "请输入数字 [1-5]: " choice
}

function create_config() {
    echo -e "\n${PINK}--- 开始创建 NekoLink 配置 ---${NC}"
    
    read -p "请输入接口名称 ( 默认 nekotun0 ): " iface
    [ -z "$iface" ] && iface="nekotun0"

    echo -e "\n${CYAN}请选择节点角色：${NC}"
    echo "1. 服务端 (拥有公钥 IP，等待连接)"
    echo "2. 客户端 (连接到服务端)"
    read -p "请选择 [1-2]: " role_choice

    if [ "$role_choice" == "1" ]; then
        role="server"
        echo -e "${PINK}提示：作为服务端，请确保你的信令通道和数据协议号在防火墙已放行喵！${NC}"
        endpoint=""
    else
        role="client"
        if [ "$mode" == "ip" ]; then
            read -p "请输入服务端的公网 IP ( e.g. 1.2.3.4 ): " endpoint
        else
            read -p "请输入服务端的公网端点 ( IP:信令端口, e.g. 1.2.3.4:5678 ): " endpoint
        fi
        while [ -z "$endpoint" ]; do
            read -p "客户端必须指定对端地址喵！请重新输入: " endpoint
        done
    fi

    echo -e "\n${CYAN}选择数据传输模式：${NC}"
    echo "1. IP 协议模式 (绕过 UDP 限制，推荐)"
    echo "2. UDP 模式 (标准协议)"
    read -p "请选择 [1-2]: " mode_choice
    if [ "$mode_choice" == "1" ]; then
        mode="ip"
        read -p "请输入 IP 协议号 [143-252] ( 默认 141 ): " proto
        [ -z "$proto" ] && proto=141
        listen_port="null"
    else
        mode="udp"
        proto="null"
        read -p "请输入 WireGuard 监听端口 ( 默认 51820 ): " listen_port
        [ -z "$listen_port" ] && listen_port=51820
    fi

    read -p "请输入本地隧道内网 IP ( e.g. 10.0.0.1/24 ): " local_addr
    [ -z "$local_addr" ] && local_addr="10.0.0.1/24"

    read -p "请输入预共享密钥 (PSK, 用于自动交换公钥，两端必须一致): " psk
    [ -z "$psk" ] && psk="NekoMagic_Default_PSK"

    read -p "是否自动配置系统路由？(默认 n) [y/n]: " auto_route_choice
    if [ "$auto_route_choice" == "y" ]; then
        auto_route="true"
    else
        auto_route="false"
    fi

    if [ "$mode" == "udp" ]; then
        read -p "请输入信令交换端口 ( 默认 5678 ): " sig_port
        [ -z "$sig_port" ] && sig_port=5678
    else
        sig_port=0 # IP 模式下不使用 UDP 端口
    fi

    # 构建 JSON
    json_path="$CONFIG_DIR/$iface.json"
    
    cat > "$json_path" <<EOF
{
  "interface": "$iface",
  "mode": "$mode",
  "ip_protocol": $proto,
  "listen_port": $listen_port,
  "auto_route": $auto_route,
  "local_address": "$local_addr",
  "psk": "$psk",
  "peers": [
EOF

    if [ -n "$endpoint" ]; then
        cat >> "$json_path" <<EOF
    {
      "endpoint": "$endpoint"
    }
EOF
    fi

    cat >> "$json_path" <<EOF
  ],
  "signal_port": $sig_port
}
EOF

    echo -e "${PINK}配置已成功保存到 $json_path 喵！${NC}"
}

while true; do
    show_menu
    case $choice in
        1) create_config ;;
        2) nekolink-ctl ;;
        3) nekolink-ctl status ;;
        4) ls -l "$CONFIG_DIR"/*.json ;;
        5) exit 0 ;;
        *) echo "无效选择喵！" ;;
    esac
done
