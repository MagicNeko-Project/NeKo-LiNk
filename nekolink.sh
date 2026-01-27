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

if [ "$#" -gt 0 ]; then
    nekolink-ctl "$@"
    exit $?
fi

CONFIG_DIR="/etc/neko-link"
mkdir -p "$CONFIG_DIR"

function show_menu() {
    echo -e "${CYAN}请选择操作：${NC}"
    echo "1. 创建新配置文件 (Node Config)"
    echo "2. 重启 NekoLink 服务 (Systemd Restart)"
    echo "3. 查看运行状态 (Status)"
    echo "4. 管理密钥与公钥 (Key Management)"
    echo "5. 查看配置文件列表"
    echo "6. 退出"
    read -p "请输入数字 [1-6]: " choice
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

    read -p "请输入本地隧道接口 IP 地址 ( 示例 10.0.0.1/24 ): " local_addr
    read -p "是否开启 Keepalive 保持魔法连接？( y/n, 默认 n ): " ka_enable
    keepalive="null"
    if [ "$ka_enable" == "y" ]; then
        read -p "请输入 Keepalive 间隔时间 ( 秒, 默认 25 ): " ka_sec
        [ -z "$ka_sec" ] && ka_sec=25
        keepalive=$ka_sec
    fi

    read -p "是否需要自定义 MTU？( y/n, 默认 n, 推荐 1420 ): " mtu_enable
    mtu="null"
    if [ "$mtu_enable" == "y" ]; then
        read -p "请输入 MTU 值 ( 建议 1280-1420 ): " mtu_val
        [ -z "$mtu_val" ] && mtu_val=1420
        mtu=$mtu_val
    fi

    read -p "是否开启 TCP MSS 自动修复 ( 建议开启以防止握手成功但无法网页浏览 )？( y/n, 默认 y ): " mss_enable
    [ -z "$mss_enable" ] && mss_enable="y"
    clamp_mss="false"
    if [ "$mss_enable" == "y" ]; then
        clamp_mss="true"
    fi
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
  "persistent_keepalive": $keepalive,
  "mtu": $mtu,
  "clamp_mss": $clamp_mss,
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

function manage_keys() {
    echo -e "\n${PINK}--- NekoLink 密钥管理魔法 ---${NC}"
    read -p "请输入要管理的接口名称 ( 默认 nekotun0 ): " iface
    [ -z "$iface" ] && iface="nekotun0"
    
    key_file="$CONFIG_DIR/$iface.key"
    pub_file="$CONFIG_DIR/$iface.pub"

    echo -e "${CYAN}1. 查看当前密钥"
    echo "2. 更换/重置密钥 (在线更换)"
    echo "3. 返回主菜单${NC}"
    read -p "请选择数字 [1-3]: " km_choice

    case $km_choice in
        1)
            if [ -f "$key_file" ]; then
                echo -e "${PINK}私钥: ${NC}$(cat $key_file)"
                echo -e "${PINK}公钥: ${NC}$(cat $pub_file 2>/dev/null || echo '尚未生成')"
            else
                echo -e "${RED}喵？没找到这个接口的密钥文件。${NC}"
            fi
            ;;
        2)
            echo -e "${RED}警告：更换密钥会导致当前连接断开，并需要重新与队友交换公钥喵！${NC}"
            read -p "确定要更换吗？(y/n): " confirm
            if [ "$confirm" == "y" ]; then
                rm -f "$key_file" "$pub_file"
                echo -e "${PINK}旧密钥已驱散！正在尝试重启服务以注入新魔法...${NC}"
                systemctl restart nekolink || echo "请手动重启 nekolink-ctl 喵！"
                echo -e "${PINK}新密钥将在启动时自动生成喵！${NC}"
            fi
            ;;
        *) return ;;
    esac
}

while true; do
    show_menu
    case $choice in
        1) create_config ;;
        2) 
            echo -e "${PINK}正在通过 Systemd 重启 NekoLink 魔法...${NC}"
            systemctl restart nekolink
            echo -e "${PINK}重启指令已发送喵！可以使用选项 3 查看最新状态。${NC}"
            ;;
        3) nekolink ctl status ;;
        4) manage_keys ;;
        5) ls -l "$CONFIG_DIR"/*.json ;;
        6) exit 0 ;;
        *) echo "无效选择喵！" ;;
    esac
done
