#!/bin/bash
# NekoLink 交互式配置助手 ฅ^•ﻌ•^ฅ

set -e

# 颜色定义
PINK='\033[1;35m'
CYAN='\033[0;36m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
  echo "请使用 sudo 运行此脚本喵！"
  exit 1
fi

if [ "$#" -gt 0 ]; then
    nekolink-ctl "$@"
    exit $?
fi

if [ -f "/usr/local/share/nekolink/VERSION" ]; then
    VERSION=$(cat /usr/local/share/nekolink/VERSION)
elif [ -f "VERSION" ]; then
    VERSION=$(cat VERSION)
else
    VERSION="2.4.3-unknown"
fi
echo -e "${PINK}ฅ^•ﻌ•^ฅ 欢迎使用 NekoLink 交互式配置助手 v$VERSION！${NC}"
echo -e "${CYAN}--- 全局信令通道 [12580] (一按我帮您) 已就绪 ---${NC}"

CONFIG_DIR="/etc/neko-link"
mkdir -p "$CONFIG_DIR"

function show_menu() {
    echo -e "${CYAN}请选择操作：${NC}"
    echo "1. 创建新配置文件 (Node Config)"
    echo "2. 修改现有配置文件 (Edit Config)"
    echo "3. 重启 NekoLink 服务 (Systemd Restart)"
    echo "4. 查看运行状态 (Status)"
    echo "5. 管理密钥与公钥 (Key Management)"
    echo "6. 配置文件一键检查与修复 (Fix Configs)"
    echo "7. 查看配置文件列表"
    echo "8. 退出"
    read -p "请输入数字 [1-8]: " choice
}

function edit_config() {
    echo -e "\n${PINK}--- 正在进入配置修改魔法 ---${NC}"
    configs=("$CONFIG_DIR"/*.json)
    if [ ! -e "${configs[0]}" ]; then
        echo -e "${RED}喵？没有找到任何配置文件。${NC}"
        return
    fi

    echo -e "${CYAN}现有的配置文件列表：${NC}"
    for i in "${!configs[@]}"; do
        echo "$((i+1)). $(basename "${configs[$i]}")"
    done
    read -p "请选择要修改的配置编号: " cfg_idx
    
    selected_cfg="${configs[$((cfg_idx-1))]}"
    if [ -z "$selected_cfg" ] || [ ! -f "$selected_cfg" ]; then
        echo -e "${RED}无效的选择喵！${NC}"
        return
    fi

    iface=$(jq -r '.interface' "$selected_cfg")
    echo -e "${PINK}正在修改接口: $iface${NC}"

    # 提取现有值
    curr_mode=$(jq -r '.mode' "$selected_cfg")
    curr_proto=$(jq -r '.ip_protocol // 141' "$selected_cfg")
    curr_lport=$(jq -r '.listen_port // 51820' "$selected_cfg")
    curr_addr=$(jq -r '.local_address' "$selected_cfg")
    curr_psk=$(jq -r '.psk' "$selected_cfg")
    curr_aroute=$(jq -r '.auto_route' "$selected_cfg")
    curr_ka=$(jq -r '.persistent_keepalive // "null"' "$selected_cfg")
    curr_mtu=$(jq -r '.mtu // "null"' "$selected_cfg")
    curr_mss=$(jq -r '.clamp_mss' "$selected_cfg")
    curr_mss=$(jq -r '.clamp_mss' "$selected_cfg")
    curr_ep=$(jq -r '.peers[0].endpoint // empty' "$selected_cfg")

    # 交互式修改
    read -p "传输模式 (当前: $curr_mode, [1] ip, [2] udp, [3] tcp, 直接回车保持不变): " m_choice
    case "$m_choice" in
        1) mode="ip" ;;
        2) mode="udp" ;;
        3) mode="tcp" 
           echo -e "${PINK}... 使用 Fake-TCP 模式喵 (请确保设置 nftables 规则 DROP 相应端口的 RST 包，示例：nft add rule inet filter output tcp sport <端口> tcp flags rst drop)${NC}" ;;
        *) mode="$curr_mode" ;;
    esac

    if [ "$mode" == "ip" ]; then
        read -p "IP 协议号 (当前: $curr_proto, 直接回车保持不变): " proto
        [ -z "$proto" ] && proto=$curr_proto
        listen_port="null"
    elif [ "$mode" == "tcp" ]; then
        proto="null"
        read -p "伪装 TCP 监听端口 (当前: $curr_lport, 直接回车保持不变): " listen_port
        [ -z "$listen_port" ] && listen_port=$curr_lport
    else
        read -p "WireGuard 监听端口 (当前: $curr_lport, 直接回车保持不变): " listen_port
        [ -z "$listen_port" ] && listen_port=$curr_lport
        proto="null"
    fi

    read -p "本地隧道 IP (当前: $curr_addr, 直接回车保持不变): " local_addr
    [ -z "$local_addr" ] && local_addr="$curr_addr"

    if [ "$mode" == "ip" ]; then
        read -p "对端公网 IP (当前: $curr_ep, 直接回车保持不变): " endpoint
    else
        echo -e "${PINK}提示：对端端点应为 IP:服务端信令端口 (通常为 12580) 喵！${NC}"
        read -p "对端 Endpoint (当前: $curr_ep, 直接回车保持不变): " endpoint
    fi
    [ -z "$endpoint" ] && endpoint="$curr_ep"

    read -p "Keepalive 间隔 (当前: $curr_ka, 直接回车保持不变): " keepalive
    [ -z "$keepalive" ] && keepalive=$curr_ka

    read -p "MTU (当前: $curr_mtu, 直接回车保持不变): " mtu
    [ -z "$mtu" ] && mtu=$curr_mtu

    read -p "开启 MSS 修复? (当前: $curr_mss, [y/n], 直接回车保持不变): " mss_c
    case "$mss_c" in
        y) clamp_mss="true" ;;
        n) clamp_mss="false" ;;
        *) clamp_mss="$curr_mss" ;;
    esac

    read -p "预共享密钥 PSK (当前: $curr_psk, 直接回车保持不变): " psk
    [ -z "$psk" ] && psk="$curr_psk"

    read -p "自动系统路由? (当前: $curr_aroute, [y/n], 直接回车保持不变): " ar_c
    case "$ar_c" in
        y) auto_route="true" ;;
        n) auto_route="false" ;;
        *) auto_route="$curr_aroute" ;;
    esac

    # signal_port 统一迁移到 global.json 喵

    # 使用 jq 构建新 JSON 并覆盖
    tmp_cfg=$(mktemp)
    jq -n \
        --arg iface "$iface" \
        --arg mode "$mode" \
        --argjson proto "$proto" \
        --argjson listen_port "$listen_port" \
        --argjson auto_route "$auto_route" \
        --argjson keepalive "$keepalive" \
        --argjson mtu "$mtu" \
        --argjson clamp_mss "$clamp_mss" \
        --arg addr "$local_addr" \
        --arg psk "$psk" \
        --arg ep "$endpoint" \
        '{
            interface: $iface,
            mode: $mode,
            ip_protocol: $proto,
            listen_port: $listen_port,
            auto_route: $auto_route,
            persistent_keepalive: $keepalive,
            mtu: $mtu,
            clamp_mss: $clamp_mss,
            local_address: $addr,
            psk: $psk,
            peers: (if $ep != "" then [{endpoint: $ep}] else [] end)
        }' > "$tmp_cfg"
    
    mv "$tmp_cfg" "$selected_cfg"
    echo -e "${PINK}配置更新成功喵！${NC}"
    read -p "是否立即重启服务以应用新配置？(y/n, 默认 n): " restart_now
    if [ "$restart_now" == "y" ]; then
        systemctl restart nekolink
        echo -e "${PINK}服务已重启喵！${NC}"
    fi
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
            echo -e "${PINK}提示：请务必输入服务端的公网 IP 和信令端口 (通常为 12580) 喵！${NC}"
            read -p "请输入服务端的公网端点 ( IP:服务端信令端口, 示例 1.2.3.4:12580 ): " endpoint
        fi
        while [ -z "$endpoint" ]; do
            read -p "客户端必须指定对端地址喵！请重新输入: " endpoint
        done
    fi

    echo -e "\n${CYAN}选择数据传输模式：${NC}"
    echo "1. IP 协议模式 (绕过 UDP 限制，推荐)"
    echo "2. UDP 模式 (标准协议)"
    echo "3. TCP 伪装模式 (极致模拟，强力穿透)"
    read -p "请选择 [1-3]: " mode_choice
    case "$mode_choice" in
        1)
            mode="ip"
            read -p "请输入 IP 协议号 [143-252] ( 默认 141 ): " proto
            [ -z "$proto" ] && proto=141
            listen_port="null"
            ;;
        3)
            mode="tcp"
            echo -e "${PINK}... 使用 Fake-TCP 模式喵 (请确保设置 nftables 规则 DROP 相应端口 of RST 包)${NC}"
            proto="null"
            read -p "请输入伪装 TCP 监听端口 ( 0 为自动协商, 默认 0 ): " listen_port
            [ -z "$listen_port" ] && listen_port=0
            ;;
        *)
            mode="udp"
            proto="null"
            read -p "请输入数据隧道监听端口 ( 0 为自动协商, 默认 0 ): " listen_port
            [ -z "$listen_port" ] && listen_port=0
            ;;
    esac

    read -p "请输入本地隧道接口 IP 地址 ( 示例 10.0.0.1/24 ): " local_addr
    
    # MTU 自动探测逻辑喵
    rec_mtu=1420
    if [ "$role" == "client" ] && [ -n "$endpoint" ]; then
        echo -e "${PINK}正在为您探测最佳 MTU 推荐值，请稍等喵...${NC}"
        # 尝试调用 nekolink-ctl mtu-probe
        probe_res=$(nekolink-ctl mtu-probe "$endpoint" "$mode" 2>/dev/null | grep "RECOMMENDED_MTU=" | cut -d'=' -f2)
        if [ -n "$probe_res" ]; then
            rec_mtu=$probe_res
            echo -e "${PINK}探测成功！根据当前链路，建议 MTU 为: $rec_mtu${NC}"
        else
            echo -e "${CYAN}探测魔法失败了喵，可能是网络波动。将使用默认推荐值 1420。${NC}"
        fi
    fi

    echo -e "MTU 模式选择喵："
    echo "1. 使用探测推荐值 (固定: $rec_mtu)"
    echo "2. 手动输入自定义值 (固定)"
    echo "3. 开启自动同步 (Auto Sync, 推荐服务端使用)"
    read -p "请输入选项 [1-3, 默认 1]: " mtu_mode

    mtu="null"
    case "$mtu_mode" in
        2)
            read -p "请输入 MTU 值 ( 建议 1280-1420 ): " mtu_val
            [ -z "$mtu_val" ] && mtu_val=$rec_mtu
            mtu=$mtu_val
            ;;
        3)
            mtu=0
            echo -e "${PINK}已为您开启动态 MTU 同步魔法喵！将会自动跟随客户端的 MTU。${NC}"
            ;;
        *)
            mtu=$rec_mtu
            ;;
    esac

    read -p "是否开启 TCP MSS 自动修复 ( 建议开启以防止握手成功但无法网页浏览 )？( y/n, 默认 y ): " mss_enable
    [ -z "$mss_enable" ] && mss_enable="y"
    clamp_mss="false"
    if [ "$mss_enable" == "y" ]; then
        clamp_mss="true"
    fi
    [ -z "$local_addr" ] && local_addr="10.0.0.1/24"

    read -p "请输入 Keepalive 持续活动间隔 (秒, 0 为禁用, 默认 25): " keepalive
    [ -z "$keepalive" ] && keepalive=25

    read -p "请输入预共享密钥 (PSK, 用于自动交换公钥，两端必须一致): " psk
    [ -z "$psk" ] && psk="NekoMagic_Default_PSK"

    read -p "是否自动配置系统路由？(默认 n) [y/n]: " auto_route_choice
    if [ "$auto_route_choice" == "y" ]; then
        auto_route="true"
    else
        auto_route="false"
    fi

    # signal_port 统一迁移到 global.json 喵

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
  ]
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
function check_and_fix_configs() {
    echo -e "\n${PINK}--- 正在施展配置文件修复魔法 ---${NC}"
    configs=("$CONFIG_DIR"/*.json)
    if [ ! -e "${configs[0]}" ]; then
        echo -e "${CYAN}目录里空荡荡的喵，没有发现配置文件。${NC}"
        return
    fi

    for cfg in "${configs[@]}"; do
        ifname=$(basename "$cfg" .json)
        if [ "$ifname" == "global" ]; then continue; fi # 跳过全局配置喵
        echo -e "${CYAN}检查接口 [$ifname] 的配置...${NC}"
        
        # 定义字段及其默认值
        # 注意：这里使用数组模拟字典，因为 bash 3.x 兼容性考虑
        # 格式：字段名|默认值|如果是 null 转为什么
        fields=(
            "interface|\"$ifname\""
            "mode|\"udp\""
            "ip_protocol|null"
            "listen_port|0"
            "auto_route|false"
            "persistent_keepalive|25"
            "mtu|1420"
            "clamp_mss|true"
            "local_address|\"10.0.0.1/24\""
            "psk|\"NekoMagic_Default_PSK\""
            "peers|[]"
        )

        tmp_cfg=$(mktemp)
        cp "$cfg" "$tmp_cfg"

        for f in "${fields[@]}"; do
            key=$(echo "$f" | cut -d'|' -f1)
            default=$(echo "$f" | cut -d'|' -f2)
            
            # 检查字段是否存在
            exists=$(jq "has(\"$key\")" "$tmp_cfg")
            if [ "$exists" != "true" ]; then
                echo -e "${PINK}  补全缺失字段: $key -> $default${NC}"
                new_tmp=$(mktemp)
                jq ". + {\"$key\": $default}" "$tmp_cfg" > "$new_tmp"
                mv "$new_tmp" "$tmp_cfg"
            fi
        done

        # 移除过时的 signal_port 字段喵
        if jq -e 'has("signal_port")' "$tmp_cfg" > /dev/null; then
            echo -e "${PINK}  发现并迁移过时的 signal_port 字段...${NC}"
            new_tmp=$(mktemp)
            jq 'del(.signal_port)' "$tmp_cfg" > "$new_tmp"
            mv "$new_tmp" "$tmp_cfg"
        fi

        # 特殊逻辑修复：确保 listen_port 和 ip_protocol 在某些模式下合法
        # 暂时只做基础补全，如果主人需要更复杂的逻辑可以后续追加喵
        
        # 比较是否有变化
        if ! diff -q "$cfg" "$tmp_cfg" > /dev/null; then
            mv "$tmp_cfg" "$cfg"
            echo -e "${PINK}  修复完成喵！${NC}"
        else
            echo -e "${CYAN}  配置看起来很健康喵！${NC}"
            rm "$tmp_cfg"
        fi
    done

    # 统一维护 global.json
    echo -e "${CYAN}检查并清理全局配置 global.json...${NC}"
    global_json="$CONFIG_DIR/global.json"
    if [ ! -f "$global_json" ]; then
        echo -e "${PINK}  创建缺失的 global.json ...${NC}"
        echo '{"signal_port": 12580}' > "$global_json"
    else
        # 补全缺失，并强制移除冗余字段喵
        tmp_g=$(mktemp)
        sig=$(jq -r '.signal_port // 12580' "$global_json")
        echo "{\"signal_port\": $sig}" > "$tmp_g"
        
        if ! diff -q "$global_json" "$tmp_g" > /dev/null; then
            echo -e "${PINK}  清理 global.json 中的冗余字段成功喵！${NC}"
            mv "$tmp_g" "$global_json"
        else
            rm "$tmp_g"
        fi
    fi

    echo -e "${PINK}所有配置检查与迁移完毕喵！${NC}"
}

while true; do
    show_menu
    case $choice in
        1) create_config ;;
        2) edit_config ;;
        3) 
            echo -e "${PINK}正在通过 Systemd 重启 NekoLink 魔法...${NC}"
            systemctl restart nekolink
            echo -e "${PINK}重启指令已发送喵！可以使用选项 4 查看最新状态。${NC}"
            ;;
        4) nekolink status ;;
        5) manage_keys ;;
        6) check_and_fix_configs ;;
        7) ls -l "$CONFIG_DIR"/*.json ;;
        8) exit 0 ;;
        *) echo "无效选择喵！" ;;
    esac
done
