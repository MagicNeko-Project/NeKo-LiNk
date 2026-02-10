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
    VERSION="3.1.0"
fi
echo -e "${PINK}ฅ^•ﻌ•^ฅ 欢迎使用 NekoLink 交互式配置助手 v$VERSION！${NC}"
echo -e "${CYAN}--- 全局信令通道 [12580] (一按我帮您) 已就绪 ---${NC}"

CONFIG_DIR="/etc/neko-link"
mkdir -p "$CONFIG_DIR"

function show_menu() {
    echo -e "${CYAN}请选择操作：${NC}"
    echo "1. 创建新配置文件 (Node Config)"
    echo "2. 修改现有配置文件 (Edit Config)"
    echo "3. 热重载配置 (Hot Reload)"
    echo "4. 完全重启 NekoLink 服务 (Systemd Restart)"
    echo "5. 查看运行状态 (Status)"
    echo "6. 管理密钥与公钥 (Key Management)"
    echo "7. 配置文件一键检查与修复 (Fix Configs)"
    echo "8. 查看配置文件列表"
    echo "9. 高级设置 (Advanced Settings)"
    echo "10. 退出"
    read -p "请输入数字 [1-10]: " choice
}

function show_advanced_menu() {
    echo -e "\n${PINK}--- 高级设置探索偏殿 ---${NC}"
    echo -e "${CYAN}请选择高级魔法：${NC}"
    echo "1. 设置全局服务端监听端口 (Global Server Signaling Port)"
    echo "2. 设置全局 Loopback 接口 (Loopback Interface)"
    echo "3. 将所有隧道修改为 MTU 自动协商 (MTU Auto-Negotiation)"
    echo "4. 导入 wg-quick 配置文件 (WireGuard 兼容模式)"
    echo "5. 一键注入 SOCKS5 极速神力 (Auto-Optimize Kernel)"
    echo "6. Mullvad TCP 组件诊断 (Diagnose tcp2udp/udp2tcp)"
    echo "7. 返回主菜单"
    read -p "请输入数字 [1-7]: " adv_choice
}

function import_wgquick_config() {
    echo -e "\n${PINK}--- 开始导入 wg-quick 配置魔法 ---${NC}"
    echo -e "${CYAN}此功能会将标准 WireGuard 配置文件转换为 NekoLink 兼容格式喵！${NC}"
    echo -e "${CYAN}注意：导入后将自动开启 native_wg_compat 模式（禁用信令通道）${NC}\n"
    
    read -p "请输入 wg-quick 配置文件路径 (例如 /etc/wireguard/wg0.conf): " wg_conf_path
    
    if [ ! -f "$wg_conf_path" ]; then
        echo -e "${PINK}喵？找不到文件: $wg_conf_path${NC}"
        return
    fi
    
    # 提取接口名称
    default_iface=$(basename "$wg_conf_path" .conf)
    read -p "请输入 NekoLink 接口名称 (默认: $default_iface): " iface
    [ -z "$iface" ] && iface="$default_iface"
    
    # 解析 [Interface] 部分
    local private_key=""
    local address=""
    local listen_port="0"
    local mtu="1420"
    local table="auto"
    
    # 解析 [Peer] 部分（支持多个 Peer）
    declare -a peer_pubkeys
    declare -a peer_psks
    declare -a peer_endpoints
    declare -a peer_allowedips
    declare -a peer_keepalives
    
    local current_section=""
    local peer_idx=-1
    
    while IFS='=' read -r key value || [ -n "$key" ]; do
        # 去除首尾空格
        key=$(echo "$key" | xargs)
        value=$(echo "$value" | xargs)
        
        # 跳过空行和注释
        [ -z "$key" ] && continue
        [[ "$key" == \#* ]] && continue
        
        # 检测段落标题
        if [[ "$key" == \[Interface\]* ]]; then
            current_section="interface"
            continue
        elif [[ "$key" == \[Peer\]* ]]; then
            current_section="peer"
            peer_idx=$((peer_idx + 1))
            peer_pubkeys[$peer_idx]=""
            peer_psks[$peer_idx]=""
            peer_endpoints[$peer_idx]=""
            peer_allowedips[$peer_idx]=""
            peer_keepalives[$peer_idx]=""
            continue
        fi
        
        if [ "$current_section" == "interface" ]; then
            case "$key" in
                PrivateKey) private_key="$value" ;;
                Address) 
                    # 支持多个 Address，用逗号分隔合并
                    if [ -z "$address" ]; then
                        address="$value"
                    else
                        address="$address, $value"
                    fi
                    ;;
                ListenPort) listen_port="$value" ;;
                MTU) mtu="$value" ;;
                Mtu) mtu="$value" ;;  # 兼容小写
                Table) table="$value" ;;
            esac
        elif [ "$current_section" == "peer" ] && [ $peer_idx -ge 0 ]; then
            case "$key" in
                PublicKey) peer_pubkeys[$peer_idx]="$value" ;;
                PresharedKey) peer_psks[$peer_idx]="$value" ;;
                Endpoint) peer_endpoints[$peer_idx]="$value" ;;
                AllowedIPs) peer_allowedips[$peer_idx]="$value" ;;
                PersistentKeepalive) peer_keepalives[$peer_idx]="$value" ;;
            esac
        fi
    done < "$wg_conf_path"
    
    # 验证必要字段
    if [ -z "$private_key" ]; then
        echo -e "${PINK}喵呜... 配置文件中没有找到 PrivateKey！${NC}"
        return
    fi
    
    if [ -z "$address" ]; then
        echo -e "${PINK}喵呜... 配置文件中没有找到 Address！${NC}"
        return
    fi
    
    # 判断 auto_route：Table=off 表示不导入路由
    local auto_route="false"
    if [ "$table" != "off" ]; then
        auto_route="true"
    fi
    
    # 构建 peers JSON 数组
    local peers_json=""
    for i in "${!peer_pubkeys[@]}"; do
        local pjson="{\"public_key\": \"${peer_pubkeys[$i]}\""
        [ -n "${peer_endpoints[$i]}" ] && pjson="$pjson, \"endpoint\": \"${peer_endpoints[$i]}\""
        [ -n "${peer_psks[$i]}" ] && pjson="$pjson, \"preshared_key\": \"${peer_psks[$i]}\""
        [ -n "${peer_allowedips[$i]}" ] && pjson="$pjson, \"allowed_ips\": \"${peer_allowedips[$i]}\""
        [ -n "${peer_keepalives[$i]}" ] && pjson="$pjson, \"persistent_keepalive\": ${peer_keepalives[$i]}"
        pjson="$pjson}"
        
        if [ -z "$peers_json" ]; then
            peers_json="$pjson"
        else
            peers_json="$peers_json, $pjson"
        fi
    done
    
    # 生成 JSON 配置
    local json_path="$CONFIG_DIR/$iface.json"
    
    cat > "$json_path" <<EOF
{
  "interface": "$iface",
  "mode": "udp",
  "ip_protocol": null,
  "listen_port": $listen_port,
  "auto_route": $auto_route,
  "persistent_keepalive": null,
  "mtu": $mtu,
  "clamp_mss": true,
  "local_address": "$address",
  "psk": "NekoMagic_WG_Compat",
  "native_wg_compat": true,
  "private_key": "$private_key",
  "peers": [$peers_json]
}
EOF
    
    echo -e "\n${PINK}--- 导入结果摘要 ---${NC}"
    echo -e "${CYAN}接口名称: $iface${NC}"
    echo -e "${CYAN}本地地址: $address${NC}"
    echo -e "${CYAN}监听端口: $listen_port${NC}"
    echo -e "${CYAN}MTU: $mtu${NC}"
    echo -e "${CYAN}自动路由: $auto_route (Table=$table)${NC}"
    echo -e "${CYAN}导入 Peer 数量: $((peer_idx + 1))${NC}"
    echo -e "${CYAN}兼容模式: native_wg_compat=true${NC}"
    echo -e "\n${PINK}配置已保存到: $json_path 喵！${NC}"
    
    read -p "是否立即重载服务以应用新配置？(y/n, 默认 n): " reload_now
    if [ "$reload_now" == "y" ]; then
        nekolink-ctl reload
        echo -e "${PINK}配置已重载喵！${NC}"
    fi
}

function set_all_tunnels_auto_mtu() {
    echo -e "\n${PINK}--- 正在批量施展全隧道自动 MTU 魔法 ---${NC}"
    configs=("$CONFIG_DIR"/*.json)
    if [ ! -e "${configs[0]}" ]; then
        echo -e "${CYAN}目录里空荡荡的喵，没有发现配置文件。${NC}"
        return
    fi

    echo -e "${CYAN}确定要将所有接口的 MTU 设为 0 (自动协商) 吗喵？${NC}"
    read -p "输入 y 确认: " confirm
    if [ "$confirm" != "y" ]; then
        echo -e "${PINK}魔法中断。保持现状喵。${NC}"
        return
    fi

    for cfg in "${configs[@]}"; do
        ifname=$(basename "$cfg" .json)
        if [ "$ifname" == "global" ]; then continue; fi
        
        echo -e "${CYAN}处理接口 [$ifname] ...${NC}"
        tmp_cfg=$(mktemp)
        jq '.mtu = 0' "$cfg" > "$tmp_cfg"
        mv "$tmp_cfg" "$cfg"
    done
    
    echo -e "${PINK}批量操作完成喵！所有隧道现在都已开启 MTU 自动协商魔法。(〃'▽'〃)${NC}"
    echo -e "${CYAN}提示：重启服务后生效喵。${NC}"
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
    curr_ep=$(jq -r '.peers[0].endpoint // empty' "$selected_cfg")
    curr_s5=$(jq -r '.socks5_port // "null"' "$selected_cfg")
    curr_s5_local=$(jq -r '.socks5_listen_local // true' "$selected_cfg")
    curr_s5_loop=$(jq -r '.socks5_listen_loopback // false' "$selected_cfg")
    curr_mesh=$(jq -r '.mesh_mode // false' "$selected_cfg")
    curr_tmode=$(jq -r '.transport_mode // "tun"' "$selected_cfg")

    # 智能角色识别喵
    global_json="$CONFIG_DIR/global.json"
    global_sig_port=$( [ -f "$global_json" ] && jq -r '.signal_port // empty' "$global_json" || echo "" )
    
    if [ -n "$curr_ep" ] && [ -n "$global_sig_port" ]; then
        role_label="中转/Mesh 节点 (Relay)"
    elif [ -n "$curr_ep" ]; then
        role_label="纯客户端 (Client Only)"
    else
        role_label="纯服务端 (Server Only)"
    fi
    echo -e "${CYAN}当前节点角色识别为: ${PINK}$role_label${NC}"

    if [ -n "$curr_ep" ] && [ -z "$global_sig_port" ]; then
        read -p "想把这个客户端升级为中转节点吗喵？(允许 C -> B -> A 拓扑) [y/n, 默认 n]: " upgrade_c
        if [ "$upgrade_c" == "y" ]; then
            echo -e "${PINK}正在施展身份转化魔法...${NC}"
            set_global_signal_port
            # 重新读取
            global_sig_port=$(jq -r '.signal_port // empty' "$global_json")
            curr_mesh=true
            echo -e "${CYAN}已为您预热 Mesh 转发魔法喵！(后续步骤请确认开启)${NC}"
        fi
    fi

    # 交互式修改
    read -p "传输模式 (当前: $curr_mode, [1] ip, [2] udp, [3] Mullvad TCP 模式, 直接回车保持不变): " m_choice
    case "$m_choice" in
        1) mode="ip" ;;
        2) mode="udp" ;;
        3) mode="mullvad-tcp" 
           echo -e "${PINK}... 使用 Mullvad TCP 模式喵！${NC}" ;;
        *) mode="$curr_mode" ;;
    esac

    if [ "$mode" == "ip" ]; then
        read -p "IP 协议号 (当前: $curr_proto, 直接回车保持不变): " proto
        [ -z "$proto" ] && proto=$curr_proto
        listen_port="null"
    elif [ "$mode" == "tcp" ] || [ "$mode" == "mullvad-tcp" ]; then
        proto="null"
        read -p "TCP 监听端口 (当前: $curr_lport, 直接回车保持不变): " listen_port
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

    read -p "开启本地 SOCKS5 服务端? (当前端口: $curr_s5, 输入端口号开启如 1080, 输入 n 关闭, 直接回车保持不变): " s5_c
    case "$s5_c" in
        n) socks5_port="null" ;;
        "") socks5_port="$curr_s5" ;;
        *) socks5_port="$s5_c" ;;
    esac

    if [ "$socks5_port" != "null" ]; then
        read -p "是否在 127.0.0.1 监听 SOCKS5? (当前: $curr_s5_local, [y/n], 默认 y): " s5_l_c
        case "$s5_l_c" in
            y) s5_local="true" ;;
            n) s5_local="false" ;;
            *) s5_local="$curr_s5_local" ;;
        esac

        read -p "是否在全局 Loopback 接口监听 SOCKS5? (当前: $curr_s5_loop, [y/n], 默认 n): " s5_loop_c
        case "$s5_loop_c" in
            y) s5_loop="true" ;;
            n) s5_loop="false" ;;
            *) s5_loop="$curr_s5_loop" ;;
        esac
    else
        s5_local="true"
        s5_loop="false"
    fi

    read -p "开启二层透明桥接 (TAP) 模式? (当前: $curr_tmode, [y/n], 直接回车保持不变): " tap_c
    case "$tap_c" in
        y) transport_mode="tap" ;;
        n) transport_mode="tun" ;;
        *) transport_mode="$curr_tmode" ;;
    esac

    read -p "开启 P2P Mesh 全网状模式? (当前: $curr_mesh, [y/n], 直接回车保持不变): " mesh_c
    case "$mesh_c" in
        y) mesh_mode="true" ;;
        n) mesh_mode="false" ;;
        *) mesh_mode="$curr_mesh" ;;
    esac

    read -p "是否修改本地信令监听端口? (当前在 global.json 配置, [y/n], 默认 n): " change_sig
    if [ "$change_sig" == "y" ]; then
        set_global_signal_port
    fi

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
        --argjson socks5_port "$socks5_port" \
        --argjson s5_local "$s5_local" \
        --argjson s5_loop "$s5_loop" \
        --arg ep "$endpoint" \
        --argjson mesh "$mesh_mode" \
        --arg tmode "$transport_mode" \
        '{
            interface: $iface,
            mode: $mode,
            transport_mode: $tmode,
            mesh_mode: $mesh,
            ip_protocol: $proto,
            listen_port: $listen_port,
            auto_route: $auto_route,
            persistent_keepalive: $keepalive,
            mtu: $mtu,
            clamp_mss: $clamp_mss,
            local_address: $addr,
            psk: $psk,
            socks5_port: $socks5_port,
            socks5_listen_local: $s5_local,
            socks5_listen_loopback: $s5_loop,
            peers: (if $ep != "" then [{endpoint: $ep}] else [] end)
        }' > "$tmp_cfg"
    
    mv "$tmp_cfg" "$selected_cfg"
    echo -e "${PINK}配置更新成功喵！${NC}"
    read -p "是否立即重载服务以应用新配置？(y/n, 默认 n): " reload_now
    if [ "$reload_now" == "y" ]; then
        nekolink-ctl reload
        echo -e "${PINK}配置已重载喵！${NC}"
    fi
}

function create_config() {
    echo -e "\n${PINK}--- 开始创建 NekoLink 配置 ---${NC}"
    
    read -p "请输入接口名称 ( 默认 nekotun0 ): " iface
    [ -z "$iface" ] && iface="nekotun0"

    echo -e "\n${CYAN}请选择节点角色：${NC}"
    echo "1. 服务端 (拥有公用 IP，仅等待连接)"
    echo "2. 客户端 (连接到上游服务端)"
    echo "3. 中转/Mesh 节点 (既连接上游，也等待下游连接，适用于 A-B-C 链式拓扑)"
    read -p "请选择 [1-3]: " role_choice

    if [ "$role_choice" == "1" ]; then
        role="server"
        echo -e "${PINK}提示：作为服务端，请确保你的信令通道和数据协议号在防火墙已放行喵！${NC}"
        endpoint=""
    elif [ "$role_choice" == "3" ]; then
        role="relay"
        echo -e "${PINK}--- 魔法中转站配置开始喵！ ---${NC}"
        read -p "请输入上游服务端 (节点 A) 的 IP 地址: " server_ip
        while [ -z "$server_ip" ]; do
            read -p "中转节点必须指定上游 IP 喵！请重新输入: " server_ip
        done
        read -p "请输入上游服务端的信令端口 (通常为 12580): " server_signal_port
        [ -z "$server_signal_port" ] && server_signal_port=12580
        endpoint="${server_ip}:${server_signal_port}"
        
        echo -e "${CYAN}已配置上游目标: $endpoint${NC}"
        echo -e "${PINK}现在请配置本地监听端口，以便下游节点 (节点 C) 连接喵！${NC}"
        set_global_signal_port
    else
        role="client"
        echo -e "${PINK}--- 请输入服务端的连接信息 ---${NC}"
        
        read -p "请输入服务端的 IP 地址 (例如 1.2.3.4): " server_ip
        while [ -z "$server_ip" ]; do
            read -p "客户端必须指定服务端 IP 喵！请重新输入: " server_ip
        done
        
        read -p "请输入服务端的信令端口 (通常为 12580): " server_signal_port
        [ -z "$server_signal_port" ] && server_signal_port=12580
        
        endpoint="${server_ip}:${server_signal_port}"
        echo -e "${CYAN}已配置连接目标: $endpoint${NC}"
    fi

    echo -e "\n${CYAN}选择数据传输模式：${NC}"
    echo "1. IP 协议模式 (绕过 UDP 限制，推荐)"
    echo "2. UDP 模式 (标准协议)"
    echo "3. Mullvad TCP 模式 (稳定穿透)"
    read -p "请选择 [1-3]: " mode_choice
    case "$mode_choice" in
        1)
            mode="ip"
            read -p "请输入 IP 协议号 [143-252] ( 默认 141 ): " proto
            [ -z "$proto" ] && proto=141
            listen_port="null"
            ;;
        3)
            mode="mullvad-tcp"
            echo -e "${PINK}... 使用 Mullvad TCP 模式喵！${NC}"
            proto="null"
            read -p "请输入 TCP 监听端口 ( 默认 12581 ): " listen_port
            [ -z "$listen_port" ] && listen_port=12581
            ;;
        *)
            mode="udp"
            proto="null"
            read -p "请输入数据隧道监听端口 ( 0 为自动协商, 默认 0 ): " listen_port
            [ -z "$listen_port" ] && listen_port=0
            ;;
    esac

    echo -e "\n${CYAN}选择网络层级：${NC}"
    echo "1. 三层模式 (TUN, 标准 IP 隧道, 默认)"
    echo "2. 二层模式 (TAP, 透明桥接/交换机模式, 推荐用于 Mesh)"
    read -p "请选择 [1-2]: " tmode_choice
    [ "$tmode_choice" == "2" ] && transport_mode="tap" || transport_mode="tun"

    [ "$role" == "relay" ] && def_mesh="y" || def_mesh="n"
    read -p "是否开启 P2P Mesh 全网状模式? (y/n, 默认 $def_mesh): " mesh_choice
    [ -z "$mesh_choice" ] && mesh_choice="$def_mesh"
    [ "$mesh_choice" == "y" ] && mesh_mode="true" || mesh_mode="false"

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

    read -p "是否开启本地 SOCKS5 服务端? (输入端口号如 1080, 直接回车则不开启): " s5_port
    if [ -z "$s5_port" ]; then
        socks5_port="null"
        s5_local="true"
        s5_loop="false"
    else
        socks5_port="$s5_port"
        read -p "是否在 127.0.0.1 监听 SOCKS5? (y/n, 默认 y): " s5_l_c
        [ "$s5_l_c" == "n" ] && s5_local="false" || s5_local="true"
        read -p "是否在全局 Loopback 接口监听 SOCKS5? (y/n, 默认 n): " s5_loop_c
        [ "$s5_loop_c" == "y" ] && s5_loop="true" || s5_loop="false"
    fi

    read -p "是否优先使用 IPv6 解析? (y/n, 默认 n): " prefer_ipv6_choice
    if [ "$prefer_ipv6_choice" == "y" ]; then
        prefer_ipv6="true"
    else
        prefer_ipv6="false"
    fi

    # 客户端可以为peer指定独立的信令端口喵
    peer_signal_port="null"
    if [ "$role" == "client" ]; then
        read -p "是否为对端指定独立信令端口? (直接回车使用全局端口, 输入端口号则使用指定端口): " psport
        if [ -n "$psport" ]; then
            peer_signal_port="$psport"
        fi
    fi

    # signal_port 统一迁移到 global.json 喵

    # 构建 JSON
    json_path="$CONFIG_DIR/$iface.json"
    
    # 构建基础 JSON
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
  "socks5_port": $socks5_port,
  "socks5_listen_local": $s5_local,
  "socks5_listen_loopback": $s5_loop,
  "prefer_ipv6": $prefer_ipv6,
  "mesh_mode": $mesh_mode,
  "transport_mode": "$transport_mode",
  "peers": [
EOF

    if [ -n "$endpoint" ]; then
        if [ "$peer_signal_port" != "null" ]; then
            cat >> "$json_path" <<EOF
    {
      "endpoint": "$endpoint",
      "signal_port": $peer_signal_port
    }
EOF
        else
            cat >> "$json_path" <<EOF
    {
      "endpoint": "$endpoint"
    }
EOF
        fi
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
            "socks5_port|null",
            "mesh_mode|false",
            "transport_mode|\"tun\"",
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
        echo '{"signal_port": 12580, "loopback_interface": null, "loopback_address": null, "device_id": null}' > "$global_json"
    else
        # 补全缺失喵
        tmp_g=$(mktemp)
        sig=$(jq '.signal_port // 12580' "$global_json")
        lif=$(jq '.loopback_interface // null' "$global_json")
        laddr=$(jq '.loopback_address // null' "$global_json")
        did=$(jq '.device_id // null' "$global_json")
        
        jq -n \
            --argjson sig "$sig" \
            --argjson lif "$lif" \
            --argjson laddr "$laddr" \
            --argjson did "$did" \
            '{signal_port: $sig, loopback_interface: $lif, loopback_address: $laddr, device_id: $did}' > "$tmp_g"
        
        if ! diff -q "$global_json" "$tmp_g" > /dev/null; then
            echo -e "${PINK}  同步 global.json 配置成功喵！${NC}"
            mv "$tmp_g" "$global_json"
        else
            rm "$tmp_g"
        fi
    fi

    echo -e "${PINK}所有配置检查与迁移完毕喵！${NC}"
}

function set_global_signal_port() {
    echo -e "\n${PINK}--- 全局服务端信令监听设置 ---${NC}"
    echo -e "${CYAN}提示：此端口仅在您的节点作为“服务端”（被动等待连接）时负责监听喵。${NC}"
    echo -e "${CYAN}如果您仅作为客户端运行，NekoLink 将默认使用随机端口，无需配置此项喵。${NC}"
    global_json="$CONFIG_DIR/global.json"
    
    # 读取当前值
    if [ -f "$global_json" ]; then
        curr_port=$(jq -r '.signal_port // 12580' "$global_json")
    else
        curr_port=12580
    fi
    
    echo -e "${CYAN}当前全局信令端口: $curr_port${NC}"
    read -p "请输入新的信令端口 (直接回车保持不变): " new_port
    
    if [ -z "$new_port" ]; then
        echo -e "${PINK}保持原端口不变喵！${NC}"
        return
    fi
    
    # 验证是否为数字
    if ! [[ "$new_port" =~ ^[0-9]+$ ]]; then
        echo -e "${CYAN}喵？输入的不是有效端口号喵！${NC}"
        return
    fi
    
    # 写入 global.json
    tmp_g=$(mktemp)
    jq --argjson port "$new_port" '.signal_port = $port' "$global_json" > "$tmp_g"
    mv "$tmp_g" "$global_json"
    echo -e "${PINK}全局信令端口已更新为: $new_port 喵！${NC}"
    echo -e "${CYAN}提示：修改后请重启 nekolink 服务以生效喵。${NC}"
}

function set_global_loopback() {
    echo -e "\n${PINK}--- 全局 Loopback 接口设置魔法 ---${NC}"
    global_json="$CONFIG_DIR/global.json"
    
    # 确保 global.json 存在喵
    if [ ! -f "$global_json" ]; then echo '{"signal_port": 12580, "loopback_interface": null, "loopback_address": null, "device_id": null}' > "$global_json"; fi
    
    curr_if=$(jq -r '.loopback_interface // "null"' "$global_json")
    curr_addr=$(jq -r '.loopback_address // "null"' "$global_json")
    curr_did=$(jq -r '.device_id // "null"' "$global_json")
    
    echo -e "${CYAN}当前 Loopback 接口: $curr_if${NC}"
    echo -e "${CYAN}当前 Loopback 地址: $curr_addr${NC}"
    echo -e "${CYAN}当前 设备 ID: $curr_did${NC}"
    
    read -p "请输入 Loopback 接口名称 (例如 nekolo0, 输入 n 清除, 直接回车保持不变): " new_if
    case "$new_if" in
        n) loop_if="null" ;;
        "") loop_if="$curr_if" ;;
        *) loop_if="\"$new_if\"" 
           # 确保引用的变量正确喵
           if [[ ! "$loop_if" =~ ^\".*\"$ && "$loop_if" != "null" ]]; then loop_if="\"$loop_if\""; fi ;;
    esac
    
    read -p "请输入 Loopback IP 地址 (例如 172.16.0.1/24, 多地址用逗号分隔, 输入 n 清除, 直接回车保持不变): " new_addr
    case "$new_addr" in
        n) loop_addr="null" ;;
        "") loop_addr="$curr_addr" ;;
        *) loop_addr="\"$new_addr\"" ;;
    esac

    read -p "请输入设备 ID (用于接口标识, 输入 n 清除, 直接回车保持不变): " new_did
    case "$new_did" in
        n) loop_did="null" ;;
        "") loop_did="$curr_did" ;;
        *) loop_did="\"$new_did\"" ;;
    esac
    
    tmp_g=$(mktemp)
    jq --argjson lif "$loop_if" \
       --argjson laddr "$loop_addr" \
       --argjson ldid "$loop_did" \
       '.loopback_interface = $lif | .loopback_address = $laddr | .device_id = $ldid' "$global_json" > "$tmp_g"
    mv "$tmp_g" "$global_json"
    
    echo -e "${PINK}全局 Loopback 配置已更新喵！${NC}"
    echo -e "${CYAN}提示：修改后需要重启 nekolink 或执行热重载喵。${NC}"
}

function auto_optimize_kernel() {
    echo -e "\n${PINK}--- 正在为系统注入 SOCKS5 极速神力 (内核优化) ---${NC}"
    echo -e "${CYAN}此操作将修改 /etc/sysctl.conf 和 /etc/security/limits.conf。${NC}"
    echo -e "${CYAN}优化内容包括：开启 BBR、增加连接队列、扩大端口范围、提升文件句柄上限等喵。${NC}\n"
    
    read -p "确定要继续吗？(y/n): " confirm
    if [ "$confirm" != "y" ]; then
        echo -e "${PINK}操作取消喵。${NC}"
        return
    fi

    # 1. 备份现有配置
    echo -e "${CYAN}正在备份配置文件...${NC}"
    cp /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%F-%T)
    cp /etc/security/limits.conf /etc/security/limits.conf.bak.$(date +%F-%T)
    
    # 2. 修改 sysctl.conf
    echo -e "${CYAN}正在应用 sysctl 内核参数...${NC}"
    declare -A sysctl_params=(
        ["net.core.default_qdisc"]="fq"
        ["net.ipv4.tcp_congestion_control"]="bbr"
        ["net.core.somaxconn"]="65535"
        ["net.ipv4.tcp_max_syn_backlog"]="65535"
        ["net.ipv4.ip_local_port_range"]="10000 65000"
        ["net.ipv4.tcp_tw_reuse"]="1"
        ["fs.file-max"]="1000000"
        ["net.core.rmem_max"]="16777216"
        ["net.core.wmem_max"]="16777216"
        ["net.ipv4.tcp_rmem"]="4096 87380 16777216"
        ["net.ipv4.tcp_wmem"]="4096 16384 16777216"
    )

    for key in "${!sysctl_params[@]}"; do
        value="${sysctl_params[$key]}"
        if grep -q "^$key" /etc/sysctl.conf; then
            sed -i "s|^$key.*|$key = $value|" /etc/sysctl.conf
        else
            echo "$key = $value" >> /etc/sysctl.conf
        fi
    done
    
    # 立即生效
    sysctl -p
    
    # 3. 修改 limits.conf (所有用户)
    echo -e "${CYAN}正在提升文件描述符限制 (ulimit)...${NC}"
    if ! grep -q "* soft nofile 1000000" /etc/security/limits.conf; then
        echo "* soft nofile 1000000" >> /etc/security/limits.conf
        echo "* hard nofile 1000000" >> /etc/security/limits.conf
    fi
    if ! grep -q "root soft nofile 1000000" /etc/security/limits.conf; then
        echo "root soft nofile 1000000" >> /etc/security/limits.conf
        echo "root hard nofile 1000000" >> /etc/security/limits.conf
    fi

    echo -e "\n${PINK}注入成功！您的系统现在拥有赛车引擎般的性能了喵！( ⸝⸝•ᴗ•⸝⸝ )੭⁾⁾${NC}"
    echo -e "${CYAN}提示：部分 limits 设置需要注销重登录或重启系统后才能完全生效喵。${NC}"
}

function diagnose_mullvad_tcp() {
    echo -e "\n${PINK}--- Mullvad TCP 组件诊断工具 ---${NC}"
    echo -e "${CYAN}正在检查 tcp2udp 和 udp2tcp 运行状态喵...${NC}\n"
    
    # 检查 tcp2udp 进程
    echo -e "${CYAN}=== tcp2udp (服务端) ===${NC}"
    tcp2udp_count=$(ps aux | grep -v grep | grep -c "tcp2udp")
    if [ $tcp2udp_count -gt 0 ]; then
        echo -e "${PINK}✓ 发现 $tcp2udp_count 个 tcp2udp 进程${NC}"
        ps aux | grep -v grep | grep "tcp2udp" | while read line; do
            pid=$(echo "$line" | awk '{print $2}')
            cmd=$(echo "$line" | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; print ""}')
            echo -e "  PID: ${CYAN}$pid${NC}  命令: $cmd"
        done
    else
        echo -e "${CYAN}✗ 没有发现 tcp2udp 进程${NC}"
    fi
    
    # 检查 udp2tcp 进程
    echo -e "\n${CYAN}=== udp2tcp (客户端) ===${NC}"
    udp2tcp_count=$(ps aux | grep -v grep | grep -c "udp2tcp")
    if [ $udp2tcp_count -gt 0 ]; then
        echo -e "${PINK}✓ 发现 $udp2tcp_count 个 udp2tcp 进程${NC}"
        ps aux | grep -v grep | grep "udp2tcp" | while read line; do
            pid=$(echo "$line" | awk '{print $2}')
            cmd=$(echo "$line" | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; print ""}')
            echo -e "  PID: ${CYAN}$pid${NC}  命令: $cmd"
        done
    else
        echo -e "${CYAN}✗ 没有发现 udp2tcp 进程${NC}"
    fi
    
    # 检查二进制文件是否存在
    echo -e "\n${CYAN}=== 二进制文件检查 ===${NC}"
    if command -v tcp2udp &> /dev/null; then
        echo -e "${PINK}✓ tcp2udp: $(which tcp2udp)${NC}"
        tcp2udp --version 2>&1 | head -n 1
    else
        echo -e "${CYAN}✗ tcp2udp 未安装或不在 PATH 中${NC}"
    fi
    
    if command -v udp2tcp &> /dev/null; then
        echo -e "${PINK}✓ udp2tcp: $(which udp2tcp)${NC}"
        udp2tcp --version 2>&1 | head -n 1
    else
        echo -e "${CYAN}✗ udp2tcp 未安装或不在 PATH 中${NC}"
    fi
    
    # 检查 Mullvad TCP 模式配置
    echo -e "\n${CYAN}=== Mullvad TCP 配置检查 ===${NC}"
    mullvad_configs=$(grep -l '"mode"\s*:\s*"mullvad-tcp"' "$CONFIG_DIR"/*.json 2>/dev/null || true)
    if [ -n "$mullvad_configs" ]; then
        echo -e "${PINK}✓ 发现 Mullvad TCP 模式配置：${NC}"
        for cfg in $mullvad_configs; do
            iface=$(basename "$cfg" .json)
            tcp_port=$(jq -r '.mullvad_tcp_port // 12581' "$cfg")
            echo -e "  接口: ${CYAN}$iface${NC}  TCP端口: ${CYAN}$tcp_port${NC}"
        done
    else
        echo -e "${CYAN}✗ 没有发现使用 Mullvad TCP 模式的配置${NC}"
    fi
    
    # 端口监听检查
    echo -e "\n${CYAN}=== 端口监听检查 ===${NC}"
    echo -e "${PINK}TCP 监听端口：${NC}"
    ss -tlnp 2>/dev/null | grep -E "tcp2udp|udp2tcp" | head -n 10 || echo -e "  ${CYAN}✗ 没有发现相关监听端口${NC}"
    echo -e "${PINK}UDP 监听端口：${NC}"
    ss -ulnp 2>/dev/null | grep -E "tcp2udp|udp2tcp" | head -n 10 || echo -e "  ${CYAN}✗ 没有发现相关监听端口${NC}"
    
    echo -e "\n${PINK}诊断完成喵！(〃'▽'〃)${NC}"
}


while true; do
    show_menu
    case $choice in
        1) create_config ;;
        2) edit_config ;;
        3)
            echo -e "${PINK}正在通过 SIGHUP 施展热重载魔法...${NC}"
            nekolink-ctl reload
            echo -e "${PINK}热重载指令已发送喵！可以使用选项 5 查看最新状态。${NC}"
            ;;
        4) 
            echo -e "${PINK}正在通过 Systemd 重启 NekoLink 魔法...${NC}"
            systemctl restart nekolink
            echo -e "${PINK}重启指令已发送喵！可以使用选项 5 查看最新状态。${NC}"
            ;;
        5) nekolink status ;;
        6) manage_keys ;;
        7) check_and_fix_configs ;;
        8) ls -l "$CONFIG_DIR"/*.json ;;
        9)
            show_advanced_menu
            case "$adv_choice" in
                1) set_global_signal_port ;;
                2) set_global_loopback ;;
                3) set_all_tunnels_auto_mtu ;;
                4) import_wgquick_config ;;
                5) auto_optimize_kernel ;;
                6) diagnose_mullvad_tcp ;;
                *) continue ;;
            esac
            ;;
        10)
            echo -e "${PINK}下次再见喵！(〃'▽'〃)${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}喵？无效的选择。${NC}"
            ;;
    esac
done
