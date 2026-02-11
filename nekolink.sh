#!/bin/bash
# NekoLink 交互式配置助手 ฅ^•ﻌ•^ฅ

set -e

# 颜色与样式定义 喵！
PINK='\033[1;38;5;205m'
CYAN='\033[1;38;5;51m'
GOLD='\033[1;38;5;220m'
GREEN='\033[1;38;5;82m'
RED='\033[1;38;5;196m'
BLUE='\033[1;38;5;27m'
PURPLE='\033[1;38;5;129m'
GRAY='\033[0;38;5;245m'
BOLD='\033[1m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}ฅ^•ﻌ•^喵呜... 请使用 ${BOLD}sudo${RED} 运行此脚本喵！${NC}"
  exit 1
fi

if [ "$#" -gt 0 ]; then
    nekolink-ctl "$@"
    exit $?
fi

# 获取版本信息
if [ -f "/usr/local/share/nekolink/VERSION" ]; then
    VERSION=$(cat /usr/local/share/nekolink/VERSION)
elif [ -f "VERSION" ]; then
    VERSION=$(cat VERSION)
else
    VERSION="3.5.0-Magic"
fi

function print_banner() {
    clear
    echo -e "${PINK}"
    echo "  _   _      _20      _     _       _      "
    echo " | \ | | ___| | _____| |   (_)_ __ | | __  "
    echo " |  \| |/ _ \ |/ / _ \ |   | | '_ \| |/ /  "
    echo " | |\  |  __/   < (_) | |___| | | | |   <   "
    echo " |_| \_|\___|_|\_\___/|_____|_|_| |_|_|\_\  "
    echo -e "       ${GOLD}ฅ^•ﻌ•^ฅ ${BOLD}NekoLink Magic Edition v$VERSION${NC}"
    echo -e "${GRAY}   ----------------------------------------------${NC}"
    echo -e "${CYAN}    >>> 全局信令中枢 [12580] (一按我帮您) 已就绪喵！ <<<${NC}"
    echo ""
}

print_banner

CONFIG_DIR="/etc/neko-link"
mkdir -p "$CONFIG_DIR"

function show_menu() {
    echo -e "${PURPLE}${BOLD}--- ✧ NekoLink 魔法大厅 ✧ ---${NC}"
    echo -e "${CYAN}请选择主人想要施展的法术：${NC}"
    echo -e "  ${GOLD}1.${NC} 召唤新队员 ${GRAY}(Create Config)${NC}"
    echo -e "  ${GOLD}2.${NC} 调教现有队员 ${GRAY}(Edit Config)${NC}"
    echo -e "  ${GOLD}3.${NC} 给队员改名 ${GRAY}(Rename Interface)${NC}"
    echo -e "  ${GOLD}4.${NC} 送别老队员 ${GRAY}(Delete Interface)${NC}"
    echo -e "  ${GOLD}5.${NC} 施展热重载魔法 ${GRAY}(Hot Reload)${NC}"
    echo -e "  ${GOLD}6.${NC} 彻底唤醒 NekoLink 服务 ${GRAY}(Systemd Restart)${NC}"
    echo -e "  ${GOLD}7.${NC} 实时魔法监控看板 ${GRAY}(Live Status)${NC}"
    echo -e "  ${GOLD}8.${NC} 密钥与公钥密室 ${GRAY}(Key Management)${NC}"
    echo -e "  ${GOLD}9.${NC} 配置全自动检查与修复 ${GRAY}(Fix Configs)${NC}"
    echo -e "  ${GOLD}10.${NC} 检阅所有魔法卷轴 ${GRAY}(List Configs)${NC}"
    echo -e "  ${GOLD}11.${NC} 深入高级魔法探索偏殿 ${GRAY}(Advanced Settings)${NC}"
    echo -e "  ${RED}12.${NC} 下次再见喵 ${GRAY}(Exit)${NC}"
    echo -e "${GRAY}-------------------------------${NC}"
    read -p "请输入魔法代号 [1-12]: " choice
}

function show_advanced_menu() {
    echo -e "\n${PURPLE}${BOLD}--- ✧ 禁忌的魔法探索偏殿 ✧ ---${NC}"
    echo -e "${CYAN}这里有更深奥的黑魔法喵：${NC}"
    echo -e "  ${GOLD}1.${NC} 设置全局服务端信令端口 ${GRAY}(Global Signaling)${NC}"
    echo -e "  ${GOLD}2.${NC} 开启全局 Loopback 环回魔法 ${GRAY}(Loopback)${NC}"
    echo -e "  ${GOLD}3.${NC} 批量注入 MTU 自动协商神力 ${GRAY}(Auto-MTU)${NC}"
    echo -e "  ${GOLD}4.${NC} 吸收 wg-quick 的远古卷轴 ${GRAY}(WireGuard Import)${NC}"
    echo -e "  ${GOLD}5.${NC} 注入 SOCKS5 极速内核神力 ${GRAY}(Kernel Optimize)${NC}"
    echo -e "  ${GOLD}6.${NC} Mullvad TCP 魔法组件诊断 ${GRAY}(Diagnose)${NC}"
    echo -e "  ${GOLD}7.${NC} 返回大厅喵 ${GRAY}(Back)${NC}"
    echo -e "${GRAY}-------------------------------${NC}"
    read -p "请输入进阶代号 [1-7]: " adv_choice
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
    echo -e "\n${PURPLE}${BOLD}--- ✧ 正在进入队员调教密室 ✧ ---${NC}"
    configs=("$CONFIG_DIR"/*.json)
    if [ ! -e "${configs[0]}" ]; then
        echo -e "${RED}喵？一个人都没有，没法调教喵。${NC}"
        return
    fi

    echo -e "${CYAN}请选择要调教的队员编号：${NC}"
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

    # 提取现有值并赋予初始灵力
    curr_mode=$(jq -r '.mode' "$selected_cfg")
    curr_proto=$(jq -r '.ip_protocol // 141' "$selected_cfg")
    curr_lport=$(jq -r '.listen_port // 51820' "$selected_cfg")
    curr_addr=$(jq -r '.local_address' "$selected_cfg")
    curr_psk=$(jq -r '.psk' "$selected_cfg")
    curr_aroute=$(jq -r '.auto_route // false' "$selected_cfg")
    curr_ka=$(jq -r '.persistent_keepalive // "null"' "$selected_cfg")
    curr_mtu=$(jq -r '.mtu // "null"' "$selected_cfg")
    curr_mss=$(jq -r '.clamp_mss // true' "$selected_cfg")
    curr_ep=$(jq -r '.peers[0].endpoint // empty' "$selected_cfg")
    curr_s5=$(jq -r '.socks5_port // "null"' "$selected_cfg")
    curr_s5_local=$(jq -r '.socks5_listen_local // true' "$selected_cfg")
    curr_s5_loop=$(jq -r '.socks5_listen_loopback // false' "$selected_cfg")
    curr_mesh=$(jq -r '.mesh_mode // false' "$selected_cfg")
    curr_tmode=$(jq -r '.transport_mode // "tun"' "$selected_cfg")
    curr_sig_port=$(jq -r '.signal_port // "null"' "$selected_cfg")
    curr_dual=$(jq -r '.dual_stack // false' "$selected_cfg")
    curr_rip=$(jq -r '.raw_ip_protocol // "null"' "$selected_cfg")

    # 准备魔法变量
    mode="$curr_mode"
    proto="$curr_proto"
    listen_port="$curr_lport"
    local_addr="$curr_addr"
    endpoint="$curr_ep"
    keepalive="$curr_ka"
    mtu="$curr_mtu"
    clamp_mss="$curr_mss"
    psk="$curr_psk"
    auto_route="$curr_aroute"
    socks5_port="$curr_s5"
    s5_local="$curr_s5_local"
    s5_loop="$curr_s5_loop"
    transport_mode="$curr_tmode"
    mesh_mode="$curr_mesh"
    local_signal_port="$curr_sig_port"
    dual_stack="$curr_dual"
    raw_ip_protocol="$curr_rip"

    # 智能角色识别喵
    global_json="$CONFIG_DIR/global.json"
    global_sig_port=$( [ -f "$global_json" ] && jq -r '.signal_port // empty' "$global_json" || echo "" )
    
    if [ -n "$endpoint" ] && [ -n "$global_sig_port" ]; then
        role_label="中转/Mesh 节点 (Relay)"
    elif [ -n "$endpoint" ]; then
        role_label="纯客户端 (Client Only)"
    else
        role_label="纯服务端 (Server Only)"
    fi
    echo -e "${CYAN}当前节点角色识别为: ${PINK}$role_label${NC}"

    if [ -n "$endpoint" ] && [ -z "$global_sig_port" ]; then
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
    echo -e "\n${GOLD}✧ 传输魔法变身 (Transport Mode)${NC}"
    read -p "当前模式: $mode, [1] ip (RawIP), [2] udp, [3] Mullvad TCP, 直接回车保持不变: " m_choice
    case "$m_choice" in
        1) mode="ip" ;;
        2) mode="udp" ;;
        3) mode="mullvad-tcp" 
           echo -e "${PINK}... 已开启 Mullvad TCP 护盾魔法喵！${NC}" ;;
        *) mode="$curr_mode" ;;
    esac

        if [ "$mode" == "ip" ]; then
        read -p "IP 协议号 (当前: $curr_proto, 直接回车保持不变): " proto
        [ -z "$proto" ] && proto=$curr_proto
        listen_port="null"
        
        # 读取当前双栈状态喵
        read -p "是否同时监听 UDP 协议? (当前: $dual_stack, [y/n], 直接回车保持不变): " dual_c
        case "$dual_c" in
            y) 
                dual_stack="true"
                raw_ip_protocol="$proto"
                ;;
            n)
                dual_stack="false"
                raw_ip_protocol="null"
                ;;
            *)
                dual_stack="$curr_dual"
                if [ "$dual_stack" == "true" ]; then raw_ip_protocol="$proto"; else raw_ip_protocol="null"; fi
                ;;
        esac
    elif [ "$mode" == "tcp" ] || [ "$mode" == "mullvad-tcp" ]; then
        proto="null"
        read -p "TCP 监听端口 (当前: $curr_lport, 直接回车保持不变): " listen_port
        [ -z "$listen_port" ] && listen_port=$curr_lport
    else
        read -p "WireGuard 监听端口 (当前: $curr_lport, 直接回车保持不变): " listen_port
        [ -z "$listen_port" ] && listen_port=$curr_lport
        
        # 即使是 UDP 模式，也允许开启辅助 RawIP 协议以支持混合 Peer 喵！
        read -p "是否同时开启辅助 RawIP 监听? (当前: $dual_stack, [y/n], 默认 n): " dual_c
        case "$dual_c" in
            y) 
                dual_stack="true"
                read -p "请输入辅助 RawIP 协议号 (默认 141): " proto_choice
                [ -z "$proto_choice" ] && raw_ip_protocol=141 || raw_ip_protocol="$proto_choice"
                proto="null" # 主监听还是 UDP
                ;;
            *)
                dual_stack="$dual_stack"
                raw_ip_protocol="$raw_ip_protocol"
                proto="null"
                ;;
        esac
    fi

    echo -e "\n${GOLD}✧ 本地隧道 IP (Interface Address)${NC}"
    read -p "当前: $local_addr, 直接回车保持不变: " l_addr
    [ -z "$l_addr" ] && local_addr="$local_addr" || local_addr="$l_addr"

    echo -e "\n${GOLD}✧ 对端信号站 (Endpoint)${NC}"
    if [ "$mode" == "ip" ]; then
        read -p "对端公网 IP (当前: $endpoint, 直接回车保持不变): " ep
    else
        echo -e "${GRAY}魔法贴士：端点通常应为 IP:信令端口 (如 1.2.3.4:12580) 喵！${NC}"
        read -p "Endpoint (当前: $endpoint, 直接回车保持不变): " ep
    fi
    [ -z "$ep" ] && endpoint="$endpoint" || endpoint="$ep"

    echo -e "\n${GOLD}✧ 生命体征与颗粒度 (Keepalive & MTU)${NC}"
    read -p "Keepalive 间隔 (当前: $keepalive, 直接回车保持不变): " ka
    [ -z "$ka" ] && keepalive="$keepalive" || keepalive="$ka"

    read -p "MTU 大小 (当前: $mtu, 直接回车保持不变): " m
    [ -z "$m" ] && mtu="$mtu" || mtu="$m"

    read -p "开启 MSS 自动修复? (当前: $clamp_mss, [y/n], 直接回车保持不变): " mss_c
    case "$mss_c" in
        y) clamp_mss="true" ;;
        n) clamp_mss="false" ;;
        *) clamp_mss="$clamp_mss" ;;
    esac

    echo -e "\n${GOLD}✧ 契约与路由 (PSK & Route)${NC}"
    read -p "预共享密钥 PSK (当前: $psk, 直接回车保持不变): " p_sk
    [ -z "$p_sk" ] && psk="$psk" || psk="$p_sk"

    read -p "自动注入系统路由? (当前: $auto_route, [y/n], 直接回车保持不变): " ar_c
    case "$ar_c" in
        y) auto_route="true" ;;
        n) auto_route="false" ;;
        *) auto_route="$auto_route" ;;
    esac

    echo -e "\n${GOLD}✧ SOCKS5 代理神力 (Optional Proxy)${NC}"
    read -p "代理端口 (当前: $socks5_port, 输入端口开启如 1080, 输入 n 关闭, 直接回车保持不变): " s5_c
    case "$s5_c" in
        n) socks5_port="null" ;;
        "") socks5_port="$socks5_port" ;;
        *) socks5_port="$s5_c" ;;
    esac

    if [ "$socks5_port" != "null" ]; then
        read -p "是否在 127.0.0.1 监听 SOCKS5? (当前: $s5_local, [y/n], 默认 y): " s5_l_c
        case "$s5_l_c" in
            y) s5_local="true" ;;
            n) s5_local="false" ;;
            *) s5_local="$s5_local" ;;
        esac

        read -p "是否在全局 Loopback 接口监听 SOCKS5? (当前: $s5_loop, [y/n], 默认 n): " s5_loop_c
        case "$s5_loop_c" in
            y) s5_loop="true" ;;
            n) s5_loop="false" ;;
            *) s5_loop="$s5_loop" ;;
        esac
    else
        s5_local="true"
        s5_loop="false"
    fi

    echo -e "\n${GOLD}✧ 物理形态与网格协议 (TAP & Mesh)${NC}"
    read -p "开启二层透明桥接 (TAP) 模式? (当前: $transport_mode, [y/n], 直接回车保持不变): " tap_c
    case "$tap_c" in
        y) transport_mode="tap" ;;
        n) transport_mode="tun" ;;
        *) transport_mode="$transport_mode" ;;
    esac

    read -p "开启 P2P Mesh 全网状模式? (当前: $mesh_mode, [y/n], 直接回车保持不变): " mesh_c
    case "$mesh_c" in
        y) mesh_mode="true" ;;
        n) mesh_mode="false" ;;
        *) mesh_mode="$mesh_mode" ;;
    esac

    echo -e "\n${GOLD}✧ 信令枢纽调谐 (Signaling Port)${NC}"
    read -p "是否修改信令监听端口? (当前接口: $local_signal_port, 全局: $global_sig_port, [y/n], 默认 n): " change_sig
    if [ "$change_sig" == "y" ]; then
        echo -e "  ${GOLD}1.${NC} 修改角色全局端口 ${GRAY}(影响所有队员)${NC}"
        echo -e "  ${GOLD}2.${NC} 修改该队员专属端口 ${GRAY}(仅限当前接口)${NC}"
        read -p "请选择调教方式 [1-2]: " sig_choice
        if [ "$sig_choice" == "1" ]; then
            set_global_signal_port
        elif [ "$sig_choice" == "2" ]; then
           read -p "请输入专属信令端口 (输入 null 清除): " lsig
           if [ -n "$lsig" ]; then
               local_signal_port="$lsig"
           fi
        fi
    fi

    # 对端管理
    curr_peers=$(jq -c '.peers // []' "$selected_cfg")
    echo -e "\n${PURPLE}${BOLD}--- ✧ 招募与编排队员对端 (Peers) ✧ ---${NC}"
    read -p "是否需要打理对端队员列表? (y/n, 默认 n): " manage_p_choice
    if [ "$manage_p_choice" == "y" ]; then
        peers_json=$(add_peers_interactively "$curr_peers")
    else
        peers_json="$curr_peers"
    fi

    # 使用 jq 构建新 JSON 并覆盖
    tmp_cfg=$(mktemp)
    jq -n \
        --arg iface "$iface" --arg mode "$mode" --argjson proto "$proto" \
        --argjson listen_port "$listen_port" --argjson auto_route "$auto_route" \
        --argjson keepalive "$keepalive" --argjson mtu "$mtu" --argjson clamp_mss "$clamp_mss" \
        --arg addr "$local_addr" --arg psk "$psk" --argjson socks5_port "$socks5_port" \
        --argjson s5l "$s5_local" --argjson s5loop "$s5_loop" \
        --argjson sig_port "$local_signal_port" \
        --argjson mm "$mesh_mode" --arg tm "$transport_mode" \
        --argjson ds "$dual_stack" --argjson rip "$raw_ip_protocol" \
        --argjson peers "$peers_json" \
        '{
            interface: $iface, mode: $mode, ip_protocol: $proto, listen_port: $listen_port,
            auto_route: $auto_route, persistent_keepalive: $keepalive, mtu: $mtu,
            clamp_mss: $clamp_mss, local_address: $addr, psk: $psk,
            socks5_port: $socks5_port, socks5_listen_local: $s5l, socks5_listen_loopback: $s5loop,
            signal_port: $sig_port, mesh_mode: $mm, transport_mode: $tm,
            dual_stack: $ds, raw_ip_protocol: $rip, peers: $peers
        }' > "$tmp_cfg"
    
    mv "$tmp_cfg" "$selected_cfg"
    echo -e "${PINK}配置更新成功喵！${NC}"
    read -p "是否立即重载服务以应用新配置？(y/n, 默认 n): " reload_now
    if [ "$reload_now" == "y" ]; then
        nekolink-ctl reload
        echo -e "${PINK}配置已重载喵！${NC}"
    fi
}

function print_peers() {
    local peer_json="$1"
    echo -e "${CYAN}当前已配置对端清单：${NC}" >&2
    echo "$peer_json" | jq -r 'if . == null then empty else to_entries | .[] | "\(.key + 1). [\(.value.mode // "默认")] \(.value.endpoint) (信令端口: \(.value.signal_port // "默认"))" end' >&2
}

function add_peers_interactively() {
    local existing_peers="${1:-[]}"
    local peers="$existing_peers"
    [ "$peers" == "null" ] && peers="[]"
    
    while true; do
        echo -e "\n${PURPLE}${BOLD}--- ✧ 编队管理中心 (Peer Management) ✧ ---${NC}" >&2
        if [ "$peers" == "[]" ] || [ -z "$peers" ]; then
            echo -e "${GRAY}( 目前阵型里还没有其他小伙伴喵 )${NC}" >&2
        else
            print_peers "$peers"
        fi
        
        echo -e "\n${CYAN}选择招募或整编指令：${NC}" >&2
        echo -e "  ${GOLD}1.${NC} 招待新伙伴入队 ${GRAY}(Add)${NC}" >&2
        echo -e "  ${GOLD}2.${NC} 劝退某个伙伴 ${GRAY}(Delete)${NC}" >&2
        echo -e "  ${GOLD}3.${NC} 保存阵型并返回调教密室 ${GRAY}(Save & Exit)${NC}" >&2
        read -p "请指令代号 [1-3]: " peer_op
        
        case "$peer_op" in
            1)
                echo -e "\n${GOLD}✧ [伙伴情报录入]${NC}" >&2
                read -p "请输入伙伴的公网 IP/域名: " p_ip
                if [ -z "$p_ip" ]; then echo -e "${RED}伙伴的名字不能为空喵！${NC}" >&2; continue; fi
                
                read -p "请输入伙伴的信令端口 (默认 12580): " p_sig_port
                [ -z "$p_sig_port" ] && p_sig_port=12580
                
                echo -e "${CYAN}请选择与该伙伴通讯的魔法属性：${NC}" >&2
                echo -e "  ${GOLD}1.${NC} 跟随全局魔法 ${GRAY}(Use Global Default)${NC}" >&2
                echo -e "  ${GOLD}2.${NC} 强制使用 UDP 术式" >&2
                echo -e "  ${GOLD}3.${NC} 强制使用 RawIP 秘术 (ip)" >&2
                echo -e "  ${GOLD}4.${NC} 强制使用 TCP 护盾 (mullvad-tcp)" >&2
                read -p "请选择属性 [1-4]: " p_mode_choice
                p_mode="null"
                case "$p_mode_choice" in
                    2) p_mode="udp" ;;
                    3) p_mode="ip" ;;
                    4) p_mode="mullvad-tcp" ;;
                esac
                
                new_peer=$(jq -n --arg ep "$p_ip:$p_sig_port" --arg mode "$p_mode" --argjson sport "$p_sig_port" \
                    '{endpoint: $ep, signal_port: $sport, mode: (if $mode == "null" then null else $mode end)}')
                
                peers=$(echo "$peers" | jq ". += [$new_peer]")
                echo -e "${PINK}新伙伴已成功捕获并登记在案！喵呜～${NC}" >&2
                ;;
            2)
                if [ "$peers" == "[]" ]; then echo -e "${RED}没有队员可以驱逐喵！${NC}" >&2; continue; fi
                read -p "请输入要劝退的队员编号: " p_idx
                peers=$(echo "$peers" | jq "del(.[$((p_idx-1))])")
                echo -e "${PINK}呼... 已成功送别对端 $p_idx 队员喵！(〃'▽'〃)${NC}" >&2
                ;;
            3)
                break
                ;;
            *)
                echo "不正确的指令喵！" >&2
                ;;
        esac
    done
    echo "$peers"
}

function create_config() {
    echo -e "\n${PURPLE}${BOLD}--- ✧ 开启一段新的隧道冒险 ✧ ---${NC}"
    echo -e "${CYAN}我们要召唤哪一位新的战斗队员呢喵？${NC}"
    
    read -p "请输入魔法接口名称 ( 默认 nekotun0 ): " iface
    [ -z "$iface" ] && iface="nekotun0"

    echo -e "\n${GOLD}✧ [第1步] 选择物理形态 (Transport Layer)${NC}"
    echo -e "${GRAY}注：TAP 模式像镜子一样透明，适合构建复杂的局域网网格喵！${NC}"
    echo "  1. 三层模式 (TUN, 标准 IP 隧道, 适合大多数场景)"
    echo "  2. 二层模式 (TAP, 透明桥接模式, 适合二层组网/Mesh)"
    read -p "请选择形态数字 [1-2]: " tmode_choice
    [ "$tmode_choice" == "2" ] && transport_mode="tap" || transport_mode="tun"

    echo -e "\n${GOLD}✧ [第2步] 定义战场角色 (Node Role)${NC}"
    echo "  1. 守护者 (Server, 拥有公网身份，静候连接)"
    echo "  2. 侦察兵 (Client, 主动出击，连接上游)"
    echo "  3. 圣骑士 (Relay/Mesh, 承上启下，构建全网状网格)"
    read -p "请选择角色数字 [1-3]: " role_choice

    peers_json="[]"
    case "$role_choice" in
        1)
            role="server"
            echo -e "${PINK}★ 守护者贴士：作为服务端，请确保防火墙已对信令端口(默认12580)敞开怀抱喵！${NC}"
            ;;
        2|3)
            [ "$role_choice" == "3" ] && role="relay" || role="client"
            echo -e "${PINK}--- 配置上游对端 (Peers) ---${NC}"
            peers_json=$(add_peers_interactively "[]")
            if [ "$role" == "relay" ]; then
                echo -e "${PINK}现在请配置本地监听端口，以便下游节点连接喵！${NC}"
                set_global_signal_port
            fi
            ;;
    esac

    echo -e "\n${GOLD}✧ [第3步] 选择数据传输魔法 (Transport Mode)${NC}"
    echo -e "${GRAY}注：IP 模式最隐蔽，UDP 最通用，TCP 最稳定喵！${NC}"
    echo "  1. ✨ 纯净 IP 协议 (Raw IP, 100% 模拟物理握手)"
    echo "  2. 🌀 标准 UDP 模式 (WireGuard 原生动力)"
    echo "  3. 🛡️ Mullvad TCP 重甲 (无惧严苛阻断)"
    read -p "请选择魔法类型 [1-3]: " mode_choice
    case "$mode_choice" in
        1)
            mode="ip"
            read -p "请输入 IP 协议号 [1-255] ( 默认 141 ): " proto
            [ -z "$proto" ] && proto=141
            listen_port="null"
            
            echo -e "${GRAY}魔法贴士：开启双栈监听可以让您同时接纳 UDP 队友喵！${NC}"
            read -p "是否同时开启 UDP 双栈监听? [y/n] (默认 y): " dual_c
            [ -z "$dual_c" ] && dual_c="y"
            if [ "$dual_c" == "y" ]; then
                dual_stack="true"
                raw_ip_protocol="$proto"
            else
                dual_stack="false"
                raw_ip_protocol="null"
            fi
            ;;
        3)
            mode="mullvad-tcp"
            proto="null"
            dual_stack="false"
            raw_ip_protocol="null"
            read -p "请输入 TCP 护盾监听端口 ( 默认 12581 ): " listen_port
            [ -z "$listen_port" ] && listen_port=12581
            ;;
        *)
            mode="udp"
            proto="null"
            echo -e "${GRAY}魔法贴士：设为 0 可以让系统在握手时自动分配最合适的监听位置喵。${NC}"
            read -p "请输入 UDP 监听端口 ( 0 为自动, 默认 0 ): " listen_port
            [ -z "$listen_port" ] && listen_port=0
            
            echo -e "${GRAY}魔法贴士：开启辅助 RawIP 监听可以同时接纳 IP 协议的队友喵！${NC}"
            read -p "是否同时开启辅助 RawIP 监听? [y/n] (默认 n): " dual_c
            if [ "$dual_c" == "y" ]; then
                dual_stack="true"
                read -p "请输入辅助 RawIP 协议号 (默认 141): " proto_choice
                [ -z "$proto_choice" ] && raw_ip_protocol=141 || raw_ip_protocol="$proto_choice"
            else
                dual_stack="false"
                raw_ip_protocol="null"
            fi
            ;;
    esac

    [ "$role" == "relay" ] && def_mesh="y" || def_mesh="n"
    echo -e "\n${GOLD}✧ [第4步] 魔法网格协同 (Mesh Mode)${NC}"
    echo -e "${GRAY}注：开启 Mesh 后，队员们会自动寻找并连接彼此喵！${NC}"
    read -p "是否开启 P2P Mesh 全网状模式? (y/n, 默认 $def_mesh): " mesh_choice
    [ -z "$mesh_choice" ] && mesh_choice="$def_mesh"
    [ "$mesh_choice" == "y" ] && mesh_mode="true" || mesh_mode="false"

    echo -e "\n${GOLD}✧ [第5步] 灵魂地址与呼吸 (IP & Keepalive)${NC}"
    read -p "请输入隧道接口 IP 地址 ( 示例 10.0.0.1/24 ): " local_addr
    [ -z "$local_addr" ] && local_addr="10.0.0.1/24"

    read -p "Keepalive 呼吸间隔 (秒, 默认 25): " keepalive
    [ -z "$keepalive" ] && keepalive=25

    echo -e "\n${GOLD}✧ [第6步] 传输颗粒度调校 (MTU & MSS)${NC}"
    mtu=0
    read -p "MTU 配置：(1. 固定 1420, 2. 手动, 3. 自动同步, 默认 3): " mtu_m
    case "$mtu_m" in
        1) mtu=1420 ;;
        2) read -p "请输入具体数值: " mtu ;;
        *) mtu=0 ;;
    esac

    read -p "是否开启 MSS 自动修复? (y/n, 默认 y): " mss_c
    [ "$mss_c" == "n" ] && clamp_mss="false" || clamp_mss="true"

    echo -e "\n${GOLD}✧ [第7步] 契约符号与信令端口 (PSK & Signaling)${NC}"
    read -p "预共享密钥 (PSK, 建议设个复杂的暗号): " psk
    [ -z "$psk" ] && psk="NekoMagic_Default_PSK"

    read -p "是否为该接口配置专属信令监听端口? (留空则使用全局或随机): " lsig_port
    [ -z "$lsig_port" ] && local_signal_port="null" || local_signal_port="$lsig_port"

    echo -e "\n${GOLD}✧ [第8步] SOCKS5 代理神力 (Optional Proxy)${NC}"
    read -p "是否在本端开启 SOCKS5 代理? (输入端口号如 1080, 留空跳过): " s5_port
    if [ -z "$s5_port" ]; then
        socks5_port="null"; s5_local="true"; s5_loop="false"
    else
        socks5_port="$s5_port"
        read -p "是否仅限 127.0.0.1 访问? (y/n, 默认 y): " s5_l_c
        [ "$s5_l_c" == "n" ] && s5_local="false" || s5_local="true"
        read -p "是否允许通过 Loopback 魔法共享? (y/n, 默认 n): " s5_loop_c
        [ "$s5_loop_c" == "y" ] && s5_loop="true" || s5_loop="false"
    fi

    # 构建 JSON
    json_path="$CONFIG_DIR/$iface.json"
    jq -n \
        --arg iface "$iface" --arg mode "$mode" --argjson proto "$proto" \
        --argjson lp "$listen_port" --argjson mtu "$mtu" --argjson cm "$clamp_mss" \
        --arg la "$local_addr" --arg psk "$psk" --argjson s5p "$socks5_port" \
        --argjson s5l "$s5_local" --argjson s5loop "$s5_loop" --argjson sp "$local_signal_port" \
        --argjson mm "$mesh_mode" --arg tm "$transport_mode" \
        --argjson ds "$dual_stack" --argjson rip "$raw_ip_protocol" \
        --argjson keepalive "$keepalive" --argjson peers "$peers_json" \
        '{
            interface: $iface, mode: $mode, ip_protocol: $proto, listen_port: $lp,
            mtu: $mtu, clamp_mss: $cm, local_address: $la, psk: $psk,
            socks5_port: $s5p, socks5_listen_local: $s5l, socks5_listen_loopback: $s5loop,
            signal_port: $sp, mesh_mode: $mm, transport_mode: $tm,
            dual_stack: $ds, raw_ip_protocol: $rip, persistent_keepalive: $keepalive,
            peers: $peers
        }' > "$json_path"

    echo -e "${PINK}配置创建成功： $json_path 喵！${NC}"
}

function manage_keys() {
    echo -e "\n${PURPLE}${BOLD}--- ✧ NekoLink 密钥管理密室 ✧ ---${NC}"
    read -p "请输入要打理的队员接口名称 ( 默认 nekotun0 ): " iface
    [ -z "$iface" ] && iface="nekotun0"
    
    key_file="$CONFIG_DIR/$iface.key"
    pub_file="$CONFIG_DIR/$iface.pub"

    echo -e "${CYAN}请选择处理密钥的方式：${NC}"
    echo -e "  ${GOLD}1.${NC} 偷看当前队员的秘密 ${GRAY}(Show Keys)${NC}"
    echo -e "  ${GOLD}2.${NC} 替换/重置密钥魔法 ${GRAY}(Reset Keys)${NC}"
    echo -e "  ${GOLD}3.${NC} 悄悄离开喵 ${GRAY}(Back)${NC}"
    read -p "请选择魔法代号 [1-3]: " km_choice

    case $km_choice in
        1)
            if [ -f "$key_file" ]; then
                echo -e "${PINK}🗝️ 队员私钥: ${BOLD}$(cat $key_file)${NC}"
                echo -e "${PINK}📜 队员公钥: ${BOLD}$(cat $pub_file 2>/dev/null || echo '尚未生成')${NC}"
            else
                echo -e "${RED}喵呜... 没找到这个队员的秘密文件喵。${NC}"
            fi
            ;;
        2)
            echo -e "${RED}${BOLD}⚠ 严重警告：${NC}${RED}更换密钥会导致魔法链路断开，且需要重新与所有小伙伴交换公钥喵！${NC}"
            read -p "主人真的确定要重塑密钥吗？(y/n): " confirm
            if [ "$confirm" == "y" ]; then
                rm -f "$key_file" "$pub_file"
                echo -e "${PINK}旧密钥已彻底驱散！正在重新注入新魔法...${NC}"
                systemctl restart nekolink || echo -e "${CYAN}请主人待会儿手动唤醒 nekolink-ctl 喵！${NC}"
                echo -e "${PINK}新密钥将在下一次觉醒时自动萌发喵！${NC}"
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

function rename_config() {
    echo -e "\n${PINK}--- 正在启动接口重命名魔法 ---${NC}"
    configs=("$CONFIG_DIR"/*.json)
    if [ ! -e "${configs[0]}" ]; then
        echo -e "${RED}喵？没有找到任何配置文件。${NC}"
        return
    fi

    echo -e "${CYAN}请选择要重命名的配置：${NC}"
    for i in "${!configs[@]}"; do
        ifname=$(basename "${configs[$i]}" .json)
        if [ "$ifname" == "global" ]; then continue; fi
        echo "$((i+1)). $ifname"
    done
    read -p "请输入编号: " cfg_idx
    
    selected_cfg="${configs[$((cfg_idx-1))]}"
    if [ -z "$selected_cfg" ] || [ ! -f "$selected_cfg" ]; then
        echo -e "${RED}无效的选择喵！${NC}"
        return
    fi

    old_iface=$(basename "$selected_cfg" .json)
    echo -e "${CYAN}当前接口名称: ${PINK}$old_iface${NC}"
    read -p "请输入新的接口名称: " new_iface
    
    if [ -z "$new_iface" ]; then
        echo -e "${RED}名称不能为空喵！${NC}"
        return
    fi
    
    if [ -f "$CONFIG_DIR/$new_iface.json" ]; then
        echo -e "${RED}警告：名称 $new_iface 已存在喵！${NC}"
        return
    fi

    echo -e "${PINK}正在施展重命名咒语...${NC}"
    
    # 1. 更新 JSON 内部字段
    tmp_cfg=$(mktemp)
    jq --arg new_name "$new_iface" '.interface = $new_name' "$selected_cfg" > "$tmp_cfg"
    mv "$tmp_cfg" "$CONFIG_DIR/$new_iface.json"
    rm -f "$selected_cfg"

    # 2. 重命名配套的密钥文件
    [ -f "$CONFIG_DIR/$old_iface.key" ] && mv "$CONFIG_DIR/$old_iface.key" "$CONFIG_DIR/$new_iface.key"
    [ -f "$CONFIG_DIR/$old_iface.pub" ] && mv "$CONFIG_DIR/$old_iface.pub" "$CONFIG_DIR/$new_iface.pub"

    echo -e "${PINK}重命名成功！$old_iface -> $new_iface 喵！${NC}"
    read -p "是否立即重载服务？(y/n, 默认 n): " reload_now
    if [ "$reload_now" == "y" ]; then
        nekolink-ctl reload
        echo -e "${PINK}已发送重载指令喵！${NC}"
    fi
}

function delete_config() {
    echo -e "\n${PINK}--- 正在进入接口驱逐仪式 (删除) ---${NC}"
    configs=("$CONFIG_DIR"/*.json)
    if [ ! -e "${configs[0]}" ]; then
        echo -e "${RED}喵？目录里已经是空的了喵。${NC}"
        return
    fi

    echo -e "${CYAN}请选择要删除的配置：${NC}"
    for i in "${!configs[@]}"; do
        ifname=$(basename "${configs[$i]}" .json)
        if [ "$ifname" == "global" ]; then continue; fi
        echo "$((i+1)). $ifname"
    done
    read -p "请输入编号: " cfg_idx
    
    selected_cfg="${configs[$((cfg_idx-1))]}"
    if [ -z "$selected_cfg" ] || [ ! -f "$selected_cfg" ]; then
        echo -e "${RED}无效的选择喵！${NC}"
        return
    fi

    iface=$(basename "$selected_cfg" .json)
    echo -e "${RED}⚠ 警告：您即将删除接口 $iface 及其所有关联密钥！此操作不可逆喵！${NC}"
    read -p "确定要继续吗？请输入 '$iface' 以确认: " confirm
    
    if [ "$confirm" != "$iface" ]; then
        echo -e "${PINK}呼... 驱逐仪式已取消。${NC}"
        return
    fi

    echo -e "${PINK}正在抹除 $iface 的存在...${NC}"
    rm -f "$selected_cfg"
    rm -f "$CONFIG_DIR/$iface.key"
    rm -f "$CONFIG_DIR/$iface.pub"

    echo -e "${PINK}接口 $iface 已被成功驱逐喵！(〃'▽'〃)${NC}"
    read -p "是否立即重载服务以彻底清除状态？(y/n, 默认 n): " reload_now
    if [ "$reload_now" == "y" ]; then
        nekolink-ctl reload
        echo -e "${PINK}由于删除了配置，服务已重载喵！${NC}"
    fi
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


function show_live_dashboard() {
    while true; do
        clear
        print_banner
        echo -e "${PURPLE}${BOLD}--- ✧ 实时魔法监控看板 ✧ ---${NC}"
        echo -e "${GRAY}(采集频率: 2s, 按 'q' 键返回大厅)${NC}\n"
        
        # 核心状态
        echo -e "${GOLD}[ 核心状态 ]${NC}"
        if systemctl is-active --quiet nekolink; then
            echo -e "  服务状态: ${GREEN}● 活跃中 (Running)${NC}"
        else
            echo -e "  服务状态: ${RED}○ 已沉睡 (Stopped)${NC}"
        fi
        
        echo -e "\n${GOLD}[ 魔法链路 ]${NC}"
        # 获取 ctl status 并修饰喵
        nekolink-ctl status 2>/dev/null | head -n 30 | sed 's/^/  /' || echo -e "  ${RED}无法获取详细状态喵...${NC}"
        
        echo -e "\n${GOLD}[ 流量统计 ]${NC}"
        if command -v ip >/dev/null; then
             # 提取 RX/TX 数据并萌化喵
             ip -s link show | grep -A 1 "neko" | grep -v "link/none" | sed 's/RX: bytes  packets  errors  dropped overrun mcast/  📥 接收 (RX):/' | sed 's/TX: bytes  packets  errors  dropped carrier collsns/  📤 发送 (TX):/' | sed 's/^/  /' || echo -e "  ${GRAY}暂无活跃隧道流量数据喵${NC}"
        else
             echo -e "  ${GRAY}缺少 ip 命令，无法统计流量喵${NC}"
        fi

        echo -e "\n${PINK}★ 请主人放心，一切都在猫娘的掌控之中喵！(〃'▽'〃)${NC}"
        
        # 等待输入并刷新
        if read -t 2 -n 1 key && [[ $key == "q" ]]; then
            break
        fi
    done
}


while true; do
    show_menu
    case $choice in
        1) create_config ;;
        2) edit_config ;;
        3) rename_config ;;
        4) delete_config ;;
        5)
            echo -e "${PINK}正在通过 SIGHUP 施展热重载魔法...${NC}"
            nekolink-ctl reload
            echo -e "${PINK}热重载指令已发送喵！可以使用选项 7 查看最新状态。${NC}"
            ;;
        6) 
            echo -e "${PINK}正在通过 Systemd 重启 NekoLink 魔法...${NC}"
            systemctl restart nekolink
            echo -e "${PINK}重启指令已发送喵！可以使用选项 7 查看最新状态。${NC}"
            ;;
        7) show_live_dashboard ;;
        8) manage_keys ;;
        9) check_and_fix_configs ;;
        10) ls -lh "$CONFIG_DIR"/*.json ;;
        11)
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
        12)
            echo -e "${PINK}下次再见喵！保持次元壁稳固喵！(〃'▽'〃)${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}喵？无效的选择。请仔细检阅魔法清单喵。${NC}"
            ;;
    esac
done
