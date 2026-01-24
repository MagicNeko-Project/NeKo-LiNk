#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// --- 配置结构体 (仅用于 Fake-TCP) ---

struct shadow_config {
    __u32 mode;       // 1=Raw-IP (废弃), 2=Fake-TCP
    __u32 proto_num;  // 协议号 (Fake-TCP 模式下未使用)
    __u16 local_port; // 本地监听端口 (大端序)
    __u16 reserved;
};

// --- Maps (映射表) ---

// 1. Raw 模式入站/出站白名单: 协议号 -> 占位符
// Key: IP 协议号 (__u8)
// Value: 0 (占位)
// 只有在这些 Map 中的协议号，才会被认为是 "Neko 管理的 Raw 流量" (虽然目前不转换，但保留机制)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u8));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, 16);
} raw_allow_map SEC(".maps");

// 2. Fake-TCP 模式主要配置映射
// Key: 端口 (__u16, Big Endian) - TCP 目的端口或 UDP 源端口
// Value: 配置结构体
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u16));
    __uint(value_size, sizeof(struct shadow_config));
    __uint(max_entries, 128);
} port_shadow_map SEC(".maps");

// --- 辅助函数 ---

static __always_inline void full_ip_recompute(struct iphdr *ip) {
    __u32 csum = 0;
    __u16 *p = (__u16 *)ip;
    ip->check = 0;
    
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        csum += p[i];
    }
    
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = ~(__u16)csum;
}

static __always_inline int safe_move_ipv4_back(void *data_end, void *base, int dist) {
    if ((void *)base + 20 > data_end) return -1;
    unsigned char *src = (unsigned char *)base + dist;
    unsigned char *dst = (unsigned char *)base;
    if ((void *)src + 20 > data_end) return -1;
    
    #pragma unroll
    for (int i = 0; i < 20; i++) {
        dst[i] = src[i];
    }
    return 0;
}

static __always_inline int safe_move_ipv4_forward(void *data_end, void *base, int dist) {
    unsigned char *src = (unsigned char *)base;
    unsigned char *dst = (unsigned char *)base + dist;

    if ((void *)dst + 20 > data_end) return -1;
    if ((void *)src + 20 > data_end) return -1;

    #pragma unroll
    for (int i = 19; i >= 0; i--) {
        dst[i] = src[i];
    }
    return 0;
}

// --- 入站处理 (Ingress) ---

SEC("tc/ingress")
int tc_shadow_ingress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)eth + sizeof(*eth) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (struct iphdr *)((void *)eth + sizeof(*eth));
    if ((void *)ip + sizeof(*ip) > data_end) return TC_ACT_OK;

    // --- 1. 检查 Raw 模式 (基于 IP 协议号) ---
    // 逻辑变更: Legacy Raw 模式下，直接 Pass，不进行 UDP 转换。
    // 这里仅做允许检查 (如果有需要的话，可以用于统计或未来扩展)
    __u8 *allowed = bpf_map_lookup_elem(&raw_allow_map, &ip->protocol);
    if (allowed) {
        // bpf_printk("入站 Raw 允许: 协议 %d", ip->protocol);
        return TC_ACT_OK; // 直接放行给内核 ListenIP
    }

    // --- 2. 检查 Fake-TCP 模式 (基于 TCP 目的端口) ---
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((void *)ip + (ip->ihl * 4));
        if ((void *)tcp + sizeof(*tcp) > data_end) return TC_ACT_OK;

        struct shadow_config *cfg = bpf_map_lookup_elem(&port_shadow_map, &tcp->dest);
        if (cfg && cfg->mode == 2) {
            // bpf_printk("入站 Fake-TCP 转换: %d", bpf_ntohs(tcp->dest));
            
            __be16 s_p = tcp->source;
            __be16 d_p = tcp->dest;
            void *ip_ptr = (void *)eth + sizeof(*eth);
            
            if (safe_move_ipv4_forward(data_end, ip_ptr, 12) < 0) return TC_ACT_OK;
            if (bpf_skb_adjust_room(skb, -12, BPF_ADJ_ROOM_NET, 0) < 0) return TC_ACT_OK;
            
            data = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            eth = (struct ethhdr *)data;
            if ((void *)eth + sizeof(*eth) > data_end) return TC_ACT_OK;

            struct iphdr *new_ip = (struct iphdr *)((void *)eth + sizeof(*eth));
            if ((void *)new_ip + sizeof(*new_ip) > data_end) return TC_ACT_OK;
            
            struct udphdr *udp = (struct udphdr *)((void *)new_ip + 20);
            if ((void *)udp + sizeof(*udp) > data_end) return TC_ACT_OK;

            udp->source = s_p;
            udp->dest = d_p;
            udp->len = bpf_htons(bpf_ntohs(new_ip->tot_len) - 12 - 20);
            udp->check = 0;

            new_ip->protocol = IPPROTO_UDP;
            new_ip->tot_len = bpf_htons(bpf_ntohs(new_ip->tot_len) - 12);
            full_ip_recompute(new_ip);
        }
    }

    return TC_ACT_OK;
}

// --- 出站处理 (Egress) ---

SEC("tc/egress")
int tc_shadow_egress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)eth + sizeof(*eth) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (struct iphdr *)((void *)eth + sizeof(*eth));
    if ((void *)ip + sizeof(*ip) > data_end) return TC_ACT_OK;

    // --- 1. 检查 Raw 模式 ---
    // 如果是 Raw 模式，协议号本身就是 target，不需要转换。
    // bpf_map_lookup_elem(&raw_allow_map, &ip->protocol); 
    // Pass implicitly.

    // --- 2. 检查 Fake-TCP 模式 (基于 UDP 源端口) ---
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)((void *)ip + (ip->ihl * 4));
        if ((void *)udp + sizeof(*udp) > data_end) return TC_ACT_OK;

        struct shadow_config *cfg = bpf_map_lookup_elem(&port_shadow_map, &udp->source);
        if (cfg && cfg->mode == 2) {
            // bpf_printk("出站 Fake-TCP 转换: %d", bpf_ntohs(udp->source));
            
            __be16 s_p = udp->source;
            __be16 d_p = udp->dest;
            __u32 jitter = skb->tstamp; 

            if (bpf_skb_adjust_room(skb, 12, BPF_ADJ_ROOM_NET, 0) < 0) return TC_ACT_OK;
            data = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            eth = (struct ethhdr *)data;
            if ((void *)eth + sizeof(*eth) > data_end) return TC_ACT_OK;
            
            void *gap_ptr = (void *)eth + sizeof(*eth);
            if (safe_move_ipv4_back(data_end, gap_ptr, 12) < 0) return TC_ACT_OK;
            
            struct iphdr *new_ip = (struct iphdr *)gap_ptr;
            if ((void *)new_ip + sizeof(*new_ip) > data_end) return TC_ACT_OK;
            
            struct tcphdr *tcp = (struct tcphdr *)((void *)new_ip + 20);
            if ((void *)tcp + sizeof(*tcp) > data_end) return TC_ACT_OK;

            tcp->source = s_p;
            tcp->dest = d_p;
            tcp->seq = bpf_htonl(1024 + (jitter & 0xFFFF));
            tcp->ack_seq = bpf_htonl(1);
            tcp->doff = 5;
            tcp->psh = 1;
            tcp->ack = 1;
            tcp->window = bpf_htons(64512);
            tcp->check = 0;

            new_ip->protocol = IPPROTO_TCP;
            new_ip->tot_len = bpf_htons(bpf_ntohs(new_ip->tot_len) + 12);
            full_ip_recompute(new_ip);
        }
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
