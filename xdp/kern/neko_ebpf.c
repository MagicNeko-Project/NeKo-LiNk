#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// --- Configuration Struct ---

struct shadow_config {
    __u32 mode;       // 1=Raw-IP (Custom Proto), 2=Fake-TCP
    __u32 proto_num;  // Only used for Mode 1
    __u16 local_port; // Port the app is listening on (Big Endian)
    __u16 reserved;   
};

// --- Maps ---

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u16));
    __uint(value_size, sizeof(struct shadow_config));
    __uint(max_entries, 128);
} port_shadow_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u8));
    __uint(value_size, sizeof(struct shadow_config));
    __uint(max_entries, 128);
} proto_shadow_map SEC(".maps");

// --- Helper: IP Checksum ---

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

// --- Ingress: TC (Restore Context) ---

SEC("tc/ingress")
int tc_shadow_ingress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)eth + sizeof(*eth) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (struct iphdr *)((void *)eth + sizeof(*eth));
    if ((void *)ip + sizeof(*ip) > data_end) return TC_ACT_OK;

    // --- Mode 1: Restore Raw-IP (Add UDP Head) ---
    struct shadow_config *cfg = bpf_map_lookup_elem(&proto_shadow_map, &ip->protocol);
    if (cfg && cfg->mode == 1) {
        // bpf_printk("[eBPF] Ingress Mode 1: Restoration triggered (proto %d)\n", ip->protocol);

        if (bpf_skb_adjust_room(skb, 8, BPF_ADJ_ROOM_NET, 0) < 0) return TC_ACT_OK;
        
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        eth = (struct ethhdr *)data;
        ip = (struct iphdr *)((void *)eth + sizeof(*eth));
        if ((void *)ip + sizeof(*ip) > data_end) return TC_ACT_OK;

        struct udphdr *udp = (struct udphdr *)((void *)ip + (ip->ihl * 4));
        if ((void *)udp + sizeof(*udp) > data_end) return TC_ACT_OK;

        udp->dest = cfg->local_port;
        udp->source = bpf_htons(12345);
        udp->len = bpf_htons(bpf_ntohs(ip->tot_len) + 8 - (ip->ihl * 4));
        udp->check = 0;

        ip->protocol = IPPROTO_UDP;
        ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) + 8);
        full_ip_recompute(ip);
        
        return TC_ACT_OK;
    }

    // --- Mode 2: Restore Fake-TCP (TCP 20 -> UDP 8) ---
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((void *)ip + (ip->ihl * 4));
        if ((void *)tcp + sizeof(*tcp) > data_end) return TC_ACT_OK;

        cfg = bpf_map_lookup_elem(&port_shadow_map, &tcp->dest);
        if (cfg && cfg->mode == 2) {
            __be16 s_p = tcp->source;
            __be16 d_p = tcp->dest;

            if (bpf_skb_adjust_room(skb, -12, BPF_ADJ_ROOM_NET, 0) < 0) return TC_ACT_OK;
            
            data = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            ip = (struct iphdr *)((void *)data + sizeof(struct ethhdr));
            if ((void *)ip + sizeof(*ip) > data_end) return TC_ACT_OK;
            
            struct udphdr *udp = (struct udphdr *)((void *)ip + (ip->ihl * 4));
            if ((void *)udp + sizeof(*udp) > data_end) return TC_ACT_OK;

            udp->source = s_p;
            udp->dest = d_p;
            udp->len = bpf_htons(bpf_ntohs(ip->tot_len) - 12 - (ip->ihl * 4));
            udp->check = 0;

            ip->protocol = IPPROTO_UDP;
            ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) - 12);
            full_ip_recompute(ip);
        }
    }

    return TC_ACT_OK;
}

// --- Egress: TC (Apply Transformation) ---

SEC("tc/egress")
int tc_shadow_egress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)eth + sizeof(*eth) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (struct iphdr *)((void *)eth + sizeof(*eth));
    if ((void *)ip + sizeof(*ip) > data_end) return TC_ACT_OK;

    if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK;

    struct udphdr *udp = (struct udphdr *)((void *)ip + (ip->ihl * 4));
    if ((void *)udp + sizeof(*udp) > data_end) return TC_ACT_OK;

    struct shadow_config *cfg = bpf_map_lookup_elem(&port_shadow_map, &udp->source);
    if (!cfg) return TC_ACT_OK;

    // --- Mode 1: Apply Raw-IP (Delete UDP Head) ---
    if (cfg->mode == 1) {
        if (bpf_skb_adjust_room(skb, -8, BPF_ADJ_ROOM_NET, 0) < 0) return TC_ACT_OK;
        
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        ip = (struct iphdr *)((void *)data + sizeof(struct ethhdr));
        if ((void *)ip + sizeof(*ip) > data_end) return TC_ACT_OK;

        ip->protocol = (__u8)cfg->proto_num;
        ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) - 8);
        full_ip_recompute(ip);
        return TC_ACT_OK;
    }

    // --- Mode 2: Apply Fake-TCP (UDP 8 -> TCP 20) ---
    if (cfg->mode == 2) {
        __be16 s_p = udp->source;
        __be16 d_p = udp->dest;
        __u32 jitter = skb->tstamp; 

        if (bpf_skb_adjust_room(skb, 12, BPF_ADJ_ROOM_NET, 0) < 0) return TC_ACT_OK;
        
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        ip = (struct iphdr *)((void *)data + sizeof(struct ethhdr));
        if ((void *)ip + sizeof(*ip) > data_end) return TC_ACT_OK;

        struct tcphdr *tcp = (struct tcphdr *)((void *)ip + (ip->ihl * 4));
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

        ip->protocol = IPPROTO_TCP;
        ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) + 12);
        full_ip_recompute(ip);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
