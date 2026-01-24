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
    __u32 mode;       // 1=Raw-IP, 2=Fake-TCP
    __u32 proto_num;  // Protocol number for Raw-IP
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

// --- Helpers ---

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

// Moves 20 bytes: BASE...BASE+19 -> DEST...DEST+19
// Verifier needs consistent bounds checks inside loop or static access
// We use simple unroll with explicit check for simplicity and safety.
static __always_inline int safe_move_ipv4_back(void *data_end, void *base, int dist) {
    if ((void *)base + 20 > data_end) return -1;
    // dist is typically 8 or 12. 
    // Source: base + dist
    // Dest:   base
    // Verify source bounds?
    // We are copying Source -> Dest.
    unsigned char *src = (unsigned char *)base + dist;
    unsigned char *dst = (unsigned char *)base;
    
    // Bounds check for source
    if ((void *)src + 20 > data_end) return -1;
    
    #pragma unroll
    for (int i = 0; i < 20; i++) {
        dst[i] = src[i];
    }
    return 0;
}

static __always_inline int safe_move_ipv4_forward(void *data_end, void *base, int dist) {
    // Source: base
    // Dest:   base + dist
    unsigned char *src = (unsigned char *)base;
    unsigned char *dst = (unsigned char *)base + dist;

    // Bounds check
    if ((void *)dst + 20 > data_end) return -1;
    if ((void *)src + 20 > data_end) return -1;

    #pragma unroll
    for (int i = 19; i >= 0; i--) {
        dst[i] = src[i];
    }
    return 0;
}

// --- Ingress: TC ---

SEC("tc/ingress")
int tc_shadow_ingress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)eth + sizeof(*eth) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (struct iphdr *)((void *)eth + sizeof(*eth));
    if ((void *)ip + sizeof(*ip) > data_end) return TC_ACT_OK;

    // Mode 1: Proto-based (Raw-IP)
    struct shadow_config *cfg = bpf_map_lookup_elem(&proto_shadow_map, &ip->protocol);
    if (cfg && cfg->mode == 1) {
        if (bpf_skb_adjust_room(skb, 8, BPF_ADJ_ROOM_NET, 0) < 0) return TC_ACT_OK;
        
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        eth = (struct ethhdr *)data;
        if ((void *)eth + sizeof(*eth) > data_end) return TC_ACT_OK;
        
        void *gap_ptr = (void *)eth + sizeof(*eth);
        if (safe_move_ipv4_back(data_end, gap_ptr, 8) < 0) return TC_ACT_OK;
        
        struct iphdr *new_ip = (struct iphdr *)gap_ptr;
        // Verify IP bounds again
        if ((void *)new_ip + sizeof(*new_ip) > data_end) return TC_ACT_OK;
        
        struct udphdr *udp = (struct udphdr *)((void *)new_ip + 20); // Assume IHL=5 used in move
        if ((void *)udp + sizeof(*udp) > data_end) return TC_ACT_OK;
        
        udp->dest = cfg->local_port;
        udp->source = bpf_htons(12345);
        udp->len = bpf_htons(bpf_ntohs(new_ip->tot_len) + 8 - 20);
        udp->check = 0;

        new_ip->protocol = IPPROTO_UDP;
        new_ip->tot_len = bpf_htons(bpf_ntohs(new_ip->tot_len) + 8);
        full_ip_recompute(new_ip);
        
        return TC_ACT_OK;
    }

    // Mode 2: Port-based (Fake-TCP)
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((void *)ip + (ip->ihl * 4));
        if ((void *)tcp + sizeof(*tcp) > data_end) return TC_ACT_OK;

        cfg = bpf_map_lookup_elem(&port_shadow_map, &tcp->dest);
        if (cfg && cfg->mode == 2) {
            __be16 s_p = tcp->source;
            __be16 d_p = tcp->dest;
            
            // To shrink, we need to overwrite TCP with UDP, but maintain IP at start.
            // Move IP forward by 12 bytes? 
            // Correct approach for shrinking 12 bytes:
            // 1. Move IP forward 12 bytes. 
            //    Source: IP at [Eth+14]. Dest: [Eth+26].
            //    It overwrites tcp[0..7].
            //    Old TCP started at [Eth+34].
            //    So new IP ends at [Eth+46]. 
            //    New UDP (8 bytes) starts at [Eth+46].
            //    Old UDP space was TCP space [Eth+34..Eth+54].
            //    We effectively compacted.
            
            // Pre-move safety check
            void *ip_ptr = (void *)eth + sizeof(*eth);
            if (safe_move_ipv4_forward(data_end, ip_ptr, 12) < 0) return TC_ACT_OK;
            
            // Allow shrink
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

// --- Egress: TC ---

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

    // Mode 1: Raw-IP (Delete UDP 8 bytes)
    if (cfg->mode == 1) {
        // Move IP forward 8 bytes
        void *ip_ptr = (void *)eth + sizeof(*eth);
        if (safe_move_ipv4_forward(data_end, ip_ptr, 8) < 0) return TC_ACT_OK;
        
        if (bpf_skb_adjust_room(skb, -8, BPF_ADJ_ROOM_NET, 0) < 0) return TC_ACT_OK;
        
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        eth = (struct ethhdr *)data;
        if ((void *)eth + sizeof(*eth) > data_end) return TC_ACT_OK; // Safe re-check
        
        ip = (struct iphdr *)((void *)eth + sizeof(*eth));
        if ((void *)ip + sizeof(*ip) > data_end) return TC_ACT_OK;

        ip->protocol = (__u8)cfg->proto_num;
        ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) - 8);
        full_ip_recompute(ip);
        return TC_ACT_OK;
    }

    // Mode 2: Fake-TCP (Expand 12 bytes)
    if (cfg->mode == 2) {
        __be16 s_p = udp->source;
        __be16 d_p = udp->dest;
        __u32 jitter = skb->tstamp; 

        if (bpf_skb_adjust_room(skb, 12, BPF_ADJ_ROOM_NET, 0) < 0) return TC_ACT_OK;
        
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        eth = (struct ethhdr *)data;
        if ((void *)eth + sizeof(*eth) > data_end) return TC_ACT_OK;
        
        void *gap_ptr = (void *)eth + sizeof(*eth);
        // Move IP back 12 bytes
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

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
