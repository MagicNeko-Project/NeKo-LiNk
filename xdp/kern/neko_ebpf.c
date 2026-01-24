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

// --- Helper: Manual IP Checksum ---

static __always_inline void recalculate_ip_checksum(struct iphdr *ip) {
    __u32 csum = 0;
    __u16 *p = (__u16 *)ip;
    ip->check = 0;
    
    // IPv4 Header is usually 20 bytes (10 u16)
    // We use a fixed loop for the verifier
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        csum += p[i];
    }
    
    // Fold 32-bit sum to 16 bits
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = ~(__u16)csum;
}

// --- Ingress: TC (Restore) ---

SEC("tc/ingress")
int tc_shadow_ingress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

    // --- Mode 1: Restore Raw-IP (Add UDP Head) ---
    struct shadow_config *cfg = bpf_map_lookup_elem(&proto_shadow_map, &ip->protocol);
    if (cfg && cfg->mode == 1) {
        if (bpf_skb_adjust_room(skb, 8, BPF_ADJ_ROOM_NET, 0) < 0) return TC_ACT_OK;
        
        // Refresh pointers
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        eth = data;
        ip = (void *)(eth + sizeof(struct ethhdr));
        if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end) return TC_ACT_OK;

        udp->dest = cfg->local_port;
        udp->source = bpf_htons(12345);
        udp->len = bpf_htons(bpf_ntohs(ip->tot_len) + 8 - (ip->ihl * 4));
        udp->check = 0;

        ip->protocol = IPPROTO_UDP;
        ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) + 8);
        recalculate_ip_checksum(ip);
        
        return TC_ACT_OK;
    }

    // --- Mode 2: Restore Fake-TCP (TCP 20 -> UDP 8) ---
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;

        cfg = bpf_map_lookup_elem(&port_shadow_map, &tcp->dest);
        if (cfg && cfg->mode == 2) {
            __be16 src_p = tcp->source;
            __be16 dst_p = tcp->dest;

            if (bpf_skb_adjust_room(skb, -12, BPF_ADJ_ROOM_NET, 0) < 0) return TC_ACT_OK;
            
            data = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            ip = (void *)(data + sizeof(struct ethhdr));
            if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
            
            struct udphdr *udp = (void *)ip + (ip->ihl * 4);
            if ((void *)(udp + 1) > data_end) return TC_ACT_OK;

            udp->source = src_p;
            udp->dest = dst_p;
            udp->len = bpf_htons(bpf_ntohs(ip->tot_len) - 12 - (ip->ihl * 4));
            udp->check = 0;

            ip->protocol = IPPROTO_UDP;
            ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) - 12);
            recalculate_ip_checksum(ip);
        }
    }

    return TC_ACT_OK;
}

// --- Egress: TC (Apply) ---

SEC("tc/egress")
int tc_shadow_egress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

    if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK;

    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end) return TC_ACT_OK;

    struct shadow_config *cfg = bpf_map_lookup_elem(&port_shadow_map, &udp->source);
    if (!cfg) return TC_ACT_OK;

    // --- Mode 1: Apply Raw-IP (Delete UDP Head) ---
    if (cfg->mode == 1) {
        if (bpf_skb_adjust_room(skb, -8, BPF_ADJ_ROOM_NET, 0) < 0) return TC_ACT_OK;
        
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        ip = (void *)(data + sizeof(struct ethhdr));
        if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

        ip->protocol = (__u8)cfg->proto_num;
        ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) - 8);
        recalculate_ip_checksum(ip);
        return TC_ACT_OK;
    }

    // --- Mode 2: Apply Fake-TCP (UDP 8 -> TCP 20) ---
    if (cfg->mode == 2) {
        __be16 src_p = udp->source;
        __be16 dst_p = udp->dest;

        if (bpf_skb_adjust_room(skb, 12, BPF_ADJ_ROOM_NET, 0) < 0) return TC_ACT_OK;
        
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        ip = (void *)(data + sizeof(struct ethhdr));
        if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;

        tcp->source = src_p;
        tcp->dest = dst_p;
        tcp->seq = bpf_htonl(100);
        tcp->ack_seq = bpf_htonl(1);
        tcp->doff = 5;
        tcp->psh = 1;
        tcp->ack = 1;
        tcp->window = bpf_htons(8192);
        tcp->check = 0;

        ip->protocol = IPPROTO_TCP;
        ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) + 12);
        recalculate_ip_checksum(ip);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
