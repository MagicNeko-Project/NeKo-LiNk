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
    __u32 proto_num;  // Only used for Mode 1
    __u32 reserved[2];
};

// --- Multi-Instance Maps ---

// Key: Destination Port (Big Endian, u16)
// Value: shadow_config
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__be16));
    __uint(value_size, sizeof(struct shadow_config));
    __uint(max_entries, 128);
} port_shadow_map SEC(".maps");

// Key: Protocol Number (u8)
// Value: shadow_config
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u8));
    __uint(value_size, sizeof(struct shadow_config));
    __uint(max_entries, 128);
} proto_shadow_map SEC(".maps");

// --- Ingress: XDP (Restore Obfuscation) ---

SEC("xdp")
int xdp_shadow_ingress(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    // --- Check Proto-based Shadowing (Mode 1) ---
    struct shadow_config *cfg = bpf_map_lookup_elem(&proto_shadow_map, &ip->protocol);
    if (cfg && cfg->mode == 1) {
        // Mode 1: Leave it for now - Raw-IP usually doesn't need "restoration" to UDP 
        // to be recognized by a Raw user-space socket.
        return XDP_PASS;
    }

    // --- Check Port-based Shadowing (Mode 2: Fake-TCP) ---
    if (ip->protocol == IPPROTO_TCP) {
        __u32 ihl = ip->ihl * 4;
        if (ihl < 20 || ihl > 60) return XDP_PASS;

        void *tcp_ptr = (void *)ip + ihl;
        struct tcphdr *tcp = tcp_ptr;
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;

        // Lookup by Dest Port
        cfg = bpf_map_lookup_elem(&port_shadow_map, &tcp->dest);
        if (cfg && cfg->mode == 2) {
            // Restore Fake TCP to UDP
            ip->protocol = IPPROTO_UDP;
            struct udphdr *udp = (void *)tcp;
            udp->source = tcp->source;
            udp->dest = tcp->dest;
            udp->len = bpf_htons(bpf_ntohs(ip->tot_len) - ihl);
            udp->check = 0; 
        }
    }

    return XDP_PASS;
}

// --- Egress: TC (Apply Obfuscation) ---

SEC("tc")
int tc_shadow_egress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

    if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK;

    __u32 ihl = ip->ihl * 4;
    if (ihl < 20 || ihl > 60) return TC_ACT_OK;

    void *udp_ptr = (void *)ip + ihl;
    struct udphdr *udp = udp_ptr;
    if ((void *)(udp + 1) > data_end) return TC_ACT_OK;

    // Lookup by Source Port (The port our app is using)
    struct shadow_config *cfg = bpf_map_lookup_elem(&port_shadow_map, &udp->source);
    if (!cfg) return TC_ACT_OK;

    // --- Apply Mode 1: Raw-IP ---
    if (cfg->mode == 1) {
        // Shrink 8 bytes (remove UDP header)
        if (bpf_skb_adjust_room(skb, -8, BPF_ADJ_ROOM_NET, 0) < 0) return TC_ACT_OK;
        
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        eth = data;
        ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

        ip->protocol = (__u8)cfg->proto_num;
        ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) - 8);
    }

    // --- Apply Mode 2: Fake-TCP ---
    else if (cfg->mode == 2) {
        // Expand 12 bytes (UDP 8 -> TCP 20)
        if (bpf_skb_adjust_room(skb, 12, BPF_ADJ_ROOM_NET, 0) < 0) return TC_ACT_OK;
        
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        eth = data;
        ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

        ip->protocol = IPPROTO_TCP;
        ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) + 12);
        
        __u32 new_ihl = ip->ihl * 4;
        if (new_ihl < 20 || new_ihl > 60) return TC_ACT_OK;

        void *tcp_ptr = (void *)ip + new_ihl;
        struct tcphdr *tcp = tcp_ptr;
        if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;

        // Note: UDP headers are overwritten now
        // But the previous WriteToUDP in userspace set the dest port correctly in the new TCP header area.
        // Actually, let's just make it look like a valid PSH+ACK
        tcp->seq = bpf_htonl(1024);
        tcp->ack_seq = bpf_htonl(1);
        tcp->doff = 5;
        tcp->psh = 1;
        tcp->ack = 1;
        tcp->window = bpf_htons(16384);
        tcp->check = 0;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
