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

    // --- Mode 1: Restore Raw-IP to UDP ---
    struct shadow_config *cfg = bpf_map_lookup_elem(&proto_shadow_map, &ip->protocol);
    if (cfg && cfg->mode == 1) {
        // Expand 8 bytes for UDP header
        if (bpf_skb_adjust_room(skb, 8, BPF_ADJ_ROOM_NET, 0) < 0) return TC_ACT_OK;
        
        // Re-fetch pointers
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
        ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

        __u32 ihl = ip->ihl * 4;
        if (ihl < 20 || ihl > 60) return TC_ACT_OK;
        
        struct udphdr *udp = (void *)ip + ihl;
        if ((void *)(udp + 1) > data_end) return TC_ACT_OK;

        // Populate UDP header
        // Since it was Raw-IP, we don't have ports. We use local_port for dest.
        udp->dest = cfg->local_port;
        udp->source = bpf_htons(12345); // Dummy source
        udp->len = bpf_htons(bpf_ntohs(ip->tot_len) + 8 - ihl);
        udp->check = 0;

        ip->protocol = IPPROTO_UDP;
        ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) + 8);
        return TC_ACT_OK;
    }

    // --- Mode 2: Restore Fake-TCP to UDP ---
    if (ip->protocol == IPPROTO_TCP) {
        __u32 ihl = ip->ihl * 4;
        if (ihl < 20 || ihl > 60) return TC_ACT_OK;

        struct tcphdr *tcp = (void *)ip + ihl;
        if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;

        cfg = bpf_map_lookup_elem(&port_shadow_map, &tcp->dest);
        if (cfg && cfg->mode == 2) {
            // Shrink 12 bytes (TCP 20 -> UDP 8)
            if (bpf_skb_adjust_room(skb, -12, BPF_ADJ_ROOM_NET, 0) < 0) return TC_ACT_OK;
            
            data = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            eth = data;
            if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
            ip = (void *)(eth + 1);
            if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

            struct udphdr *udp = (void *)ip + (ip->ihl * 4);
            if ((void *)(udp + 1) > data_end) return TC_ACT_OK;

            // Use original ports from TCP header (already shifted)
            // Note: bpf_skb_adjust_room with negative index shifts the payload "right"? 
            // Actually it just cuts space. The data after TCP header is now after UDP header.
            // We need to re-set the UDP header fields.
            ip->protocol = IPPROTO_UDP;
            ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) - 12);
            
            // Re-fetch TCP ports if they were moved... 
            // In fact, the first 8 bytes of 'tcp' are now where 'udp' is.
            // tcp->source/dest share positions with udp->source/dest.
            udp->len = bpf_htons(bpf_ntohs(ip->tot_len) - (ip->ihl * 4));
            udp->check = 0;
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

    __u32 ihl = ip->ihl * 4;
    if (ihl < 20 || ihl > 60) return TC_ACT_OK;

    struct udphdr *udp = (void *)ip + ihl;
    if ((void *)(udp + 1) > data_end) return TC_ACT_OK;

    // Lookup by Source Port
    struct shadow_config *cfg = bpf_map_lookup_elem(&port_shadow_map, &udp->source);
    if (!cfg) return TC_ACT_OK;

    // --- Mode 1: Apply Raw-IP (Delete UDP) ---
    if (cfg->mode == 1) {
        if (bpf_skb_adjust_room(skb, -8, BPF_ADJ_ROOM_NET, 0) < 0) return TC_ACT_OK;
        
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
        ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

        ip->protocol = (__u8)cfg->proto_num;
        ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) - 8);
        return TC_ACT_OK;
    }

    // --- Mode 2: Apply Fake-TCP (Expand) ---
    if (cfg->mode == 2) {
        if (bpf_skb_adjust_room(skb, 12, BPF_ADJ_ROOM_NET, 0) < 0) return TC_ACT_OK;
        
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
        ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

        ip->protocol = IPPROTO_TCP;
        ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) + 12);
        
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;

        tcp->seq = bpf_htonl(2024);
        tcp->ack_seq = bpf_htonl(1);
        tcp->doff = 5;
        tcp->psh = 1;
        tcp->ack = 1;
        tcp->window = bpf_htons(32768);
        tcp->check = 0;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
