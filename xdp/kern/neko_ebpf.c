#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// --- Configuration Maps ---

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 8);
} config_map SEC(".maps");

/* Config Keys:
   0: Mode (0=Off, 1=Raw-IP, 2=Fake-TCP)
   1: Local VPN Port (Host Order)
   2: Raw Protocol Num (e.g., 250)
*/

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

    __u32 key_mode = 0;
    __u32 *mode = bpf_map_lookup_elem(&config_map, &key_mode);
    if (!mode || *mode == 0) return XDP_PASS;

    // --- MODE 1: Raw-IP -> Restore UDP (Insert Header) ---
    if (*mode == 1) {
        __u32 key_proto = 2;
        __u32 *proto_num = bpf_map_lookup_elem(&config_map, &key_proto);
        if (proto_num && ip->protocol == (__u8)*proto_num) {
            // In XDP, inserting a header requires bpf_xdp_adjust_head
            // We need to shift everything left? No, adjust_head(ctx, -8) effectively pushes head back.
            // But for Raw-IP, the payload starts after IP header. We want to insert 8 bytes UDP.
            // Simplified: We don't necessarily need to turn it back to UDP for legacy raw 
            // if the app is still using raw socket. 
            // BUT for consistency, if we use eBPF, we WANT to use UDP socket in user-space.
            
            // XDP adjust head is tricky for ingress redirection. 
            // Let's implement Fake-TCP restore first and stick to it, 
            // or use TC for ingress if we need complex resizing.
            // Actually, for Mode 1 (Raw-IP), the app might stay on Raw Socket 
            // and we just use eBPF for some other filtering? No point.
            
            // If the user wants eBPF for Raw mode, it's usually for the "TC egress" part
            // to avoid user-space raw socket overhead when sending.
        }
    }

    // --- MODE 2: Fake-TCP -> Restore UDP ---
    if (*mode == 2 && ip->protocol == IPPROTO_TCP) {
        __u32 ihl = ip->ihl * 4;
        if (ihl < 20 || ihl > 60) return XDP_PASS;

        void *tcp_ptr = (void *)ip + ihl;
        struct tcphdr *tcp = tcp_ptr;
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;

        __u32 key_port = 1;
        __u32 *local_port = bpf_map_lookup_elem(&config_map, &key_port);
        if (local_port && tcp->dest == bpf_htons((__u16)*local_port)) {
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

    __u32 key_port = 1;
    __u32 *local_port = bpf_map_lookup_elem(&config_map, &key_port);
    if (local_port && udp->source == bpf_htons((__u16)*local_port)) {
        __u32 key_mode = 0;
        __u32 *mode = bpf_map_lookup_elem(&config_map, &key_mode);
        if (!mode) return TC_ACT_OK;

        // --- MODE 1: Apply Raw-IP (Strip UDP) ---
        if (*mode == 1) {
            __u32 key_proto = 2;
            __u32 *proto_num = bpf_map_lookup_elem(&config_map, &key_proto);
            if (proto_num) {
                // Shrink 8 bytes (remove UDP)
                if (bpf_skb_adjust_room(skb, -8, BPF_ADJ_ROOM_NET, 0) < 0) return TC_ACT_OK;
                
                data = (void *)(long)skb->data;
                data_end = (void *)(long)skb->data_end;
                eth = data;
                ip = (void *)(eth + 1);
                if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

                ip->protocol = (__u8)*proto_num;
                ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) - 8);
                // Checksum will be updated by stack or we could use bpf_l3_csum_replace
            }
        }

        // --- MODE 2: Apply Fake-TCP (Expand & Insert) ---
        else if (*mode == 2) {
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

            tcp->seq = bpf_htonl(1000);
            tcp->ack_seq = bpf_htonl(1);
            tcp->doff = 5;
            tcp->psh = 1;
            tcp->ack = 1;
            tcp->window = bpf_htons(4096);
            tcp->check = 0;
        }
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
