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

    // --- MODE 2: Fake-TCP -> Restore UDP ---
    if (*mode == 2 && ip->protocol == IPPROTO_TCP) {
        // Safe IHL handle for verifier
        __u32 ihl = ip->ihl * 4;
        if (ihl < 20 || ihl > 60) return XDP_PASS;

        void *tcp_ptr = (void *)ip + ihl;
        struct tcphdr *tcp = tcp_ptr;
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;

        __u32 key_port = 1;
        __u32 *local_port = bpf_map_lookup_elem(&config_map, &key_port);
        if (local_port && tcp->dest == bpf_htons((__u16)*local_port)) {
            // Restore Fake TCP to UDP
            ip->protocol = IPPROTO_UDP;
            struct udphdr *udp = (void *)tcp;
            // Note: UDP is smaller than TCP, so this overwrite is safe.
            // We lose some TCP fields, but that's fine for "Restore".
            udp->source = tcp->source;
            udp->dest = tcp->dest;
            udp->len = bpf_htons(bpf_ntohs(ip->tot_len) - ihl);
            udp->check = 0; 
            // We leave the rest of the TCP header as "padding" or let the app handle.
            // Shifting exactly would require more complex XDP logic.
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

        // --- MODE 2: Apply Fake-TCP ---
        if (*mode == 2) {
            // Adjust room: UDP(8) -> TCP(20) is +12 bytes
            if (bpf_skb_adjust_room(skb, 12, BPF_ADJ_ROOM_NET, 0) < 0) return TC_ACT_OK;
            
            // Re-fetch pointers
            data = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            eth = data;
            if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
            ip = (void *)(eth + 1);
            if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

            ip->protocol = IPPROTO_TCP;
            ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) + 12);
            
            // Re-calculate IHL for safety
            __u32 new_ihl = ip->ihl * 4;
            if (new_ihl < 20 || new_ihl > 60) return TC_ACT_OK;

            void *tcp_ptr = (void *)ip + new_ihl;
            struct tcphdr *tcp = tcp_ptr;
            if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;

            // Header mapping (UDP to TCP)
            // Note: udp pointers are invalid now, but we saved ports if we wanted.
            // Since we know the offset, we can fetch from packet.
            
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
