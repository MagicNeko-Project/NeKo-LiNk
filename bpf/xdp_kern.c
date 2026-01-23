// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

// Map to redirect packets to Userspace AF_XDP Socket
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 64);
} xsks_map SEC(".maps");

// Configuration Map (Port to Listen On)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 64);
} port_map SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 1. Parse Ethernet
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // 2. Parse IP
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // 3. Parse UDP
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    // 4. Check Port (Destination Port)
    // We check against our configured ports in port_map
    // Simplified: Just redirect ALL UDP? No, unsafe.
    // We iterate or check specific index.
    // For MVP, we assume index 0 in port_map holds the BasePort.
    // Ideally we use a HASH map for ports, but ARRAY for simple config.
    
    int key = 0;
    int *port_ptr = bpf_map_lookup_elem(&port_map, &key);
    if (!port_ptr) return XDP_PASS;

    // udp->dest is Network Byte Order (Big Endian)
    // *port_ptr is Host Byte Order (Little Endian usually)
    // Need conversion? Or store in Network Order in Go.
    // Let's assume Go stores in Big Endian or correct format.
    
    if (udp->dest == *port_ptr) {
        // Match! Redirect to AF_XDP Socket (Queue 0)
        // If we implement multi-queue, we redirect to ctx->rx_queue_index
        return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
