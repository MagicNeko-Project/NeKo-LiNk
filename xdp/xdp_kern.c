// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

// Basic Map Def for legacy support
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

struct bpf_map_def SEC("maps") xsks_map = {
    .type = BPF_MAP_TYPE_XSKMAP,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 64,
};

// Config Map
// Key 0: Mode (1=UDP, 2=Raw)
// Key 1: Target Value (Port or ProtocolNum)
struct bpf_map_def SEC("maps") config_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 4,
};

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) return XDP_PASS;
    
    // Check Protocol
    // Allow IP (0x0800)
    if (eth->h_proto == __constant_htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)(ip + 1) > data_end) return XDP_PASS;
        
        // IP Logic continues below
    } else if (eth->h_proto == __constant_htons(ETH_P_ARP)) {
        // ARP (0x0806)
        // Only allow in Mode 0 (Promiscuous)
        // We will check map below
    } else {
        return XDP_PASS;
    }
    
    // Legacy IP Pointer logic (moved inside if, but we need it for Mode 1/2 checks)
    // Refactor: Extract IP only if IP
    struct iphdr *ip = NULL;
    if (eth->h_proto == __constant_htons(ETH_P_IP)) {
         ip = data + sizeof(*eth);
    }

    // Load Config
    int key_mode = 0;
    int key_val = 1;
    int *mode = bpf_map_lookup_elem(&config_map, &key_mode);
    int *val = bpf_map_lookup_elem(&config_map, &key_val); // Port (Host) or Proto
    
    if (!mode || !val) return XDP_PASS;

    // MODE 1: UDP
    if (*mode == 1) {
        if (!ip) return XDP_PASS; // ARP not allowed in UDP Mode
        if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end) return XDP_PASS;
        
        if (udp->dest == *val) {
             return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
        }
    }
    
    // MODE 2: RAW (IP Protocol)
    else if (*mode == 2) {
        if (!ip) return XDP_PASS; // ARP not allowed in Raw Filter Mode
        if (ip->protocol == *val) {
            return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
        }
    }
    
    // MODE 0: Promiscuous (Redirect ALL IP + ARP)
    // Used for Veth interface where we want to capture everything from Host
    else if (*mode == 0) {
        // We already validated Eth is IP or ARP above.
        return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
