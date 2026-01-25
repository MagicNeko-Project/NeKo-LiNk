// +build ignore

#include <stddef.h>
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
    
    // Check Protocol: We need to filter for specific modes, BUT Mode 0 = All.
    // So we can't filter globally at the top.
    
    // Load Config first
    int key_mode = 0;
    int key_val = 1;
    int *mode = bpf_map_lookup_elem(&config_map, &key_mode);
    int *val = bpf_map_lookup_elem(&config_map, &key_val); // Port (Host) or Proto
    
    if (!mode || !val) return XDP_PASS;
    
    // MODE 0: Promiscuous (Redirect ALL)
    if (*mode == 0) {
         // Force Queue 0.
         // In Generic XDP (SKB Mode), rx_queue_index might depend on CPU.
         // We only attached AF_XDP to Queue 0.
         return bpf_redirect_map(&xsks_map, 0, 0);
    }

    // Filter Logic for Mode 1 & 2 (IP Only)
    struct iphdr *ip = NULL;
    if (eth->h_proto == __constant_htons(ETH_P_IP)) {
        ip = data + sizeof(*eth);
        if ((void *)(ip + 1) > data_end) return XDP_PASS;
    } else {
        // Mode 1/2 only support IPv4 for now filtering
        return XDP_PASS;
    }

    // MODE 1: UDP
    if (*mode == 1) {
        if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end) return XDP_PASS;
        
        if (udp->dest == *val) {
             return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
        }
    }
    
    // MODE 2: RAW (IP Protocol)
    else if (*mode == 2) {
        if (ip->protocol == *val) {
            return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
