// +build ignore

#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

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

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    // Mode 0: Promiscuous / Redirect All
    // Always redirect everything to the AF_XDP socket on Queue 0.
    // This is used for the "Raw Tunnel" Veth interface.
    return bpf_redirect_map(&xsks_map, 0, 0);
}

char _license[] SEC("license") = "GPL";
