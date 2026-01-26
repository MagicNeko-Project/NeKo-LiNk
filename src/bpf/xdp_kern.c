#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
    int index = ctx->rx_queue_index;

    // Debug logging (cat /sys/kernel/debug/tracing/trace_pipe)
    // bpf_printk("AF_XDP: Packet received on queue %d\n", index);

    // Redirect to AF_XDP socket if map entry exists
    if (bpf_map_lookup_elem(&xsks_map, &index))
        return bpf_redirect_map(&xsks_map, index, 0);

    // Default: Pass to kernel stack
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
