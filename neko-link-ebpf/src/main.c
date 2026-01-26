#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
    bpf_printk("NekoLink: Packet passed");
    return XDP_PASS;
}

SEC("classifier")
int tc_pass(struct __sk_buff *skb) {
    return 0; // TC_ACT_OK
}

char _license[] SEC("license") = "GPL";
