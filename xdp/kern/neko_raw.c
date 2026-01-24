#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// --- Maps (仅 Raw Allow) ---

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u8));  // IP Proto
    __uint(value_size, sizeof(__u8)); // Placeholder
    __uint(max_entries, 16);
} raw_allow_map SEC(".maps");

// --- 入站处理 (Ingress) ---

SEC("tc/ingress")
int tc_shadow_ingress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)eth + sizeof(*eth) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (struct iphdr *)((void *)eth + sizeof(*eth));
    if ((void *)ip + sizeof(*ip) > data_end) return TC_ACT_OK;

    // Raw 模式仅检查允许列表
    __u8 *allowed = bpf_map_lookup_elem(&raw_allow_map, &ip->protocol);
    if (allowed) {
        return TC_ACT_OK; // 允许通过
    }

    return TC_ACT_OK;
}

// --- 出站处理 (Egress) ---

SEC("tc/egress")
int tc_shadow_egress(struct __sk_buff *skb) {
    // Raw 模式出站不做任何封包/解包
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
