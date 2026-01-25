#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// --- Legacy Map Definition (No BTF) ---

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

struct bpf_map_def SEC("maps") raw_allow_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u8),
	.value_size = sizeof(__u8),
	.max_entries = 16,
};

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
    __u8 proto = ip->protocol; // 复制到栈变量以确保内存对齐 (BPF 要求)
    __u8 *allowed = bpf_map_lookup_elem(&raw_allow_map, &proto);
    if (allowed) {
        // bpf_printk("Allowed Proto: %d\n", proto);
        return TC_ACT_OK; // 允许通过
    }
    
    // 如果没有匹配，默认也通过？或者 Drop？
    // 根据设计，我们只“Steer”也就是“标记/允许”，还是说要拦截非允许流量？
    // 如果 Raw Socket 仅用于特定协议，那么非该协议的流量本来就不会进 Raw Socket。
    // 但为了纯净，我们可以选择忽略。
    // 目前保持 TC_ACT_OK 以防误杀。
    // bpf_printk("Pass Unknown Proto: %d\n", proto);
    return TC_ACT_OK;

    return TC_ACT_OK;
}

// --- 出站处理 (Egress) ---

SEC("tc/egress")
int tc_shadow_egress(struct __sk_buff *skb) {
    // Raw 模式出站不做任何封包/解包
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
