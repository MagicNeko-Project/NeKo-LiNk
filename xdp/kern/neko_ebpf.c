#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// --- Configuration Struct ---

struct shadow_config {
    __u32 mode;       // 1=Raw-IP, 2=Fake-TCP
    __u32 proto_num;  // Protocol number for Raw-IP
    __u16 local_port; // Port the app is listening on (Big Endian)
    __u16 reserved;
};

// --- Maps ---

// Map 1: Port-based (For Egress & Fake-TCP Ingress)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u16));
    __uint(value_size, sizeof(struct shadow_config));
    __uint(max_entries, 128);
} port_shadow_map SEC(".maps");

// Map 2: Protocol-based (Only for Raw-IP Ingress)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u8));
    __uint(value_size, sizeof(struct shadow_config));
    __uint(max_entries, 128);
} proto_shadow_map SEC(".maps");

// --- Helper: IP Checksum ---

static __always_inline void full_ip_recompute(struct iphdr *ip) {
    __u32 csum = 0;
    __u16 *p = (__u16 *)ip;
    ip->check = 0;
    
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        csum += p[i];
    }
    
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = ~(__u16)csum;
}

// --- Helper: Memmove ---
// Since we don't have standard memmove, we use a fixed size loop.
// IP Header is typically 20 bytes. We assume no options for simplicity in this hot path,
// or we just move the fixed 20 bytes. 
// If IHL > 5, specific options might be lost or we need larger loop. 
// For now, standard IPv4 header is 20 bytes.

static __always_inline void move_ipv4_header_back(void *base, int dist) {
    // Moves 20 bytes from [base] to [base - dist]
    // Used in Ingress to fill the gap created by bpf_skb_adjust_room(NET, +)
    // Actually, calling adjust_room(NET, +8) creates gap at [Eth+14].
    // Original IP was at [Eth+14]. Now it is at [Eth+14+8].
    // The [Eth+14]..[Eth+22] is the gap. 
    // We want IP to be at [Eth+14]. UDP at [Eth+34].
    // Wait.
    // If we adjust +8 at NET. The packet expands. 
    // Data layout: [Eth] [GAP 8] [Old IP Data...].
    // Pointers: data -> Eth. data + 14 -> GAP. data + 22 -> IP.
    // Target: [Eth] [IP] [UDP] [Payload].
    // So we need to move IP (20 bytes) from [data+22] to [data+14].
    // Then correct IP len/proto.
    // Then write UDP at [data+34] (which is 14 + 20).
    
    // We are copying *bytes*.
    // From: base + dist (Source) -> base (Dest)
    // But bpf has constraints. We must verify pointers.
    // We assume caller verified boundaries.
    
    unsigned char *src = (unsigned char *)base + dist;
    unsigned char *dst = (unsigned char *)base;
    
    #pragma unroll
    for (int i = 0; i < 20; i++) {
        dst[i] = src[i];
    }
}

static __always_inline void move_ipv4_header_forward(void *base, int dist) {
    // Moves 20 bytes from [base] to [base + dist]
    // Used in Egress. 
    // Original: [Eth] [IP] [UDP] [Payload]
    // We want: [Eth] [IP (overwriting UDP)] [Payload]
    // Then shrink.
    // So we move IP from [Eth+14] to [Eth+14+8]. 
    // Wait. 
    // If we want [Eth] [IP] [Payload].
    // Payload starts at [Eth+14+20+8].
    // If we just move IP forward by 8 bytes?
    // Dest: [Eth+14+8]. Src: [Eth+14].
    // Then Layout: [Eth] [Garbage] [IP] [Payload].
    // Then we shrink 8 bytes at NET.
    // Shrink removes [Eth+14]..[Eth+22] (Garbage).
    // Result: [Eth] [IP] [Payload].
    // Correct.
    
    // We need to copy backwards to handle overlap safely?
    // Src: 0..19. Dst: 8..27. Overlap!
    // We must copy from end to start.
    
    unsigned char *src = (unsigned char *)base;
    unsigned char *dst = (unsigned char *)base + dist;
    
    #pragma unroll
    for (int i = 19; i >= 0; i--) {
        dst[i] = src[i];
    }
}

// --- Ingress: TC (Restore) ---

SEC("tc/ingress")
int tc_shadow_ingress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)eth + sizeof(*eth) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (struct iphdr *)((void *)eth + sizeof(*eth));
    if ((void *)ip + sizeof(*ip) > data_end) return TC_ACT_OK;

    // --- Mode 1: Protocol-based (Raw-IP) ---
    struct shadow_config *cfg = bpf_map_lookup_elem(&proto_shadow_map, &ip->protocol);
    if (cfg && cfg->mode == 1) {
        // 1. Expand room by 8 bytes at NET layer (inserting gap before IP)
        if (bpf_skb_adjust_room(skb, 8, BPF_ADJ_ROOM_NET, 0) < 0) return TC_ACT_OK;
        
        // 2. Refresh pointers
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        
        eth = (struct ethhdr *)data;
        if ((void *)eth + sizeof(*eth) > data_end) return TC_ACT_OK;
        
        // Gap is at data + sizeof(eth). 
        // Old IP is at data + sizeof(eth) + 8.
        void *gap_ptr = (void *)eth + sizeof(*eth);
        struct iphdr *old_ip = (struct iphdr *)(gap_ptr + 8);
        if ((void *)old_ip + sizeof(*old_ip) > data_end) return TC_ACT_OK;
        
        // 3. Move IP header back into Gap
        move_ipv4_header_back(gap_ptr, 8);
        
        // 4. Now IP is at gap_ptr. UDP is at gap_ptr + 20.
        struct iphdr *new_ip = (struct iphdr *)gap_ptr;
        struct udphdr *udp = (struct udphdr *)((void *)new_ip + sizeof(struct iphdr));
        if ((void *)udp + sizeof(*udp) > data_end) return TC_ACT_OK;
        
        // 5. Fill UDP
        udp->dest = cfg->local_port; 
        udp->source = bpf_htons(12345);
        // Len = Total - IPHead(20). (Payload + UDP).
        // New Total Len will be Old Total + 8.
        // So UDP Len = (Old Total + 8) - 20 ? No.
        // Old IP Len included payload.
        // UDP Len = Payload + 8. 
        // Payload = Old IP Len - Old IHL(20).
        udp->len = bpf_htons(bpf_ntohs(new_ip->tot_len) + 8 - 20);
        udp->check = 0;

        // 6. Update IP
        new_ip->protocol = IPPROTO_UDP;
        new_ip->tot_len = bpf_htons(bpf_ntohs(new_ip->tot_len) + 8);
        full_ip_recompute(new_ip);
        
        return TC_ACT_OK;
    }

    // --- Mode 2: Port-based (Fake-TCP) ---
    // Fake-TCP: [IP] [TCP] [Payload] -> [IP] [UDP] [Payload]
    // TCP=20 bytes. UDP=8 bytes. We shrink by 12 bytes.
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((void *)ip + (ip->ihl * 4));
        if ((void *)tcp + sizeof(*tcp) > data_end) return TC_ACT_OK;

        cfg = bpf_map_lookup_elem(&port_shadow_map, &tcp->dest);
        if (cfg && cfg->mode == 2) {
            __be16 s_p = tcp->source;
            __be16 d_p = tcp->dest;

            // Shrink 12 bytes. 
            // If we shrink at NET, we lose start of IP. 
            // We want to keep IP. 
            // We want to shrink the space *between* IP and Payload?
            // adjust_room doesn't support arbitrary offset easily.
            // Strategy: 
            // 1. Move IP header *forward* by 12 bytes? No, we want to remove space.
            // Packet: [Eth] [IP] [TCP(20)] [Payload]
            // Target: [Eth] [IP] [UDP(8)] [Payload]
            // Delta: -12.
            // If we shrink at NET, we cut [Eth+14]..[Eth+26].
            // We lose 12 bytes of IP header. Bad.
            
            // Correct logic:
            // 1. Convert TCP header to UDP header (in place). 
            //    TCP is 20 bytes. UDP is 8. We have 12 bytes unused gap after UDP.
            //    [Eth] [IP] [UDP] [Gap 12] [Payload].
            // 2. We need to move [IP] [UDP] *forward* by 12 bytes? No.
            //    We want to delete the Gap.
            //    We can move [IP] [UDP] *forward* into new position? No.
            //    We can move [Payload] back? No, can't move payload easily.
            
            // Allow simplified approach for Mode 2:
            // Just use the first 8 bytes of TCP header space for UDP.
            // The remaining 12 bytes of TCP header become "garbage" between UDP and Payload?
            // If we pass that to Go, Go receives 12 bytes of junk.
            // Go code `xdp/socket.go` or `wg_bind.go` handles this?
            // In generic mode (Go), we strip TCP header (20 bytes).
            // Here eBPF is converting.
            // If we leave 12 bytes junk, Go sees UDP payload = [Junk 12] + [Real Payload].
            // Go app expects pure payload.
            
            // Best EBPF way for Mode 2 Middle Removal:
            // 1. Move IP header *forward* by 12 bytes.
            //    [Eth] [Gap 12] [IP] [TCP...]
            // 2. Overwrite TCP with UDP (offsets change).
            //    Wait, complex.
            
            // Alternative:
            // 1. `bpf_skb_adjust_room(skb, -12, BPF_ADJ_ROOM_NET, 0)` -> Cuts 12 bytes at start of IP.
            //    [Eth] [IP_Part2] [TCP]...
            //    We lost 12 bytes.
            //    So, PRE-MOVE:
            //    Move IP header *forward* by 12 bytes? No.
            //    Move IP header *backward*? We don't have space.
            
            // Actually:
            // 1. Move IP header (20 bytes) *forward* (towards payload) by 12 bytes?
            //    Src: [Eth+14]. Dst: [Eth+26].
            //    We are overwriting start of TCP.
            //    [Eth] [Garbage 12] [IP] [TCP_Tail / Payload].
            //    Basically we consumed 12 bytes of TCP header. 
            //    TCP header was 20 bytes. 8 bytes remain.
            //    Those 8 bytes are exactly space for UDP!
            //    So:
            //    Step A: Move IP forward 12 bytes.
            //    Step B: Shrink 12 bytes at NET. (Removes Garbage).
            //    Result: [Eth] [IP] [8 bytes TCP tail] [Payload].
            //    We treat [8 bytes TCP tail] as our new UDP header location.
            
            // Implementation:
            // 1. Refresh pointers.
            void *ip_ptr = (void *)eth + sizeof(*eth);
            move_ipv4_header_forward(ip_ptr, 12);
            
            // 2. Shrink
            if (bpf_skb_adjust_room(skb, -12, BPF_ADJ_ROOM_NET, 0) < 0) return TC_ACT_OK;
            
            // 3. Refresh pointers
            data = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            eth = (struct ethhdr *)data;
            struct iphdr *new_ip = (struct iphdr *)((void *)eth + sizeof(*eth));
            if ((void *)new_ip + sizeof(*new_ip) > data_end) return TC_ACT_OK;
            
            struct udphdr *udp = (struct udphdr *)((void *)new_ip + 20); // IP is 20 bytes
            if ((void *)udp + sizeof(*udp) > data_end) return TC_ACT_OK;
            
            udp->source = s_p;
            udp->dest = d_p;
            udp->len = bpf_htons(bpf_ntohs(new_ip->tot_len) - 12 - 20);
            udp->check = 0;

            new_ip->protocol = IPPROTO_UDP;
            new_ip->tot_len = bpf_htons(bpf_ntohs(new_ip->tot_len) - 12);
            full_ip_recompute(new_ip);
        }
    }

    return TC_ACT_OK;
}

// --- Egress: TC (Apply) ---

SEC("tc/egress")
int tc_shadow_egress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)eth + sizeof(*eth) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (struct iphdr *)((void *)eth + sizeof(*eth));
    if ((void *)ip + sizeof(*ip) > data_end) return TC_ACT_OK;

    if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK;

    struct udphdr *udp = (struct udphdr *)((void *)ip + (ip->ihl * 4));
    if ((void *)udp + sizeof(*udp) > data_end) return TC_ACT_OK;

    struct shadow_config *cfg = bpf_map_lookup_elem(&port_shadow_map, &udp->source);
    if (!cfg) return TC_ACT_OK;

    // --- Mode 1: Apply Raw-IP (Delete UDP Head) ---
    // Remove 8 bytes (UDP). 
    // Logic: 
    // 1. Move IP header *forward* by 8 bytes.
    //    Overwrites UDP.
    //    [Eth] [Garbage 8] [IP] [Payload]
    // 2. Shrink 8 bytes at NET.
    //    [Eth] [IP] [Payload]
    if (cfg->mode == 1) {
        void *ip_ptr = (void *)eth + sizeof(*eth);
        move_ipv4_header_forward(ip_ptr, 8);
        
        if (bpf_skb_adjust_room(skb, -8, BPF_ADJ_ROOM_NET, 0) < 0) return TC_ACT_OK;
        
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        eth = (struct ethhdr *)data;
        ip = (struct iphdr *)((void *)eth + sizeof(*eth));
        if ((void *)ip + sizeof(*ip) > data_end) return TC_ACT_OK;

        ip->protocol = (__u8)cfg->proto_num;
        ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) - 8);
        full_ip_recompute(ip);
        return TC_ACT_OK;
    }

    // --- Mode 2: Apply Fake-TCP (UDP 8 -> TCP 20) ---
    // Expand 12 bytes.
    // Logic:
    // 1. Expand 12 bytes at NET.
    //    [Eth] [Gap 12] [IP] [UDP] [Payload]
    // 2. Move IP back 12 bytes.
    //    [Eth] [IP] [Gap 12] [UDP] [Payload]
    //    Wait. [Gap 12] + [UDP 8] = 20 Bytes!
    //    Exactly space for TCP.
    if (cfg->mode == 2) {
        __be16 s_p = udp->source;
        __be16 d_p = udp->dest;
        __u32 jitter = skb->tstamp; 

        if (bpf_skb_adjust_room(skb, 12, BPF_ADJ_ROOM_NET, 0) < 0) return TC_ACT_OK;
        
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        eth = (struct ethhdr *)data;
        
        void *gap_ptr = (void *)eth + sizeof(*eth);
        move_ipv4_header_back(gap_ptr, 12);
        
        struct iphdr *new_ip = (struct iphdr *)gap_ptr;
        if ((void *)new_ip + sizeof(*new_ip) > data_end) return TC_ACT_OK;
        
        struct tcphdr *tcp = (struct tcphdr *)((void *)new_ip + 20);
        if ((void *)tcp + sizeof(*tcp) > data_end) return TC_ACT_OK;

        tcp->source = s_p;
        tcp->dest = d_p;
        tcp->seq = bpf_htonl(1024 + (jitter & 0xFFFF));
        tcp->ack_seq = bpf_htonl(1);
        tcp->doff = 5;
        tcp->psh = 1;
        tcp->ack = 1;
        tcp->window = bpf_htons(64512);
        tcp->check = 0;

        new_ip->protocol = IPPROTO_TCP;
        new_ip->tot_len = bpf_htons(bpf_ntohs(new_ip->tot_len) + 12);
        full_ip_recompute(new_ip);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
