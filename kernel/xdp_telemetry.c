#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#ifndef IP_MF
#define IP_MF 0x2000
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF
#endif

// Max packets per second allowed from ONE source IP before it is dropped.
#define RATE_LIMIT_PPS 20000
#define NS_PER_SEC 1000000000ULL

// Indexes inside the per-CPU "counters" map
#define CNT_DROPPED 0      // every dropped packet (all reasons)
#define CNT_RATELIMITED 1  // subset: dropped by the rate limiter
#define CNT_PASSED 2       // IPv4 packets allowed through

// Known-bad source IPs (filled by the Go control plane)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 20000);
    __type(key, __u32);
    __type(value, __u32);
} blocklist SEC(".maps");

struct frag_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 ip_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 5000);
    __type(key, struct frag_key);
    __type(value, __u32);
} fragment_cache SEC(".maps");

// Per-source-IP packet counter for the current 1-second window
struct rate_state {
    __u64 window_start;
    __u32 count;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct rate_state);
} rate_map SEC(".maps");

// Lockless per-CPU counters read by the Go control plane
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

static __always_inline void count_event(__u32 idx) {
    __u64 *c = bpf_map_lookup_elem(&counters, &idx);
    if (c) {
        *c += 1;
    }
}

SEC("xdp")
int extract_network_telemetry(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    __u32 src_ip = ip->saddr;

    // 1. Known-bad IP blocklist
    if (bpf_map_lookup_elem(&blocklist, &src_ip)) {
        count_event(CNT_DROPPED);
        return XDP_DROP;
    }

    // 2. Per-IP rate limit (flood protection for unknown sources)
    __u64 now = bpf_ktime_get_ns();
    struct rate_state *rs = bpf_map_lookup_elem(&rate_map, &src_ip);
    if (!rs) {
        struct rate_state init = { .window_start = now, .count = 1 };
        bpf_map_update_elem(&rate_map, &src_ip, &init, BPF_ANY);
    } else if (now - rs->window_start > NS_PER_SEC) {
        rs->window_start = now;
        rs->count = 1;
    } else {
        rs->count++;
        if (rs->count > RATE_LIMIT_PPS) {
            count_event(CNT_DROPPED);
            count_event(CNT_RATELIMITED);
            return XDP_DROP;
        }
    }

    // 3. Zero-trust: drop fragmented packets
    if (ip->frag_off & bpf_htons(IP_MF | IP_OFFSET)) {
        struct frag_key fkey = {};
        fkey.src_ip = ip->saddr;
        fkey.dst_ip = ip->daddr;
        fkey.ip_id = ip->id;
        __u32 threat = 1;
        bpf_map_update_elem(&fragment_cache, &fkey, &threat, BPF_ANY);
        count_event(CNT_DROPPED);
        return XDP_DROP;
    }

    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) goto allow;

    // 4. Demo payload signature "PWND" (first 4 payload bytes of one packet)
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_hdr_len;
        if ((void *)(tcp + 1) > data_end) goto allow;

        int tcp_hdr_len = tcp->doff * 4;
        if (tcp_hdr_len < sizeof(struct tcphdr)) goto allow;

        unsigned char *payload = (unsigned char *)tcp + tcp_hdr_len;
        if ((void *)(payload + 4) > data_end) goto allow;

        if (*(__u32 *)payload == 0x444E5750) {
            count_event(CNT_DROPPED);
            return XDP_DROP;
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_hdr_len;
        if ((void *)(udp + 1) > data_end) goto allow;

        unsigned char *payload = (unsigned char *)udp + sizeof(struct udphdr);
        if ((void *)(payload + 4) > data_end) goto allow;

        if (*(__u32 *)payload == 0x444E5750) {
            count_event(CNT_DROPPED);
            return XDP_DROP;
        }
    }

allow: ;
    count_event(CNT_PASSED);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
