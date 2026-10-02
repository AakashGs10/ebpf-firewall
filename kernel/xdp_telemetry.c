#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// Explicit macro definitions to avoid missing header identifiers in eBPF target
#ifndef IP_MF
#define IP_MF 0x2000
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF
#endif

// 1. Memory Maps
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 20000); // Fixed: Increased to 20,000 for IPsum + Auto-bans
    __type(key, __u32);
    __type(value, __u32);
} blocklist SEC(".maps");

// Fragment Tracking Structure
struct frag_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 ip_id;
};

// LRU Map to track active fragmented flows
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 5000);
    __type(key, struct frag_key);
    __type(value, __u32);
} fragment_cache SEC(".maps");

// High-Speed PERCPU Drop Counters
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_metrics SEC(".maps");

// Rate Limiter State (Auto-Ban)
struct rl_state {
    __u64 last_time;
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);
    __type(value, struct rl_state);
} rate_limit_map SEC(".maps");

// 2. Telemetry Structure
struct packet_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 _padding;
    __u16 packet_size;
};

// Helper macro to increment drop count at bare-metal speed
#define INCREMENT_DROP_METRIC() \
    do { \
        __u32 key = 0; \
        __u64 *drop_count = bpf_map_lookup_elem(&drop_metrics, &key); \
        if (drop_count) { \
            *drop_count += 1; \
        } \
    } while(0)

// 3. The eBPF Hook
SEC("xdp")
int extract_network_telemetry(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // --- L2: ETHERNET ---
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    // --- L3: IP ---
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    
    __u32 src_ip = ip->saddr;

    // IP Blocklist check
    __u32 *blocked = bpf_map_lookup_elem(&blocklist, &src_ip);
    if (blocked) {
        INCREMENT_DROP_METRIC();
        return XDP_DROP;
    }

    // ----------------------------------------------------
    // ANTI-DDOS RATE LIMITER (AUTO-BAN)
    // ----------------------------------------------------
    struct rl_state *state = bpf_map_lookup_elem(&rate_limit_map, &src_ip);
    __u64 now = bpf_ktime_get_ns();
    if (state) {
        if (now - state->last_time > 1000000000ULL) { // 1 second passed
            state->last_time = now;
            state->count = 1;
        } else {
            state->count++;
            if (state->count > 1000) { // Flood detected! Drop and Auto-Ban.
                __u32 ban_val = 1;
                bpf_map_update_elem(&blocklist, &src_ip, &ban_val, BPF_ANY);
                INCREMENT_DROP_METRIC();
                return XDP_DROP;
            }
        }
    } else {
        struct rl_state new_state = { .last_time = now, .count = 1 };
        bpf_map_update_elem(&rate_limit_map, &src_ip, &new_state, BPF_ANY);
    }

    // ----------------------------------------------------
    // FRAGMENTATION DETECTION (ZERO-TRUST POLICY)
    // ----------------------------------------------------
    if (ip->frag_off & bpf_htons(IP_MF | IP_OFFSET)) {
        struct frag_key fkey = {};
        fkey.src_ip = ip->saddr;
        fkey.dst_ip = ip->daddr;
        fkey.ip_id = ip->id;

        __u32 initial_threat_state = 1;
        bpf_map_update_elem(&fragment_cache, &fkey, &initial_threat_state, BPF_ANY);
        
        INCREMENT_DROP_METRIC();
        return XDP_DROP;
    }

    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) return XDP_PASS;

    __u16 src_port = 0;
    __u16 dst_port = 0;

    // --- L4/L7: TCP DEEP PACKET INSPECTION ---
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_hdr_len;
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;

        int tcp_hdr_len = tcp->doff * 4;
        if (tcp_hdr_len < sizeof(struct tcphdr)) return XDP_PASS;

        src_port = tcp->source;
        dst_port = tcp->dest;

        unsigned char *payload = (unsigned char *)tcp + tcp_hdr_len;
        if ((void *)(payload + 4) > data_end) goto emit_telemetry;

        __u32 *payload_word = (__u32 *)payload;
        if (*payload_word == 0x444E5750) {
            INCREMENT_DROP_METRIC();
            return XDP_DROP; // "PWND"
        }

    // --- L4/L7: UDP DEEP PACKET INSPECTION ---
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_hdr_len;
        if ((void *)(udp + 1) > data_end) return XDP_PASS;

        src_port = udp->source;
        dst_port = udp->dest;

        unsigned char *payload = (unsigned char *)udp + sizeof(struct udphdr);
        if ((void *)(payload + 4) > data_end) goto emit_telemetry;

        __u32 *payload_word = (__u32 *)payload;
        if (*payload_word == 0x444E5750) {
            INCREMENT_DROP_METRIC();
            return XDP_DROP; // "PWND"
        }
    } else {
        return XDP_PASS;
    }

emit_telemetry: ;
    // --- L7: TELEMETRY EXPORT ---
    struct packet_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(struct packet_event), 0);
    if (!event) return XDP_PASS;

    event->src_ip = ip->saddr;
    event->dst_ip = ip->daddr;
    event->src_port = src_port;
    event->dst_port = dst_port;
    event->protocol = ip->protocol;
    event->packet_size = data_end - data;

    bpf_ringbuf_submit(event, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";