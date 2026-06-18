#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

// ip key
struct lpm_key {
    __u32 prefixlen;
    __u32 ip;
};
struct block_info {
    __u64 expires_at_ns;
    __u64 hit_count;
    __u32 reason;
};
enum block_reason {
    BLOCK_MANUAL = 0,
    BLOCK_RATELIMIT = 1,
    BLOCK_L7_DETECT = 2,
    BLOCK_THREATFEED = 3,
    BLOCK_DDOS_PROTECT = 4,
};

// longest prefix match trie
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 255);
    __uint(map_flags, BPF_F_NO_PREALLOC);

    __type(key, struct lpm_key);
    __type(value, struct block_info);
} lpm_map SEC(".maps");

// define xdp section
SEC("xdp")
int filter(struct xdp_md *ctx) {
    // cast it into a long pointer
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;

    // check if packet shape is correct
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // only deal with ipv4 currently
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);

    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // traceprint ip
    bpf_printk("src=%x", bpf_ntohl(ip->saddr));
    struct lpm_key key = {};

    key.prefixlen = 32;
    key.ip = bpf_ntohl(ip->saddr);

    struct block_info *blocked;

    // get value from trie if ip exists in it
    blocked = bpf_map_lookup_elem(&lpm_map, &key);

    // print status
    if (blocked) {
        __u64 now = bpf_ktime_get_ns();
        if (blocked->expires_at_ns && now > blocked->expires_at_ns)
            return XDP_PASS;
        bpf_printk("DROP");
        __sync_fetch_and_add((long *)&blocked->hit_count, 1);
        return XDP_DROP;
    }
    bpf_printk("PASS");

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
