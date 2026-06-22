#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD

#define RATE 1000ULL //must be smaller than NS_PER_SEC
#define BURST 1000ULL

#define NS_PER_SEC 1000000000ULL
#define NS_PER_TOKEN (NS_PER_SEC / RATE)

// ip key
struct lpm_key {
  __u32 prefixlen;
  __u32 ip;
};
struct lpm_keyipv6 {
  __u32 prefixlen;
  __u8 ip[16];
};

struct block_info {
    __u64 expires_at_ns;
    __u64 hit_count;
    __u32 reason;
};
enum block_reason {
    BLOCK_MANUAL     = 0,
    BLOCK_RATELIMIT  = 1,
    BLOCK_L7_DETECT  = 2,
    BLOCK_THREATFEED = 3,
    BLOCK_DDOS_PROTECT  = 4,
};

// longest prefix match trie
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 1024);
  __uint(map_flags, BPF_F_NO_PREALLOC);

  __type(key, struct lpm_key);
  __type(value, struct block_info);
} lpm_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 1024);
  __uint(map_flags, BPF_F_NO_PREALLOC);

  __type(key, struct lpm_keyipv6);
  __type(value, struct block_info);
} lpm_map_ipv6 SEC(".maps");

struct buckets{
    __u64 last_updated_at;
    __u64 tokens;
};

struct{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);

    __type(key, __u32);
    __type(value, struct buckets);
} ratelimit_per_ipv4 SEC(".maps");

static __always_inline int check_block(struct block_info *blocked, __u64 now) {
  if (!blocked)
    return XDP_PASS;

  //__u64 now = bpf_ktime_get_ns();
  if (blocked->expires_at_ns && now > blocked->expires_at_ns)
    return XDP_PASS;

  bpf_printk("DROP reason=%d", blocked->reason);
  __sync_fetch_and_add(&blocked->hit_count, 1);
  return XDP_DROP;
} //this common for both ipv4 and ipv6

static __always_inline int check_ratelim(__u32 req_ip, __u64 now) {
    struct buckets *req_buck = bpf_map_lookup_elem(&ratelimit_per_ipv4, &req_ip);
    // if the bucket doesnt exist -- new ip
    if (!req_buck){
        // default bucket values
        struct buckets new_bucket ={
            .last_updated_at = now,
            .tokens = BURST-1,
        };

        //inserting into map
        bpf_map_update_elem(
            &ratelimit_per_ipv4,
            &req_ip,
            &new_bucket,
            BPF_NOEXIST
        );

        return XDP_PASS;
    }

    // time spent and tokens accumulated
    __u64 elapsed = now - req_buck->last_updated_at;
    __u64 new_tokens = elapsed / NS_PER_TOKEN;

    // if new tokens was generated
    if (new_tokens > 0) {

        // update tokens
        req_buck->tokens += new_tokens;

        // limits max tokens at any instant to BURST value
        if (req_buck->tokens > BURST)
            req_buck->tokens = BURST;

        // allows us to retain the remainder
        req_buck->last_updated_at +=
            new_tokens * NS_PER_TOKEN;
    }

    // if no free tokens
    if (req_buck->tokens == 0)
        return XDP_DROP;

    // 1 token consumed
    req_buck ->tokens--;

    return XDP_PASS;
}

// define xdp section
SEC("xdp")
int filter(struct xdp_md *ctx) {

  __u64 now = bpf_ktime_get_ns();

  // cast it into a long pointer
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth = data;

  // check if packet shape is correct
  if ((void *)(eth + 1) > data_end)
    return XDP_PASS;

  // ipv4
  if (eth->h_proto == bpf_htons(ETH_P_IP)){
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
      return XDP_PASS;
    // bpf_printk("src=%x", bpf_ntohl(ip->saddr));
    struct lpm_key key = {};
    key.prefixlen = 32;
    key.ip = ip->saddr;

    int block_status = check_block(bpf_map_lookup_elem(&lpm_map, &key),now);
    if (block_status == XDP_DROP){
        return XDP_DROP;
    }

    return check_ratelim(ip->saddr, now);
  }

  // ipv6
  else if (eth->h_proto == bpf_htons(ETH_P_IPV6)){
    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
      return XDP_PASS;
    // bpf_printk("ipv6 packet received"); //printing the entire thing is pain, plus we'll have to remove this anyways for benchmarking
    struct lpm_keyipv6 key6 = {};
    key6.prefixlen = 128;
    __builtin_memcpy(key6.ip, ip6->saddr.in6_u.u6_addr8, 16);
    return check_block(bpf_map_lookup_elem(&lpm_map_ipv6, &key6),now);
  }
  else //neither ipv4 nor ipv6, pass
    return XDP_PASS;
}


char LICENSE[] SEC("license") = "GPL";
