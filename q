[1mdiff --git a/bpf/ssl_hook.bpf.c b/bpf/ssl_hook.bpf.c[m
[1mindex b348093..15efcab 100644[m
[1m--- a/bpf/ssl_hook.bpf.c[m
[1m+++ b/bpf/ssl_hook.bpf.c[m
[36m@@ -33,7 +33,6 @@[m [mstruct ssl_state {[m
     __u64 ssl;[m
 };[m
 [m
[31m-[m
 struct conn_info {[m
     __u16 family;[m
     __u16 client_port;[m
[36m@@ -42,7 +41,6 @@[m [mstruct conn_info {[m
     __u8 server_ip[16];[m
 };[m
 [m
[31m-[m
 struct ssl_key {[m
     __u64 ssl;[m
     __u32 pid;[m
[36m@@ -366,7 +364,7 @@[m [mint BPF_KRETPROBE(accept4_exit) {[m
 // finally map sslptr -> connection info[m
 SEC("uprobe/SSL_set_fd")[m
 int BPF_UPROBE(ssl_set_fd, void *ssl, int fd) {[m
[31m-    [m
[32m+[m
     if (!is_target())[m
         return 0;[m
 [m
[1mdiff --git a/bpf/xdp_filter.bpf.c b/bpf/xdp_filter.bpf.c[m
[1mindex b606073..e68a0a6 100644[m
[1m--- a/bpf/xdp_filter.bpf.c[m
[1m+++ b/bpf/xdp_filter.bpf.c[m
[36m@@ -2,10 +2,10 @@[m
 #include <bpf/bpf_endian.h>[m
 #include <bpf/bpf_helpers.h>[m
 [m
[31m-#define ETH_P_IP   0x0800[m
[32m+[m[32m#define ETH_P_IP 0x0800[m
 #define ETH_P_IPV6 0x86DD[m
 [m
[31m-#define RATE 1000ULL //must be smaller than NS_PER_SEC[m
[32m+[m[32m#define RATE 1000ULL // must be smaller than NS_PER_SEC[m
 #define BURST 1000ULL[m
 [m
 #define NS_PER_SEC 1000000000ULL[m
[36m@@ -13,12 +13,12 @@[m
 [m
 // ip key[m
 struct lpm_key {[m
[31m-  __u32 prefixlen;[m
[31m-  __u32 ip;[m
[32m+[m[32m    __u32 prefixlen;[m
[32m+[m[32m    __u32 ip;[m
 };[m
 struct lpm_keyipv6 {[m
[31m-  __u32 prefixlen;[m
[31m-  __u8 ip[16];[m
[32m+[m[32m    __u32 prefixlen;[m
[32m+[m[32m    __u8 ip[16];[m
 };[m
 [m
 struct block_info {[m
[36m@@ -27,44 +27,44 @@[m [mstruct block_info {[m
     __u32 reason;[m
 };[m
 enum block_reason {[m
[31m-    BLOCK_MANUAL     = 0,[m
[31m-    BLOCK_RATELIMIT  = 1,[m
[31m-    BLOCK_L7_DETECT  = 2,[m
[32m+[m[32m    BLOCK_MANUAL = 0,[m
[32m+[m[32m    BLOCK_RATELIMIT = 1,[m
[32m+[m[32m    BLOCK_L7_DETECT = 2,[m
     BLOCK_THREATFEED = 3,[m
[31m-    BLOCK_DDOS_PROTECT  = 4,[m
[32m+[m[32m    BLOCK_DDOS_PROTECT = 4,[m
 };[m
 [m
 // longest prefix match trie[m
 struct {[m
[31m-  __uint(type, BPF_MAP_TYPE_LPM_TRIE);[m
[31m-  __uint(max_entries, 1024);[m
[31m-  __uint(map_flags, BPF_F_NO_PREALLOC);[m
[32m+[m[32m    __uint(type, BPF_MAP_TYPE_LPM_TRIE);[m
[32m+[m[32m    __uint(max_entries, 1024);[m
[32m+[m[32m    __uint(map_flags, BPF_F_NO_PREALLOC);[m
 [m
[31m-  __type(key, struct lpm_key);[m
[31m-  __type(value, struct block_info);[m
[32m+[m[32m    __type(key, struct lpm_key);[m
[32m+[m[32m    __type(value, struct block_info);[m
 } lpm_map SEC(".maps");[m
 struct {[m
[31m-  __uint(type, BPF_MAP_TYPE_LPM_TRIE);[m
[31m-  __uint(max_entries, 1024);[m
[31m-  __uint(map_flags, BPF_F_NO_PREALLOC);[m
[32m+[m[32m    __uint(type, BPF_MAP_TYPE_LPM_TRIE);[m
[32m+[m[32m    __uint(max_entries, 1024);[m
[32m+[m[32m    __uint(map_flags, BPF_F_NO_PREALLOC);[m
 [m
[31m-  __type(key, struct lpm_keyipv6);[m
[31m-  __type(value, struct block_info);[m
[32m+[m[32m    __type(key, struct lpm_keyipv6);[m
[32m+[m[32m    __type(value, struct block_info);[m
 } lpm_map_ipv6 SEC(".maps");[m
 [m
[31m-struct buckets{[m
[32m+[m[32mstruct buckets {[m
     __u64 last_updated_at;[m
     __u64 tokens;[m
 };[m
 [m
[31m-struct{[m
[32m+[m[32mstruct {[m
     __uint(type, BPF_MAP_TYPE_LRU_HASH);[m
     __uint(max_entries, 100000);[m
 [m
     __type(key, __u32);[m
     __type(value, struct buckets);[m
 } ratelimit_per_ipv4 SEC(".maps");[m
[31m-struct{[m
[32m+[m[32mstruct {[m
     __uint(type, BPF_MAP_TYPE_LRU_HASH);[m
     __uint(max_entries, 100000);[m
 [m
[36m@@ -73,35 +73,32 @@[m [mstruct{[m
 } ratelimit_per_ipv6 SEC(".maps");[m
 [m
 static __always_inline int check_block(struct block_info *blocked, __u64 now) {[m
[31m-  if (!blocked)[m
[31m-    return XDP_PASS;[m
[32m+[m[32m    if (!blocked)[m
[32m+[m[32m        return XDP_PASS;[m
 [m
[31m-  //__u64 now = bpf_ktime_get_ns();[m
[31m-  if (blocked->expires_at_ns && now > blocked->expires_at_ns)[m
[31m-    return XDP_PASS;[m
[32m+[m[32m    //__u64 now = bpf_ktime_get_ns();[m
[32m+[m[32m    if (blocked->expires_at_ns && now > blocked->expires_at_ns)[m
[32m+[m[32m        return XDP_PASS;[m
 [m
[31m-  bpf_printk("DROP reason=%d", blocked->reason);[m
[31m-  __sync_fetch_and_add(&blocked->hit_count, 1);[m
[31m-  return XDP_DROP;[m
[31m-} //this common for both ipv4 and ipv6[m
[32m+[m[32m    bpf_printk("DROP reason=%d", blocked->reason);[m
[32m+[m[32m    __sync_fetch_and_add(&blocked->hit_count, 1);[m
[32m+[m[32m    return XDP_DROP;[m
[32m+[m[32m} // this common for both ipv4 and ipv6[m
 [m
 static __always_inline int check_ratelim_ipv4(__u32 req_ip, __u64 now) {[m
[31m-    struct buckets *req_buck = bpf_map_lookup_elem(&ratelimit_per_ipv4, &req_ip);[m
[32m+[m[32m    struct buckets *req_buck =[m
[32m+[m[32m        bpf_map_lookup_elem(&ratelimit_per_ipv4, &req_ip);[m
     // if the bucket doesnt exist -- new ip[m
[31m-    if (!req_buck){[m
[32m+[m[32m    if (!req_buck) {[m
         // default bucket values[m
[31m-        struct buckets new_bucket ={[m
[32m+[m[32m        struct buckets new_bucket = {[m
             .last_updated_at = now,[m
[31m-            .tokens = BURST-1,[m
[32m+[m[32m            .tokens = BURST - 1,[m
         };[m
 [m
[31m-        //inserting into map[m
[31m-        bpf_map_update_elem([m
[31m-            &ratelimit_per_ipv4,[m
[31m-            &req_ip,[m
[31m-            &new_bucket,[m
[31m-            BPF_NOEXIST[m
[31m-        );[m
[32m+[m[32m        // inserting into map[m
[32m+[m[32m        bpf_map_update_elem(&ratelimit_per_ipv4, &req_ip, &new_bucket,[m
[32m+[m[32m                            BPF_NOEXIST);[m
 [m
         return XDP_PASS;[m
     }[m
[36m@@ -121,8 +118,7 @@[m [mstatic __always_inline int check_ratelim_ipv4(__u32 req_ip, __u64 now) {[m
             req_buck->tokens = BURST;[m
 [m
         // allows us to retain the remainder[m
[31m-        req_buck->last_updated_at +=[m
[31m-            new_tokens * NS_PER_TOKEN;[m
[32m+[m[32m        req_buck->last_updated_at += new_tokens * NS_PER_TOKEN;[m
     }[m
 [m
     // if no free tokens[m
[36m@@ -130,7 +126,7 @@[m [mstatic __always_inline int check_ratelim_ipv4(__u32 req_ip, __u64 now) {[m
         return XDP_DROP;[m
 [m
     // 1 token consumed[m
[31m-    req_buck ->tokens--;[m
[32m+[m[32m    req_buck->tokens--;[m
 [m
     return XDP_PASS;[m
 }[m
[36m@@ -138,20 +134,16 @@[m [mstatic __always_inline int check_ratelim_ipv4(__u32 req_ip, __u64 now) {[m
 static __always_inline int check_ratelim_ipv6(__u8 req_ip[16], __u64 now) {[m
     struct buckets *req_buck = bpf_map_lookup_elem(&ratelimit_per_ipv6, req_ip);[m
     // if the bucket doesnt exist -- new ip[m
[31m-    if (!req_buck){[m
[32m+[m[32m    if (!req_buck) {[m
         // default bucket values[m
[31m-        struct buckets new_bucket ={[m
[32m+[m[32m        struct buckets new_bucket = {[m
             .last_updated_at = now,[m
[31m-            .tokens = BURST-1,[m
[32m+[m[32m            .tokens = BURST - 1,[m
         };[m
 [m
[31m-        //inserting into map[m
[31m-        bpf_map_update_elem([m
[31m-            &ratelimit_per_ipv6,[m
[31m-            req_ip,[m
[31m-            &new_bucket,[m
[31m-            BPF_NOEXIST[m
[31m-        );[m
[32m+[m[32m        // inserting into map[m
[32m+[m[32m        bpf_map_update_elem(&ratelimit_per_ipv6, req_ip, &new_bucket,[m
[32m+[m[32m                            BPF_NOEXIST);[m
 [m
         return XDP_PASS;[m
     }[m
[36m@@ -171,8 +163,7 @@[m [mstatic __always_inline int check_ratelim_ipv6(__u8 req_ip[16], __u64 now) {[m
             req_buck->tokens = BURST;[m
 [m
         // allows us to retain the remainder[m
[31m-        req_buck->last_updated_at +=[m
[31m-            new_tokens * NS_PER_TOKEN;[m
[32m+[m[32m        req_buck->last_updated_at += new_tokens * NS_PER_TOKEN;[m
     }[m
 [m
     // if no free tokens[m
[36m@@ -180,7 +171,7 @@[m [mstatic __always_inline int check_ratelim_ipv6(__u8 req_ip[16], __u64 now) {[m
         return XDP_DROP;[m
 [m
     // 1 token consumed[m
[31m-    req_buck ->tokens--;[m
[32m+[m[32m    req_buck->tokens--;[m
 [m
     return XDP_PASS;[m
 }[m
[36m@@ -188,57 +179,60 @@[m [mstatic __always_inline int check_ratelim_ipv6(__u8 req_ip[16], __u64 now) {[m
 // define xdp section[m
 SEC("xdp")[m
 int filter(struct xdp_md *ctx) {[m
[32m+[m[32m    bpf_printk("XDP HIT");[m
[32m+[m[32m    __u64 now = bpf_ktime_get_ns();[m
 [m
[31m-  __u64 now = bpf_ktime_get_ns();[m
[31m-[m
[31m-  // cast it into a long pointer[m
[31m-  void *data_end = (void *)(long)ctx->data_end;[m
[31m-  void *data = (void *)(long)ctx->data;[m
[31m-[m
[31m-  struct ethhdr *eth = data;[m
[32m+[m[32m    // cast it into a long pointer[m
[32m+[m[32m    void *data_end = (void *)(long)ctx->data_end;[m
[32m+[m[32m    void *data = (void *)(long)ctx->data;[m
 [m
[31m-  // check if packet shape is correct[m
[31m-  if ((void *)(eth + 1) > data_end)[m
[31m-    return XDP_PASS;[m
[32m+[m[32m    struct ethhdr *eth = data;[m
 [m
[31m-  // ipv4[m
[31m-  if (eth->h_proto == bpf_htons(ETH_P_IP)){[m
[31m-    struct iphdr *ip = (void *)(eth + 1);[m
[31m-    if ((void *)(ip + 1) > data_end)[m
[31m-      return XDP_PASS;[m
[31m-    // bpf_printk("src=%x", bpf_ntohl(ip->saddr));[m
[31m-    struct lpm_key key = {};[m
[31m-    key.prefixlen = 32;[m
[31m-    key.ip = ip->saddr;[m
[31m-[m
[31m-    int block_status = check_block(bpf_map_lookup_elem(&lpm_map, &key),now);[m
[31m-    if (block_status == XDP_DROP){[m
[31m-        return XDP_DROP;[m
[31m-    }[m
[32m+[m[32m    // check if packet shape is correct[m
[32m+[m[32m    if ((void *)(eth + 1) > data_end)[m
[32m+[m[32m        return XDP_PASS;[m
 [m
[31m-    return check_ratelim_ipv4(ip->saddr, now);[m
[31m-  }[m
[31m-[m
[31m-  // ipv6[m
[31m-  else if (eth->h_proto == bpf_htons(ETH_P_IPV6)){[m
[31m-    struct ipv6hdr *ip6 = (void *)(eth + 1);[m
[31m-    if ((void *)(ip6 + 1) > data_end)[m
[31m-      return XDP_PASS;[m
[31m-    // bpf_printk("ipv6 packet received"); //printing the entire thing is pain, plus we'll have to remove this anyways for benchmarking[m
[31m-    struct lpm_keyipv6 key6 = {};[m
[31m-    key6.prefixlen = 128;[m
[31m-    __builtin_memcpy(key6.ip, ip6->saddr.in6_u.u6_addr8, 16);[m
[31m-[m
[31m-    int block_status = check_block(bpf_map_lookup_elem(&lpm_map_ipv6, &key6),now);[m
[31m-    if (block_status == XDP_DROP){[m
[31m-        return XDP_DROP;[m
[32m+[m[32m    // ipv4[m
[32m+[m[32m    if (eth->h_proto == bpf_htons(ETH_P_IP)) {[m
[32m+[m[32m        struct iphdr *ip = (void *)(eth + 1);[m
[32m+[m[32m        if ((void *)(ip + 1) > data_end)[m
[32m+[m[32m            return XDP_PASS;[m
[32m+[m[32m        // bpf_printk("src=%x", bpf_ntohl(ip->saddr));[m
[32m+[m[32m        struct lpm_key key = {};[m
[32m+[m[32m        key.prefixlen = 32;[m
[32m+[m[32m        key.ip = ip->saddr;[m
[32m+[m
[32m+[m[32m        bpf_printk("lookup=%x", key.ip);[m
[32m+[m
[32m+[m[32m        int block_status =[m
[32m+[m[32m            check_block(bpf_map_lookup_elem(&lpm_map, &key), now);[m
[32m+[m[32m        if (block_status == XDP_DROP) {[m
[32m+[m[32m            return XDP_DROP;[m
[32m+[m[32m        }[m
[32m+[m
[32m+[m[32m        return check_ratelim_ipv4(ip->saddr, now);[m
     }[m
 [m
[31m-    return check_ratelim_ipv6(key6.ip, now);[m
[31m-  }[m
[31m-  else //neither ipv4 nor ipv6, pass[m
[31m-    return XDP_PASS;[m
[32m+[m[32m    // ipv6[m
[32m+[m[32m    else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {[m
[32m+[m[32m        struct ipv6hdr *ip6 = (void *)(eth + 1);[m
[32m+[m[32m        if ((void *)(ip6 + 1) > data_end)[m
[32m+[m[32m            return XDP_PASS;[m
[32m+[m[32m        // bpf_printk("ipv6 packet received"); //printing the entire thing is[m
[32m+[m[32m        // pain, plus we'll have to remove this anyways for benchmarking[m
[32m+[m[32m        struct lpm_keyipv6 key6 = {};[m
[32m+[m[32m        key6.prefixlen = 128;[m
[32m+[m[32m        __builtin_memcpy(key6.ip, ip6->saddr.in6_u.u6_addr8, 16);[m
[32m+[m
[32m+[m[32m        int block_status =[m
[32m+[m[32m            check_block(bpf_map_lookup_elem(&lpm_map_ipv6, &key6), now);[m
[32m+[m[32m        if (block_status == XDP_DROP) {[m
[32m+[m[32m            return XDP_DROP;[m
[32m+[m[32m        }[m
[32m+[m
[32m+[m[32m        return check_ratelim_ipv6(key6.ip, now);[m
[32m+[m[32m    } else // neither ipv4 nor ipv6, pass[m
[32m+[m[32m        return XDP_PASS;[m
 }[m
 [m
[31m-[m
 char LICENSE[] SEC("license") = "GPL";[m
[1mdiff --git a/internal/analysis/analyse.go b/internal/analysis/analyse.go[m
[1mindex 29b6c7e..0cb8cde 100644[m
[1m--- a/internal/analysis/analyse.go[m
[1m+++ b/internal/analysis/analyse.go[m
[36m@@ -73,7 +73,6 @@[m [mvar cmdPatterns = []string{[m
 	"cat /etc/passwd",[m
 	"cat /etc/shadow",[m
 	"whoami",[m
[31m-	"id",[m
 	"uname -a",[m
 	"ls",[m
 	"pwd",[m
[36m@@ -107,6 +106,7 @@[m [mfunc AnalyseReq(req parser.HTTPRequest, ctx RequestContext) []Detection {[m
 	for _, detector := range detectors {[m
 		if det := detector(ctx, req); det != nil {[m
 			detections = append(detections, *det)[m
[32m+[m			[32mbreak[m
 		}[m
 	}[m
 	return detections[m
[1mdiff --git a/internal/analysis/policy.go b/internal/analysis/policy.go[m
[1mindex 6159d4b..e4dc8cb 100644[m
[1m--- a/internal/analysis/policy.go[m
[1m+++ b/internal/analysis/policy.go[m
[36m@@ -32,7 +32,7 @@[m [mfunc Decide(clientIP string, detections []Detection) Action {[m
 	}[m
 [m
 	// decide action[m
[31m-	if state.Score >= 90 {[m
[32m+[m	[32mif state.Score >= 70 {[m
 		return Block[m
 	}[m
 [m
[1mdiff --git a/internal/filter/filter.go b/internal/filter/filter.go[m
[1mindex b00c8e1..36d9947 100644[m
[1m--- a/internal/filter/filter.go[m
[1m+++ b/internal/filter/filter.go[m
[36m@@ -74,6 +74,8 @@[m [mfunc (f *Filter) AddBlocked(cidr string, duration time.Duration, reason uint32)[m
 			cidr += "/32" // bare IPv4[m
 		}[m
 	}[m
[32m+[m	[32m// debug[m
[32m+[m	[32mfmt.Println("Blocking", cidr)[m
 [m
 	_, ipnet, err := net.ParseCIDR(cidr)[m
 	if err != nil {[m
[36m@@ -88,11 +90,13 @@[m [mfunc (f *Filter) AddBlocked(cidr string, duration time.Duration, reason uint32)[m
 [m
 	if ip4 := ipnet.IP.To4(); ip4 != nil {[m
 		key := LPMKey{PrefixLen: uint32(ones), IP: binary.LittleEndian.Uint32(ip4)}[m
[32m+[m		[32mfmt.Printf("Go key: %#x\n", key.IP)[m
 		return f.objs.LpmMap.Put(key, value)[m
 	}[m
 [m
 	key := LPMKey6{PrefixLen: uint32(ones)}[m
 	copy(key.IP[:], ipnet.IP.To16())[m
[32m+[m	[32mfmt.Printf("Go key: %#x\n", key.IP)[m
 	return f.objs.LpmMapIpv6.Put(key, value)[m
 }[m
 [m
[1mdiff --git a/internal/sniffer/sniffer.go b/internal/sniffer/sniffer.go[m
[1mindex 6ca6675..5c582da 100644[m
[1m--- a/internal/sniffer/sniffer.go[m
[1m+++ b/internal/sniffer/sniffer.go[m
[36m@@ -301,6 +301,9 @@[m [mfunc main() {[m
 [m
 					action := analysis.Decide(clientIP, detections)[m
 [m
[32m+[m					[32m// debug[m
[32m+[m					[32mfmt.Println("action =", action)[m
[32m+[m
 					if action == analysis.Block {[m
 						if err := fw.AddBlocked([m
 							clientIP,[m
[36m@@ -309,7 +312,7 @@[m [mfunc main() {[m
 						); err != nil {[m
 							log.Printf("failed to block %s: %v", clientIP, err)[m
 						}[m
[31m-						continue[m
[32m+[m						[32mfw.DumpMap()[m
 					}[m
 [m
 					masking.MaskRequest(m.Request)[m
[36m@@ -350,6 +353,9 @@[m [mfunc main() {[m
 [m
 						action := analysis.Decide(clientIP, detections)[m
 [m
[32m+[m						[32m// debug[m
[32m+[m						[32mfmt.Println("action =", action)[m
[32m+[m
 						if action == analysis.Block {[m
 							if err := fw.AddBlocked([m
 								clientIP,[m
[36m@@ -358,7 +364,7 @@[m [mfunc main() {[m
 							); err != nil {[m
 								log.Printf("failed to block %s: %v", clientIP, err)[m
 							}[m
[31m-							continue[m
[32m+[m							[32mfw.DumpMap()[m
 						}[m
 [m
 						masking.MaskRequest(m.Request)[m
[36m@@ -404,6 +410,9 @@[m [mfunc main() {[m
 				// decide what to do[m
 				action := analysis.Decide(clientIP, detections)[m
 [m
[32m+[m				[32m// debug[m
[32m+[m				[32mfmt.Println("action =", action)[m
[32m+[m
 				if action == analysis.Block {[m
 					if err := fw.AddBlocked([m
 						clientIP,[m
[36m@@ -412,7 +421,7 @@[m [mfunc main() {[m
 					); err != nil {[m
 						log.Printf("failed to block %s: %v", clientIP, err)[m
 					}[m
[31m-					continue[m
[32m+[m					[32mfw.DumpMap()[m
 				}[m
 				// mask req before logging[m
 				masking.MaskRequest(req)[m
