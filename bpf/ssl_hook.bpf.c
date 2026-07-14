#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define MAX_BUF_SIZE 8192
#define DIR_SEND 0
#define DIR_RECV 1
#define DIR_CLOSE 2

#define AF_INET_ 2
#define AF_INET6_ 10

struct ssl_buf {
    __u64 timens;
    __u32 tid;
    __u32 pid;
    __u32 len;
    __u32 dir;
    __u64 ssl_ptr;
    __u16 family;
    __u16 client_port;
    __u16 server_port;
    __u8 client_ip[16];
    __u8 server_ip[16];
    __u8 buf[MAX_BUF_SIZE];
};

// used to pass info from uprobe to uretprobe via the bufs buffer
struct ssl_state {
    __u64 buf;
    __u64 ssl;
};


struct conn_info {
    __u16 family;
    __u16 client_port;
    __u16 server_port;
    __u8 client_ip[16];
    __u8 server_ip[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32); // tid
    __type(value, struct ssl_state);
} bufs SEC(".maps");

// hashmaps to obtain socket info and associate it to a sslpt
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32); // tid
    __type(value, struct conn_info);
} tid_to_conn SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, int); // fd
    __type(value, struct conn_info);
} fd_to_conn SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64); // sslptr
    __type(value, struct conn_info);
} ssl_to_conn SEC(".maps");

// ringbuffer that the go daemon will read from
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8192 * 128);
} ringbuf SEC(".maps");

// only capture nginx traffic
static __always_inline int is_target(void) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    return comm[0] == 'n' && comm[1] == 'g' && comm[2] == 'i' &&
           comm[3] == 'n' && comm[4] == 'x' && comm[5] == '\0';
}

// probes to store plaintext and key by tid
SEC("uprobe/SSL_read")
int BPF_UPROBE(ssl_read_entry, void *ssl, void *buf, int num) {
    if (!is_target())
        return 0;

    // tid = the id of the thread which is pid but naming it as tid
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    // store sslstate in buffer for later use
    struct ssl_state s;
    s.buf = (__u64)buf;
    s.ssl = (__u64)ssl;

    // store state in hashmap
    bpf_map_update_elem(&bufs, &tid, &s, BPF_ANY);
    return 0;
}

SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write_entry, void *ssl, void *buf, int num) {
    if (!is_target())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    struct ssl_state s;
    s.buf = (__u64)buf;
    s.ssl = (__u64)ssl;

    bpf_map_update_elem(&bufs, &tid, &s, BPF_ANY);
    return 0;
}

SEC("uprobe/SSL_free")
int BPF_UPROBE(ssl_free_entry, void *ssl) {
    if (!is_target())
        return 0;

    struct ssl_buf *e =
        bpf_ringbuf_reserve(&ringbuf, sizeof(struct ssl_buf), 0);
    if (!e)
        return 0;
    e->timens = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = (__u32)bpf_get_current_pid_tgid();
    e->len = 0;
    e->dir = DIR_CLOSE;
    e->ssl_ptr = (__u64)ssl;
    e->family = 0;
    e->client_port = 0;
    e->server_port = 0;
    __builtin_memset(e->client_ip, 0, sizeof(e->client_ip));
    __builtin_memset(e->server_ip, 0, sizeof(e->server_ip));
    bpf_ringbuf_submit(e, 0);

    __u64 ssl_key = (__u64)ssl;
    bpf_map_delete_elem(&ssl_to_conn, &ssl_key);
    return 0;
}

// exit probes to obtain plaintext from hash buffer along with connection info
SEC("uretprobe/SSL_read")
int BPF_URETPROBE(ssl_read_exit) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 pid = pid_tgid >> 32;

    // obtain associated buffer pointer
    struct ssl_state *s = bpf_map_lookup_elem(&bufs, &tid);
    if (!s)
        return 0;

    // get the return value of the symbol
    long ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0) {
        bpf_map_delete_elem(&bufs, &tid);
        return 0;
    }

    // prevent copying beyond buffer size
    __u32 len = (__u32)ret;
    if (len > MAX_BUF_SIZE - 1)
        len = MAX_BUF_SIZE - 1;
    len &= (MAX_BUF_SIZE - 1);

    // reserve space for sslevent
    struct ssl_buf *e =
        bpf_ringbuf_reserve(&ringbuf, sizeof(struct ssl_buf), 0);
    if (!e) {
        bpf_map_delete_elem(&bufs, &tid);
        return 0;
    }
    // package the ssl buffer event and submit to ringbuffer
    e->timens = bpf_ktime_get_ns();
    e->pid = pid;
    e->tid = tid;
    e->len = len;
    e->dir = DIR_RECV;
    e->ssl_ptr = (__u64)s->ssl;
    bpf_probe_read_user(e->buf, len, (void *)s->buf);

    // obtain connection info
    struct conn_info *c = bpf_map_lookup_elem(&ssl_to_conn, &e->ssl_ptr);
    if (c) {
        e->family = c->family;
        e->client_port = bpf_ntohs(c->client_port);
        e->server_port = bpf_ntohs(c->server_port);
        __builtin_memcpy(e->client_ip, c->client_ip, 16);
        __builtin_memcpy(e->server_ip, c->server_ip, 16);
    } else {
        e->family = 0;
        e->client_port = 0;
        e->server_port = 0;
        __builtin_memset(e->client_ip, 0, 16);
        __builtin_memset(e->server_ip, 0, 16);
    }

    // submit to ringbuffer and delete in hash
    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&bufs, &tid);
    return 0;
}

SEC("uretprobe/SSL_write")
int BPF_URETPROBE(ssl_write_exit) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 pid = pid_tgid >> 32;

    struct ssl_state *s = bpf_map_lookup_elem(&bufs, &tid);
    if (!s)
        return 0;

    long ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0) {
        bpf_map_delete_elem(&bufs, &tid);
        return 0;
    }
    __u32 len = (__u32)ret;

    if (len > MAX_BUF_SIZE - 1)
        len = MAX_BUF_SIZE - 1;
    len &= (MAX_BUF_SIZE - 1);

    struct ssl_buf *e =
        bpf_ringbuf_reserve(&ringbuf, sizeof(struct ssl_buf), 0);
    if (!e) {
        bpf_map_delete_elem(&bufs, &tid);
        return 0;
    }

    e->pid = pid;
    e->timens = bpf_ktime_get_ns();
    e->tid = tid;
    e->len = len;
    e->dir = DIR_SEND;
    e->ssl_ptr = (__u64)s->ssl;
    bpf_probe_read_user(e->buf, len, (void *)s->buf);

    struct conn_info *c = bpf_map_lookup_elem(&ssl_to_conn, &e->ssl_ptr);
    if (c) {
        e->family = c->family;
        e->client_port = bpf_ntohs(c->client_port);
        e->server_port = bpf_ntohs(c->server_port);
        __builtin_memcpy(e->client_ip, c->client_ip, 16);
        __builtin_memcpy(e->server_ip, c->server_ip, 16);
    } else {
        e->family = 0;
        e->client_port = 0;
        e->server_port = 0;
        __builtin_memset(e->client_ip, 0, 16);
        __builtin_memset(e->server_ip, 0, 16);
    }

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&bufs, &tid);
    return 0;
}

// use to key connection info by tid
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept_exit, struct sock *sk) {
    // process only for nginx content
    if (!is_target())
        return 0;

    if (!sk)
        return 0;

    __u32 tid = (__u32)bpf_get_current_pid_tgid();

    struct conn_info conn = {};
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    conn.family = family;

    if (family == AF_INET6_) {
        BPF_CORE_READ_INTO(&conn.client_ip, sk, __sk_common.skc_v6_daddr);
        BPF_CORE_READ_INTO(&conn.server_ip, sk, __sk_common.skc_v6_rcv_saddr);
    } else {
        __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __builtin_memcpy(conn.client_ip, &daddr, sizeof(daddr));
        __builtin_memcpy(conn.server_ip, &saddr, sizeof(saddr));
    }

    conn.client_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
    __u16 lport = BPF_CORE_READ(sk, __sk_common.skc_num);
    conn.server_port = bpf_htons(lport);

    bpf_map_update_elem(&tid_to_conn, &tid, &conn, BPF_ANY);
    return 0;
}

// use tid to obtain connection info and key by file descriptor instead
SEC("kretprobe/__x64_sys_accept")
int BPF_KRETPROBE(accept_exit) {
    if (!is_target())
        return 0;

    __u32 tid = (__u32)bpf_get_current_pid_tgid();

    int newfd = PT_REGS_RC(ctx);
    if (newfd < 0)
        return 0;

    struct conn_info *conn = bpf_map_lookup_elem(&tid_to_conn, &tid);
    if (!conn)
        return 0;

    bpf_map_update_elem(&fd_to_conn, &newfd, conn, BPF_ANY);
    // delete elem after user
    bpf_map_delete_elem(&tid_to_conn, &tid);
    return 0;
}

SEC("kretprobe/__x64_sys_accept4")
int BPF_KRETPROBE(accept4_exit) {
    if (!is_target())
        return 0;

    __u32 tid = (__u32)bpf_get_current_pid_tgid();

    int newfd = PT_REGS_RC(ctx);
    if (newfd < 0)
        return 0;

    struct conn_info *conn = bpf_map_lookup_elem(&tid_to_conn, &tid);
    if (!conn)
        return 0;

    bpf_map_update_elem(&fd_to_conn, &newfd, conn, BPF_ANY);
    bpf_map_delete_elem(&tid_to_conn, &tid);
    return 0;
}

// finally map sslptr -> connection info
SEC("uprobe/SSL_set_fd")
int BPF_UPROBE(ssl_set_fd, void *ssl, int fd) {

    struct conn_info *conn = bpf_map_lookup_elem(&fd_to_conn, &fd);
    if (!conn)
        return 0;

    __u64 ssl_key = (__u64)ssl;

    // map will be used by read/write exit probes to obtain client/server ip and
    // port
    bpf_map_update_elem(&ssl_to_conn, &ssl_key, conn, BPF_ANY);
    bpf_map_delete_elem(&fd_to_conn, &fd);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
