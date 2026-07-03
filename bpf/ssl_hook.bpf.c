#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_BUF_SIZE 8160
#define DIR_SEND 0 // send and recv dir for ssl buf
#define DIR_RECV 1

// each buf read and obtained
struct ssl_buf {
    __u64 timens;
    __u32 tid;
    __u32 pid;
    __u32 len;
    __u32 dir;
    __u64 ssl_ptr;
    __u8 buf[MAX_BUF_SIZE];
};

// used to pass info from uprobe to uretprobe via the bufs buffer
struct ssl_state {
    __u64 buf;
    __u64 ssl;
};

// to contain pointers to ssl bufs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct ssl_state);
} bufs SEC(".maps");

// ring buf to contain actual text
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8192 * 128);
} ringbuf SEC(".maps");

SEC("uprobe/SSL_read")
int BPF_UPROBE(ssl_read_entry, void *ssl, void *buf, int num) {
    // obtain process id and thread group id
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // tid = the id of the thread which is pid but naming it as tid
    __u32 tid = (__u32)pid_tgid;

    // store ssl state in buffer for later use
    struct ssl_state s;
    s.buf = (__u64)buf;
    s.ssl = (__u64)ssl;

    bpf_map_update_elem(&bufs, &tid, &s, BPF_ANY);
    return 0;
}
// will take care of what this returns later
SEC("uprobe/SSL_read_ex")
int BPF_UPROBE(ssl_readex_entry, void *ssl, void *buf, int num, size_t *read) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    struct ssl_state s;
    s.buf = (__u64)buf;
    s.ssl = (__u64)ssl;
    bpf_map_update_elem(&bufs, &tid, &s, BPF_ANY);
    return 0;
}

SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write_entry, void *ssl, void *buf, int num) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    struct ssl_state s;
    s.buf = (__u64)buf;
    s.ssl = (__u64)ssl;
    bpf_map_update_elem(&bufs, &tid, &s, BPF_ANY);
    return 0;
}

// will take care of what this returns later part 2
SEC("uprobe/SSL_write_ex")
int BPF_UPROBE(ssl_writeex_entry, void *ssl, void *buf, int num,
               size_t *write) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    struct ssl_state s;
    s.buf = (__u64)buf;
    s.ssl = (__u64)ssl;
    bpf_map_update_elem(&bufs, &tid, &s, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(ssl_read_exit) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 pid = pid_tgid >> 32;

    // obtain associated buf pointer

    struct ssl_state *s = bpf_map_lookup_elem(&bufs, &tid);
    if (!s)
        return 0;

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

    // use ssl_buf struct to reserve space
    struct ssl_buf *e =
        bpf_ringbuf_reserve(&ringbuf, sizeof(struct ssl_buf), 0);

    if (!e) {
        bpf_map_delete_elem(&bufs, &tid);
        return 0;
    }
    e->timens = bpf_ktime_get_ns();
    e->pid = pid;
    e->tid = tid;
    e->len = len;
    e->dir = DIR_RECV;
    e->ssl_ptr = (__u64)s->ssl;
    bpf_probe_read_user(e->buf, len, (void *)s->buf);
    // for debug purposes
    bpf_printk("read_exit tid=%u ret=%ld buf_ptr=%llx ssl_ptr=%llx", tid, len,
               e->buf, e->ssl_ptr);
    // copy to ringbuffer and delete in hash
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
    bpf_printk("read_exit tid=%u ret=%ld buf_ptr=%llx ssl_ptr=%llx", tid, len,
               e->buf, e->ssl_ptr);
    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&bufs, &tid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
