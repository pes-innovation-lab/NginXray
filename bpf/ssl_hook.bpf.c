#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_BUF_SIZE 8192

// each buf read and obtained
struct ssl_buf {
    __u32 tid;
    __u32 len;
    __u8 buf[MAX_BUF_SIZE];
};

// to contain pointers to ssl bufs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
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

    // convert into useable pointer
    __u64 bufp = (__u64)buf;

    bpf_map_update_elem(&bufs, &tid, &bufp, BPF_ANY);
    return 0;
}

SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write_entry, void *ssl, void *buf, int num) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 bufp = (__u64)buf;

    bpf_map_update_elem(&bufs, &tid, &bufp, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(ssl_read_exit) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    // obtain associated buf pointer
    __u64 *bufp = bpf_map_lookup_elem(&bufs, &tid);
    if (!bufp)
        return 0;

    int len = PT_REGS_RC(ctx);
    if (len <= 0) {
        bpf_map_delete_elem(&bufs, &tid);
        return 0;
    }

    // prevent copying beyond buffer size
    if (len > MAX_BUF_SIZE)
        len = MAX_BUF_SIZE;

    // use ssl_data struct to reserve space
    struct ssl_buf *e =
        bpf_ringbuf_reserve(&ringbuf, sizeof(struct ssl_buf), 0);

    if (!e) {
        bpf_map_delete_elem(&bufs, &tid);
        return 0;
    }

    e->tid = tid;
    e->len = len;

    bpf_probe_read_user(e->buf, len, (void *)*bufp);

    // copy to ringbuffer and delete in hash
    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&bufs, &tid);

    return 0;
}

SEC("uretprobe/SSL_write")
int BPF_URETPROBE(ssl_write_exit) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    __u64 *bufp = bpf_map_lookup_elem(&bufs, &tid);
    if (!bufp)
        return 0;

    int len = PT_REGS_RC(ctx);
    if (len <= 0) {
        bpf_map_delete_elem(&bufs, &tid);
        return 0;
    }

    if (len > MAX_BUF_SIZE)
        len = MAX_BUF_SIZE;

    struct ssl_buf *e =
        bpf_ringbuf_reserve(&ringbuf, sizeof(struct ssl_buf), 0);

    if (!e) {
        bpf_map_delete_elem(&bufs, &tid);
        return 0;
    }

    e->tid = tid;
    e->len = len;

    bpf_probe_read_user(e->buf, len, (void *)*bufp);

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&bufs, &tid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
