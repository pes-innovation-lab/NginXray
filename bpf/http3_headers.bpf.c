#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define OFF_NAME       144
#define OFF_VALUE      160
#define OFF_ADDR_TEXT  120

#define NGX_OK    0
#define NGX_DONE  -4

#define MAX_NAME  128
#define MAX_VALUE 512
#define MAX_IP    64

struct req_header {
    __u64 pid_tgid;
    __u64 ts_ns;
    __u64 conn;
    __u64 req_id;
    __s32 ret;
    __u32 name_len;
    __u32 value_len;
    char  name[MAX_NAME];
    char  value[MAX_VALUE];
    __u32 ip_len;
    char  ip[MAX_IP];
};

struct probe_state {
    __u64 c_ptr;
    __u64 st_ptr;
    __u64 req_id;
};

#define HOOK_FIELD_L    0
#define HOOK_FIELD_LRI  1
#define HOOK_FIELD_LPBI 2
#define HOOK_FIELD_RI   3
#define HOOK_FIELD_PBI  4

struct res_header {
    __u64 pid_tgid;
    __u64 ts_ns;
    __u64 conn;
    __u32 hook;
    __u32 dynamic;
    __s64 index;
    __u32 name_len;
    __u32 value_len;
    char  name[MAX_NAME];
    char  value[MAX_VALUE];
    __u32 ip_len;
    char  ip[MAX_IP];
};

#define TABLE_OP_INSERT     0
#define TABLE_OP_REF_INSERT 1
#define TABLE_OP_DUPLICATE  2

struct table_event {
    __u64 pid_tgid;
    __u64 ts_ns;
    __u64 conn;
    __u32 op;
    __u32 dynamic;
    __s64 index;
    __u32 name_len;
    __u32 value_len;
    char  name[MAX_NAME];
    char  value[MAX_VALUE];
    __u32 ip_len;
    char  ip[MAX_IP];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct probe_state);
} st_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u64);
} request_id_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u64);
} pid_conn_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} req_counter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} resp_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} table_events SEC(".maps");

SEC("uprobe/ngx_http_v3_parse_headers")
int BPF_UPROBE(entry_parse_headers)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct probe_state st = {};
    st.c_ptr  = (__u64)PT_REGS_PARM1(ctx);
    st.st_ptr = (__u64)PT_REGS_PARM2(ctx);

    __u64 *existing_id = bpf_map_lookup_elem(&request_id_map, &st.c_ptr);
    if (existing_id) {
        st.req_id = *existing_id;
    } else {
        __u32 zero = 0;
        __u64 *cnt = bpf_map_lookup_elem(&req_counter_map, &zero);
        __u64 local = 0;
        if (cnt){
            __sync_fetch_and_add(cnt, 1);
            local = *cnt - 1;
        }

        st.req_id = local;

        bpf_map_update_elem(&request_id_map, &st.c_ptr, &st.req_id, BPF_ANY);
    }

    bpf_map_update_elem(&st_map, &pid_tgid, &st, BPF_ANY);
    bpf_map_update_elem(&pid_conn_map, &pid_tgid, &st.c_ptr, BPF_ANY);
    return 0;
}

static __always_inline void read_ngx_str(char *dst, __u32 dst_cap, __u32 *out_len, __u64 str_ptr)
{
    __u64 len = 0;
    __u64 data = 0;

    *out_len = 0;
    if (!str_ptr)
        return;

    bpf_probe_read_user(&len, sizeof(len), (void *)str_ptr);
    bpf_probe_read_user(&data, sizeof(data), (void *)(str_ptr + 8));

    __u32 l = (__u32)len;
    l &= (dst_cap - 1);

    if (data && l > 0) {
        long err = bpf_probe_read_user(dst, l, (void *)data);
        if (err == 0)
            *out_len = l;
    }
}

static __always_inline void read_literal(char *dst, __u32 dst_cap, __u32 *out_len, __u64 data, __u64 len)
{
    *out_len = 0;

    __u32 l = (__u32)len;
    l &= (dst_cap - 1);

    if (data && l > 0) {
        long err = bpf_probe_read_user(dst, l, (void *)data);
        if (err == 0)
            *out_len = l;
    }
}

static __always_inline void read_conn_ip(char *dst, __u32 dst_cap, __u32 *out_len, __u64 c_ptr)
{
    __u64 addr_len = 0;
    __u64 addr_data = 0;

    *out_len = 0;
    if (!c_ptr)
        return;

    bpf_probe_read_user(&addr_len, sizeof(addr_len), (void *)(c_ptr + OFF_ADDR_TEXT));
    bpf_probe_read_user(&addr_data, sizeof(addr_data), (void *)(c_ptr + OFF_ADDR_TEXT + 8));

    __u32 l = (__u32)addr_len;
    l &= (dst_cap - 1);

    if (addr_data && l > 0) {
        long err = bpf_probe_read_user(dst, l, (void *)addr_data);
        if (err == 0)
            *out_len = l;
    }
}

static __always_inline __u64 lookup_conn_by_pid(__u64 pid_tgid)
{
    __u64 *c_ptr = bpf_map_lookup_elem(&pid_conn_map, &pid_tgid);
    return c_ptr ? *c_ptr : 0;
}

SEC("uretprobe/ngx_http_v3_parse_headers")
int BPF_URETPROBE(ret_parse_headers)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct probe_state *stp = bpf_map_lookup_elem(&st_map, &pid_tgid);
    if (!stp)
        return 0;

    __u64 c_ptr  = stp->c_ptr;
    __u64 st_ptr = stp->st_ptr;
    __u64 req_id = stp->req_id;
    bpf_map_delete_elem(&st_map, &pid_tgid);

    __s32 rc = PT_REGS_RC(ctx);

    bpf_printk("uretprobe triggered");

    if (rc != NGX_OK && rc != NGX_DONE) {
        return 0;
    }

    struct req_header *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) {
        bpf_printk("ring buffer not assigned");
        return 0;
    }

    ev->pid_tgid = pid_tgid;
    ev->ts_ns = bpf_ktime_get_ns();
    ev->conn = c_ptr;
    ev->req_id = req_id;
    ev->ret = rc;
    ev->name_len = 0;
    ev->value_len = 0;
    ev->name[0] = 0;
    ev->value[0] = 0;
    ev->ip_len = 0;
    ev->ip[0] = 0;

    if (rc == NGX_OK || rc == NGX_DONE) {
        __u64 name_len = 0;
        __u64 name_data = 0;
        __u64 value_len = 0;
        __u64 value_data = 0;

        bpf_probe_read_user(&name_len, sizeof(name_len), (void *)(st_ptr + OFF_NAME));
        bpf_probe_read_user(&name_data, sizeof(name_data), (void *)(st_ptr + OFF_NAME + 8));
        bpf_probe_read_user(&value_len, sizeof(value_len), (void *)(st_ptr + OFF_VALUE));
        bpf_probe_read_user(&value_data, sizeof(value_data), (void *)(st_ptr + OFF_VALUE + 8));

        __u32 nlen = (__u32)name_len;
        __u32 vlen = (__u32)value_len;

        nlen &= (MAX_NAME - 1);
        vlen &= (MAX_VALUE - 1);

        if (name_data && nlen > 0) {
            long err = bpf_probe_read_user(&ev->name, nlen, (void *)name_data);
            if (err == 0)
                ev->name_len = nlen;
            else{
                bpf_printk("name - error with _read_user");
            }
        } else {
            bpf_printk("name - pointer failed or size error");
        }

        if (value_data && vlen > 0) {
            long err = bpf_probe_read_user(&ev->value, vlen, (void *)value_data);
            if (err == 0)
                ev->value_len = vlen;
            else{
                bpf_printk("value - error with _read_user");
            }
        } else {
            bpf_printk("value - pointer failed or size error");
        }

        __u32 iplen = 0;
        read_conn_ip(ev->ip, MAX_IP, &iplen, c_ptr);
        ev->ip_len = iplen;
    }

    if (rc == NGX_DONE) {
        bpf_map_delete_elem(&request_id_map, &c_ptr);
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("uprobe/ngx_http_v3_encode_field_lri")
int BPF_UPROBE(entry_encode_field_lri)
{
    bpf_printk("field_lri fired");
    __u64 dynamic = (__u64)PT_REGS_PARM2(ctx);
    __s64 index   = (__s64)PT_REGS_PARM3(ctx);
    __u64 data    = (__u64)PT_REGS_PARM4(ctx);
    __u64 val_len = (__u64)PT_REGS_PARM5(ctx);

    bpf_printk("field_lri fired: dynamic=%d index=%lld data=%d val_len=%lld", dynamic, index,data,val_len);

    struct res_header *ev = bpf_ringbuf_reserve(&resp_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->pid_tgid = bpf_get_current_pid_tgid();
    ev->ts_ns = bpf_ktime_get_ns();
    ev->conn = lookup_conn_by_pid(ev->pid_tgid);
    ev->hook = HOOK_FIELD_LRI;
    ev->dynamic = (__u32)dynamic;
    ev->index = index;
    ev->name_len = 0;
    ev->value_len = 0;
    ev->name[0] = 0;
    ev->value[0] = 0;

    read_literal(ev->value, MAX_VALUE, &ev->value_len, data, val_len);
    ev->ip[0] = 0;
    read_conn_ip(ev->ip, MAX_IP, &ev->ip_len, ev->conn);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("uprobe/ngx_http_v3_insert")
int BPF_UPROBE(entry_insert)
{
    __u64 c         = (__u64)PT_REGS_PARM1(ctx);
    __u64 name_ptr  = (__u64)PT_REGS_PARM2(ctx);
    __u64 value_ptr = (__u64)PT_REGS_PARM3(ctx);

    struct table_event *ev = bpf_ringbuf_reserve(&table_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->pid_tgid = bpf_get_current_pid_tgid();
    ev->ts_ns = bpf_ktime_get_ns();
    ev->conn = c;
    ev->op = TABLE_OP_INSERT;
    ev->dynamic = 0;
    ev->index = -1;
    ev->name_len = 0;
    ev->value_len = 0;
    ev->name[0] = 0;
    ev->value[0] = 0;
    ev->ip[0] = 0;

    read_ngx_str(ev->name, MAX_NAME, &ev->name_len, name_ptr);
    read_ngx_str(ev->value, MAX_VALUE, &ev->value_len, value_ptr);
    read_conn_ip(ev->ip, MAX_IP, &ev->ip_len, c);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("uprobe/ngx_http_v3_ref_insert")
int BPF_UPROBE(entry_ref_insert)
{
    __u64 c         = (__u64)PT_REGS_PARM1(ctx);
    __u64 dynamic   = (__u64)PT_REGS_PARM2(ctx);
    __s64 index     = (__s64)PT_REGS_PARM3(ctx);
    __u64 value_ptr = (__u64)PT_REGS_PARM4(ctx);

    struct table_event *ev = bpf_ringbuf_reserve(&table_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->pid_tgid = bpf_get_current_pid_tgid();
    ev->ts_ns = bpf_ktime_get_ns();
    ev->conn = c;
    ev->op = TABLE_OP_REF_INSERT;
    ev->dynamic = (__u32)dynamic;
    ev->index = index;
    ev->name_len = 0;
    ev->value_len = 0;
    ev->name[0] = 0;
    ev->value[0] = 0;
    ev->ip[0] = 0;

    read_ngx_str(ev->value, MAX_VALUE, &ev->value_len, value_ptr);
    read_conn_ip(ev->ip, MAX_IP, &ev->ip_len, c);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("uprobe/ngx_http_v3_duplicate")
int BPF_UPROBE(entry_duplicate)
{
    __u64 c     = (__u64)PT_REGS_PARM1(ctx);
    __s64 index = (__s64)PT_REGS_PARM2(ctx);

    struct table_event *ev = bpf_ringbuf_reserve(&table_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->pid_tgid = bpf_get_current_pid_tgid();
    ev->ts_ns = bpf_ktime_get_ns();
    ev->conn = c;
    ev->op = TABLE_OP_DUPLICATE;
    ev->dynamic = 1;
    ev->index = index;
    ev->name_len = 0;
    ev->value_len = 0;
    ev->name[0] = 0;
    ev->value[0] = 0;
    ev->ip[0] = 0;

    read_conn_ip(ev->ip, MAX_IP, &ev->ip_len, c);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
