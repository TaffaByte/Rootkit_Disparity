/* SPDX-License-Identifier: GPL-2.0 */
/*
 * detector.bpf.c - Layer 1, in-kernel ground truth.
 *
 * Collects state from immutable kernel structures that a userland getdents64
 * rootkit cannot forge, and hands it to the userspace reconciliation engine:
 *
 *   PROCESSES: tp/sched/sched_switch records every pid that is actually placed
 *     on a CPU runqueue into `sched_pids`. A scheduled pid that does not appear
 *     in a /proc walk is a hidden task.
 *
 *   FILES: fentry/vfs_open and kprobe/ext4_lookup record (parent_ino, name)
 *     pairs the kernel actually resolved on disk, streamed over a ring buffer.
 *     A resolved entry missing from the directory's getdents64 listing is a
 *     hidden file.
 *
 * All reads use CO-RE (BPF_CORE_READ) so one binary relocates across kernels.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "../common.h"

char LICENSE[] SEC("license") = "GPL";

/* ground-truth live/scheduled pids (pid -> last sched_event) */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct sched_event);
} sched_pids SEC(".maps");

/* stream of resolved directory entries to userspace */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);   /* 1 MiB */
} file_events SEC(".maps");

static __always_inline void record_sched(__u32 pid, __u32 tgid, const char *src)
{
	struct sched_event ev = {};

	if (pid == 0)
		return;
	ev.ts_ns = bpf_ktime_get_ns();
	ev.pid = pid;
	ev.tgid = tgid;
	bpf_probe_read_kernel_str(ev.comm, sizeof(ev.comm), src);
	bpf_map_update_elem(&sched_pids, &pid, &ev, BPF_ANY);
}

SEC("tp/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
	/* next_pid is the task about to run; record it as "scheduled". */
	record_sched((__u32)ctx->next_pid, 0, ctx->next_comm);
	return 0;
}

/* emit a file_event from a dentry + its parent directory inode */
static __always_inline void emit_file(struct dentry *dentry, __u64 parent_ino)
{
	struct file_event *e;
	struct qstr dn;
	__u64 ino = 0;

	e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
	if (!e)
		return;

	e->ts_ns = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->parent_ino = parent_ino;

	dn = BPF_CORE_READ(dentry, d_name);
	bpf_probe_read_kernel_str(e->name, sizeof(e->name), dn.name);

	ino = BPF_CORE_READ(dentry, d_inode, i_ino);
	e->ino = ino;

	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
}

/* fentry/vfs_open(const struct path *path, struct file *file) */
SEC("fentry/vfs_open")
int BPF_PROG(on_vfs_open, const struct path *path, struct file *file)
{
	struct dentry *dentry = BPF_CORE_READ(path, dentry);
	__u64 parent_ino = BPF_CORE_READ(dentry, d_parent, d_inode, i_ino);

	emit_file(dentry, parent_ino);
	return 0;
}

/* kprobe ext4_lookup(struct inode *dir, struct dentry *dentry, unsigned flags) */
SEC("kprobe/ext4_lookup")
int BPF_KPROBE(on_ext4_lookup, struct inode *dir, struct dentry *dentry,
	       unsigned int flags)
{
	__u64 parent_ino = BPF_CORE_READ(dir, i_ino);

	emit_file(dentry, parent_ino);
	return 0;
}
