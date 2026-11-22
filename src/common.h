/* SPDX-License-Identifier: GPL-2.0 */
/*
 * common.h - structures shared between BPF programs and userspace loaders.
 *
 * Cross-Layer Disparity Detection
 * Operating Systems (Fall 2026), Habib University.
 *
 * This header is included by both the restricted BPF C sources (compiled with
 * clang -target bpf) and the normal userspace loaders (compiled with gcc), so
 * it must stay free of libc and kernel headers and use only fixed-width ints.
 */
#ifndef __COMMON_H
#define __COMMON_H

/*
 * BPF sources include vmlinux.h first, which defines __u32/__u64. When this
 * header is pulled into a normal userspace loader (no vmlinux.h), fetch the
 * same fixed-width kernel types from the system headers.
 */
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define TASK_COMM_LEN 16
#define MAX_NAME_LEN  64

/*
 * file_event: emitted by the detector's ground-truth probes (vfs_open /
 * ext4_lookup) every time the kernel actually resolves a directory entry.
 * The reconciliation engine compares the set of (parent_ino, name) pairs seen
 * here against what userland getdents64 is willing to report.
 */
struct file_event {
	__u64 ts_ns;        /* bpf_ktime_get_ns() at the probe              */
	__u64 parent_ino;   /* inode number of the containing directory     */
	__u64 ino;          /* inode number of the entry itself (0 if n/a)  */
	__u32 pid;          /* pid that triggered the lookup                */
	char  name[MAX_NAME_LEN];
	char  comm[TASK_COMM_LEN];
};

/*
 * sched_event: ground truth that a pid was actually placed on a CPU runqueue.
 * Harvested from tracepoint sched:sched_switch. A pid present here but absent
 * from a /proc enumeration is a candidate hidden task.
 */
struct sched_event {
	__u64 ts_ns;        /* last time this pid was scheduled             */
	__u32 pid;
	__u32 tgid;
	char  comm[TASK_COMM_LEN];
};

/*
 * rk_config: runtime configuration for the adversarial rootkit, written by its
 * userspace loader into a single-entry BPF array map. Exposing `enabled` lets
 * the loader toggle the hook on and off to emulate "pulsed" (intermittent
 * unhooking) evasion without reloading the program.
 */
struct rk_config {
	__u32 enabled;              /* 1 = hook active, 0 = pass-through     */
	__u32 hide_pid;            /* a /proc PID to hide, 0 = none          */
	__u32 prefix_len;          /* length of prefix below                 */
	char  prefix[MAX_NAME_LEN]; /* hide dir entries starting with this   */
};

#endif /* __COMMON_H */
