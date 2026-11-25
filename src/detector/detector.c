// SPDX-License-Identifier: GPL-2.0
/*
 * detector.c - Layer 2, the out-of-band reconciliation engine.
 *
 * Drains the kernel ground truth produced by detector.bpf.c and, on a fixed
 * cadence, compares it against what userland getdents64 is willing to report:
 *
 *   Delta_anomaly = Entities(kernel ground truth) \ Entities(getdents64 view)
 *
 * A pid that is being scheduled but is missing from a /proc walk, or a file the
 * kernel resolved on disk but that is missing from its directory listing, is
 * flagged. Each flag is confirmed out-of-band (kill(pid,0) / faccessat) and must
 * persist for --confirm scans before it is reported, which suppresses the
 * benign races that high-churn workloads create.
 *
 * Alerts are written as one JSON object per line to --out (and stdout), with a
 * wall-clock timestamp the benchmark harness uses to compute MTTD.
 *
 * Usage:
 *   sudo ./detector --watch /proc --watch /opt/demo [--interval-ms 250]
 *                   [--confirm 2] [--out results/alerts.jsonl]
 */
#include <argp.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "common.h"
#include "detector.skel.h"

#define MAX_WATCH   16
#define GT_CAP      8192     /* ground-truth file table capacity */
#define BUF_SZ      (1 << 16)

/* ---- local getdents64 (bypass libc readdir caching) -------------------- */
struct linux_dirent64 {
	unsigned long long d_ino;
	long long          d_off;
	unsigned short     d_reclen;
	unsigned char      d_type;
	char               d_name[];
};
static long sys_getdents64(int fd, void *buf, size_t n)
{
	return syscall(SYS_getdents64, fd, buf, n);
}

/* ---- ground-truth file table: (parent_ino, name) -> last seen ---------- */
struct gt_file {
	int        used;
	__u64      parent_ino;
	__u64      last_ns;
	int        strikes;        /* consecutive scans seen hidden */
	int        reported;
	char       name[MAX_NAME_LEN];
};
static struct gt_file gt[GT_CAP];

/* ---- hidden-pid tracking for strike counting --------------------------- */
struct pid_strike { __u32 pid; int strikes; int reported; };
static struct pid_strike pstk[GT_CAP];

/* Candidate snapshot: sched_pids entries that are alive and not us.
 * Captured BEFORE the fresh /proc scan so the two views are maximally
 * close in time (kills the daemon-fork TOCTOU false positive). */
struct pid_cand {
	__u32 pid;
	char  comm[TASK_COMM_LEN];
};
static struct pid_cand candidates[65536];

/* ---- watched dirs ------------------------------------------------------ */
struct watch { char path[256]; int is_proc; __u64 ino; };
static struct watch watches[MAX_WATCH];
static int n_watch;

/* ---- cli env ----------------------------------------------------------- */
static struct env {
	int interval_ms;
	int confirm;
	const char *out;
	const char *scenario;
} env = { .interval_ms = 250, .confirm = 2, .out = NULL, .scenario = "live" };

static volatile sig_atomic_t stop;
static void on_sigint(int sig) { stop = 1; }
static FILE *outf;

const char *argp_program_version = "detector 1.0";
static const char doc[] = "Cross-layer disparity detection engine.";
static const struct argp_option opts[] = {
	{ "watch",       'w', "DIR", 0, "Directory to reconcile (repeatable; /proc => pid mode)" },
	{ "interval-ms", 't', "MS",  0, "Reconciliation cadence (default 250)" },
	{ "confirm",     'c', "N",   0, "Scans a disparity must persist before alert (default 2)" },
	{ "out",         'o', "FILE",0, "Append JSONL alerts to FILE" },
	{ "scenario",    's', "STR", 0, "Scenario label recorded in each alert" },
	{},
};
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'w':
		if (n_watch < MAX_WATCH) {
			snprintf(watches[n_watch].path, sizeof(watches[0].path), "%s", arg);
			watches[n_watch].is_proc = (strcmp(arg, "/proc") == 0);
			n_watch++;
		}
		break;
	case 't': env.interval_ms = atoi(arg); break;
	case 'c': env.confirm = atoi(arg); break;
	case 'o': env.out = arg; break;
	case 's': env.scenario = arg; break;
	default: return ARGP_ERR_UNKNOWN;
	}
	return 0;
}
static const struct argp argp = { opts, parse_opt, NULL, doc };

static double wall_now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void alert(const char *type, const char *name, long id, __u64 pino)
{
	char line[512];
	snprintf(line, sizeof(line),
		 "{\"ts\":%.6f,\"type\":\"%s\",\"name\":\"%s\",\"id\":%ld,"
		 "\"parent_ino\":%llu,\"scenario\":\"%s\"}",
		 wall_now(), type, name, id, (unsigned long long)pino, env.scenario);
	printf("[ALERT] %s\n", line);
	fflush(stdout);
	if (outf) { fprintf(outf, "%s\n", line); fflush(outf); }
}

/* ---- ground-truth file table helpers ----------------------------------- */
static unsigned hash_gt(__u64 pino, const char *name)
{
	unsigned h = 2166136261u ^ (unsigned)pino;
	for (const char *p = name; *p; p++) h = (h ^ (unsigned char)*p) * 16777619u;
	return h % GT_CAP;
}
static void gt_upsert(__u64 pino, const char *name, __u64 ns)
{
	if (!name[0]) return;
	unsigned h = hash_gt(pino, name);
	for (int i = 0; i < GT_CAP; i++) {
		struct gt_file *g = &gt[(h + i) % GT_CAP];
		if (g->used && g->parent_ino == pino && !strcmp(g->name, name)) {
			g->last_ns = ns; return;
		}
		if (!g->used) {
			g->used = 1; g->parent_ino = pino; g->last_ns = ns;
			g->strikes = 0; g->reported = 0;
			snprintf(g->name, sizeof(g->name), "%s", name);
			return;
		}
	}
}

/* ringbuf callback: stash resolved entries into the ground-truth table */
static int on_event(void *ctx, void *data, size_t sz)
{
	struct file_event *e = data;
	gt_upsert(e->parent_ino, e->name, e->ts_ns);
	return 0;
}

/* enumerate a directory with raw getdents64; call cb(name,d_type) per entry */
static int enum_dir(const char *path, void (*cb)(const char *, int, void *), void *arg)
{
	char buf[BUF_SZ];
	int fd = open(path, O_RDONLY | O_DIRECTORY);
	if (fd < 0) return -1;
	for (;;) {
		long n = sys_getdents64(fd, buf, sizeof(buf));
		if (n <= 0) break;
		for (long off = 0; off < n;) {
			struct linux_dirent64 *d = (void *)(buf + off);
			cb(d->d_name, d->d_type, arg);
			off += d->d_reclen;
		}
	}
	close(fd);
	return 0;
}

/* ---- /proc pid reconciliation ------------------------------------------ */
static struct pid_strike *pstk_get(__u32 pid)
{
	unsigned h = pid % GT_CAP;
	for (int i = 0; i < GT_CAP; i++) {
		struct pid_strike *p = &pstk[(h + i) % GT_CAP];
		if (p->pid == pid) return p;
		if (p->pid == 0) { p->pid = pid; return p; }
	}
	return NULL;
}

static void reconcile_pids(struct detector_bpf *skel)
{
	int mfd = bpf_map__fd(skel->maps.sched_pids);
	__u32 key = 0, next;
	struct sched_event ev;
	int n_cand = 0;

	/* Phase 1: gather alive candidates from the kernel ground-truth map.
	 * We do NOT take the /proc snapshot yet — that would reintroduce the
	 * race (child forked after snapshot but before map walk). */
	int have = (bpf_map_get_next_key(mfd, NULL, &key) == 0);
	while (have) {
		int more = (bpf_map_get_next_key(mfd, &key, &next) == 0);
		if (bpf_map_lookup_elem(mfd, &key, &ev) == 0) {
			__u32 pid = key;
			if (pid != (__u32)getpid() && kill(pid, 0) == 0 &&
			    n_cand < 65536) {
				candidates[n_cand].pid = pid;
				memcpy(candidates[n_cand].comm, ev.comm, TASK_COMM_LEN);
				n_cand++;
			}
		}
		key = next;
		have = more;
	}

	/* Phase 2: fresh /proc snapshot, taken AFTER candidate collection so
	 * any PID in `candidates` had its /proc entry created in the interim. */
	n_visible = 0;
	enum_dir("/proc", collect_pid, NULL);

	/* Phase 3: reconcile. Visible => reset strikes/reported (handles
	 * pulse-off and PID recycle). Hidden and not yet reported => strike.
	 * Hidden and already reported => silent (no alert spam). */
	for (int i = 0; i < n_cand; i++) {
		__u32 pid = candidates[i].pid;
		struct pid_strike *p = pstk_get(pid);
		if (!p)
			continue;

		if (pid_visible(pid)) {
			p->strikes  = 0;
			p->reported = 0;
		} else if (!p->reported) {
			if (++p->strikes >= env.confirm) {
				alert("hidden_pid", candidates[i].comm, pid, 0);
				p->reported = 1;
			}
		}
	}
}

/* ---- file reconciliation for one watched dir --------------------------- */
static char  vis_names[4096][MAX_NAME_LEN];
static int   n_vis;
static void collect_name(const char *name, int type, void *arg)
{
	if (!strcmp(name, ".") || !strcmp(name, "..")) return;
	if (n_vis < 4096)
		snprintf(vis_names[n_vis++], MAX_NAME_LEN, "%s", name);
}
static int name_visible(const char *name)
{
	for (int i = 0; i < n_vis; i++) if (!strcmp(vis_names[i], name)) return 1;
	return 0;
}

static void reconcile_files(struct watch *w)
{
	int dfd = open(w->path, O_RDONLY | O_DIRECTORY);
	if (dfd < 0)
		return;

	n_vis = 0;
	enum_dir(w->path, collect_name, NULL);

	for (int i = 0; i < GT_CAP; i++) {
		struct gt_file *g = &gt[i];
		if (!g->used || g->parent_ino != w->ino)
			continue;

		/* Still on disk (open-by-name is not hidden by getdents
		 * tampering) AND absent from the raw listing => hidden.
		 * f_exists==0 means deleted or renamed away => benign, reset. */
		int f_exists = (faccessat(dfd, g->name, F_OK, 0) == 0);

		if (!f_exists) {
			/* Deleted or renamed on disk — reset tracking. The
			 * gt[] entry stays so future re-creations are picked
			 * up by the ringbuf callback (gt_upsert updates it). */
			g->strikes  = 0;
			g->reported = 0;
		} else if (!name_visible(g->name)) {
			if (!g->reported) {
				if (++g->strikes >= env.confirm) {
					alert("hidden_file", g->name, 0, g->parent_ino);
					g->reported = 1;
				}
			}
		} else {
			/* Visible again — rootkit pulsed off, or this is a
			 * fresh file that happens to share the name. Reset so
			 * a re-hide fires a fresh alert. */
			g->strikes  = 0;
			g->reported = 0;
		}
	}
	close(dfd);
}

int main(int argc, char **argv)
{
	struct detector_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err) return err;
	if (n_watch == 0) {
		fprintf(stderr, "no --watch dirs given\n");
		return 2;
	}
	for (int i = 0; i < n_watch; i++) {
		struct stat st;
		if (!watches[i].is_proc && stat(watches[i].path, &st) == 0)
			watches[i].ino = st.st_ino;
	}
	if (env.out) {
		outf = fopen(env.out, "a");
		if (!outf) fprintf(stderr, "warn: cannot open %s\n", env.out);
	}

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	skel = detector_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "open/load failed\n"); return 1; }
	err = detector_bpf__attach(skel);
	if (err) { fprintf(stderr, "attach failed: %d\n", err); goto cleanup; }

	rb = ring_buffer__new(bpf_map__fd(skel->maps.file_events), on_event, NULL, NULL);
	if (!rb) { fprintf(stderr, "ringbuf failed\n"); goto cleanup; }

	signal(SIGINT, on_sigint);
	signal(SIGTERM, on_sigint);
	printf("[detector] watching %d dir(s), interval=%dms confirm=%d scenario=%s\n",
	       n_watch, env.interval_ms, env.confirm, env.scenario);

	while (!stop) {
		ring_buffer__poll(rb, env.interval_ms);   /* drains + paces */
		for (int i = 0; i < n_watch; i++) {
			if (watches[i].is_proc) reconcile_pids(skel);
			else                    reconcile_files(&watches[i]);
		}
	}
	printf("\n[detector] stopped.\n");

cleanup:
	ring_buffer__free(rb);
	detector_bpf__destroy(skel);
	if (outf) fclose(outf);
	return err != 0;
}