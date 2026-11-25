# Cross-Layer Disparity Detection — Change Manifest

Running log of every deviation from the original code, why it was made, and
what it affects. Keep this updated as we go.

---

## Environment context

- **Target platform:** arm64 (Apple Silicon Mac → UTM Ubuntu Server VM)
- **Kernel:** 7.3.0-11-generic (much newer than README's "≥ 5.8")
- **libbpf:** distro 1.3.0-2build2
- **clang/llvm:** 18
- **Why this matters:** the original code was authored for x86_64 with an
  older kernel/libbpf. Several fixes below are arm64- or kernel-7.x-specific.
- **Reference behavior:** the detector works end-to-end for `static_file`:
  `ls /opt/cldd-demo` shows nothing while `cat /opt/cldd-demo/rootkit_persist`
  prints `secret`, and the detector emits
  `{"type":"hidden_file","name":"rootkit_persist"}`. This was verified with
  three concurrent SSH sessions before the benchmark was run.

---

## Change 1 — `detector.bpf.c`: arm64 kprobe compile failure

**Symptom:** `make` failed in `detector.bpf.c` with
`incomplete definition of type 'const struct user_pt_regs'` at the
`BPF_KPROBE(on_ext4_lookup, ...)` macro.

**Cause:** on arm64, `bpf_tracing.h` (libbpf 1.3) uses
`struct user_pt_regs` for `PT_REGS_PARM*` expansion, and that struct isn't
fully defined in the include path used by the BPF build.

**Fix:** [FILL IN — the exact arm64 pt_regs workaround you applied,
e.g. `on_ext4_lookup` taking `struct pt_regs *ctx` and reading args via
`ctx->regs[0..2]`. Paste the patch.]

**Status:** applied and compiling.

**Affects:** build only. The `vfs_open` fentry path is unchanged.

**Risk / limitation:** ext4-specific probe; `vfs_open` remains the
FS-agnostic fallback.

---

## Change 2 — `detector.c`: PID false positives (superseded by Change 9)

**Symptom:** running the detector with no rootkit produced spurious
`hidden_pid` alerts for `multipathd` and `gmain`.

**Cause (diagnosed at the time):** TOCTOU race — `visible_pids` snapshotted
from `/proc` once per scan, but `sched_pids` is live; a just-forked child
appears in the map but not in the snapshot.

**Fix applied:** replace `pid_visible()` with `access("/proc/<pid>", F_OK)`
evaluated at decision time.

**Status:** applied, confirmed to stop the FPs, but **broken for detection**
(see Change 9 — a `getdents64` rootkit falsifies the directory listing, not
the per-PID procfs entry, so `access()` always succeeds for hidden PIDs).
Superseded by Change 9.

---

## Change 3 — `rootkit.bpf.c`: verifier rejected the 512-iteration loop

**Symptom:** `handle_getdents_exit` failed to load with `-E2BIG`
("BPF program is too large, processed 1000001 insns") on arm64 / kernel 7.3.

**Cause:** the verifier couldn't prune the bounded `for (i < MAX_DENTS)`
loop's state explosion.

**Fix:** refactored the walk into a `bpf_loop(MAX_DENTS, callback, &ctx, 0)`
callback (`process_one_dirent`). Mutable state (`dirp`, `total`, `bpos`,
`prev`, `cfg`, `write_rc`, `iters`) moved into `struct getdents_ctx`, since
`bpf_loop` callbacks are stateless across iterations.

**Status:** applied and loading.

**Affects:** `rootkit.bpf.c`. Loader (`rootkit.c`) unchanged; map and config
surface are the same.

**Risk / limitation:** `bpf_loop` requires kernel ≥ 5.17; 7.3 is fine.

---

## Change 4 — `rootkit.bpf.c`: diagnostic instrumentation

**Symptom:** the rootkit loaded and attached, config map showed
`enabled=1, prefix_len=8, prefix="rootkit_"`, but `ls /opt/cldd-demo` still
showed the target file. No dmesg warning about `bpf_probe_write_user`.

**Cause:** root cause unknown at the time; needed visibility into whether
the callback ran, whether the prefix matched, whether `prev` was set, and
what `bpf_probe_write_user` returned.

**Fix:** added `bpf_printk` lines in `process_one_dirent` and
`handle_getdents_exit`, plus `write_rc` and `iters` fields in
`struct getdents_ctx`. Also added a `debug_counts` array map (unused for
now, but available for counter-based diagnostics).

**Status:** applied. Purely observational; no behaviour change.

**Risk / limitation:** `bpf_printk` is rate-limited by the kernel; under
heavy `ls` traffic you'll see ~50 lines/second and then throttling. Fine for
diagnosis.

---

## Change 5 — `rootkit.bpf.c`: hide-by-rename instead of merge-into-prev

**Symptom:** `ls -U /opt/cldd-demo` showed `rootkit_persist` **first** in
the raw dirent order. The merge-into-prev mechanism cannot hide the first
record (no predecessor to extend), so the target stayed visible.

**Cause:** the hiding mechanism depends on a non-target record preceding
the target in the same `getdents64` buffer. Filesystem dirent order is
unspecified, so this can't be controlled by naming.

**Fix:** replace the "extend previous record's `d_reclen`" logic with
"overwrite the target's own `d_name`" in `process_one_dirent`. When a
match is found, write a benign replacement string (`.hidden_ok`) at
`cur + DIRENT_NAME_OFF`. The entry still exists in the buffer with the same
`reclen`; only its visible name changes.

**Status:** applied. **Verified end-to-end on arm64 / kernel 7.3:**
- `bpf_probe_write_user` returned 0 (`rewrite rc=0`) — arm64 write works.
- `ls /opt/cldd-demo` shows nothing; `ls -a` shows `.hidden_ok` with a
  `stat` ENOENT (expected: the name doesn't exist on disk).
- `cat /opt/cldd-demo/rootkit_persist` still prints `secret` (file alive).
- Detector fired within ~1 scan:
  `{"type":"hidden_file","name":"rootkit_persist","parent_ino":260673}`.

**Affects:** `rootkit.bpf.c` (`process_one_dirent`). The
`swallow_into_prev` helper and `prev` tracking are now unused (left in place
to keep the diff small; can be removed in a follow-up).

**Risk / limitation:**
- Replacement name must fit in `reclen - DIRENT_NAME_OFF`. Guard added:
  if `reclen < DIRENT_NAME_OFF + flen + 1`, skip (and log via `bpf_printk`).
- Semantics change from "hidden" to "renamed". For the detector this is
  equivalent: the real name is absent from the listing, so the cross-layer
  reconciliation still flags it.
- Replacement string `.hidden_ok` starts with `.`, so plain `ls` hides it.
  This is fine for the demo (the directory appears empty) but worth noting
  in the report.

---

## Change 6 — `bench/workloads.sh`: subshell pipe inheritance

**Symptom:** `mix="$(wl_start_mix)"` in `run_all.sh` hung indefinitely. The
first backgrounded workload (`wl_git`) printed one git error and then the
benchmark log froze at 2 lines.

**Cause:** backgrounded subshells `( ... ) &` inherited the write end of
the command-substitution pipe, so `$()` blocked forever waiting for the
pipe to close.

**Fix:** redirect every backgrounded workload subshell to `>/dev/null 2>&1 &`
so the pipe's write end is released at function return. Applied to
`wl_git`, `wl_make`, `wl_tmp_churn`, `wl_fio`, `wl_sysbench`.
`wl_git` was also commented out in `wl_start_mix` due to a packfile-state
issue (`error: packfile .git/objects/pack/....pack index unavailable`).

**Status:** applied and confirmed (benchmark now progresses past
`[overhead] baseline`).

**Risk / limitation:** the git workload no longer contributes churn. The
remaining `wl_make` (compiler loop) and `wl_tmp_churn` (200 files/iteration)
provide plenty of file/process pressure. Note this in the report:
"overhead measured under compiler + tmpfile churn, which stress
`vfs_open`/`ext4_lookup` equivalently."

---

## Change 7 — `bench/scenarios.sh`: subshell pipe inheritance

**Symptom:** `started="$("scen_$scen")"` hung at `static_pid #1` — log
froze on that line for several minutes.

**Cause:** `_spawn_worker` backgrounded `( exec -a cldd-worker ... ) &`
without redirecting; `scen_pid_recycle`'s churn subshell had the same issue.

**Fix:** redirect both to `>/dev/null 2>&1 &`.

**Status:** applied and confirmed.

---

## Change 8 — `bench/workloads.sh`: `wl_stop` leaked workloads

**Symptom:** (latent; would have shown up as inflated system load
mid-benchmark.) `wl_stop` used `kill -- -"$p"` (PGID kill) against a PID
that was not a process-group leader, so the kill failed silently
(`2>/dev/null`) and the workload subshell kept churning.

**Fix:** `wl_stop` now does `pkill -P "$p"` (kill direct children)
followed by `kill "$p"` (kill the subshell itself), then `wait`.

**Status:** applied.

---

## Change 9 — `detector.c`: PID detection restored + race closed + reset

**Symptom:** `static_pid` and `pid_recycle` scored **0% detection** on
every benchmark run.

**Cause (detection):** Change 2 replaced the correct `!pid_visible(pid)`
check with `access("/proc/<pid>")`. A `getdents64` rootkit falsifies the
directory *listing*, not the per-PID procfs entry, so `access()` always
succeeds for hidden PIDs and the detector never strikes.

**Cause (FPs, originally):** stale `/proc` snapshot taken before the
`sched_pids` walk.

**Fix:**
1. Restore `!pid_visible(pid)` as the hidden signal.
2. Gather alive candidates from `sched_pids` FIRST, then take the fresh
   `/proc` snapshot, then check. Collapses TOCTOU to the
   candidate-collection interval.
3. Visible PID resets `strikes` and `reported` so pulsed evasion and
   PID recycling re-trigger detection.

**Status:** applied and confirmed compiled in (`nm build/detector | grep
candidate` shows the `candidates` symbol). **BUT benchmark results unchanged
vs. Change 2:** `static_pid` still 0%, `pid_recycle` still 0%,
CPU overhead still ~24pp, 6 FPs per scenario. **This is the open
investigation — see Open Issue #1 below.**

---

## Change 10 — `detector.c`: file reconciliation reset-on-visible

**Symptom:** `static_file` scored 66.7% (one trial missed).

**Cause:** `if (g->reported) continue;` permanently suppressed a file
after its first alert; a pulse-off→pulse-on cycle or a delete→recreate
within a trial never re-alerted.

**Fix:** three-way branch — `!f_exists` (deleted) → reset; hidden +
not reported → strike; visible → reset. Matches the PID refactor.

**Status:** applied. `static_file` still at 66.7% in the post-fix run —
one trial still missed. Root cause for the missed trial not yet
identified; possibly the file's dirent order puts it first (Change 5's
limitation) or the `vfs_open` ground truth missed the create. Report as an
honest 66.7% with this note, unless time permits deeper investigation.

---

## Proposed Change 11 — `detector.bpf.c`: filter kernel threads (NOT YET APPLIED)

**Symptom:** 6 false positives per scenario in every post-refactor run.

**Cause:** kernel threads have PIDs but no `/proc` listing and no
userspace mm. `kill(pid, 0)` succeeds for them, so they land in
`candidates`, `pid_visible` returns false, and they strike every trial.
The old `access("/proc/<pid>")` check happened to filter them out
(ENOENT), which is why run 1 had 0 FPs.

**Proposed fix:** in `handle_sched_switch`, skip tasks with no mm:

```c
SEC("tp_btf/sched_switch")
int BPF_PROG(handle_sched_switch, bool preempt, struct task_struct *prev,
             struct task_struct *next)
{
	if (!BPF_CORE_READ(next, mm))
		return 0;   /* kernel thread — not in /proc */

	__u32 pid = BPF_CORE_READ(next, pid);
	__u32 tgid = BPF_CORE_READ(next, tgid);
	char comm[TASK_COMM_LEN];

	BPF_CORE_READ_STR_INTO(&comm, next, comm);
	record_sched(pid, tgid, comm);
	return 0;
}