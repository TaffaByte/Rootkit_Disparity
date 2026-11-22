# Architecture

```
                         userland view (tamperable)
        ┌───────────────────────────────────────────────┐
        │  ls / ps / readdir  ->  getdents64()           │
        └───────────────▲───────────────────────────────┘
                        │ records
          ┌─────────────┴──────────────┐
          │  LAYER 0 — ADVERSARY        │   src/rootkit/
          │  tp sys_exit_getdents64     │   extends prev d_reclen with
          │  bpf_probe_write_user()     │   bpf_probe_write_user to excise
          │  hides rootkit_* / PID N    │   target dir entries
          └─────────────────────────────┘

        kernel ground truth (NOT tamperable from userland)
        ┌───────────────────────────────────────────────┐
        │  LAYER 1 — GROUND TRUTH        src/detector/*.bpf.c
        │  tp sched:sched_switch   -> sched_pids map (live pids)
        │  fentry vfs_open         -> ring buffer (parent_ino, name)
        │  kprobe ext4_lookup      -> ring buffer (parent_ino, name)
        └───────────────▲───────────────────────────────┘
                        │ maps + ringbuf
          ┌─────────────┴──────────────┐
          │  LAYER 2 — RECONCILIATION   │   src/detector/detector.c
          │  every INTERVAL_MS:         │
          │   Δ = GroundTruth \ getdents64(view)
          │   confirm with kill(pid,0) / faccessat()
          │   persist for CONFIRM scans -> ALERT (JSONL)
          └─────────────────────────────┘
```

## Reconciliation, precisely

For processes:

```
GT_pids      = { pid : scheduled recently (sched_switch) and kill(pid,0)==0 }
Visible_pids = { pid : numeric entry in getdents64("/proc") }
Hidden_pids  = GT_pids \ Visible_pids        # confirmed over CONFIRM scans
```

For files in a watched directory `D` (inode `d`):

```
GT_files      = { name : vfs_open/ext4_lookup resolved (parent_ino==d) }
Visible_files = { name : getdents64(D) }
Hidden_files  = { name in GT_files : faccessat(D,name)==0 and name ∉ Visible_files }
```

The `CONFIRM` threshold and the out-of-band existence checks are what keep
benign races (a process exiting mid-scan, a temp file deleted between resolve
and listing) from becoming false positives — the central tension the evaluation
measures.

## Why each probe is "ground truth"

- `sched_switch` fires from the scheduler core (OSTEP: CPU scheduling, MLFQ/CFS).
  A task cannot run without being switched onto a runqueue, so a userland
  `getdents64` filter on `/proc` cannot erase it from this view.
- `vfs_open` / `ext4_lookup` sit at the VFS and filesystem layer (OSTEP: file
  system implementation, inodes). A file that is opened or path-resolved was
  really there on disk, regardless of what a tampered `readdir` later claims.

## Evaluation dimensions (map to `bench/`)

| Dimension             | Where measured                                   |
|-----------------------|--------------------------------------------------|
| Detection efficacy / MTTD | `markers.jsonl` vs `alerts_*.jsonl`, `metrics.py` |
| Resilience vs evasion | `scen_pulsed`, `scen_pid_recycle` in `scenarios.sh` |
| False positives       | benign `wl_*` mix running during every trial     |
| Performance overhead  | `overhead.csv` (detector off vs on)              |
