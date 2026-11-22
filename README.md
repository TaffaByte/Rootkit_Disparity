# Cross-Layer Disparity Detection

Auditing kernel scheduler/inode invariants against tampered userspace directory
enumeration to expose stealth `getdents64` (eBPF) rootkits.

**Operating Systems — Fall 2026, Habib University**
Syed Hassan Askari Zaidi · Farooq Ahmed · Mustafa Farhan Qureshi

---

## Research question

> Can cross-layer reconciliation between low-level kernel scheduler/inode
> structures and userland `getdents64` directory streams reliably expose stealth
> eBPF rootkits, what tactics evade this disparity check, and what is its
> workload overhead?

A userland rootkit can rewrite the results of `getdents64(2)` so that `ls`,
`ps`, and `readdir` never see a hidden file or `/proc/<pid>` entry. Tools built
on that interface inherit an untrusted view of the system. This project builds
the attack, then a detector that never trusts userland enumeration: it harvests
ground truth from kernel structures the rootkit cannot forge (the scheduler
runqueue and the VFS/inode layer) and flags anything present in the kernel but
missing from the userland listing.

See **[docs/architecture.md](docs/architecture.md)** for the full design and
**[SAFETY.md](SAFETY.md)** before running anything.

## Layout

```
src/common.h            structs shared by BPF + userspace
src/rootkit/            Layer 0 — adversarial getdents64 hiding rootkit
src/detector/           Layer 1 (ground-truth BPF) + Layer 2 (reconciliation)
tools/gen_vmlinux.sh    generate src/vmlinux.h from the running kernel's BTF
bench/                  workloads, red-team scenarios, orchestrator, metrics, plots
results/ figures/       produced by the benchmark (git-ignored)
docs/                   architecture notes
```

## Requirements

A **disposable Linux VM**, kernel ≥ 5.8 with BTF (`CONFIG_DEBUG_INFO_BTF=y` —
default on stock Ubuntu generic kernels), and `root`.

```bash
sudo apt update
sudo apt install -y clang llvm libelf-dev libbpf-dev zlib1g-dev \
     linux-tools-common linux-tools-generic linux-headers-$(uname -r) \
     gcc make git
# optional, for richer workloads:
sudo apt install -y fio sysbench
```

> `bpftool` ships in `linux-tools-$(uname -r)`. If `make` cannot find it, use
> `BPFTOOL=/usr/lib/linux-tools/$(uname -r)/bpftool make`.

## Build

```bash
make            # generates src/vmlinux.h, builds build/rootkit and build/detector
```

## Quick demo (watch the disparity appear)

Terminal A — start the detector:

```bash
sudo ./build/detector --watch /proc --watch /opt/cldd-demo --out results/alerts.jsonl
```

Terminal B — plant a file, then turn on the rootkit:

```bash
sudo mkdir -p /opt/cldd-demo && echo secret | sudo tee /opt/cldd-demo/rootkit_persist
ls /opt/cldd-demo                       # file is visible
sudo ./build/rootkit --prefix rootkit_  # hook on
ls /opt/cldd-demo                        # file is GONE from userland
```

Terminal A prints an alert like:

```
[ALERT] {"ts":...,"type":"hidden_file","name":"rootkit_persist","id":0,...}
```

because `vfs_open`/`ext4_lookup` recorded the file the kernel really has, while
`getdents64` no longer reports it. Hide a process instead with
`sudo ./build/rootkit --hide-pid <PID>` and watch for a `hidden_pid` alert.

## Full evaluation

```bash
sudo -E DURATION=30 TRIALS=3 bench/run_all.sh
```

This runs every scenario (`static_file`, `static_pid`, `pulsed`,
`pid_recycle`) under a benign high-churn workload mix, then computes metrics and
renders figures:

```
results/metrics.csv     detection rate, MTTD, false positives per scenario
results/summary.json    rollup incl. CPU overhead
figures/*.png           MTTD, detection, false positives, overhead
```

Re-aggregate without re-running: `python3 bench/metrics.py && python3 bench/plot.py`.

## Notes / honest caveats

- The eBPF programs follow libbpf CO-RE conventions but were authored, not
  verifier-tested, in a container without BTF. On first load the verifier may
  ask for a small tweak (a bound, a `NULL` check); the loaders print the exact
  message.
- `ext4_lookup` only fires on ext4; `vfs_open` is the filesystem-agnostic
  fallback and carries the file ground truth on any FS.
- A target entry that lands first in a `getdents64` block is not hidden (it
  cannot be merged "upward"); real targets never sort first. See the comment in
  `rootkit.bpf.c`.

## License

MIT — see [LICENSE](LICENSE). For education and defensive research only.
