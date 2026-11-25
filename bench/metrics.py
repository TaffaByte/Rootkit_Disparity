#!/usr/bin/env python3
"""metrics.py - turn raw run data into evaluation metrics.

Trial-aware marker matching: markers carry a "trial" field from
scenarios.sh; if missing, infer from chronological order. Alerts only
match markers from the SAME trial, and only if 0 <= alert.ts - marker.ts
<= DURATION + BUFFER. This prevents cross-trial contamination that
inflated MTTD in earlier versions.
"""
import csv, glob, json, os, re, statistics as st
from collections import defaultdict

RAW       = "results/raw"
SCENARIOS = ["static_file", "static_pid", "pulsed", "pid_recycle"]
DURATION  = int(os.environ.get("DURATION", "30"))
BUFFER    = 5


def load_jsonl(path):
    out = []
    if not os.path.exists(path):
        return out
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return out


def key_of(ev):
    if ev["type"] == "hidden_pid":
        return ("hidden_pid", str(ev["id"]))
    return ("hidden_file", ev["name"])


def assign_trial_numbers(markers_by_scen):
    """If markers lack a trial field, infer from chronological order."""
    for scen, ms in markers_by_scen.items():
        if any("trial" in m for m in ms):
            continue
        ms_sorted = sorted(ms, key=lambda x: x["ts"])
        for i, m in enumerate(ms_sorted, 1):
            m["trial"] = i


def main():
    markers = load_jsonl(f"{RAW}/markers.jsonl")
    markers_by_scen = defaultdict(list)
    for m in markers:
        markers_by_scen[m["scenario"]].append(m)
    assign_trial_numbers(markers_by_scen)

    rows, mttd_raw, summary = [], [], {}

    for scen in SCENARIOS:
        trial_files = sorted(glob.glob(f"{RAW}/alerts_{scen}_*.jsonl"))
        n_trials = len(trial_files)
        scen_markers = markers_by_scen.get(scen, [])
        n_markers = len(scen_markers)
        if n_markers != n_trials:
            print(f"WARN: {scen}: {n_trials} trial files but {n_markers} markers",
                  file=__import__("sys").stderr)

        detected, mttds, fps = 0, [], 0

        for tf in trial_files:
            trial = int(re.search(r"_(\d+)\.jsonl$", tf).group(1))
            alerts = load_jsonl(tf)
            trial_markers = [m for m in scen_markers if m.get("trial") == trial]
            planted_keys = {key_of(m) for m in trial_markers}

            matched_this_trial = False
            for a in alerts:
                k = key_of(a)
                cands = [m for m in trial_markers
                    if key_of(m) == k
                    and -1.0 <= a["ts"] - m["ts"] <= DURATION + BUFFER]
                if cands:
                    m = max(cands, key=lambda x: x["ts"])
                    dt = a["ts"] - m["ts"]
                    if not matched_this_trial:
                        detected += 1
                        matched_this_trial = True
                    mttds.append(dt)
                    mttd_raw.append((scen, trial, round(dt, 4)))
                elif k not in planted_keys:
                    fps += 1

        det_rate = (detected / n_trials) if n_trials else 0.0
        row = {
            "scenario":       scen,
            "trials":         n_trials,
            "detected":       detected,
            "detection_rate": round(det_rate, 4),
            "mttd_mean_s":    round(st.mean(mttds), 4) if mttds else "",
            "mttd_stdev_s":   round(st.pstdev(mttds), 4) if len(mttds) > 1 else "",
            "false_positives": fps,
        }
        rows.append(row)
        summary[scen] = row

    os.makedirs("results", exist_ok=True)
    with open("results/metrics.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    with open("results/mttd_raw.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["scenario", "trial", "mttd_s"])
        w.writerows(mttd_raw)

    overhead = {}
    ovp = f"{RAW}/overhead.csv"
    if os.path.exists(ovp):
        with open(ovp) as f:
            for r in csv.DictReader(f):
                overhead[r["detector"]] = float(r["cpu_busy_pct"])
    if "off" in overhead and "on" in overhead:
        overhead["delta_pct"] = round(overhead["on"] - overhead["off"], 2)
    summary["overhead"] = overhead

    with open("results/summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    print("\n== Evaluation summary ==")
    print(f"{'scenario':<14}{'trials':>7}{'det.rate':>10}{'MTTD(s)':>10}{'±stdev':>9}{'FP':>5}")
    for r in rows:
        print(f"{r['scenario']:<14}{r['trials']:>7}{r['detection_rate']:>10}"
              f"{str(r['mttd_mean_s']):>10}{str(r['mttd_stdev_s']):>9}"
              f"{r['false_positives']:>5}")
    if "delta_pct" in overhead:
        print(f"\nCPU overhead (detector on - off): {overhead['delta_pct']} pp "
              f"(off={overhead['off']}%, on={overhead['on']}%)")
    print("\nwrote results/metrics.csv, results/mttd_raw.csv, results/summary.json")


if __name__ == "__main__":
    main()