#!/usr/bin/env python3
"""metrics.py - turn raw run data into the evaluation metrics.

Reads:
    results/raw/markers.jsonl                 planted artifacts (ground truth)
    results/raw/alerts_<scenario>_<trial>.jsonl   detector alerts
    results/raw/overhead.csv                  detector-off vs on CPU

Writes:
    results/metrics.csv      one row per scenario (detection rate, MTTD, FP)
    results/mttd_raw.csv     every matched (scenario, trial, mttd_s)
    results/summary.json     machine-readable rollup

Definitions:
    detection rate = trials where the planted artifact was flagged / trials
    MTTD           = alert.ts - marker.ts for the matching alert (seconds)
    false positive = an alert that matches no planted marker in that scenario
"""
import csv
import glob
import json
import os
import re
import statistics as st
from collections import defaultdict

RAW = "results/raw"
SCENARIOS = ["static_file", "static_pid", "pulsed", "pid_recycle"]


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
    """Identity of a hidden entity: files by name, pids by id."""
    if ev["type"] == "hidden_pid":
        return ("hidden_pid", str(ev["id"]))
    return ("hidden_file", ev["name"])


def main():
    markers = load_jsonl(f"{RAW}/markers.jsonl")
    markers_by_scen = defaultdict(list)
    for m in markers:
        markers_by_scen[m["scenario"]].append(m)

    rows = []
    mttd_raw = []
    summary = {}

    for scen in SCENARIOS:
        trial_files = sorted(glob.glob(f"{RAW}/alerts_{scen}_*.jsonl"))
        n_trials = len(trial_files)
        detected = 0
        mttds = []
        false_positives = 0

        for tf in trial_files:
            trial = int(re.search(r"_(\d+)\.jsonl$", tf).group(1))
            alerts = load_jsonl(tf)
            scen_markers = markers_by_scen.get(scen, [])
            planted_keys = {key_of(m) for m in scen_markers}

            matched_this_trial = False
            for a in alerts:
                k = key_of(a)
                # nearest earlier marker with same identity
                cands = [m for m in scen_markers
                         if key_of(m) == k and m["ts"] <= a["ts"]]
                if cands:
                    m = max(cands, key=lambda x: x["ts"])
                    dt = a["ts"] - m["ts"]
                    if not matched_this_trial:
                        detected += 1
                        matched_this_trial = True
                    mttds.append(dt)
                    mttd_raw.append((scen, trial, round(dt, 4)))
                elif k not in planted_keys:
                    false_positives += 1

        det_rate = (detected / n_trials) if n_trials else 0.0
        row = {
            "scenario": scen,
            "trials": n_trials,
            "detected": detected,
            "detection_rate": round(det_rate, 4),
            "mttd_mean_s": round(st.mean(mttds), 4) if mttds else "",
            "mttd_stdev_s": round(st.pstdev(mttds), 4) if len(mttds) > 1 else "",
            "false_positives": false_positives,
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

    # overhead
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

    # console table
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
