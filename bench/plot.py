#!/usr/bin/env python3
"""plot.py - render the report figures from results/metrics.csv + summary.json.

Writes PNGs into figures/:
    fig_mttd.png        mean MTTD per scenario (error bars = stdev)
    fig_detection.png   detection rate per scenario
    fig_fp.png          false positives per scenario under benign churn
    fig_overhead.png    CPU busy: detector off vs on

Figures are intentionally generated only from measured runs; if you have not
run bench/run_all.sh yet there is nothing to plot.
"""
import csv
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

FIG = "figures"
os.makedirs(FIG, exist_ok=True)


def load_metrics():
    rows = []
    with open("results/metrics.csv") as f:
        for r in csv.DictReader(f):
            rows.append(r)
    return rows


def f(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


def bar(names, vals, title, ylabel, path, errs=None, pct=False):
    fig, ax = plt.subplots(figsize=(6, 3.6))
    ax.bar(names, vals, yerr=errs, capsize=4, color="#3b6ea5",
           edgecolor="#1f3a5f")
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    if pct:
        ax.set_ylim(0, 1.05)
    ax.grid(axis="y", linestyle=":", alpha=0.5)
    plt.xticks(rotation=15)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print("wrote", path)


def main():
    rows = load_metrics()
    names = [r["scenario"] for r in rows]

    bar(names, [f(r["mttd_mean_s"]) for r in rows],
        "Mean Time To Detect by scenario", "MTTD (s)",
        f"{FIG}/fig_mttd.png",
        errs=[f(r["mttd_stdev_s"]) for r in rows])

    bar(names, [f(r["detection_rate"]) for r in rows],
        "Detection rate by scenario", "fraction detected",
        f"{FIG}/fig_detection.png", pct=True)

    bar(names, [f(r["false_positives"]) for r in rows],
        "False positives under benign churn", "alerts (spurious)",
        f"{FIG}/fig_fp.png")

    if os.path.exists("results/summary.json"):
        with open("results/summary.json") as fp:
            s = json.load(fp)
        ov = s.get("overhead", {})
        if "off" in ov and "on" in ov:
            bar(["detector off", "detector on"], [ov["off"], ov["on"]],
                "CPU utilisation under fixed workload", "CPU busy (%)",
                f"{FIG}/fig_overhead.png")

    print("\nfigures ready in figures/. Drop them into the report's Results section.")


if __name__ == "__main__":
    main()
