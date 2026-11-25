#!/usr/bin/env bash
# run_all.sh - end-to-end evaluation orchestrator.
#
# Runs the scenario x trial matrix with the benign workload mix, drives the
# detector, and captures everything the metrics step needs:
#   results/raw/alerts_<scen>_<trial>.jsonl   detector alerts
#   results/raw/markers.jsonl                 when/what was planted (ground truth)
#   results/raw/overhead.csv                  detector-off vs detector-on cost
#
# Then: python3 bench/metrics.py && python3 bench/plot.py
#
# MUST be run as root (eBPF load + bpf_probe_write_user).  See SAFETY.md.
set -uo pipefail
cd "$(dirname "$0")/.."

# ---- config ----------------------------------------------------------------
DEMO="${DEMO:-/opt/cldd-demo}"
DETECTOR="${DETECTOR:-build/detector}"
ROOTKIT="${ROOTKIT:-build/rootkit}"
DURATION="${DURATION:-30}"          # seconds of observation per trial
SETTLE="${SETTLE:-2}"               # detector warm-up before the attack
TRIALS="${TRIALS:-3}"
INTERVAL_MS="${INTERVAL_MS:-250}"
CONFIRM="${CONFIRM:-2}"
SCENARIOS=(static_file static_pid pulsed pid_recycle)

export DEMO ROOTKIT
MARKERS="results/raw/markers.jsonl"; export MARKERS

source bench/workloads.sh
source bench/scenarios.sh

die() { echo "error: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "run as root (sudo -E bench/run_all.sh)"
[[ -x "$DETECTOR" && -x "$ROOTKIT" ]] || die "build first: make"

rm -rf results/raw && mkdir -p results/raw "$DEMO"
: > "$MARKERS"

# ---- overhead: fixed workload, detector OFF then ON ------------------------
measure_cpu_window() { # duration -> busy%
	local dur="$1" a b idle1 idle2 tot1 tot2
	a=($(grep '^cpu ' /proc/stat)); idle1=${a[4]}; tot1=0; for v in "${a[@]:1}"; do tot1=$((tot1+v)); done
	sleep "$dur"
	b=($(grep '^cpu ' /proc/stat)); idle2=${b[4]}; tot2=0; for v in "${b[@]:1}"; do tot2=$((tot2+v)); done
	awk -v i=$((idle2-idle1)) -v t=$((tot2-tot1)) 'BEGIN{printf "%.2f", t? (100*(1-i/t)):0}'
}

echo "scenario,detector,cpu_busy_pct" > results/raw/overhead.csv
echo "[overhead] baseline (detector OFF)"
mix="$(wl_start_mix)"; sleep 2
echo "overhead,off,$(measure_cpu_window "$DURATION")" >> results/raw/overhead.csv
wl_stop_mix "$mix"

echo "[overhead] instrumented (detector ON)"
"$DETECTOR" --watch /proc --watch "$DEMO" --interval-ms "$INTERVAL_MS" \
	--confirm "$CONFIRM" --scenario overhead \
	--out results/raw/alerts_overhead.jsonl >/dev/null 2>&1 &
det=$!; sleep "$SETTLE"
mix="$(wl_start_mix)"; sleep 2
echo "overhead,on,$(measure_cpu_window "$DURATION")" >> results/raw/overhead.csv
wl_stop_mix "$mix"; kill "$det" 2>/dev/null; wait "$det" 2>/dev/null

# ---- scenario x trial matrix ----------------------------------------------
for scen in "${SCENARIOS[@]}"; do
  for t in $(seq 1 "$TRIALS"); do
	echo "[trial] $scen #$t"
	alerts="results/raw/alerts_${scen}_${t}.jsonl"; : > "$alerts"
	export TRIAL="$t" SCEN="$scen" DURATION

	"$DETECTOR" --watch /proc --watch "$DEMO" --interval-ms "$INTERVAL_MS" \
		--confirm "$CONFIRM" --scenario "$scen" --out "$alerts" >/dev/null 2>&1 &
	det=$!
	sleep "$SETTLE"

	mix="$(wl_start_mix)"                 # benign churn (false-positive pressure)
	started="$("scen_$scen")"             # plant attack + write marker
	sleep "$DURATION"

	# teardown: scenario pids, workload, detector, artifacts
	for p in $started; do kill -- -"$p" 2>/dev/null; kill "$p" 2>/dev/null; done
	pkill -f "$ROOTKIT" 2>/dev/null
	wl_stop_mix "$mix"
	kill "$det" 2>/dev/null; wait "$det" 2>/dev/null
	rm -f "$DEMO"/rootkit_* 2>/dev/null
	sleep 1
  done
done

echo "[done] raw data in results/raw/. Computing metrics..."
python3 bench/metrics.py && python3 bench/plot.py
echo "[done] metrics in results/, figures in figures/."
