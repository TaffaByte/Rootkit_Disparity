#!/usr/bin/env bash
# scenarios.sh - red-team scenarios. Sourced by run_all.sh.
#
# Each scen_* function:
#   - plants the hidden artifact (file and/or process),
#   - starts the rootkit in the appropriate evasion mode,
#   - appends a ground-truth marker (when/what was planted) to $MARKERS,
#   - echoes the PIDs it started so run_all.sh can tear them down.
#
# Markers are the source of truth for MTTD: MTTD = alert.ts - marker.ts.

DEMO="${DEMO:-/opt/cldd-demo}"
ROOTKIT="${ROOTKIT:-build/rootkit}"
MARKERS="${MARKERS:-results/raw/markers.jsonl}"

_now() { date +%s.%N; }
_marker() { # type name id scenario
	printf '{"ts":%s,"type":"%s","name":"%s","id":%s,"scenario":"%s"}\n' \
		"$(_now)" "$1" "$2" "${3:-0}" "$4" >> "$MARKERS"
}

# Spawn a long-lived benign-looking worker; echo its PID.
_spawn_worker() {
	( exec -a cldd-worker sleep 100000 ) >/dev/null 2>&1 &
	echo $!
}

# 1) Static file hiding: one persistent file, steady hook.
scen_static_file() {
	mkdir -p "$DEMO"; echo secret > "$DEMO/rootkit_persist"
	sudo "$ROOTKIT" --prefix rootkit_ >/dev/null 2>&1 &
	local rk=$!
	sleep 0.5
	_marker hidden_file rootkit_persist 0 static_file
	echo "$rk"
}

# 2) Static PID hiding: hide a live worker's /proc entry, steady hook.
scen_static_pid() {
	local w; w="$(_spawn_worker)"
	sudo "$ROOTKIT" --hide-pid "$w" >/dev/null 2>&1 &
	local rk=$!
	sleep 0.5
	_marker hidden_pid cldd-worker "$w" static_pid
	echo "$rk $w"
}

# 3) Pulsed evasion: hook toggles on/off; file still exists continuously.
scen_pulsed() {
	mkdir -p "$DEMO"; echo secret > "$DEMO/rootkit_pulse"
	sudo "$ROOTKIT" --prefix rootkit_ --pulse 500 >/dev/null 2>&1 &
	local rk=$!
	sleep 0.5
	_marker hidden_file rootkit_pulse 0 pulsed
	echo "$rk"
}

# 4) PID recycling: heavy short-lived fork churn (recycled pids) PLUS one
#    genuinely hidden long-lived worker. The churn must NOT be flagged
#    (kill(pid,0) fails for the dead ones); the real hidden pid must be.
scen_pid_recycle() {
	local w; w="$(_spawn_worker)"
	sudo "$ROOTKIT" --hide-pid "$w" >/dev/null 2>&1 &
	local rk=$!
	( while :; do ( exec -a recycled sleep 0.05 ) & done ) >/dev/null 2>&1 &   # recycled pids
	local churn=$!
	sleep 0.5
	_marker hidden_pid cldd-worker "$w" pid_recycle
	echo "$rk $w $churn"
}
