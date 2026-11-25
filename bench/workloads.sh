#!/usr/bin/env bash
# workloads.sh - benign high-churn workloads used to measure false positives
# and performance overhead. Sourced by run_all.sh. Each wl_* function starts a
# background workload and echoes its PID; wl_stop <pid> ends it.
#
# Optional tools (fio, sysbench) are skipped gracefully if not installed.

WL_TMP="${WL_TMP:-/tmp/cldd-churn}"

wl_stop() { local p="$1"; [[ -n "$p" ]] && kill -- -"$p" 2>/dev/null; wait "$p" 2>/dev/null; }

# Rapid git activity: init a repo and churn commits/branches (file create/stat/unlink).
wl_git() {
	( set -m
	  rm -rf "$WL_TMP/git"; mkdir -p "$WL_TMP/git"; cd "$WL_TMP/git" || exit
	  git init -q .; git config user.email a@b.c; git config user.name t
	  i=0
	  while :; do
		echo "$RANDOM" > "f$((i%64)).txt"
		git add -A; git commit -q -m "c$i" 2>/dev/null
		[[ $((i%20)) -eq 0 ]] && { git checkout -q -b "b$i" 2>/dev/null; git checkout -q - 2>/dev/null; }
		i=$((i+1))
	  done ) >/dev/null 2>&1 &
	echo $!
}

# make-style build churn: compile a trivial program in a loop.
wl_make() {
	( set -m
	  rm -rf "$WL_TMP/build"; mkdir -p "$WL_TMP/build"; cd "$WL_TMP/build" || exit
	  printf 'int main(){return 0;}\n' > m.c
	  while :; do cc m.c -o m.out 2>/dev/null; rm -f m.out; done ) >/dev/null 2>&1 &
	echo $!
}

# /tmp inode churn: create/stat/delete many short-lived files.
wl_tmp_churn() {
	( set -m
	  mkdir -p "$WL_TMP/churn"
	  while :; do
		for n in $(seq 1 200); do : > "$WL_TMP/churn/t$n"; done
		ls "$WL_TMP/churn" >/dev/null
		rm -f "$WL_TMP"/churn/t*
	  done ) >/dev/null 2>&1 &
	echo $!
}

# fio random read/write (optional).
wl_fio() {
	command -v fio >/dev/null || { echo ""; return; }
	( set -m
	  mkdir -p "$WL_TMP/fio"
	  fio --name=rw --directory="$WL_TMP/fio" --rw=randrw --bs=4k \
	      --size=128M --numjobs=2 --time_based --runtime=3600 \
	      --group_reporting >/dev/null 2>&1 ) >/dev/null 2>&1 &
	echo $!
}

# sysbench CPU (optional).
wl_sysbench() {
	command -v sysbench >/dev/null || { echo ""; return; }
	( set -m
	  sysbench cpu --cpu-max-prime=20000 --time=3600 --threads=2 run >/dev/null 2>&1 ) >/dev/null 2>&1 &
	echo $!
}

# Start the standard benign mix; returns space-separated PIDs.
wl_start_mix() {
	local pids=()
	# pids+=("$(wl_git)")
	pids+=("$(wl_make)")
	pids+=("$(wl_tmp_churn)")
	local f; f="$(wl_fio)";       [[ -n "$f" ]] && pids+=("$f")
	local s; s="$(wl_sysbench)";  [[ -n "$s" ]] && pids+=("$s")
	echo "${pids[@]}"
}
wl_stop_mix() { for p in $1; do wl_stop "$p"; done; }
