#!/usr/bin/env bash
# Generate src/vmlinux.h from the running kernel's BTF (CO-RE type source).
# Requires bpftool and CONFIG_DEBUG_INFO_BTF=y (default on stock Ubuntu).
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
	echo "error: /sys/kernel/btf/vmlinux not readable." >&2
	echo "       Your kernel was built without BTF. Install a BTF-enabled" >&2
	echo "       kernel (stock Ubuntu generic) or generate from DWARF." >&2
	exit 1
fi
command -v bpftool >/dev/null || {
	echo "error: bpftool not found. Install linux-tools-\$(uname -r)." >&2
	exit 1
}
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/vmlinux.h
echo "wrote src/vmlinux.h ($(wc -l < src/vmlinux.h) lines)"
