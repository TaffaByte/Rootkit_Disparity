# Safety, Scope, and Ethics

This repository contains a **deliberately offensive component** (`src/rootkit/`)
whose only purpose is to give the defensive detector (`src/detector/`) a real
adversary to catch. It is coursework for an Operating Systems class, not a
security product.

## What the "rootkit" does and does not do

- It hooks `getdents64(2)` and hides directory entries whose name matches a
  **prefix you choose** (default `rootkit_`) or a **single PID you pass on the
  command line**. That is the whole payload.
- It has **no persistence**, no network code, no privilege escalation, no
  self-replication, and no capability to damage data. Detaching it (Ctrl-C) or
  rebooting fully removes it.
- `bpf_probe_write_user` **taints the kernel** and prints a warning to `dmesg`.
  That is expected and is one reason to run this only in a throwaway VM.

## Rules for running this

1. Run **only** inside a disposable virtual machine or an isolated lab host you
   own. Never on a shared, production, or university-managed machine.
2. Requires `root`/`CAP_BPF`+`CAP_SYS_ADMIN`. Loading eBPF and writing user
   memory are privileged operations by design.
3. Do not point the hide prefix/PID at anything you do not control.
4. The code is released for education and defensive research. Using the
   offensive component against systems you are not authorised to test may be
   illegal.

## Why an attacker component is included at all

Cross-view / cross-layer rootkit detection can only be evaluated against a
rootkit. The adversary here is intentionally minimal: it implements exactly the
`getdents64`-tampering technique described in the proposal, so the detector's
true-positive, MTTD, and false-positive numbers mean something. Everything that
makes real malware dangerous (persistence, spread, payloads) is deliberately
absent.
