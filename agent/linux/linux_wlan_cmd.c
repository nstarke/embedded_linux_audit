// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * `linux wlan` -- WLAN NIC tooling. `wlan list` enumerates the wireless NICs
 * on the host and reports which the fuzzer supports; `wlan fuzz` is a
 * class-directed black-box fuzzer for WLAN NIC firmware host-command
 * interfaces (engine + per-vendor targets under agent/linux/wlan/). This file
 * is the CLI/dispatch layer.
 *
 * AUTHORIZED USE ONLY: run the fuzzer against your own hardware. It crashes
 * device firmware by design (nothing persistent -- WLAN firmware lives in RAM).
 */
#include "embedded_linux_audit_cmd.h"
#include "linux/wlan/wlan_fuzz.h"
#include "linux/linux_wlan_util.h"

#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void fuzz_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s wlan fuzz --target <name> [options]\n"
		"  Class-directed firmware fuzzer for WLAN NIC host-command interfaces.\n"
		"  AUTHORIZED USE ONLY -- crashes device firmware by design.\n"
		"\n"
		"  targets: ath9k-htc rtw88-usb mwifiex-usb mt7601u carl9170 rtl8xxxu\n"
		"           ath10k ath11k ath12k mt76 brcmfmac (PCIe/SDIO via ela_kmod shim)\n"
		"  --target NAME    NIC target to fuzz (required)\n"
		"  --iterations N   cases to run (default 100000)\n"
		"  --probe-every N  liveness probe interval (default 8)\n"
		"  --seed N         rng seed (default 1234)\n"
		"  --out DIR        crash output dir (default crashes)\n"
		"  --fw PATH        firmware image (target-specific)\n"
		"  --replay FILE    reproduce a saved crash on hardware (target read\n"
		"                   from the file's '# target=' header if not given)\n"
		"  --show FILE      decode a crash file into a readable command/field\n"
		"                   breakdown for triage (offline, no hardware)\n"
		"  --selftest       run offline engine self-tests (no hardware)\n",
		prog);
}

static struct target *resolve_target(const char *tname, const char *fw)
{
	if (!strcmp(tname, "ath9k-htc"))
		return target_ath9k_htc(fw);
	if (!strcmp(tname, "rtw88-usb"))
		return target_rtw88();
	if (!strcmp(tname, "mwifiex-usb"))
		return target_mwifiex();
	if (!strcmp(tname, "mt7601u"))
		return target_mt7601u();
	if (!strcmp(tname, "carl9170"))
		return target_carl9170();
	if (!strcmp(tname, "rtl8xxxu"))
		return target_rtl8xxxu();
	if (!strcmp(tname, "ath10k"))
		return target_ath10k();
	if (!strcmp(tname, "ath11k"))
		return target_ath11k();
	if (!strcmp(tname, "ath12k"))
		return target_ath12k();
	if (!strcmp(tname, "mt76"))
		return target_mt76();
	if (!strcmp(tname, "brcmfmac"))
		return target_brcmfmac();
	return NULL;
}

static int wlan_fuzz_cmd_main(int argc, char **argv)
{
	enum {
		OPT_TARGET = 1, OPT_ITERATIONS, OPT_PROBE_EVERY, OPT_SEED,
		OPT_OUT, OPT_FW, OPT_REPLAY, OPT_SELFTEST, OPT_SHOW,
	};
	static const struct option long_opts[] = {
		{ "target",      required_argument, NULL, OPT_TARGET },
		{ "iterations",  required_argument, NULL, OPT_ITERATIONS },
		{ "probe-every", required_argument, NULL, OPT_PROBE_EVERY },
		{ "seed",        required_argument, NULL, OPT_SEED },
		{ "out",         required_argument, NULL, OPT_OUT },
		{ "fw",          required_argument, NULL, OPT_FW },
		{ "replay",      required_argument, NULL, OPT_REPLAY },
		{ "show",        required_argument, NULL, OPT_SHOW },
		{ "selftest",    no_argument,       NULL, OPT_SELFTEST },
		{ "help",        no_argument,       NULL, 'h' },
		{ 0, 0, 0, 0 }
	};
	struct fuzz_opts o = {
		.iterations = 100000,
		.probe_every = 8,
		.seed = 1234,
		.out_dir = "crashes",
		.replay_path = NULL,
	};
	const char *tname = NULL;
	const char *fw = NULL;
	const char *show_path = NULL;
	char inferred[32];
	struct target *t;
	int opt;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "h", long_opts, NULL)) != -1) {
		switch (opt) {
		case OPT_TARGET:
			tname = optarg;
			break;
		case OPT_ITERATIONS:
			o.iterations = atol(optarg);
			break;
		case OPT_PROBE_EVERY:
			o.probe_every = atoi(optarg);
			break;
		case OPT_SEED:
			o.seed = strtoull(optarg, NULL, 0);
			break;
		case OPT_OUT:
			o.out_dir = optarg;
			break;
		case OPT_FW:
			fw = optarg;
			break;
		case OPT_REPLAY:
			o.replay_path = optarg;
			break;
		case OPT_SHOW:
			show_path = optarg;
			break;
		case OPT_SELFTEST:
			return wlan_fuzz_selftest_run();
		case 'h':
			fuzz_usage("embedded_linux_audit");
			return 0;
		default:
			fuzz_usage("embedded_linux_audit");
			return 2;
		}
	}

	if (optind < argc) {
		fprintf(stderr, "wlan fuzz: unexpected argument: %s\n",
			argv[optind]);
		fuzz_usage("embedded_linux_audit");
		return 2;
	}
	if (o.probe_every < 1) {
		fprintf(stderr, "wlan fuzz: --probe-every must be >= 1\n");
		return 2;
	}

	/* --show and --replay embed the target in the crash file's
	 * "# target=" header, so --target is optional for them (an explicit
	 * --target still wins). */
	if (!tname && (show_path || o.replay_path)) {
		const char *src = show_path ? show_path : o.replay_path;

		if (wlan_fuzz_peek_target(src, inferred, sizeof(inferred)) == 0)
			tname = inferred;
	}

	if (!tname) {
		fprintf(stderr, "wlan fuzz: --target is required%s\n",
			(show_path || o.replay_path) ?
				" (crash file has no '# target=' header)" : "");
		fuzz_usage("embedded_linux_audit");
		return 2;
	}

	t = resolve_target(tname, fw);
	if (!t) {
		fprintf(stderr, "wlan fuzz: unknown target: %s\n", tname);
		fuzz_usage("embedded_linux_audit");
		return 2;
	}

	/* --show decodes a crash file offline (no hardware) for triage. */
	if (show_path)
		return wlan_fuzz_show(t, show_path);

	return wlan_fuzz_run(t, &o);
}

static void wlan_usage(void)
{
	fprintf(stderr,
		"Usage: embedded_linux_audit linux wlan <subcommand>\n"
		"  list   Enumerate WLAN NICs on the host and show which the fuzzer supports\n"
		"  fuzz   Class-directed WLAN firmware fuzzer (see: linux wlan fuzz --help)\n");
}

/* Read a sysfs symlink and return just its basename (e.g. the driver name). */
static int read_link_base(const char *path, char *out, size_t outsz)
{
	char buf[512];
	const char *base;
	size_t len;
	ssize_t n = readlink(path, buf, sizeof(buf) - 1);

	if (n < 0 || outsz == 0)
		return -1;
	buf[n] = '\0';
	base = strrchr(buf, '/');
	base = base ? base + 1 : buf;
	len = strlen(base);
	if (len >= outsz)
		len = outsz - 1;
	memcpy(out, base, len);
	out[len] = '\0';
	return 0;
}

/*
 * linux_wlan_list_main enumerates wireless NICs from sysfs. A netdev is
 * wireless iff it has a phy80211 link; for each we read the bound driver and
 * bus and map them to a fuzzer target.
 */
static int linux_wlan_list_main(int argc, char **argv)
{
	DIR *d;
	struct dirent *de;
	int found = 0, supported = 0;

	if (argc > 1) {
		if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ||
		    !strcmp(argv[1], "help")) {
			fprintf(stderr,
				"Usage: embedded_linux_audit linux wlan list\n"
				"  List WLAN NICs on the host and the fuzzer target that supports each.\n");
			return 0;
		}
		fprintf(stderr, "wlan list: unexpected argument: %s\n", argv[1]);
		return 2;
	}

	/* LCOV_EXCL_START -- reads live sysfs; covered only in the field */
	d = opendir("/sys/class/net");
	if (!d) {
		fprintf(stderr, "wlan list: cannot open /sys/class/net: %s\n",
			strerror(errno));
		return 1;
	}
	printf("%-12s %-6s %-16s %-5s %-14s %s\n",
	       "INTERFACE", "PHY", "DRIVER", "BUS", "FUZZER TARGET", "TRANSPORT");
	while ((de = readdir(d))) {
		char path[512], phy[64], drv[64], bus[32];
		const char *target, *transport;

		if (de->d_name[0] == '.')
			continue;
		snprintf(path, sizeof(path), "/sys/class/net/%s/phy80211",
			 de->d_name);
		if (access(path, F_OK) != 0)
			continue;	/* not a wireless interface */
		found++;
		if (read_link_base(path, phy, sizeof(phy)) != 0)
			snprintf(phy, sizeof(phy), "?");
		snprintf(path, sizeof(path), "/sys/class/net/%s/device/driver",
			 de->d_name);
		if (read_link_base(path, drv, sizeof(drv)) != 0)
			snprintf(drv, sizeof(drv), "?");
		snprintf(path, sizeof(path), "/sys/class/net/%s/device/subsystem",
			 de->d_name);
		if (read_link_base(path, bus, sizeof(bus)) != 0)
			snprintf(bus, sizeof(bus), "?");

		target = wlan_target_for_driver(drv, bus);
		if (target)
			supported++;
		transport = target ?
			(wlan_target_uses_kmod(target) ? "ela_kmod shim" : "usbfs") :
			"-";
		printf("%-12s %-6s %-16s %-5s %-14s %s\n", de->d_name, phy, drv,
		       bus, target ? target : "(unsupported)", transport);
	}
	closedir(d);

	if (!found) {
		printf("No WLAN interfaces found.\n");
		return 0;
	}
	printf("\n%d WLAN interface(s), %d fuzzable with `linux wlan fuzz --target <name>`.\n",
	       found, supported);
	return 0;
	/* LCOV_EXCL_STOP */
}

/*
 * linux_wlan_main dispatches the `linux wlan` command group: `list` to
 * enumerate NICs and `fuzz` to run the firmware fuzzer.
 */
int linux_wlan_main(int argc, char **argv)
{
	if (argc < 2 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ||
	    !strcmp(argv[1], "help")) {
		wlan_usage();
		return argc < 2 ? 2 : 0;
	}

	if (!strcmp(argv[1], "list"))
		return linux_wlan_list_main(argc - 1, argv + 1);
	if (!strcmp(argv[1], "fuzz"))
		return wlan_fuzz_cmd_main(argc - 1, argv + 1);

	fprintf(stderr, "Unknown wlan subcommand: %s\n\n", argv[1]);
	wlan_usage();
	return 2;
}
