// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * `linux bt` -- Bluetooth controller tooling, the Bluetooth counterpart of
 * `linux wlan` / `linux eth`. `bt list` enumerates the host's Bluetooth
 * controllers; `bt fuzz` is a class-directed fuzzer for the host->controller
 * HCI command interface. Shares the NIC-fuzz engine (grammar/mutation/loop/
 * remote-crash-stream) with the WLAN and ethernet fuzzers.
 *
 * AUTHORIZED USE ONLY: run against your own hardware. Fuzzing HCI commands
 * exercises the kernel HCI layer + driver + controller firmware by design and
 * can wedge or panic the host.
 */
#include "embedded_linux_audit_cmd.h"
#include "linux/bt/bt_fuzz.h"
#include "linux/wlan/wlan_fuzz_stream.h"
#include "linux/linux_bt_util.h"
#include "linux/fuzz_daemon.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- small sysfs helpers -------------------------------------------------- */

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

/* LCOV_EXCL_START -- thin sysfs I/O; exercised only in the field */
static int read_text_line(const char *path, char *out, size_t outsz)
{
	int fd;
	ssize_t n;

	if (outsz == 0)
		return -1;
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	n = read(fd, out, outsz - 1);
	close(fd);
	if (n < 0)
		return -1;
	out[n] = '\0';
	out[strcspn(out, "\r\n")] = '\0';
	return 0;
}
/* LCOV_EXCL_STOP */

static void fuzz_usage(void)
{
	fprintf(stderr,
		"Usage: embedded_linux_audit linux bt fuzz --target <name> [options]\n"
		"  Class-directed fuzzer for the Bluetooth HCI command interface.\n"
		"  AUTHORIZED USE ONLY -- exercises the host kernel + controller firmware.\n"
		"\n"
		"  targets: hci-generic (HCI command fuzz over a raw HCI User Channel;\n"
		"                        needs --hci, root, and the controller DOWN; targets\n"
		"                        the HOST KERNEL + controller firmware -- can panic host)\n"
		"  --target NAME    fuzz target (required; currently only hci-generic)\n"
		"  --hci NAME       controller to fuzz (e.g. hci0; default hci0)\n"
		"  --iterations N   cases to run (default 100000)\n"
		"  --probe-every N  liveness probe interval (default 8)\n"
		"  --seed N         rng seed (default 1234)\n"
		"  --out DIR        crash output dir (default crashes)\n"
		"  --replay FILE    reproduce a saved crash on hardware\n"
		"  --show FILE      decode a crash file for triage (offline, no hardware)\n"
		"  --insecure       skip TLS verification when streaming payloads to the\n"
		"                   agent API (--output-http) for remote crash capture\n"
		"  --daemon         detach and run in the background (for API spawn);\n"
		"                   logs to <out>/bt-fuzz-daemon.log\n"
		"  --selftest       run offline engine self-tests (no hardware)\n");
}

static int bt_fuzz_cmd_main(int argc, char **argv)
{
	enum {
		OPT_TARGET = 1, OPT_ITERATIONS, OPT_PROBE_EVERY, OPT_SEED,
		OPT_OUT, OPT_REPLAY, OPT_SHOW, OPT_HCI, OPT_INSECURE,
		OPT_SELFTEST, OPT_DAEMON,
	};
	static const struct option long_opts[] = {
		{ "target",      required_argument, NULL, OPT_TARGET },
		{ "iterations",  required_argument, NULL, OPT_ITERATIONS },
		{ "probe-every", required_argument, NULL, OPT_PROBE_EVERY },
		{ "seed",        required_argument, NULL, OPT_SEED },
		{ "out",         required_argument, NULL, OPT_OUT },
		{ "replay",      required_argument, NULL, OPT_REPLAY },
		{ "show",        required_argument, NULL, OPT_SHOW },
		{ "hci",         required_argument, NULL, OPT_HCI },
		{ "insecure",    no_argument,       NULL, OPT_INSECURE },
		{ "selftest",    no_argument,       NULL, OPT_SELFTEST },
		{ "daemon",      no_argument,       NULL, OPT_DAEMON },
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
	const char *hci = "hci0";
	const char *show_path = NULL;
	char inferred[32];
	struct target *t;
	int insecure = 0, dev_index = 0, daemon_mode = 0, opt;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "h", long_opts, NULL)) != -1) {
		switch (opt) {
		case OPT_TARGET: tname = optarg; break;
		case OPT_ITERATIONS: o.iterations = atol(optarg); break;
		case OPT_PROBE_EVERY: o.probe_every = atoi(optarg); break;
		case OPT_SEED: o.seed = strtoull(optarg, NULL, 0); break;
		case OPT_OUT: o.out_dir = optarg; break;
		case OPT_REPLAY: o.replay_path = optarg; break;
		case OPT_SHOW: show_path = optarg; break;
		case OPT_HCI: hci = optarg; break;
		case OPT_INSECURE: insecure = 1; break;
		case OPT_DAEMON: daemon_mode = 1; break;
		case OPT_SELFTEST: return wlan_fuzz_selftest_run();
		case 'h': fuzz_usage(); return 0;
		default: fuzz_usage(); return 2;
		}
	}
	if (optind < argc) {
		fprintf(stderr, "bt fuzz: unexpected argument: %s\n", argv[optind]);
		fuzz_usage();
		return 2;
	}
	if (o.probe_every < 1) {
		fprintf(stderr, "bt fuzz: --probe-every must be >= 1\n");
		return 2;
	}

	if (!tname && (show_path || o.replay_path)) {
		const char *src = show_path ? show_path : o.replay_path;

		if (wlan_fuzz_peek_target(src, inferred, sizeof(inferred)) == 0)
			tname = inferred;
	}
	if (!tname) {
		fprintf(stderr, "bt fuzz: --target is required%s\n",
			(show_path || o.replay_path) ?
				" (crash file has no '# target=' header)" : "");
		fuzz_usage();
		return 2;
	}
	if (strcmp(tname, "hci-generic") != 0) {
		fprintf(stderr, "bt fuzz: unknown target: %s\n", tname);
		fuzz_usage();
		return 2;
	}
	/* --show decodes offline and needs no controller. */
	if (!show_path && bt_parse_hci_dev(hci, &dev_index) != 0) {
		fprintf(stderr, "bt fuzz: bad --hci '%s' (want hciN, e.g. hci0)\n", hci);
		return 2;
	}

	t = target_hci_generic(dev_index);

	if (show_path)
		return wlan_fuzz_show(t, show_path);

	/* HCI fuzzing traverses the kernel HCI layer and can panic the host, so
	 * stream each command to the agent API first (when --output-http is set)
	 * -- the last one survives a panic as a remote crash artifact. */
	if (!o.replay_path) {
		struct wlan_fuzz_stream stream;
		int rc;

		if (daemon_mode && ela_fuzz_daemonize("bt-fuzz", o.out_dir) == 1)
			return 0;	/* parent detached; child runs the fuzz */

		if (wlan_fuzz_stream_open(&stream, tname, "bt-fuzz", 1, insecure) == 0)
			o.sink = &stream.sink;
		rc = wlan_fuzz_run(t, &o);
		if (o.sink)
			wlan_fuzz_stream_done(&stream);
		return rc;
	}

	return wlan_fuzz_run(t, &o);
}

/* ---- list ----------------------------------------------------------------- */

static int bt_list_main(int argc, char **argv)
{
	DIR *d;
	struct dirent *de;
	int found = 0;

	if (argc > 1) {
		if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ||
		    !strcmp(argv[1], "help")) {
			fprintf(stderr,
				"Usage: embedded_linux_audit linux bt list\n"
				"  List Bluetooth controllers on the host and the fuzzer target.\n");
			return 0;
		}
		fprintf(stderr, "bt list: unexpected argument: %s\n", argv[1]);
		return 2;
	}

	/* LCOV_EXCL_START -- reads live sysfs; covered only in the field */
	d = opendir("/sys/class/bluetooth");
	if (!d) {
		printf("No Bluetooth controllers found (no /sys/class/bluetooth).\n");
		return 0;
	}
	printf("%-8s %-18s %-8s %-14s %s\n",
	       "CONTROLLER", "ADDRESS", "BUS", "FUZZER TARGET", "TRANSPORT");
	while ((de = readdir(d))) {
		char path[512], addr[32], bus[32], drv[64];

		if (strncmp(de->d_name, "hci", 3) != 0)
			continue;
		found++;
		snprintf(path, sizeof(path), "/sys/class/bluetooth/%s/address",
			 de->d_name);
		if (read_text_line(path, addr, sizeof(addr)) != 0)
			snprintf(addr, sizeof(addr), "?");
		snprintf(path, sizeof(path),
			 "/sys/class/bluetooth/%s/device/subsystem", de->d_name);
		if (read_link_base(path, bus, sizeof(bus)) != 0)
			snprintf(bus, sizeof(bus), "?");
		snprintf(path, sizeof(path),
			 "/sys/class/bluetooth/%s/device/driver", de->d_name);
		if (read_link_base(path, drv, sizeof(drv)) != 0)
			snprintf(drv, sizeof(drv), "?");
		(void)drv;
		printf("%-8s %-18s %-8s %-14s %s\n", de->d_name, addr, bus,
		       "hci-generic", "HCI User Channel");
	}
	closedir(d);

	if (!found) {
		printf("No Bluetooth controllers found.\n");
		return 0;
	}
	printf("\n%d Bluetooth controller(s), fuzzable with "
	       "`linux bt fuzz --target hci-generic --hci <name>`.\n", found);
	return 0;
	/* LCOV_EXCL_STOP */
}

static void bt_usage(void)
{
	fprintf(stderr,
		"Usage: embedded_linux_audit linux bt <subcommand>\n"
		"  list   Enumerate Bluetooth controllers on the host\n"
		"  fuzz   Class-directed Bluetooth HCI fuzzer (see: linux bt fuzz --help)\n");
}

int linux_bt_main(int argc, char **argv)
{
	if (argc < 2 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ||
	    !strcmp(argv[1], "help")) {
		bt_usage();
		return argc < 2 ? 2 : 0;
	}
	if (!strcmp(argv[1], "list"))
		return bt_list_main(argc - 1, argv + 1);
	if (!strcmp(argv[1], "fuzz"))
		return bt_fuzz_cmd_main(argc - 1, argv + 1);

	fprintf(stderr, "Unknown bt subcommand: %s\n\n", argv[1]);
	bt_usage();
	return 2;
}
