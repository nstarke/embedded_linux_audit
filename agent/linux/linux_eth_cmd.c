// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * `linux eth` -- ethernet NIC tooling, the ethernet counterpart of `linux
 * wlan`. `eth list` enumerates the host's ethernet NICs and reports which
 * `eth fuzz` target supports each; `eth fuzz` is a class-directed black-box
 * fuzzer for ethernet NIC command interfaces. It shares the NIC-fuzz engine
 * (grammar/mutation/loop/remote-crash-stream) with the WLAN fuzzer.
 *
 * AUTHORIZED USE ONLY: run against your own hardware. The ethtool-generic and
 * firmware targets exercise the host kernel driver / device firmware by design
 * and can wedge or panic the host.
 */
#include "embedded_linux_audit_cmd.h"
#include "linux/eth/eth_fuzz.h"
#include "linux/wlan/wlan_fuzz_stream.h"
#include "linux/linux_eth_util.h"
#include "linux/linux_wlan_util.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- small sysfs helpers (mirror linux_wlan_cmd.c) ------------------------ */

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

static int read_text_file(const char *path, char *buf, size_t bufsz)
{
	int fd;
	ssize_t n;

	if (bufsz == 0)
		return -1;
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	n = read(fd, buf, bufsz - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = '\0';
	return 0;
}

/* Extract a KEY=value line's value from device/uevent (driver-name fallback). */
static int uevent_value(const char *iface, const char *key, char *out,
			size_t outsz)
{
	char path[512], text[4096];

	snprintf(path, sizeof(path), "/sys/class/net/%s/device/uevent", iface);
	if (read_text_file(path, text, sizeof(text)) != 0)
		return -1;
	return wlan_uevent_value(text, key, out, outsz);
}

static void read_iface_driver(const char *iface, char *out, size_t outsz)
{
	char path[512];

	snprintf(path, sizeof(path), "/sys/class/net/%s/device/driver", iface);
	if (read_link_base(path, out, outsz) == 0)
		return;
	if (uevent_value(iface, "DRIVER", out, outsz) == 0)
		return;
	snprintf(out, outsz, "?");
}

/* A physical ethernet NIC: ARPHRD_ETHER (type 1), a real device link, and not
 * a wireless radio (which is also type 1). Excludes lo/veth/bridge/bond/tun. */
static int iface_is_eth_nic(const char *iface)
{
	char path[512], type[16];
	int has_phy, has_wext;

	snprintf(path, sizeof(path), "/sys/class/net/%s/type", iface);
	if (read_text_file(path, type, sizeof(type)) != 0 ||
	    atoi(type) != 1)
		return 0;
	snprintf(path, sizeof(path), "/sys/class/net/%s/device", iface);
	if (access(path, F_OK) != 0)
		return 0;	/* no backing device: virtual interface */
	snprintf(path, sizeof(path), "/sys/class/net/%s/phy80211", iface);
	has_phy = access(path, F_OK) == 0;
	snprintf(path, sizeof(path), "/sys/class/net/%s/wireless", iface);
	has_wext = access(path, F_OK) == 0;
	return !has_phy && !has_wext;	/* wireless NICs belong to `wlan list` */
}
/* LCOV_EXCL_STOP */

static struct target *resolve_target(const char *tname, const char *iface)
{
	if (!strcmp(tname, "ethtool-generic"))
		return target_ethtool_generic(iface);
	if (!strcmp(tname, "bnxt"))
		return target_bnxt();
	if (!strcmp(tname, "i40e"))
		return target_i40e();
	if (!strcmp(tname, "ice"))
		return target_ice();
	if (!strcmp(tname, "cxgb4"))
		return target_cxgb4();
	if (!strcmp(tname, "mlx5"))
		return target_mlx5();
	return NULL;
}

static void fuzz_usage(void)
{
	fprintf(stderr,
		"Usage: embedded_linux_audit linux eth fuzz --target <name> [options]\n"
		"  Class-directed fuzzer for ethernet NIC command interfaces.\n"
		"  AUTHORIZED USE ONLY -- exercises the host driver/firmware by design.\n"
		"\n"
		"  targets: ethtool-generic (blind SIOCETHTOOL ioctl fuzz of any NIC;\n"
		"                            needs --iface, root; targets the HOST KERNEL\n"
		"                            -- can panic it; no persistent EEPROM/flash writes)\n"
		"           bnxt i40e ice cxgb4 mlx5 (firmware mailbox/admin-queue commands\n"
		"                            via the ela_kmod shim; PCIe NICs)\n"
		"  --target NAME    NIC target to fuzz (required)\n"
		"  --iface NAME     ethtool-generic only: network interface (e.g. eth0)\n"
		"  --iterations N   cases to run (default 100000)\n"
		"  --probe-every N  liveness probe interval (default 8)\n"
		"  --seed N         rng seed (default 1234)\n"
		"  --out DIR        crash output dir (default crashes)\n"
		"  --replay FILE    reproduce a saved crash on hardware\n"
		"  --show FILE      decode a crash file for triage (offline, no hardware)\n"
		"  --insecure       skip TLS verification when streaming payloads to the\n"
		"                   agent API (--output-http) for remote crash capture\n"
		"  --selftest       run offline engine self-tests (no hardware)\n");
}

static int eth_fuzz_cmd_main(int argc, char **argv)
{
	enum {
		OPT_TARGET = 1, OPT_ITERATIONS, OPT_PROBE_EVERY, OPT_SEED,
		OPT_OUT, OPT_REPLAY, OPT_SHOW, OPT_IFACE, OPT_INSECURE,
		OPT_SELFTEST,
	};
	static const struct option long_opts[] = {
		{ "target",      required_argument, NULL, OPT_TARGET },
		{ "iterations",  required_argument, NULL, OPT_ITERATIONS },
		{ "probe-every", required_argument, NULL, OPT_PROBE_EVERY },
		{ "seed",        required_argument, NULL, OPT_SEED },
		{ "out",         required_argument, NULL, OPT_OUT },
		{ "replay",      required_argument, NULL, OPT_REPLAY },
		{ "show",        required_argument, NULL, OPT_SHOW },
		{ "iface",       required_argument, NULL, OPT_IFACE },
		{ "insecure",    no_argument,       NULL, OPT_INSECURE },
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
	const char *iface = NULL;
	const char *show_path = NULL;
	char inferred[32];
	struct target *t;
	int insecure = 0, opt;

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
		case OPT_IFACE: iface = optarg; break;
		case OPT_INSECURE: insecure = 1; break;
		case OPT_SELFTEST: return wlan_fuzz_selftest_run();
		case 'h': fuzz_usage(); return 0;
		default: fuzz_usage(); return 2;
		}
	}
	if (optind < argc) {
		fprintf(stderr, "eth fuzz: unexpected argument: %s\n", argv[optind]);
		fuzz_usage();
		return 2;
	}
	if (o.probe_every < 1) {
		fprintf(stderr, "eth fuzz: --probe-every must be >= 1\n");
		return 2;
	}

	if (!tname && (show_path || o.replay_path)) {
		const char *src = show_path ? show_path : o.replay_path;

		if (wlan_fuzz_peek_target(src, inferred, sizeof(inferred)) == 0)
			tname = inferred;
	}
	if (!tname) {
		fprintf(stderr, "eth fuzz: --target is required%s\n",
			(show_path || o.replay_path) ?
				" (crash file has no '# target=' header)" : "");
		fuzz_usage();
		return 2;
	}

	if (!strcmp(tname, "ethtool-generic") && !show_path) {
		if (!iface) {
			fprintf(stderr,
				"eth fuzz: --target ethtool-generic requires --iface <name>\n");
			fuzz_usage();
			return 2;
		}
		if (!wlan_valid_iface(iface)) {
			fprintf(stderr,
				"eth fuzz: bad --iface '%s' (1-15 chars, no '/' or whitespace)\n",
				iface);
			return 2;
		}
	}

	t = resolve_target(tname, iface);
	if (!t) {
		fprintf(stderr, "eth fuzz: unknown target: %s\n", tname);
		fuzz_usage();
		return 2;
	}

	if (show_path)
		return wlan_fuzz_show(t, show_path);

	/* ethtool-generic fuzzes the host kernel and can panic it. Stream each
	 * payload to the agent API first so the last one survives a panic. */
	if (!o.replay_path && !strcmp(tname, "ethtool-generic")) {
		struct wlan_fuzz_stream stream;
		int rc;

		if (wlan_fuzz_stream_open(&stream, tname, "eth-fuzz", insecure) == 0)
			o.sink = &stream.sink;
		rc = wlan_fuzz_run(t, &o);
		if (o.sink)
			wlan_fuzz_stream_done(&stream);
		return rc;
	}

	return wlan_fuzz_run(t, &o);
}

/* ---- list ----------------------------------------------------------------- */

static int eth_list_main(int argc, char **argv)
{
	DIR *d;
	struct dirent *de;
	int found = 0, supported = 0;

	if (argc > 1) {
		if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ||
		    !strcmp(argv[1], "help")) {
			fprintf(stderr,
				"Usage: embedded_linux_audit linux eth list\n"
				"  List ethernet NICs on the host and the fuzzer target that supports each.\n");
			return 0;
		}
		fprintf(stderr, "eth list: unexpected argument: %s\n", argv[1]);
		return 2;
	}

	/* LCOV_EXCL_START -- reads live sysfs; covered only in the field */
	d = opendir("/sys/class/net");
	if (!d) {
		fprintf(stderr, "eth list: cannot open /sys/class/net: %s\n",
			strerror(errno));
		return 1;
	}
	printf("%-12s %-14s %-5s %-16s %s\n",
	       "INTERFACE", "DRIVER", "BUS", "FUZZER TARGET", "TRANSPORT");
	while ((de = readdir(d))) {
		char path[512], drv[64], bus[32];
		const char *target, *transport;

		if (de->d_name[0] == '.')
			continue;
		if (!iface_is_eth_nic(de->d_name))
			continue;
		found++;
		read_iface_driver(de->d_name, drv, sizeof(drv));
		snprintf(path, sizeof(path), "/sys/class/net/%s/device/subsystem",
			 de->d_name);
		if (read_link_base(path, bus, sizeof(bus)) != 0)
			snprintf(bus, sizeof(bus), "?");

		target = eth_target_for_driver(drv);
		if (target)
			supported++;
		transport = target ?
			(eth_target_uses_kmod(target) ? "ela_kmod shim" : "-") :
			"ethtool ioctl";
		printf("%-12s %-14s %-5s %-16s %s\n", de->d_name, drv, bus,
		       target ? target : "ethtool-generic", transport);
	}
	closedir(d);

	if (!found) {
		printf("No ethernet NICs found.\n");
		return 0;
	}
	printf("\n%d ethernet NIC(s), %d with a class-directed firmware target; every"
	       " NIC is also fuzzable blind with `--target ethtool-generic --iface <name>`.\n",
	       found, supported);
	return 0;
	/* LCOV_EXCL_STOP */
}

static void eth_usage(void)
{
	fprintf(stderr,
		"Usage: embedded_linux_audit linux eth <subcommand>\n"
		"  list   Enumerate ethernet NICs on the host and show which the fuzzer supports\n"
		"  fuzz   Class-directed ethernet NIC fuzzer (see: linux eth fuzz --help)\n");
}

int linux_eth_main(int argc, char **argv)
{
	if (argc < 2 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ||
	    !strcmp(argv[1], "help")) {
		eth_usage();
		return argc < 2 ? 2 : 0;
	}
	if (!strcmp(argv[1], "list"))
		return eth_list_main(argc - 1, argv + 1);
	if (!strcmp(argv[1], "fuzz"))
		return eth_fuzz_cmd_main(argc - 1, argv + 1);

	fprintf(stderr, "Unknown eth subcommand: %s\n\n", argv[1]);
	eth_usage();
	return 2;
}
