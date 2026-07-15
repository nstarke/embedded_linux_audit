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
#include "linux/wlan/wlan_fuzz_stream.h"
#include "linux/linux_wlan_util.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
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
		"           usb-generic (blind fuzz any USB NIC by VID:PID; needs --usb-id)\n"
		"           wext-generic (blind fuzz a WEXT driver's ioctls; needs --iface,\n"
		"                        root; targets the HOST KERNEL -- can panic it)\n"
		"  --target NAME    NIC target to fuzz (required)\n"
		"  --usb-id V:P     usb-generic only: target USB device by hex VID:PID\n"
		"                   (e.g. 0bda:8179; product '*' or omitted = any)\n"
		"  --iface NAME     wext-generic only: network interface to fuzz (e.g. wlan0)\n"
		"  --insecure       wext-generic only: skip TLS verification when streaming\n"
		"                   payloads to the agent API (--output-http) for remote\n"
		"                   crash capture (the host can panic; the API keeps the\n"
		"                   last payload and saves it as a triage result on drop)\n"
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

static struct target *resolve_target(const char *tname, const char *fw,
				     uint16_t usb_vid, uint16_t usb_pid,
				     const char *iface)
{
	if (!strcmp(tname, "usb-generic"))
		return target_usb_generic(usb_vid, usb_pid);
	if (!strcmp(tname, "wext-generic"))
		return target_wext_generic(iface);
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
		OPT_OUT, OPT_FW, OPT_REPLAY, OPT_SELFTEST, OPT_SHOW, OPT_USB_ID,
		OPT_IFACE, OPT_INSECURE,
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
		{ "usb-id",      required_argument, NULL, OPT_USB_ID },
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
	const char *fw = NULL;
	const char *show_path = NULL;
	const char *usb_id = NULL;
	const char *iface = NULL;
	uint16_t usb_vid = 0, usb_pid = 0;
	int insecure = 0;
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
		case OPT_USB_ID:
			usb_id = optarg;
			break;
		case OPT_IFACE:
			iface = optarg;
			break;
		case OPT_INSECURE:
			insecure = 1;
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

	/* usb-generic addresses a device by VID:PID. --show decodes offline and
	 * needs no device, so the id is only required for hardware runs. */
	if (usb_id && wlan_parse_usb_id(usb_id, &usb_vid, &usb_pid) != 0) {
		fprintf(stderr,
			"wlan fuzz: bad --usb-id '%s' (want hex VID:PID, e.g. 0bda:8179)\n",
			usb_id);
		return 2;
	}
	if (!strcmp(tname, "usb-generic") && !usb_id && !show_path) {
		fprintf(stderr,
			"wlan fuzz: --target usb-generic requires --usb-id <VID:PID>\n");
		fuzz_usage("embedded_linux_audit");
		return 2;
	}

	/* wext-generic addresses a driver by interface name; likewise only
	 * needed for a hardware run (not offline --show). */
	if (!strcmp(tname, "wext-generic") && !show_path) {
		if (!iface) {
			fprintf(stderr,
				"wlan fuzz: --target wext-generic requires --iface <name>\n");
			fuzz_usage("embedded_linux_audit");
			return 2;
		}
		if (!wlan_valid_iface(iface)) {
			fprintf(stderr,
				"wlan fuzz: bad --iface '%s' (1-15 chars, no '/' or whitespace)\n",
				iface);
			return 2;
		}
	}

	t = resolve_target(tname, fw, usb_vid, usb_pid, iface);
	if (!t) {
		fprintf(stderr, "wlan fuzz: unknown target: %s\n", tname);
		fuzz_usage("embedded_linux_audit");
		return 2;
	}

	/* --show decodes a crash file offline (no hardware) for triage. */
	if (show_path)
		return wlan_fuzz_show(t, show_path);

	/* When an agent API is configured, connect so confirmed crashes are
	 * uploaded as they are found. wext-generic additionally streams every
	 * payload before it executes (the host-panic dead-man's-switch), since it
	 * fuzzes the host kernel and a panic would kill local triage. */
	if (!o.replay_path) {
		struct wlan_fuzz_stream stream;
		int stream_payloads = !strcmp(tname, "wext-generic");
		int rc;

		if (wlan_fuzz_stream_open(&stream, tname, "wlan-fuzz",
					  stream_payloads, insecure) == 0)
			o.sink = &stream.sink;
		rc = wlan_fuzz_run(t, &o);
		if (o.sink)
			wlan_fuzz_stream_done(&stream);
		return rc;
	}

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

/* LCOV_EXCL_START -- thin sysfs/procfs I/O wrappers; exercised only in the field */

/* Read up to bufsz-1 bytes of a (small) file, NUL-terminate. 0 ok, -1 fail. */
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

/*
 * True if `iface` appears as an interface column in a /proc/net/wireless dump
 * (a line "  <iface>: ..."). Matches the name only when bounded by whitespace
 * on the left and ':' on the right, so "wlan0" does not match "wlan01".
 */
static int proc_wireless_has(const char *buf, const char *iface)
{
	size_t ilen = strlen(iface);
	const char *p = buf;

	while ((p = strstr(p, iface))) {
		char before = (p == buf) ? '\n' : p[-1];
		char after = p[ilen];

		if (after == ':' &&
		    (before == ' ' || before == '\t' || before == '\n'))
			return 1;
		p += ilen;
	}
	return 0;
}

/* True if the netdev's own uevent advertises DEVTYPE=wlan. */
static int uevent_is_wlan(const char *iface)
{
	char path[512], text[4096], val[32];

	snprintf(path, sizeof(path), "/sys/class/net/%s/uevent", iface);
	if (read_text_file(path, text, sizeof(text)) != 0)
		return 0;
	if (wlan_uevent_value(text, "DEVTYPE", val, sizeof(val)) != 0)
		return 0;
	return !strcmp(val, "wlan");
}

/*
 * Resolve the bound driver name for a netdev: prefer the device/driver
 * symlink, falling back to DRIVER= in device/uevent (present for some
 * out-of-tree modules that do not expose the symlink). "?" if unknown.
 */
static void read_iface_driver(const char *iface, char *out, size_t outsz)
{
	char path[512], text[4096];

	snprintf(path, sizeof(path), "/sys/class/net/%s/device/driver", iface);
	if (read_link_base(path, out, outsz) == 0)
		return;
	snprintf(path, sizeof(path), "/sys/class/net/%s/device/uevent", iface);
	if (read_text_file(path, text, sizeof(text)) == 0 &&
	    wlan_uevent_value(text, "DRIVER", out, outsz) == 0)
		return;
	snprintf(out, outsz, "?");
}

/*
 * Read the parent USB device's VID:PID for a netdev into "vvvv:pppp". The
 * device symlink points at the USB *interface*; its parent (..) is the USB
 * device, which carries idVendor/idProduct. Returns 0 on success, -1 if not a
 * USB device or the attrs are unreadable.
 */
static int read_iface_usb_id(const char *iface, char *out, size_t outsz)
{
	char path[512], vid[8], pid[8];	/* idVendor/idProduct are 4 hex digits */

	snprintf(path, sizeof(path), "/sys/class/net/%s/device/../idVendor",
		 iface);
	if (read_text_file(path, vid, sizeof(vid)) != 0)
		return -1;
	snprintf(path, sizeof(path), "/sys/class/net/%s/device/../idProduct",
		 iface);
	if (read_text_file(path, pid, sizeof(pid)) != 0)
		return -1;
	vid[strcspn(vid, "\r\n")] = '\0';
	pid[strcspn(pid, "\r\n")] = '\0';
	if (!*vid || !*pid)
		return -1;
	snprintf(out, outsz, "%s:%s", vid, pid);
	return 0;
}
/* LCOV_EXCL_STOP */

/*
 * linux_wlan_list_main enumerates wireless NICs from sysfs. A netdev is
 * treated as wireless when any kernel marker says so -- a phy80211 link, a
 * wireless/ dir, a /proc/net/wireless row, or DEVTYPE=wlan -- and, failing
 * all of those, when its name matches a wireless pattern (proprietary stacks
 * that register no cfg80211/WEXT node; flagged "name?" and low-confidence).
 * For each we read the bound driver and bus and map them to a fuzzer target.
 */
static int linux_wlan_list_main(int argc, char **argv)
{
	struct blind_cand {
		int  kind;	/* 0 = usb-generic (by id), 1 = wext-generic */
		char name[32];
		char id[20];	/* usb: "vvvv:pppp" or empty; wext: unused */
	} cand[64] = { { 0, { 0 }, { 0 } } };
	char procwl[8192];
	int have_procwl;
	DIR *d;
	struct dirent *de;
	int found = 0, supported = 0, guessed = 0, ncand = 0, i;

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

	/* Read /proc/net/wireless once; it lists every WEXT/cfg80211 iface. */
	have_procwl = read_text_file("/proc/net/wireless", procwl,
				     sizeof(procwl)) == 0;

	printf("%-12s %-6s %-16s %-5s %-10s %-8s %-14s %s\n",
	       "INTERFACE", "PHY", "DRIVER", "BUS", "USBID", "DETECT",
	       "FUZZER TARGET", "TRANSPORT");
	while ((de = readdir(d))) {
		char path[512], phy[64], drv[64], bus[32], usbid[20];
		int has_phy, has_wext, in_procwl, is_wlan;
		enum wlan_wireless_confidence conf;
		const char *target, *transport, *detect;

		if (de->d_name[0] == '.')
			continue;

		snprintf(path, sizeof(path), "/sys/class/net/%s/phy80211",
			 de->d_name);
		has_phy = access(path, F_OK) == 0;
		snprintf(path, sizeof(path), "/sys/class/net/%s/wireless",
			 de->d_name);
		has_wext = access(path, F_OK) == 0;
		in_procwl = have_procwl && proc_wireless_has(procwl, de->d_name);
		is_wlan = uevent_is_wlan(de->d_name);

		conf = wlan_classify_wireless(has_phy, has_wext, in_procwl,
					      is_wlan, de->d_name);
		if (conf == WLAN_WIRELESS_NO)
			continue;	/* not a wireless interface */
		found++;
		if (conf == WLAN_WIRELESS_NAME) {
			guessed++;
			detect = "name?";
		} else {
			detect = has_phy ? "phy80211" :
				 has_wext ? "wext" :
				 in_procwl ? "proc" : "devtype";
		}

		snprintf(path, sizeof(path), "/sys/class/net/%s/phy80211",
			 de->d_name);
		if (read_link_base(path, phy, sizeof(phy)) != 0)
			snprintf(phy, sizeof(phy), "-");
		read_iface_driver(de->d_name, drv, sizeof(drv));
		snprintf(path, sizeof(path), "/sys/class/net/%s/device/subsystem",
			 de->d_name);
		if (read_link_base(path, bus, sizeof(bus)) != 0)
			snprintf(bus, sizeof(bus), "?");
		if (strcmp(bus, "usb") != 0 ||
		    read_iface_usb_id(de->d_name, usbid, sizeof(usbid)) != 0)
			snprintf(usbid, sizeof(usbid), "-");

		target = wlan_target_for_driver(drv, bus);
		if (target)
			supported++;
		transport = target ?
			(wlan_target_uses_kmod(target) ? "ela_kmod shim" : "usbfs") :
			"-";
		printf("%-12s %-6s %-16s %-5s %-10s %-8s %-14s %s\n", de->d_name,
		       phy, drv, bus, usbid, detect,
		       target ? target : "(unsupported)", transport);

		/* No class-directed target, but reachable for a blind sweep:
		 * a USB NIC via `usb-generic`, and/or a WEXT driver (DETECT=wext)
		 * via `wext-generic`. Record each applicable option for the hints. */
		if (!target && !strcmp(bus, "usb") &&
		    ncand < (int)(sizeof(cand) / sizeof(cand[0]))) {
			cand[ncand].kind = 0;
			snprintf(cand[ncand].name, sizeof(cand[ncand].name), "%s",
				 de->d_name);
			snprintf(cand[ncand].id, sizeof(cand[ncand].id), "%s",
				 strcmp(usbid, "-") ? usbid : "");
			ncand++;
		}
		if (!target && has_wext &&
		    ncand < (int)(sizeof(cand) / sizeof(cand[0]))) {
			cand[ncand].kind = 1;
			snprintf(cand[ncand].name, sizeof(cand[ncand].name), "%s",
				 de->d_name);
			ncand++;
		}
	}
	closedir(d);

	if (!found) {
		printf("No WLAN interfaces found.\n");
		return 0;
	}
	if (guessed)
		printf("\n%d WLAN interface(s) (%d name-only guess(es), no kernel"
		       " wireless marker), %d fuzzable with `linux wlan fuzz"
		       " --target <name>`.\n", found, guessed, supported);
	else
		printf("\n%d WLAN interface(s), %d fuzzable with `linux wlan fuzz --target <name>`.\n",
		       found, supported);

	/* Point the operator at the blind fallbacks for NICs with no
	 * class-directed target (proprietary/unknown firmware). */
	{
		int nusb = 0, nwext = 0;

		for (i = 0; i < ncand; i++)
			cand[i].kind ? nwext++ : nusb++;

		if (nusb) {
			printf("\n%d USB NIC(s) with no class-directed target -- blind-fuzz"
			       " with `--target usb-generic` (shallow coverage):\n", nusb);
			for (i = 0; i < ncand; i++) {
				if (cand[i].kind)
					continue;
				if (cand[i].id[0])
					printf("  %-12s linux wlan fuzz --target usb-generic --usb-id %s\n",
					       cand[i].name, cand[i].id);
				else
					printf("  %-12s (VID:PID unreadable; pass --usb-id <VID:PID> from lsusb)\n",
					       cand[i].name);
			}
		}
		if (nwext) {
			printf("\n%d WEXT NIC(s) with no class-directed target -- blind-fuzz"
			       " the driver ioctls with `--target wext-generic` (root; can"
			       " panic the host):\n", nwext);
			for (i = 0; i < ncand; i++)
				if (cand[i].kind)
					printf("  %-12s sudo linux wlan fuzz --target wext-generic --iface %s\n",
					       cand[i].name, cand[i].name);
		}
	}
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
