// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * `linux cpu` -- CPU instruction fuzzer, the ELA analog of sandsifter. `cpu
 * list` reports the host ISA and the fuzz mode that applies; `cpu fuzz`
 * discovers undocumented / undefined-but-present / anomalous machine
 * instructions on the CPU the agent is running on.
 *
 * You can only execute the ISA you are running on, so there is no --target: the
 * ISA is the host's, taken from the binary's compile-time architecture (it is
 * native to its target). x86/x86_64 use a sandsifter-style length-guided tunnel;
 * fixed-width ISAs (AArch64/ARM32/MIPS/PowerPC/RISC-V) sweep their encoding
 * space. See docs/agent/linux/cpu-fuzz.md.
 *
 * AUTHORIZED USE ONLY: this executes fuzzer-generated machine code on the host
 * CPU. It is isolated in short-lived child processes, but a hostile instruction
 * can still wedge a core or panic the host. Run it on hardware you own and can
 * power-cycle -- never inside another sandbox / under ptrace.
 */
#include "embedded_linux_audit_cmd.h"
#include "arch/arch_target.h"
#include "linux/cpu/cpu_fuzz.h"
#include "linux/cpu/cpu_fuzz_stream.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * The host ISA name for the module dispatcher: ARCH_ISA carries the family, and
 * ARCH_ENDIANNESS disambiguates the byte order the fixed-width modules need
 * (ARCH_ISA alone does not distinguish e.g. mips from mipsel).
 */
static const char *host_isa_name(void)
{
	int big = !strcmp(ARCH_ENDIANNESS, "big");

	if (!strcmp(ARCH_ISA, "aarch64"))
		return big ? "aarch64-be" : "aarch64-le";
	if (!strcmp(ARCH_ISA, "arm32"))
		return big ? "arm32-be" : "arm32";
	if (!strcmp(ARCH_ISA, "mips"))
		return big ? "mips" : "mipsel";
	if (!strcmp(ARCH_ISA, "mips64"))
		return big ? "mips64" : "mips64el";
	if (!strcmp(ARCH_ISA, "powerpc"))
		return "powerpc";
	if (!strcmp(ARCH_ISA, "powerpc64"))
		return big ? "powerpc64" : "powerpc64le";
	return ARCH_ISA;	/* x86, x86_64, riscv32, riscv64 */
}

static int parse_mode(const char *s, enum cpu_mode *out)
{
	if (!strcmp(s, "tunnel")) { *out = CPU_MODE_TUNNEL; return 0; }
	if (!strcmp(s, "brute"))  { *out = CPU_MODE_BRUTE;  return 0; }
	if (!strcmp(s, "random")) { *out = CPU_MODE_RANDOM; return 0; }
	if (!strcmp(s, "sweep"))  { *out = CPU_MODE_SWEEP;  return 0; }
	return -1;
}

static void fuzz_usage(void)
{
	fprintf(stderr,
		"Usage: embedded_linux_audit linux cpu fuzz [options]\n"
		"  Discover undocumented/undefined-but-present machine instructions\n"
		"  on the host CPU (ISA = %s). AUTHORIZED USE ONLY -- executes\n"
		"  generated machine code; can wedge a core or panic the host.\n"
		"\n"
		"  --mode NAME      tunnel|brute|random (x86) or sweep (fixed-width);\n"
		"                     default is ISA-appropriate\n"
		"  --iterations N   candidates to run (default 1000000)\n"
		"  --length N       x86 max candidate byte length, 1..15 (default 15)\n"
		"  --probe-every N  progress/stream heartbeat cadence (default 4096)\n"
		"  --seed N         rng seed / sweep base (default 1)\n"
		"  --out DIR        finding output dir (default crashes)\n"
		"  --replay FILE    re-execute a saved/returned finding on this CPU\n"
		"                     (ISA taken from the file header; must match host)\n"
		"  --show FILE      decode a finding offline (no execution)\n"
		"  --thumb          ARM32 host: fuzz the Thumb (T32) set instead of A32\n"
		"  --insecure       skip TLS verify when streaming to --output-http\n"
		"  --selftest       run offline engine self-tests (no execution)\n",
		host_isa_name());
}

static int cpu_fuzz_cmd_main(int argc, char **argv)
{
	enum {
		OPT_MODE = 1, OPT_ITERATIONS, OPT_LENGTH, OPT_PROBE_EVERY,
		OPT_SEED, OPT_OUT, OPT_REPLAY, OPT_SHOW, OPT_INSECURE,
		OPT_SELFTEST, OPT_THUMB,
	};
	static const struct option long_opts[] = {
		{ "mode",        required_argument, NULL, OPT_MODE },
		{ "iterations",  required_argument, NULL, OPT_ITERATIONS },
		{ "length",      required_argument, NULL, OPT_LENGTH },
		{ "probe-every", required_argument, NULL, OPT_PROBE_EVERY },
		{ "seed",        required_argument, NULL, OPT_SEED },
		{ "out",         required_argument, NULL, OPT_OUT },
		{ "replay",      required_argument, NULL, OPT_REPLAY },
		{ "show",        required_argument, NULL, OPT_SHOW },
		{ "insecure",    no_argument,       NULL, OPT_INSECURE },
		{ "selftest",    no_argument,       NULL, OPT_SELFTEST },
		{ "thumb",       no_argument,       NULL, OPT_THUMB },
		{ "help",        no_argument,       NULL, 'h' },
		{ 0, 0, 0, 0 }
	};
	struct cpu_fuzz_opts o = {
		.iterations = 1000000,
		.max_len = 0,
		.probe_every = 4096,
		.seed = 1,
		.out_dir = "crashes",
	};
	const char *show_path = NULL;
	const char *isa_name = host_isa_name();
	struct cpu_isa *isa;
	int insecure = 0, thumb = 0, opt;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "h", long_opts, NULL)) != -1) {
		switch (opt) {
		case OPT_MODE:
			if (parse_mode(optarg, &o.mode) != 0) {
				fprintf(stderr, "cpu fuzz: bad --mode '%s'\n", optarg);
				return 2;
			}
			o.mode_explicit = 1;
			break;
		case OPT_ITERATIONS: o.iterations = atol(optarg); break;
		case OPT_LENGTH:     o.max_len = atoi(optarg); break;
		case OPT_PROBE_EVERY: o.probe_every = atoi(optarg); break;
		case OPT_SEED:       o.seed = strtoull(optarg, NULL, 0); break;
		case OPT_OUT:        o.out_dir = optarg; break;
		case OPT_REPLAY:     o.replay_path = optarg; break;
		case OPT_SHOW:       show_path = optarg; break;
		case OPT_INSECURE:   insecure = 1; break;
		case OPT_THUMB:      thumb = 1; break;
		case OPT_SELFTEST:   return cpu_fuzz_selftest_run();
		case 'h':            fuzz_usage(); return 0;
		default:             fuzz_usage(); return 2;
		}
	}
	if (optind < argc) {
		fprintf(stderr, "cpu fuzz: unexpected argument: %s\n", argv[optind]);
		fuzz_usage();
		return 2;
	}
	if (o.probe_every < 1)
		o.probe_every = 1;
	if (o.max_len < 0 || o.max_len > 15) {
		fprintf(stderr, "cpu fuzz: --length must be 1..15\n");
		return 2;
	}
	if (thumb) {
		if (strcmp(ARCH_ISA, "arm32") == 0) {
			isa_name = "arm32-thumb";	/* fuzz T32, not A32 */
		} else {
			fprintf(stderr, "cpu fuzz: --thumb applies only to an "
				"ARM32 host (this host is %s); ignoring\n", ARCH_ISA);
		}
	}

	/*
	 * --show decodes offline, so it uses whatever ISA the finding file
	 * records. --replay re-executes on THIS CPU, so a finding file returned
	 * from the fuzzing process (streamed to the agent API and downloaded
	 * back, or copied off the target) must match the host ISA -- you cannot
	 * execute a foreign ISA. Both take the ISA from the "# target=cpu-<isa>"
	 * header when present.
	 */
	if (show_path || o.replay_path) {
		const char *src = show_path ? show_path : o.replay_path;
		char inferred[32];

		if (cpu_fuzz_peek_isa(src, inferred, sizeof(inferred)) == 0) {
			if (o.replay_path && !show_path &&
			    strcmp(inferred, host_isa_name()) != 0 &&
			    strcmp(inferred, ARCH_ISA) != 0) {
				fprintf(stderr,
					"cpu fuzz: cannot replay -- finding file is for "
					"ISA '%s' but this host is '%s'.\n"
					"  Replay must run on a matching CPU; use --show to "
					"decode it here.\n",
					inferred, host_isa_name());
				return 2;
			}
			isa_name = inferred;
		}
	}

	isa = cpu_isa_for(isa_name);
	if (!isa) {
		fprintf(stderr,
			"cpu fuzz: no fuzz module for host ISA '%s'\n"
			"  supported: x86, x86_64, aarch64, arm32, mips, mips64,\n"
			"             powerpc, powerpc64, riscv32, riscv64\n",
			isa_name);
		return 2;
	}

	if (!o.mode_explicit)
		o.mode = isa->variable_length ? CPU_MODE_TUNNEL : CPU_MODE_SWEEP;

	if (show_path)
		return cpu_fuzz_show(isa, show_path);
	if (o.replay_path)
		return cpu_fuzz_run(isa, &o);

	/* Live fuzz: open the remote dead-man's-switch stream if --output-http is
	 * set (a wedged core can take the host down before local triage runs). */
	{
		struct cpu_fuzz_stream stream;
		char tag[48];
		int rc;

		snprintf(tag, sizeof(tag), "cpu-%s", isa->name);
		if (cpu_fuzz_stream_open(&stream, tag, 1, insecure) == 0)
			o.sink = &stream.sink;
		rc = cpu_fuzz_run(isa, &o);
		if (o.sink)
			cpu_fuzz_stream_done(&stream);
		return rc;
	}
}

static int cpu_list_main(int argc, char **argv)
{
	const char *isa_name = host_isa_name();
	struct cpu_isa *isa;

	if (argc > 1) {
		if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ||
		    !strcmp(argv[1], "help")) {
			fprintf(stderr,
				"Usage: embedded_linux_audit linux cpu list\n"
				"  Show the host ISA and the applicable cpu fuzz mode.\n");
			return 0;
		}
		fprintf(stderr, "cpu list: unexpected argument: %s\n", argv[1]);
		return 2;
	}

	isa = cpu_isa_for(isa_name);
	printf("%-14s %-10s %-10s %s\n", "HOST ISA", "WIDTH", "MODE",
	       "FUZZER");
	if (!isa) {
		printf("%-14s %-10s %-10s %s\n", isa_name, "-", "-",
		       "(unsupported)");
		printf("\nNo cpu fuzz module for this ISA.\n");
		return 0;
	}
	printf("%-14s %-10s %-10s %s\n", isa->name,
	       isa->variable_length ? "1-15 (var)" : "4 (fixed)",
	       isa->variable_length ? "tunnel" : "sweep",
	       "supported");
	printf("\nFuzz it with: linux cpu fuzz%s\n",
	       isa->variable_length ? " [--mode tunnel|brute|random]" :
				      " [--mode sweep]");
	printf("AUTHORIZED USE ONLY -- executes generated machine code on this "
	       "CPU; can wedge a core or panic the host.\n");
	return 0;
}

static void cpu_usage(void)
{
	fprintf(stderr,
		"Usage: embedded_linux_audit linux cpu <subcommand>\n"
		"  list   Show the host ISA and applicable fuzz mode\n"
		"  fuzz   CPU instruction fuzzer (see: linux cpu fuzz --help)\n");
}

int linux_cpu_main(int argc, char **argv)
{
	if (argc < 2 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ||
	    !strcmp(argv[1], "help")) {
		cpu_usage();
		return argc < 2 ? 2 : 0;
	}
	if (!strcmp(argv[1], "list"))
		return cpu_list_main(argc - 1, argv + 1);
	if (!strcmp(argv[1], "fuzz"))
		return cpu_fuzz_cmd_main(argc - 1, argv + 1);

	fprintf(stderr, "Unknown cpu subcommand: %s\n\n", argv[1]);
	cpu_usage();
	return 2;
}
