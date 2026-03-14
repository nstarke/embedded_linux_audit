// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "tpm2_internal.h"

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(ELA_HAS_TPM2)

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <command>\n"
		"       %s list-commands\n"
		"\n"
		"TPM2 support is not compiled into this build.\n",
		prog, prog);
}

int tpm2_scan_main(int argc, char **argv)
{
	int opt;
	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ 0, 0, 0, 0 }
	};

	optind = 1;
	while ((opt = getopt_long(argc, argv, "h", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	if (optind >= argc || !strcmp(argv[optind], "help") ||
	    !strcmp(argv[optind], "--help") || !strcmp(argv[optind], "-h")) {
		usage(argv[0]);
		return optind >= argc ? 2 : 0;
	}

	fprintf(stderr, "tpm2: TPM2-TSS support is unavailable in this build\n");
	return 1;
}

#else

struct tpm2_command_desc {
	const char *name;
	const char *summary;
};

static const struct tpm2_command_desc supported_commands[] = {
	{ "createprimary", "Create a primary object and optionally serialize the ESYS context" },
	{ "getcap", "Query a small built-in set of TPM2 capabilities" },
	{ "nvreadpublic", "Read the public metadata for an NV index" },
	{ "pcrread", "Read PCR values for one or more PCR banks" },
};

static void usage(const char *prog)
{
	size_t i;

	fprintf(stderr,
		"Usage: %s <command> [command-options]\n"
		"       %s list-commands\n"
		"\n"
		"Built-in TPM2 commands implemented through TPM2-TSS:\n",
		prog, prog);

	for (i = 0; i < sizeof(supported_commands) / sizeof(supported_commands[0]); i++)
		fprintf(stderr, "  %-13s %s\n", supported_commands[i].name, supported_commands[i].summary);

	fprintf(stderr,
		"\n"
		"Examples:\n"
		"  %s getcap properties-fixed\n"
		"  %s pcrread sha256:0,1,2\n"
		"  %s nvreadpublic 0x1500016\n"
		"  %s createprimary -C o -g sha256 -G rsa -c primary.ctx\n",
		prog, prog, prog, prog);
}

static int cmd_list_commands(int argc)
{
	size_t i;

	if (argc != 2) {
		fprintf(stderr, "tpm2: list-commands does not accept additional arguments\n");
		return 2;
	}

	for (i = 0; i < sizeof(supported_commands) / sizeof(supported_commands[0]); i++)
		printf("%s\n", supported_commands[i].name);

	return 0;
}

int tpm2_scan_main(int argc, char **argv)
{
	int opt;
	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ 0, 0, 0, 0 }
	};

	optind = 1;
	while ((opt = getopt_long(argc, argv, "h", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	if (optind >= argc) {
		usage(argv[0]);
		return 2;
	}

	if (!strcmp(argv[optind], "help") || !strcmp(argv[optind], "--help") || !strcmp(argv[optind], "-h")) {
		usage(argv[0]);
		return 0;
	}

	if (!strcmp(argv[optind], "list-commands"))
		return cmd_list_commands(argc - optind + 1);
	if (!strcmp(argv[optind], "getcap"))
		return cmd_getcap(argc, argv);
	if (!strcmp(argv[optind], "pcrread"))
		return cmd_pcrread(argc, argv);
	if (!strcmp(argv[optind], "nvreadpublic"))
		return cmd_nvreadpublic(argc, argv);
	if (!strcmp(argv[optind], "createprimary"))
		return cmd_createprimary(argc, argv);

	fprintf(stderr, "tpm2: unsupported TPM2 command: %s\n", argv[optind]);
	usage(argv[0]);
	return 2;
}

#endif
