// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../embedded_linux_audit_cmd.h"
#include "../util/command_parse_util.h"
#include "../util/output_buffer.h"
#include "../util/record_formatter.h"
#include "../net/http_client.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * Compile-time architecture properties derived from the target triple.
 *
 * These values are baked in at build time so they reflect the binary's
 * actual target, not the host running the binary.  The compiler macros used
 * here are defined by GCC and Clang (including Zig cc / LLVM).
 * ---------------------------------------------------------------------- */

/* ISA family ------------------------------------------------------------ */
#if defined(__x86_64__)
#  define ARCH_ISA "x86_64"
#elif defined(__i386__)
#  define ARCH_ISA "x86"
#elif defined(__aarch64__)
#  define ARCH_ISA "aarch64"
#elif defined(__arm__)
#  define ARCH_ISA "arm32"
#elif defined(__mips64)
#  define ARCH_ISA "mips64"
#elif defined(__mips__)
#  define ARCH_ISA "mips"
#elif defined(__powerpc64__)
#  define ARCH_ISA "powerpc64"
#elif defined(__powerpc__)
#  define ARCH_ISA "powerpc"
#elif defined(__riscv)
#  if __riscv_xlen == 64
#    define ARCH_ISA "riscv64"
#  else
#    define ARCH_ISA "riscv32"
#  endif
#else
#  define ARCH_ISA "unknown"
#endif

/* Pointer width → bit size ---------------------------------------------- */
#if defined(__SIZEOF_POINTER__)
#  if __SIZEOF_POINTER__ == 8
#    define ARCH_BITS "64"
#  else
#    define ARCH_BITS "32"
#  endif
#elif defined(__LP64__) || defined(_LP64)
#  define ARCH_BITS "64"
#else
#  define ARCH_BITS "32"
#endif

/* Endianness ------------------------------------------------------------ */
#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__)
#  if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#    define ARCH_ENDIANNESS "big"
#  else
#    define ARCH_ENDIANNESS "little"
#  endif
#elif defined(__BIG_ENDIAN__)
#  define ARCH_ENDIANNESS "big"
#else
#  define ARCH_ENDIANNESS "little"
#endif

/* -------------------------------------------------------------------------
 * Output helpers
 * ---------------------------------------------------------------------- */

/*
 * All functions in this file require real hardware, network I/O, or OS-level
 * services (ptrace, SSH, sockets, TPM2, EFI) and cannot be exercised in the
 * unit-test environment.
 */
/* LCOV_EXCL_START */

static const char *arch_content_type(const char *fmt)
{
	if (fmt && !strcmp(fmt, "json"))
		return "application/json; charset=utf-8";
	if (fmt && !strcmp(fmt, "csv"))
		return "text/csv; charset=utf-8";
	return "text/plain; charset=utf-8";
}

/*
 * Build one output line for an arch value in the requested format and
 * dispatch it to all configured output channels (stdout, TCP, HTTP).
 *
 * subname: "bit", "isa", or "endianness"
 * value:   the string value to emit
 */
static int arch_emit(const char *fmt, const char *subname, const char *value,
		     int output_sock, const char *output_uri, bool insecure)
{
	struct output_buffer line = {0};
	int ret = 0;

	if (ela_format_arch_record(&line, fmt, subname, value) != 0) {
		ret = -1;
		goto out;
	}

	if (!line.data) {
		ret = -1;
		goto out;
	}

	if (output_sock >= 0)
		ela_send_all(output_sock, (const uint8_t *)line.data, line.len);

	if (output_uri && *output_uri) {
		char errbuf[256];
		char *upload_uri = ela_http_build_upload_uri(output_uri, "arch", NULL);

		if (!upload_uri) {
			fprintf(stderr, "arch: failed to build HTTP upload URI\n");
			ret = 1;
		} else {
			if (ela_http_post(upload_uri,
					  (const uint8_t *)line.data,
					  line.len,
					  arch_content_type(fmt),
					  insecure,
					  false,
					  errbuf,
					  sizeof(errbuf)) < 0) {
				fprintf(stderr, "arch: HTTP POST failed to %s: %s\n",
					upload_uri, errbuf[0] ? errbuf : "unknown error");
				ret = 1;
			}
			free(upload_uri);
		}
	} else {
		fwrite(line.data, 1, line.len, stdout);
	}

out:
	free(line.data);
	return ret;
}

/* -------------------------------------------------------------------------
 * Command implementation
 * ---------------------------------------------------------------------- */

static void usage(const char *prog)
{
	printf("Usage: %s <subcommand>\n", prog);
	printf("\n");
	printf("Subcommands:\n");
	printf("  bit           Print the pointer width of the compiled binary: 32 or 64\n");
	printf("  isa           Print the instruction set architecture: x86, x86_64, arm32,\n");
	printf("                  aarch64, mips, mips64, powerpc, powerpc64, riscv32, riscv64\n");
	printf("  endianness    Print the byte order of the compiled binary: big or little\n");
	printf("\n");
	printf("All values are derived from compiler macros at build time and reflect\n");
	printf("the compilation target, not the host running the binary.\n");
	printf("\n");
	printf("Output format is controlled by ELA_OUTPUT_FORMAT / --output-format:\n");
	printf("  txt (default)  bare value on a single line\n");
	printf("  csv            CSV-quoted value\n");
	printf("  json           {\"record\":\"arch\",\"subcommand\":\"...\",\"value\":\"...\"}\n");
}

int arch_main(int argc, char **argv)
{
	const char *output_format  = getenv("ELA_OUTPUT_FORMAT");
	const char *output_tcp     = getenv("ELA_OUTPUT_TCP");
	const char *output_http    = getenv("ELA_OUTPUT_HTTP");
	const char *output_https   = getenv("ELA_OUTPUT_HTTPS");
	const char *parsed_http    = NULL;
	const char *parsed_https   = NULL;
	const char *output_uri     = NULL;
	bool insecure = getenv("ELA_OUTPUT_INSECURE") &&
			!strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");
	int output_sock = -1;
	char errbuf[256];
	const char *subname;
	const char *value;
	int ret;

	if (argc < 2 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ||
	    !strcmp(argv[1], "help")) {
		usage(argv[0]);
		return 0;
	}

	output_format = ela_output_format_or_default(output_format, "txt");

	if (!ela_output_format_is_valid(output_format)) {
		fprintf(stderr, "Invalid output format for arch: %s\n", output_format);
		return 2;
	}

	if (output_http && *output_http &&
	    ela_parse_http_output_uri(output_http,
				     &parsed_http,
				     &parsed_https,
				     errbuf,
				     sizeof(errbuf)) < 0) {
		fprintf(stderr, "%s\n", errbuf);
		return 2;
	}

	if (parsed_http)   output_uri = parsed_http;
	if (parsed_https)  output_uri = parsed_https;
	if (output_https && *output_https) output_uri = output_https;

	if (output_tcp && *output_tcp) {
		output_sock = ela_connect_tcp_ipv4(output_tcp);
		if (output_sock < 0) {
			fprintf(stderr,
				"Invalid/failed output target (expected IPv4:port): %s\n",
				output_tcp);
			return 1;
		}
	}

	if (!strcmp(argv[1], "bit")) {
		subname = "bit";
		value   = ARCH_BITS;
	} else if (!strcmp(argv[1], "isa")) {
		subname = "isa";
		value   = ARCH_ISA;
	} else if (!strcmp(argv[1], "endianness")) {
		subname = "endianness";
		value   = ARCH_ENDIANNESS;
	} else {
		fprintf(stderr, "Unknown arch subcommand: %s\n\n", argv[1]);
		usage(argv[0]);
		if (output_sock >= 0) close(output_sock);
		return 2;
	}

	ret = arch_emit(output_format, subname, value, output_sock, output_uri, insecure);

	if (output_sock >= 0)
		close(output_sock);

	return ret < 0 ? 1 : ret;
}

/* LCOV_EXCL_STOP */
