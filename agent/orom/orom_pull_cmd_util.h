// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef OROM_PULL_CMD_UTIL_H
#define OROM_PULL_CMD_UTIL_H

#include "../util/orom_util.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Environment variable values that seed orom arg parsing defaults. */
struct ela_orom_env {
	const char *verbose;       /* ELA_VERBOSE */
	const char *insecure;      /* ELA_OUTPUT_INSECURE */
	const char *output_tcp;    /* ELA_OUTPUT_TCP */
	const char *output_http;   /* ELA_OUTPUT_HTTP */
	const char *output_https;  /* ELA_OUTPUT_HTTPS */
	const char *output_fmt;    /* ELA_OUTPUT_FORMAT */
};

/* Parsed and validated result from ela_orom_parse_args. */
struct ela_orom_parsed_args {
	const char *action;       /* "pull" or "list" */
	const char *output_tcp;   /* tcp output spec, or NULL */
	const char *output_uri;   /* resolved http or https URI, or NULL */
	bool verbose;
	bool insecure;
	enum orom_output_format fmt;
};

/*
 * Parse argc/argv and validate flags.  env provides the env-var defaults
 * that would normally come from getenv() in orom_group_main.
 *
 * Returns:
 *   0  – success; *out is valid, caller should proceed to ISA check + execute
 *   1  – help requested; caller should print usage and return 0
 *   2  – usage/argument error; message written to errbuf if non-NULL
 */
int ela_orom_parse_args(int argc, char **argv,
			const char *fw_mode,
			const struct ela_orom_env *env,
			struct ela_orom_parsed_args *out,
			char *errbuf, size_t errbuf_sz);

/*
 * Build the "OROM <name> <rom_len>\n" TCP header into hdr[hdr_sz].
 * Returns the number of bytes written (excluding NUL), or -1 on overflow.
 */
int ela_orom_build_tcp_header(char *hdr, size_t hdr_sz,
			      const char *name, size_t rom_len);

/*
 * Allocate and build the HTTP upload payload: <name>\n<data bytes>.
 * Sets *out and *out_len; caller must free *out.
 * Returns 0 on success, -1 on allocation failure or bad arguments.
 */
int ela_orom_build_http_payload(const char *name,
				const uint8_t *data, size_t data_len,
				uint8_t **out, size_t *out_len);

#endif /* OROM_PULL_CMD_UTIL_H */
