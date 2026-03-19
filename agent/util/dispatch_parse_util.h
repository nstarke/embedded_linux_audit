// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef UTIL_DISPATCH_PARSE_UTIL_H
#define UTIL_DISPATCH_PARSE_UTIL_H

#include <stdbool.h>
#include <stddef.h>

#define ELA_DISPATCH_DEFAULT_RETRY_ATTEMPTS 5

/*
 * Snapshot of relevant environment variables used as initial defaults.
 * Pass NULL for any variable that is not set.  The caller is responsible
 * for populating this from getenv() before calling ela_dispatch_parse_args.
 */
struct ela_dispatch_env {
	const char *output_format;   /* ELA_OUTPUT_FORMAT */
	const char *output_tcp;      /* ELA_OUTPUT_TCP    */
	const char *output_http;     /* ELA_OUTPUT_HTTP   */
	const char *output_https;    /* ELA_OUTPUT_HTTPS  */
	const char *quiet;           /* ELA_QUIET         */
	const char *output_insecure; /* ELA_OUTPUT_INSECURE */
	const char *ws_retry;        /* ELA_WS_RETRY_ATTEMPTS */
	const char *api_url;         /* ELA_API_URL       */
	const char *api_insecure;    /* ELA_API_INSECURE  */
	const char *script;          /* ELA_SCRIPT        */
};

/*
 * Fully-merged options produced by ela_dispatch_parse_args.
 * Pointer fields either point into argv[] strings or into env strings —
 * lifetimes are owned by the caller.
 */
struct ela_dispatch_opts {
	const char *output_format;
	const char *output_tcp;
	const char *output_http;
	const char *output_https;
	const char *script_path;
	const char *remote_target;
	const char *api_key;
	int         retry_attempts;
	bool        verbose;
	bool        insecure;
	bool        output_format_explicit;
	bool        output_explicit;
	bool        conf_needs_save;
	bool        show_help;
	int         cmd_idx;         /* index of the first non-global argument */
};

/*
 * Parse global flags from argv[1..], applying env defaults first.
 *
 * Returns  0 on success (opts->show_help may be set).
 * Returns  2 on usage error (errbuf filled when non-NULL).
 */
int ela_dispatch_parse_args(int argc, char **argv,
			    const struct ela_dispatch_env *env,
			    struct ela_dispatch_opts *opts,
			    char *errbuf, size_t errbuf_len);

#endif /* UTIL_DISPATCH_PARSE_UTIL_H */
