// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "dispatch_parse_util.h"
#include "http_uri_util.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void set_errbuf(char *errbuf, size_t errbuf_len, const char *msg)
{
	if (errbuf && errbuf_len)
		snprintf(errbuf, errbuf_len, "%s", msg);
}

static void set_errbuf_fmt(char *errbuf, size_t errbuf_len,
			   const char *fmt, const char *arg)
{
	if (errbuf && errbuf_len)
		snprintf(errbuf, errbuf_len, fmt, arg);
}

/* Apply ELA_QUIET values: "1", "true", "yes", "on" all mean quiet. */
static bool quiet_env_is_set(const char *v)
{
	if (!v)
		return false;
	return !strcmp(v, "1") || !strcmp(v, "true") ||
	       !strcmp(v, "yes") || !strcmp(v, "on");
}

/* Parse a retry-attempts integer value.  Returns 0 on success. */
static int parse_retry_attempts(const char *s, int *out)
{
	char *end;
	long v;

	if (!s || !*s)
		return -1;

	v = strtol(s, &end, 10);
	if (*end || v < 0 || v > 1000)
		return -1;

	*out = (int)v;
	return 0;
}

int ela_dispatch_parse_args(int argc, char **argv,
			    const struct ela_dispatch_env *env,
			    struct ela_dispatch_opts *opts,
			    char *errbuf, size_t errbuf_len)
{
	int cmd_idx = 1;

	if (!opts)
		return 2;

	memset(opts, 0, sizeof(*opts));
	opts->output_format    = "txt";
	opts->retry_attempts   = ELA_DISPATCH_DEFAULT_RETRY_ATTEMPTS;
	opts->verbose          = true;

	/* Apply environment defaults */
	if (env) {
		if (env->output_format && *env->output_format)
			opts->output_format = env->output_format;
		if (env->output_tcp && *env->output_tcp)
			opts->output_tcp = env->output_tcp;
		if (env->output_http && *env->output_http)
			opts->output_http = env->output_http;
		if (env->output_https && *env->output_https)
			opts->output_https = env->output_https;
		if (quiet_env_is_set(env->quiet))
			opts->verbose = false;
		if (env->output_insecure && !strcmp(env->output_insecure, "1"))
			opts->insecure = true;
		if (env->ws_retry && *env->ws_retry)
			(void)parse_retry_attempts(env->ws_retry, &opts->retry_attempts);
	}

	/* Parse CLI flags */
	while (cmd_idx < argc) {
		/* --output-format <fmt> */
		if (!strcmp(argv[cmd_idx], "--output-format")) {
			cmd_idx++;
			if (cmd_idx >= argc) {
				set_errbuf(errbuf, errbuf_len,
					   "Missing value for --output-format");
				return 2;
			}
			opts->output_format         = argv[cmd_idx++];
			opts->output_format_explicit = true;
			continue;
		}
		if (!strncmp(argv[cmd_idx], "--output-format=", 16)) {
			opts->output_format         = argv[cmd_idx] + 16;
			opts->output_format_explicit = true;
			cmd_idx++;
			continue;
		}

		/* --quiet */
		if (!strcmp(argv[cmd_idx], "--quiet")) {
			opts->verbose = false;
			cmd_idx++;
			continue;
		}

		/* --insecure */
		if (!strcmp(argv[cmd_idx], "--insecure")) {
			opts->insecure = true;
			cmd_idx++;
			continue;
		}

		/* --output-tcp <spec> */
		if (!strcmp(argv[cmd_idx], "--output-tcp")) {
			cmd_idx++;
			if (cmd_idx >= argc) {
				set_errbuf(errbuf, errbuf_len,
					   "Missing value for --output-tcp");
				return 2;
			}
			opts->output_tcp    = argv[cmd_idx++];
			opts->output_explicit = true;
			continue;
		}
		if (!strncmp(argv[cmd_idx], "--output-tcp=", 13)) {
			opts->output_tcp    = argv[cmd_idx] + 13;
			opts->output_explicit = true;
			cmd_idx++;
			continue;
		}

		/* --output-http <url> */
		if (!strcmp(argv[cmd_idx], "--output-http")) {
			const char *new_http = NULL, *new_https = NULL;
			const char *raw;

			cmd_idx++;
			if (cmd_idx >= argc) {
				set_errbuf(errbuf, errbuf_len,
					   "Missing value for --output-http");
				return 2;
			}
			raw = argv[cmd_idx++];
			if (ela_parse_http_output_uri(raw, &new_http, &new_https,
						      errbuf, errbuf_len) < 0)
				return 2;
			opts->output_http   = new_http;
			opts->output_https  = new_https;
			opts->output_explicit = true;
			continue;
		}
		if (!strncmp(argv[cmd_idx], "--output-http=", 14)) {
			const char *new_http = NULL, *new_https = NULL;
			const char *raw = argv[cmd_idx] + 14;

			if (ela_parse_http_output_uri(raw, &new_http, &new_https,
						      errbuf, errbuf_len) < 0)
				return 2;
			opts->output_http   = new_http;
			opts->output_https  = new_https;
			opts->output_explicit = true;
			cmd_idx++;
			continue;
		}

		/* --script <path> */
		if (!strcmp(argv[cmd_idx], "--script")) {
			cmd_idx++;
			if (cmd_idx >= argc) {
				set_errbuf(errbuf, errbuf_len,
					   "Missing value for --script");
				return 2;
			}
			opts->script_path = argv[cmd_idx++];
			continue;
		}
		if (!strncmp(argv[cmd_idx], "--script=", 9)) {
			opts->script_path = argv[cmd_idx] + 9;
			cmd_idx++;
			continue;
		}

		/* --remote <host:port> */
		if (!strcmp(argv[cmd_idx], "--remote")) {
			cmd_idx++;
			if (cmd_idx >= argc) {
				set_errbuf(errbuf, errbuf_len,
					   "Missing value for --remote");
				return 2;
			}
			opts->remote_target   = argv[cmd_idx++];
			opts->conf_needs_save = true;
			continue;
		}
		if (!strncmp(argv[cmd_idx], "--remote=", 9)) {
			opts->remote_target   = argv[cmd_idx] + 9;
			opts->conf_needs_save = true;
			cmd_idx++;
			continue;
		}

		/* --retry-attempts <n> */
		if (!strcmp(argv[cmd_idx], "--retry-attempts")) {
			cmd_idx++;
			if (cmd_idx >= argc ||
			    parse_retry_attempts(argv[cmd_idx], &opts->retry_attempts) != 0) {
				set_errbuf_fmt(errbuf, errbuf_len,
					       "Invalid value for --retry-attempts: %s",
					       cmd_idx < argc ? argv[cmd_idx] : "(missing)");
				return 2;
			}
			cmd_idx++;
			continue;
		}
		if (!strncmp(argv[cmd_idx], "--retry-attempts=", 17)) {
			if (parse_retry_attempts(argv[cmd_idx] + 17,
						 &opts->retry_attempts) != 0) {
				set_errbuf_fmt(errbuf, errbuf_len,
					       "Invalid value for --retry-attempts: %s",
					       argv[cmd_idx] + 17);
				return 2;
			}
			cmd_idx++;
			continue;
		}

		/* --api-key <key> */
		if (!strcmp(argv[cmd_idx], "--api-key")) {
			cmd_idx++;
			if (cmd_idx >= argc) {
				set_errbuf(errbuf, errbuf_len,
					   "Missing value for --api-key");
				return 2;
			}
			opts->api_key = argv[cmd_idx++];
			continue;
		}
		if (!strncmp(argv[cmd_idx], "--api-key=", 10)) {
			opts->api_key = argv[cmd_idx] + 10;
			cmd_idx++;
			continue;
		}

		/* Help flags */
		if (!strcmp(argv[cmd_idx], "-h") ||
		    !strcmp(argv[cmd_idx], "--help") ||
		    !strcmp(argv[cmd_idx], "help")) {
			opts->show_help = true;
			return 0;
		}

		/* First non-flag token: stop global-flag parsing */
		break;
	}

	opts->cmd_idx = cmd_idx;

	/* ELA_API_URL fallback: only when no http/https output was set yet */
	if (env && env->api_url && *env->api_url &&
	    (!opts->output_http  || !*opts->output_http) &&
	    (!opts->output_https || !*opts->output_https)) {
		const char *new_http = NULL, *new_https = NULL;

		if (ela_parse_http_output_uri(env->api_url, &new_http, &new_https,
					      errbuf, errbuf_len) < 0)
			return 2;
		opts->output_http  = new_http;
		opts->output_https = new_https;
	}

	/* ELA_API_INSECURE fallback */
	if (!opts->insecure && env && env->api_insecure &&
	    !strcmp(env->api_insecure, "true"))
		opts->insecure = true;

	/* ELA_SCRIPT fallback: only when no cmd and no script yet */
	if (!opts->script_path && opts->cmd_idx >= argc &&
	    env && env->script && *env->script)
		opts->script_path = env->script;

	return 0;
}
