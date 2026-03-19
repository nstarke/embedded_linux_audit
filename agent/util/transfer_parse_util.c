// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "transfer_parse_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int ela_transfer_parse_retry_attempts(const char *value, int *out)
{
	char *end = NULL;
	long parsed;

	if (!value || !*value || !out)
		return -1;

	parsed = strtol(value, &end, 10);
	if (*end || parsed < 0 || parsed > 1000)
		return -1;

	*out = (int)parsed;
	return 0;
}

int ela_transfer_parse_args(int argc,
			    char **argv,
			    const char *env_retry_attempts,
			    int default_retry_attempts,
			    struct ela_transfer_options *out,
			    char *errbuf,
			    size_t errbuf_len)
{
	int i;

	if (!out)
		return -1;

	memset(out, 0, sizeof(*out));
	out->retry_attempts = default_retry_attempts;

	if (env_retry_attempts && *env_retry_attempts)
		(void)ela_transfer_parse_retry_attempts(env_retry_attempts, &out->retry_attempts);

	if (argc < 2) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "missing target");
		return -1;
	}

	if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
		out->show_help = 1;
		return 0;
	}

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--insecure")) {
			out->insecure = 1;
			continue;
		}
		if (!strcmp(argv[i], "--retry-attempts")) {
			i++;
			if (i >= argc || ela_transfer_parse_retry_attempts(argv[i], &out->retry_attempts) != 0) {
				if (errbuf && errbuf_len)
					snprintf(errbuf, errbuf_len,
						 "invalid value for --retry-attempts: %s",
						 i < argc ? argv[i] : "(missing)");
				return -1;
			}
			continue;
		}
		if (!strncmp(argv[i], "--retry-attempts=", 17)) {
			if (ela_transfer_parse_retry_attempts(argv[i] + 17, &out->retry_attempts) != 0) {
				if (errbuf && errbuf_len)
					snprintf(errbuf, errbuf_len,
						 "invalid value for --retry-attempts: %s",
						 argv[i] + 17);
				return -1;
			}
			continue;
		}
		if (argv[i][0] == '-') {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "unknown option: %s", argv[i]);
			return -1;
		}
		if (!out->target) {
			out->target = argv[i];
			continue;
		}
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "unexpected argument: %s", argv[i]);
		return -1;
	}

	if (!out->target) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "missing target");
		return -1;
	}

	return 0;
}
