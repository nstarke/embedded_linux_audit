// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef UTIL_TRANSFER_PARSE_UTIL_H
#define UTIL_TRANSFER_PARSE_UTIL_H

#include <stddef.h>

struct ela_transfer_options {
	const char *target;
	int insecure;
	int retry_attempts;
	int show_help;
};

int ela_transfer_parse_args(int argc,
			    char **argv,
			    const char *env_retry_attempts,
			    int default_retry_attempts,
			    struct ela_transfer_options *out,
			    char *errbuf,
			    size_t errbuf_len);

#endif
