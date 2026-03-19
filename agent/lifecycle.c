// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "lifecycle.h"
#include "util/lifecycle_util.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

bool ela_lifecycle_logging_enabled(void)
{
	const char *ela_debug = getenv("ELA_DEBUG");

	return ela_debug && !strcmp(ela_debug, "1");
}

int ela_emit_lifecycle_event(const char *output_format,
			     const char *output_tcp,
			     const char *output_http,
			     const char *output_https,
			     bool insecure,
			     const char *command,
			     const char *phase,
			     int rc)
{
	if (!ela_lifecycle_logging_enabled())
		return 0;

	return ela_emit_lifecycle_event_ex(NULL,
					   output_format,
					   output_tcp,
					   output_http,
					   output_https,
					   insecure,
					   command,
					   phase,
					   rc);
}
