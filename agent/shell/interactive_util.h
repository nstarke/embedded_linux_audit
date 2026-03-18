// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_INTERACTIVE_UTIL_H
#define ELA_INTERACTIVE_UTIL_H

#include <stddef.h>

const char *const *ela_interactive_candidates_for_position(int argc, char **argv);
int ela_interactive_format_supported_variables(char *buf,
					       size_t buf_sz,
					       const char *ela_api_url,
					       const char *ela_api_insecure,
					       const char *ela_quiet,
					       const char *ela_output_format,
					       const char *ela_output_tcp,
					       const char *ela_script,
					       const char *ela_output_http,
					       const char *ela_output_insecure,
					       const char *ela_api_key,
					       const char *ela_verbose,
					       const char *ela_debug,
					       const char *ela_ws_retry);

#endif
