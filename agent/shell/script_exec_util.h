// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_SCRIPT_EXEC_UTIL_H
#define ELA_SCRIPT_EXEC_UTIL_H

#include <stdbool.h>
#include <stddef.h>

enum ela_script_command_kind {
	ELA_SCRIPT_COMMAND_INVALID = 0,
	ELA_SCRIPT_COMMAND_HELP,
	ELA_SCRIPT_COMMAND_SET,
	ELA_SCRIPT_COMMAND_DISPATCH,
};

struct ela_script_dispatch_plan {
	enum ela_script_command_kind kind;
	int script_cmd_idx;
	int dispatch_argc;
};

bool ela_script_is_http_source(const char *value);
const char *ela_script_basename(const char *path);
char *ela_script_url_percent_encode(const char *text);
char *ela_script_build_fallback_uri(const char *output_uri, const char *script_source);
char *ela_script_trim(char *s);
bool ela_script_line_is_ignorable(const char *trimmed);
int ela_script_plan_dispatch(int argc,
			     char **argv,
			     struct ela_script_dispatch_plan *plan,
			     char *errbuf,
			     size_t errbuf_len);

#endif
