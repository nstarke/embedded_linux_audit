// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_SCRIPT_EXEC_UTIL_H
#define ELA_SCRIPT_EXEC_UTIL_H

#include <stdbool.h>

bool ela_script_is_http_source(const char *value);
const char *ela_script_basename(const char *path);
char *ela_script_url_percent_encode(const char *text);
char *ela_script_build_fallback_uri(const char *output_uri, const char *script_source);
char *ela_script_trim(char *s);

#endif
