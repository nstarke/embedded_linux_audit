// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "ela_conf_util.h"

#include <stdio.h>
#include <string.h>

void ela_conf_trim_right(char *s)
{
	size_t n;

	if (!s)
		return;

	n = strlen(s);
	while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' ||
			 s[n - 1] == ' ' || s[n - 1] == '\t'))
		s[--n] = '\0';
}

void ela_conf_apply_line(struct ela_conf *conf, const char *line)
{
	const char *eq;
	size_t key_len;
	const char *val;

	if (!conf || !line || *line == '#' || *line == '\0')
		return;

	eq = strchr(line, '=');
	if (!eq)
		return;

	key_len = (size_t)(eq - line);
	val = eq + 1;

	if (key_len == 6 && !strncmp(line, "remote", 6)) {
		snprintf(conf->remote, sizeof(conf->remote), "%s", val);
	} else if (key_len == 11 && !strncmp(line, "output-http", 11)) {
		snprintf(conf->output_http, sizeof(conf->output_http), "%s", val);
	} else if (key_len == 13 && !strncmp(line, "output-format", 13)) {
		snprintf(conf->output_format, sizeof(conf->output_format), "%s", val);
	} else if (key_len == 8 && !strncmp(line, "insecure", 8)) {
		conf->insecure = ela_conf_string_is_true(val) ? 1 : 0;
	}
}

bool ela_conf_string_is_true(const char *value)
{
	return value &&
	       (!strcmp(value, "true") ||
		!strcmp(value, "1"));
}
