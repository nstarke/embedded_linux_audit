// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "uboot_env_format_util.h"

#include <ctype.h>
#include <string.h>

int ela_uboot_env_detect_output_format(const char *fmt)
{
	if (!fmt || !*fmt || !strcmp(fmt, "txt"))
		return ELA_UBOOT_ENV_OUTPUT_TXT;
	if (!strcmp(fmt, "csv"))
		return ELA_UBOOT_ENV_OUTPUT_CSV;
	if (!strcmp(fmt, "json"))
		return ELA_UBOOT_ENV_OUTPUT_JSON;
	return ELA_UBOOT_ENV_OUTPUT_TXT;
}

const char *ela_uboot_env_http_content_type(int fmt)
{
	switch (fmt) {
	case ELA_UBOOT_ENV_OUTPUT_JSON:
		return "application/x-ndjson; charset=utf-8";
	case ELA_UBOOT_ENV_OUTPUT_CSV:
		return "text/csv; charset=utf-8";
	case ELA_UBOOT_ENV_OUTPUT_TXT:
	default:
		return "text/plain; charset=utf-8";
	}
}

char *ela_uboot_env_trim(char *s)
{
	char *end;

	if (!s)
		return s;

	while (*s && isspace((unsigned char)*s))
		s++;

	if (!*s)
		return s;

	end = s + strlen(s) - 1;
	while (end >= s && isspace((unsigned char)*end)) {
		*end = '\0';
		end--;
	}

	return s;
}

bool ela_uboot_env_valid_var_name(const char *name)
{
	const unsigned char *p;

	if (!name || !*name)
		return false;

	for (p = (const unsigned char *)name; *p; p++) {
		if (*p == '=' || isspace(*p) || iscntrl(*p))
			return false;
	}

	return true;
}

bool ela_uboot_env_is_sensitive_var(const char *name)
{
	static const char *sensitive_vars[] = {
		"bootcmd",
		"altbootcmd",
		"bootargs",
		"boot_targets",
		"bootdelay",
		"preboot",
		"stdin",
		"stdout",
		"stderr",
	};
	size_t i;

	if (!name || !*name)
		return false;

	for (i = 0; i < sizeof(sensitive_vars) / sizeof(sensitive_vars[0]); i++) {
		if (!strcmp(name, sensitive_vars[i]))
			return true;
	}

	return false;
}

bool ela_uboot_env_has_hint_var(const uint8_t *data, size_t len, const char *hint_override)
{
	static const char *hints[] = {
		"bootcmd=", "bootargs=", "baudrate=", "ethaddr=", "stdin=",
	};
	size_t i;
	size_t off;

	if (!data || len == 0)
		return false;

	if (hint_override && *hint_override) {
		size_t hlen = strlen(hint_override);
		for (off = 0; off + hlen <= len; off++) {
			if (!memcmp(data + off, hint_override, hlen))
				return true;
		}
		return false;
	}

	for (i = 0; i < sizeof(hints) / sizeof(hints[0]); i++) {
		size_t hlen = strlen(hints[i]);
		for (off = 0; off + hlen <= len; off++) {
			if (!memcmp(data + off, hints[i], hlen))
				return true;
		}
	}

	return false;
}

int ela_uboot_env_parse_write_script_line(char *line,
					  char **name_out,
					  char **value_out,
					  bool *delete_out)
{
	char *s;
	char *eq;
	char *space;

	if (!line || !name_out || !value_out || !delete_out)
		return -1;

	*name_out = NULL;
	*value_out = NULL;
	*delete_out = false;

	s = ela_uboot_env_trim(line);
	if (!*s || *s == '#')
		return 1;

	eq = strchr(s, '=');
	space = strpbrk(s, " \t");
	if (eq && (!space || eq < space)) {
		*eq = '\0';
		*name_out = ela_uboot_env_trim(s);
		*value_out = eq + 1;
		return 0;
	}

	if (space) {
		*space = '\0';
		*name_out = ela_uboot_env_trim(s);
		*value_out = ela_uboot_env_trim(space + 1);
		if (!**value_out)
			*delete_out = true;
		return 0;
	}

	*name_out = ela_uboot_env_trim(s);
	*delete_out = true;
	return 0;
}
