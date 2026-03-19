// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_UBOOT_ENV_FORMAT_UTIL_H
#define ELA_UBOOT_ENV_FORMAT_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum ela_uboot_env_output_format {
	ELA_UBOOT_ENV_OUTPUT_TXT = 0,
	ELA_UBOOT_ENV_OUTPUT_CSV,
	ELA_UBOOT_ENV_OUTPUT_JSON,
};

int ela_uboot_env_detect_output_format(const char *fmt);
const char *ela_uboot_env_http_content_type(int fmt);
char *ela_uboot_env_trim(char *s);
bool ela_uboot_env_valid_var_name(const char *name);
bool ela_uboot_env_is_sensitive_var(const char *name);
bool ela_uboot_env_has_hint_var(const uint8_t *data, size_t len, const char *hint_override);
int ela_uboot_env_parse_write_script_line(char *line,
					  char **name_out,
					  char **value_out,
					  bool *delete_out);

#endif
