// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_UBOOT_AUDIT_UTIL_H
#define ELA_UBOOT_AUDIT_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct embedded_linux_audit_input;

struct env_kv_view {
	const char *name;
	const char *value;
};

bool ela_uboot_str_ieq(const char *a, const char *b);
bool ela_uboot_value_is_enabled(const char *value);
bool ela_uboot_value_is_disabled(const char *value);
bool ela_uboot_value_is_nonempty(const char *value);
int ela_uboot_decode_hex_signature(const char *sig, uint8_t **out, size_t *out_len);
int ela_uboot_decode_base64_signature(const char *sig, uint8_t **out, size_t *out_len);
int ela_uboot_decode_signature_value(const char *sig, uint8_t **out, size_t *out_len);
int ela_uboot_parse_env_pairs(const uint8_t *buf, size_t len, size_t data_off,
			      struct env_kv_view *pairs, size_t max_pairs);
const char *ela_uboot_find_env_value(const struct env_kv_view *pairs, size_t count, const char *name);
int ela_uboot_choose_env_data_offset(const struct embedded_linux_audit_input *input, size_t *data_off);
int ela_uboot_parse_int_value(const char *s, int *out);
bool ela_uboot_contains_token_ci(const char *s, const char *token);
bool ela_uboot_value_suggests_network_boot(const char *value);
bool ela_uboot_value_suggests_factory_reset(const char *value);
bool ela_uboot_init_path_looks_valid(const char *v);
bool ela_uboot_parse_init_parameter(const char *cmdline, char *init_value, size_t init_value_len);

#endif
