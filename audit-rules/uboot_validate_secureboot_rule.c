// SPDX-License-Identifier: MIT License - Copyright (c) 2026 Nicholas Starke

#include "uboot_scan.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

struct env_kv_view {
	const char *name;
	const char *value;
};

static bool str_ieq(const char *a, const char *b)
{
	if (!a || !b)
		return false;

	while (*a && *b) {
		if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
			return false;
		a++;
		b++;
	}

	return *a == '\0' && *b == '\0';
}

static bool value_is_enabled(const char *value)
{
	if (!value || !*value)
		return false;

	return str_ieq(value, "1") ||
	       str_ieq(value, "y") ||
	       str_ieq(value, "yes") ||
	       str_ieq(value, "true") ||
	       str_ieq(value, "on") ||
	       str_ieq(value, "enabled");
}

static bool value_is_disabled(const char *value)
{
	if (!value || !*value)
		return true;

	return str_ieq(value, "0") ||
	       str_ieq(value, "n") ||
	       str_ieq(value, "no") ||
	       str_ieq(value, "false") ||
	       str_ieq(value, "off") ||
	       str_ieq(value, "disabled");
}

static bool value_is_nonempty(const char *value)
{
	return value && *value;
}

static int parse_env_pairs(const uint8_t *buf,
			   size_t len,
			   size_t data_off,
			   struct env_kv_view *pairs,
			   size_t max_pairs)
{
	size_t off = data_off;
	size_t count = 0;

	if (!buf || data_off >= len || !pairs || !max_pairs)
		return -1;

	while (off < len && count < max_pairs) {
		const char *entry;
		size_t slen;
		const char *eq;

		if (buf[off] == '\0') {
			if (off + 1 >= len || buf[off + 1] == '\0')
				break;
			off++;
			continue;
		}

		entry = (const char *)(buf + off);
		slen = strnlen(entry, len - off);
		if (slen >= len - off)
			break;

		eq = memchr(entry, '=', slen);
		if (eq) {
			pairs[count].name = entry;
			pairs[count].value = eq + 1;
			count++;
		}

		off += slen + 1;
	}

	return (int)count;
}

static const char *find_env_value(const struct env_kv_view *pairs, size_t count, const char *name)
{
	for (size_t i = 0; i < count; i++) {
		size_t nlen;

		if (!pairs[i].name || !pairs[i].value)
			continue;

		nlen = strcspn(pairs[i].name, "=");
		if (strlen(name) == nlen && !strncmp(pairs[i].name, name, nlen))
			return pairs[i].value;
	}

	return NULL;
}

static int choose_env_data_offset(const struct uboot_audit_input *input, size_t *data_off)
{
	uint32_t stored_le;
	uint32_t stored_be;
	uint32_t calc_std;
	uint32_t calc_redund;

	if (!input || !data_off || !input->data || !input->crc32_table || input->data_len < 8)
		return -1;

	stored_le = (uint32_t)input->data[0] |
		((uint32_t)input->data[1] << 8) |
		((uint32_t)input->data[2] << 16) |
		((uint32_t)input->data[3] << 24);
	stored_be = uboot_read_be32(input->data);

	calc_std = uboot_crc32_calc(input->crc32_table, input->data + 4, input->data_len - 4);
	if (calc_std == stored_le || calc_std == stored_be) {
		*data_off = 4;
		return 0;
	}

	if (input->data_len <= 5)
		return -1;

	calc_redund = uboot_crc32_calc(input->crc32_table, input->data + 5, input->data_len - 5);
	if (calc_redund == stored_le || calc_redund == stored_be) {
		*data_off = 5;
		return 0;
	}

	return -1;
}

static int run_validate_secureboot(const struct uboot_audit_input *input, char *message, size_t message_len)
{
	struct env_kv_view pairs[512];
	const char *secureboot;
	const char *verify;
	const char *bootm_verify_sig;
	const char *signature;
	const char *signature_name;
	char detail[320] = "";
	int issues = 0;
	size_t data_off = 0;
	int count;

	if (!input || !input->data || !input->crc32_table || input->data_len < 8) {
		if (message && message_len)
			snprintf(message, message_len, "input too small (need at least 8 bytes)");
		return -1;
	}

	if (choose_env_data_offset(input, &data_off) != 0) {
		if (message && message_len)
			snprintf(message, message_len, "unable to parse env vars: invalid CRC32 for standard/redundant layouts");
		return -1;
	}

	count = parse_env_pairs(input->data, input->data_len, data_off, pairs, sizeof(pairs) / sizeof(pairs[0]));
	if (count < 0) {
		if (message && message_len)
			snprintf(message, message_len, "failed to parse environment key/value pairs");
		return -1;
	}

	secureboot = find_env_value(pairs, (size_t)count, "secureboot");
	verify = find_env_value(pairs, (size_t)count, "verify");
	bootm_verify_sig = find_env_value(pairs, (size_t)count, "bootm_verify_sig");
	signature = find_env_value(pairs, (size_t)count, "signature");
	signature_name = "signature";
	if (!value_is_nonempty(signature)) {
		signature = find_env_value(pairs, (size_t)count, "boot_signature");
		signature_name = "boot_signature";
	}
	if (!value_is_nonempty(signature)) {
		signature = find_env_value(pairs, (size_t)count, "fit_signature");
		signature_name = "fit_signature";
	}

	if (!secureboot || !value_is_enabled(secureboot)) {
		issues++;
		snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail),
			 "%ssecureboot=%s", detail[0] ? "; " : "", secureboot ? secureboot : "(missing)");
	}

	if (!verify || value_is_disabled(verify)) {
		issues++;
		snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail),
			 "%sverify=%s", detail[0] ? "; " : "", verify ? verify : "(missing)");
	}

	if (!bootm_verify_sig || !value_is_enabled(bootm_verify_sig)) {
		issues++;
		snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail),
			 "%sbootm_verify_sig=%s", detail[0] ? "; " : "", bootm_verify_sig ? bootm_verify_sig : "(missing)");
	}

	if (!value_is_nonempty(signature)) {
		issues++;
		snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail),
			 "%ssignature/boot_signature/fit_signature=(missing)", detail[0] ? "; " : "");
	}

	if (!issues) {
		if (message && message_len) {
			snprintf(message, message_len,
				 "secure boot vars validated: secureboot=%s verify=%s bootm_verify_sig=%s %s=<present>",
				 secureboot, verify, bootm_verify_sig, signature_name);
		}
		return 0;
	}

	if (message && message_len) {
		snprintf(message, message_len,
			 "secure boot variable misconfiguration: %s", detail[0] ? detail : "unknown");
	}

	return 1;
}

static const struct uboot_audit_rule uboot_validate_secureboot_rule = {
	.name = "uboot_validate_secureboot",
	.description = "Validate secure boot environment variables (secureboot, verify, bootm_verify_sig, and signature field)",
	.run = run_validate_secureboot,
};

FW_REGISTER_AUDIT_RULE(uboot_validate_secureboot_rule);