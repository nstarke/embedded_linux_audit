// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "uboot/audit-rules/uboot_audit_util.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

static int parse_env_pairs(const uint8_t *buf,
			   size_t len,
			   size_t data_off,
			   struct env_kv_view *pairs,
			   size_t max_pairs)
{
	return ela_uboot_parse_env_pairs(buf, len, data_off, pairs, max_pairs);
}

static const char *find_env_value(const struct env_kv_view *pairs, size_t count, const char *name)
{
	return ela_uboot_find_env_value(pairs, count, name);
}

static int choose_env_data_offset(const struct embedded_linux_audit_input *input, size_t *data_off)
{
	return ela_uboot_choose_env_data_offset(input, data_off);
}

static int parse_int_value(const char *s, int *out)
{
	return ela_uboot_parse_int_value(s, out);
}

static bool contains_token_ci(const char *s, const char *token)
{
	return ela_uboot_contains_token_ci(s, token);
}

static bool value_suggests_network_boot(const char *value)
{
	return ela_uboot_value_suggests_network_boot(value);
}

static bool value_suggests_factory_reset(const char *value)
{
	return ela_uboot_value_suggests_factory_reset(value);
}

static int run_validate_env_security(const struct embedded_linux_audit_input *input, char *message, size_t message_len)
{
	struct env_kv_view pairs[512];
	const char *bootdelay;
	const char *preboot;
	const char *boot_targets;
	const char *bootcmd;
	const char *altbootcmd;
	const char *bootfile;
	const char *serverip;
	const char *ipaddr;
	const char *factory_reset;
	const char *reset_to_defaults;
	const char *resetenv;
	const char *eraseenv;
	size_t data_off = 0;
	int count;
	int bootdelay_i = 0;
	int issues = 0;
	char detail[320] = "";

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

	bootdelay = find_env_value(pairs, (size_t)count, "bootdelay");
	preboot = find_env_value(pairs, (size_t)count, "preboot");
	boot_targets = find_env_value(pairs, (size_t)count, "boot_targets");
	bootcmd = find_env_value(pairs, (size_t)count, "bootcmd");
	altbootcmd = find_env_value(pairs, (size_t)count, "altbootcmd");
	bootfile = find_env_value(pairs, (size_t)count, "bootfile");
	serverip = find_env_value(pairs, (size_t)count, "serverip");
	ipaddr = find_env_value(pairs, (size_t)count, "ipaddr");
	factory_reset = find_env_value(pairs, (size_t)count, "factory_reset");
	reset_to_defaults = find_env_value(pairs, (size_t)count, "reset_to_defaults");
	resetenv = find_env_value(pairs, (size_t)count, "resetenv");
	eraseenv = find_env_value(pairs, (size_t)count, "eraseenv");

	if (!bootdelay || parse_int_value(bootdelay, &bootdelay_i) != 0) {
		issues++;
		snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail),
			 "%sbootdelay=%s", detail[0] ? "; " : "", bootdelay ? bootdelay : "(missing)");
	} else if (bootdelay_i > 0) {
		issues++;
		snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail),
			 "%sbootdelay=%d (>0)", detail[0] ? "; " : "", bootdelay_i);
	}

	if (preboot && *preboot) {
		issues++;
		snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail),
			 "%spreboot is set", detail[0] ? "; " : "");
	}

	if (boot_targets && *boot_targets) {
		if (strstr(boot_targets, "usb") || value_suggests_network_boot(boot_targets)) {
			issues++;
			snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail),
				 "%sboot_targets allows removable/network boot (%s)",
				 detail[0] ? "; " : "", boot_targets);
		}
	}

	if (value_suggests_network_boot(bootcmd)) {
		issues++;
		snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail),
			 "%sbootcmd suggests network boot", detail[0] ? "; " : "");
	}

	if (value_suggests_network_boot(altbootcmd)) {
		issues++;
		snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail),
			 "%saltbootcmd suggests network boot", detail[0] ? "; " : "");
	}

	if (value_suggests_network_boot(preboot)) {
		issues++;
		snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail),
			 "%spreboot suggests network boot", detail[0] ? "; " : "");
	}

	if ((bootfile && *bootfile) || (serverip && *serverip) || (ipaddr && *ipaddr)) {
		issues++;
		snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail),
			 "%snetwork boot variables present (bootfile/serverip/ipaddr)", detail[0] ? "; " : "");
	}

	if (value_suggests_factory_reset(bootcmd)) {
		issues++;
		snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail),
			 "%sbootcmd suggests factory reset", detail[0] ? "; " : "");
	}

	if (value_suggests_factory_reset(altbootcmd)) {
		issues++;
		snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail),
			 "%saltbootcmd suggests factory reset", detail[0] ? "; " : "");
	}

	if (value_suggests_factory_reset(preboot)) {
		issues++;
		snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail),
			 "%spreboot suggests factory reset", detail[0] ? "; " : "");
	}

	if ((factory_reset && *factory_reset) ||
	    (reset_to_defaults && *reset_to_defaults) ||
	    (resetenv && *resetenv) ||
	    (eraseenv && *eraseenv)) {
		issues++;
		snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail),
			 "%sfactory-reset variables present (factory_reset/reset_to_defaults/resetenv/eraseenv)",
			 detail[0] ? "; " : "");
	}

	if (!issues) {
		if (message && message_len)
			snprintf(message, message_len, "security-sensitive env values validated (bootdelay=%d, preboot unset)", bootdelay_i);
		return 0;
	}

	if (message && message_len)
		snprintf(message, message_len, "security-sensitive env values failed policy: %s", detail[0] ? detail : "unknown");

	return 1;
}

static const struct embedded_linux_audit_rule uboot_validate_env_security_rule = {
	.name = "uboot_validate_env_security",
	.description = "Validate security-sensitive env vars and network-boot indicators",
	.run = run_validate_env_security,
};

ELA_REGISTER_RULE(uboot_validate_env_security_rule);
