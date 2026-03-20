// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "uboot/audit-rules/uboot_audit_util.h"
#include "uboot/audit-rules/uboot_validate_env_security_util.h"

#include <stdio.h>
#include <string.h>

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
	int issues;
	char detail[320] = "";

	if (!input || !input->data || !input->crc32_table || input->data_len < 8) {
		if (message && message_len)
			snprintf(message, message_len, "input too small (need at least 8 bytes)");
		return -1;
	}

	if (ela_uboot_choose_env_data_offset(input, &data_off) != 0) {
		if (message && message_len)
			snprintf(message, message_len, "unable to parse env vars: invalid CRC32 for standard/redundant layouts");
		return -1;
	}

	count = ela_uboot_parse_env_pairs(input->data, input->data_len, data_off, pairs, sizeof(pairs) / sizeof(pairs[0]));
	if (count < 0) {
		if (message && message_len)
			snprintf(message, message_len, "failed to parse environment key/value pairs");
		return -1;
	}

	bootdelay = ela_uboot_find_env_value(pairs, (size_t)count, "bootdelay");
	preboot = ela_uboot_find_env_value(pairs, (size_t)count, "preboot");
	boot_targets = ela_uboot_find_env_value(pairs, (size_t)count, "boot_targets");
	bootcmd = ela_uboot_find_env_value(pairs, (size_t)count, "bootcmd");
	altbootcmd = ela_uboot_find_env_value(pairs, (size_t)count, "altbootcmd");
	bootfile = ela_uboot_find_env_value(pairs, (size_t)count, "bootfile");
	serverip = ela_uboot_find_env_value(pairs, (size_t)count, "serverip");
	ipaddr = ela_uboot_find_env_value(pairs, (size_t)count, "ipaddr");
	factory_reset = ela_uboot_find_env_value(pairs, (size_t)count, "factory_reset");
	reset_to_defaults = ela_uboot_find_env_value(pairs, (size_t)count, "reset_to_defaults");
	resetenv = ela_uboot_find_env_value(pairs, (size_t)count, "resetenv");
	eraseenv = ela_uboot_find_env_value(pairs, (size_t)count, "eraseenv");

	issues = ela_uboot_validate_env_security_check_vars(
		bootdelay, preboot, boot_targets, bootcmd, altbootcmd,
		bootfile, serverip, ipaddr, factory_reset, reset_to_defaults,
		resetenv, eraseenv, &bootdelay_i, detail, sizeof(detail));

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
