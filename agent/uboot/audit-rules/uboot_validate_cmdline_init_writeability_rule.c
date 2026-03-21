// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "uboot/audit-rules/uboot_audit_util.h"
#include "uboot/audit-rules/uboot_validate_cmdline_init_util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

/*
 * All functions in this file require real hardware, network I/O, or OS-level
 * services (ptrace, SSH, sockets, TPM2, EFI) and cannot be exercised in the
 * unit-test environment.
 */
/* LCOV_EXCL_START */

static bool env_block_is_writeable(const char *dev)
{
	int fd;

	if (!dev || !*dev)
		return false;

	fd = open(dev, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return false;
	close(fd);
	return true;
}

static int run_validate_cmdline_init_writeability(const struct embedded_linux_audit_input *input,
						  char *message,
						  size_t message_len)
{
	struct env_kv_view pairs[512];
	const char *bootargs;
	size_t data_off = 0;
	int count;
	char init_value[256] = {0};
	bool has_init;
	bool init_valid;
	bool writeable;

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

	bootargs = ela_uboot_find_env_value(pairs, (size_t)count, "bootargs");
	if (!bootargs || !*bootargs) {
		if (message && message_len)
			snprintf(message, message_len, "bootargs missing; no kernel cmdline parameters to evaluate");
		return 0;
	}

	has_init = ela_uboot_parse_init_parameter(bootargs, init_value, sizeof(init_value));
	init_valid = has_init && ela_uboot_init_path_looks_valid(init_value);
	writeable = has_init && init_valid && env_block_is_writeable(input->device);

	return ela_uboot_cmdline_init_writeability_result(has_init, init_valid, writeable,
							  init_value, input->device,
							  message, message_len);
}

static const struct embedded_linux_audit_rule uboot_validate_cmdline_init_writeability_rule = {
	.name = "uboot_validate_cmdline_init_writeability",
	.description = "Parse kernel cmdline from bootargs and warn when valid init= is combined with writeable env block",
	.run = run_validate_cmdline_init_writeability,
};

ELA_REGISTER_RULE(uboot_validate_cmdline_init_writeability_rule);

/* LCOV_EXCL_STOP */
