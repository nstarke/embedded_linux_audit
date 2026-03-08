// SPDX-License-Identifier: MIT License - Copyright (c) 2026 Nicholas Starke

#include "uboot_scan.h"

#include <inttypes.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static int ensure_fw_env_config_exists(void)
{
	char *argv[] = {
		"env",
		"--output-config",
		NULL,
	};

	if (access("uboot_env.config", F_OK) == 0)
		return 0;

	return uboot_env_scan_main(2, argv);
}

static int run_validate_env_writeability(const struct uboot_audit_input *input,
					 char *message,
					 size_t message_len)
{
	int fd;
	int saved_errno;
	int env_scan_rc;

	if (!input || !input->device || !*input->device) {
		if (message && message_len)
			snprintf(message, message_len, "missing audit input device path");
		return -1;
	}

	env_scan_rc = ensure_fw_env_config_exists();
	if (env_scan_rc != 0) {
		if (message && message_len) {
			snprintf(message,
				 message_len,
				 "uboot_env.config not found and env scan failed (rc=%d)",
				 env_scan_rc);
		}
		return -1;
	}

	fd = open(input->device, O_RDWR | O_CLOEXEC);
	if (fd >= 0) {
		close(fd);
		if (message && message_len) {
			snprintf(message, message_len,
				 "environment block is writable: device=%s offset=0x%jx size=0x%zx",
				 input->device,
				 (uintmax_t)input->offset,
				 input->data_len);
		}
		return 1;
	}

	saved_errno = errno;
	if (saved_errno == EACCES || saved_errno == EPERM || saved_errno == EROFS) {
		if (message && message_len) {
			snprintf(message, message_len,
				 "environment block is not writable: device=%s (%s)",
				 input->device,
				 strerror(saved_errno));
		}
		return 0;
	}

	if (message && message_len) {
		snprintf(message, message_len,
			 "unable to determine writeability for %s: %s",
			 input->device,
			 strerror(saved_errno));
	}

	return -1;
}

static const struct uboot_audit_rule uboot_validate_env_writeability_rule = {
	.name = "uboot_validate_env_writeability",
	.description = "Validate that the environment block device is not writable",
	.run = run_validate_env_writeability,
};

FW_REGISTER_AUDIT_RULE(uboot_validate_env_writeability_rule);