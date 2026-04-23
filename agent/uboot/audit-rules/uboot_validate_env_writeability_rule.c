// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "uboot/audit-rules/uboot_validate_env_writeability_util.h"

#include <inttypes.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
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

static int ensure_fw_env_config_exists(void)
{
	const char *output_tcp = getenv("ELA_OUTPUT_TCP");
	const char *output_http = getenv("ELA_OUTPUT_HTTP");
	const char *output_https = getenv("ELA_OUTPUT_HTTPS");
	const char *output_insecure = getenv("ELA_OUTPUT_INSECURE");
	/* 2 fixed + 2 tcp + 2 http + 2 https + 1 insecure + 1 NULL = 10 */
	char *argv[10];
	int argc = 0;
	const int argv_max = (int)(sizeof(argv) / sizeof(argv[0])) - 1;

	argv[argc++] = "env";
	argv[argc++] = "--output-config";
	if (output_tcp && *output_tcp && argc + 2 <= argv_max) {
		argv[argc++] = "--output-tcp";
		argv[argc++] = (char *)output_tcp;
	}
	if (output_http && *output_http && argc + 2 <= argv_max) {
		argv[argc++] = "--output-http";
		argv[argc++] = (char *)output_http;
	}
	if (output_https && *output_https && argc + 2 <= argv_max) {
		argv[argc++] = "--output-http";
		argv[argc++] = (char *)output_https;
	}
	if (output_insecure && !strcmp(output_insecure, "1") &&
	    argc + 1 <= argv_max)
		argv[argc++] = "--insecure";
	argv[argc] = NULL;

	if (access("uboot_env.config", F_OK) == 0)
		return 0;
	if (access("fw_env.config", F_OK) == 0)
		return 0;

	return uboot_env_scan_main(argc, argv);
}

static int run_validate_env_writeability(const struct embedded_linux_audit_input *input,
					 char *message,
					 size_t message_len)
{
	int fd;
	int saved_errno;
	int env_scan_rc;
	int rc;

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
	rc = ela_uboot_validate_env_errno_classify(saved_errno);
	if (message && message_len) {
		if (rc == 0) {
			snprintf(message, message_len,
				 "environment block is not writable: device=%s (%s)",
				 input->device,
				 strerror(saved_errno));
		} else {
			snprintf(message, message_len,
				 "unable to determine writeability for %s: %s",
				 input->device,
				 strerror(saved_errno));
		}
	}
	return rc;
}

static const struct embedded_linux_audit_rule uboot_validate_env_writeability_rule = {
	.name = "uboot_validate_env_writeability",
	.description = "Validate that the environment block device is not writable",
	.run = run_validate_env_writeability,
};

ELA_REGISTER_RULE(uboot_validate_env_writeability_rule);

/* LCOV_EXCL_STOP */
