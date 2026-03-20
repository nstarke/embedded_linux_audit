// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "uboot_validate_secureboot_util.h"
#include "uboot/audit-rules/uboot_audit_util.h"

#include <stdio.h>
#include <string.h>

int ela_uboot_secureboot_check_env_policy(const char *secureboot,
					  const char *verify,
					  const char *bootm_verify_sig,
					  const char *signature,
					  char *detail,
					  size_t detail_len)
{
	int issues = 0;

	if (!secureboot || !ela_uboot_value_is_enabled(secureboot)) {
		issues++;
		if (detail && detail_len)
			snprintf(detail + strlen(detail), detail_len - strlen(detail),
				 "%ssecureboot=%s",
				 detail[0] ? "; " : "",
				 secureboot ? secureboot : "(missing)");
	}

	if (!verify || ela_uboot_value_is_disabled(verify)) {
		issues++;
		if (detail && detail_len)
			snprintf(detail + strlen(detail), detail_len - strlen(detail),
				 "%sverify=%s",
				 detail[0] ? "; " : "",
				 verify ? verify : "(missing)");
	}

	if (!bootm_verify_sig || !ela_uboot_value_is_enabled(bootm_verify_sig)) {
		issues++;
		if (detail && detail_len)
			snprintf(detail + strlen(detail), detail_len - strlen(detail),
				 "%sbootm_verify_sig=%s",
				 detail[0] ? "; " : "",
				 bootm_verify_sig ? bootm_verify_sig : "(missing)");
	}

	if (!ela_uboot_value_is_nonempty(signature)) {
		issues++;
		if (detail && detail_len)
			snprintf(detail + strlen(detail), detail_len - strlen(detail),
				 "%ssignature/boot_signature/fit_signature=(missing)",
				 detail[0] ? "; " : "");
	}

	return issues;
}
