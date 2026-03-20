// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "uboot_audit_output_util.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

const char *ela_uboot_audit_http_content_type(enum uboot_output_format fmt)
{
	switch (fmt) {
	case FW_OUTPUT_JSON:
		return "application/x-ndjson; charset=utf-8";
	case FW_OUTPUT_CSV:
		return "text/csv; charset=utf-8";
	case FW_OUTPUT_TXT:
	default:
		return "text/plain; charset=utf-8";
	}
}

bool ela_uboot_audit_rule_name_selected(const char *filter,
					const struct embedded_linux_audit_rule *rule)
{
	if (!rule || !rule->name || !*rule->name)
		return false;

	if (!filter || !*filter)
		return true;

	return !strcmp(filter, rule->name);
}

const char *ela_uboot_audit_rc_to_status(int rc)
{
	if (rc == 0)
		return "pass";
	if (rc > 0)
		return "fail";
	return "error";
}

int ela_uboot_audit_format_artifact(enum uboot_output_format fmt,
				    const char *artifact_name,
				    const char *artifact_value,
				    char *buf, size_t buflen)
{
	int n;

	if (!artifact_name || !artifact_value || !buf || !buflen)
		return -1;

	if (fmt == FW_OUTPUT_JSON) {
		n = snprintf(buf, buflen,
			     "{\"record\":\"audit_artifact\",\"artifact\":\"%s\",\"value\":\"%s\"}\n",
			     artifact_name, artifact_value);
	} else if (fmt == FW_OUTPUT_CSV) {
		n = snprintf(buf, buflen, "audit_artifact,%s,%s\n",
			     artifact_name, artifact_value);
	} else {
		n = snprintf(buf, buflen, "audit artifact %s=%s\n",
			     artifact_name, artifact_value);
	}

	if (n < 0 || (size_t)n >= buflen)
		return 1;
	return 0;
}
