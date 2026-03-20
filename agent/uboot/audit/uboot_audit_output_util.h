// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_UBOOT_AUDIT_OUTPUT_UTIL_H
#define ELA_UBOOT_AUDIT_OUTPUT_UTIL_H

#include "uboot_audit_internal.h"
#include "embedded_linux_audit_cmd.h"

#include <stdbool.h>
#include <stddef.h>

/*
 * Return the HTTP Content-Type string for the given output format.
 * Always returns a non-NULL string; unknown values fall back to text/plain.
 */
const char *ela_uboot_audit_http_content_type(enum uboot_output_format fmt);

/*
 * Return true if rule should be run given the optional name filter.
 * Returns false if rule is NULL or rule->name is NULL/empty.
 * Returns true when filter is NULL or empty (no filter active).
 * Otherwise returns true only when filter exactly matches rule->name.
 */
bool ela_uboot_audit_rule_name_selected(const char *filter,
					const struct embedded_linux_audit_rule *rule);

/*
 * Map an audit rule return code to its status string.
 *   rc == 0  → "pass"
 *   rc  > 0  → "fail"
 *   rc  < 0  → "error"
 */
const char *ela_uboot_audit_rc_to_status(int rc);

/*
 * Format an artifact record into buf[buflen] according to fmt.
 * artifact_name and artifact_value must be non-NULL.
 *
 * Returns  0  on success (fully written, NUL-terminated),
 *         -1  if any pointer argument is NULL or buflen is 0,
 *          1  if the output was truncated.
 */
int ela_uboot_audit_format_artifact(enum uboot_output_format fmt,
				    const char *artifact_name,
				    const char *artifact_value,
				    char *buf, size_t buflen);

#endif /* ELA_UBOOT_AUDIT_OUTPUT_UTIL_H */
