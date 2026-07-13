// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_LINUX_AUDIT_UTIL_H
#define ELA_LINUX_AUDIT_UTIL_H

#include <stddef.h>

enum ela_linux_audit_profile {
	ELA_LINUX_AUDIT_PROFILE_EMBEDDED = 1,
	ELA_LINUX_AUDIT_PROFILE_HARDENED = 2,
};

enum ela_linux_audit_status {
	ELA_LINUX_AUDIT_PASS = 0,
	ELA_LINUX_AUDIT_FAIL,
	ELA_LINUX_AUDIT_UNKNOWN,
	ELA_LINUX_AUDIT_NOT_APPLICABLE,
};

enum ela_linux_audit_check_type {
	ELA_LINUX_AUDIT_CHECK_INTEGER_MIN = 0,
	ELA_LINUX_AUDIT_CHECK_INTEGER_MAX,
	ELA_LINUX_AUDIT_CHECK_CONFIG_OPTION,
	ELA_LINUX_AUDIT_CHECK_CMDLINE_FORBIDDEN,
	ELA_LINUX_AUDIT_CHECK_LOCKDOWN,
	ELA_LINUX_AUDIT_CHECK_LSM_ENFORCING,
	ELA_LINUX_AUDIT_CHECK_MOUNT_ABSENT,
	ELA_LINUX_AUDIT_CHECK_DEVICE_MODE,
	ELA_LINUX_AUDIT_CHECK_CORE_PATTERN,
};

struct ela_linux_audit_rule {
	const char *id;
	const char *title;
	const char *category;
	const char *severity;
	const char *description;
	const char *remediation;
	const char *path;
	unsigned int profiles;
	long embedded_minimum;
	long hardened_minimum;
	enum ela_linux_audit_check_type check_type;
	const char *expected;
};

struct ela_linux_audit_result {
	enum ela_linux_audit_status status;
	char evidence[512];
};

extern const struct ela_linux_audit_rule ela_linux_audit_rules[];
extern const size_t ela_linux_audit_rule_count;

const char *ela_linux_audit_profile_name(enum ela_linux_audit_profile profile);
int ela_linux_audit_parse_profile(const char *text, enum ela_linux_audit_profile *profile_out);
const char *ela_linux_audit_status_name(enum ela_linux_audit_status status);
int ela_linux_audit_rule_enabled(const struct ela_linux_audit_rule *rule, enum ela_linux_audit_profile profile);
const struct ela_linux_audit_rule *ela_linux_audit_find_rule(const char *id);
int ela_linux_audit_evaluate(const struct ela_linux_audit_rule *rule, enum ela_linux_audit_profile profile,
			     const char *raw_value, struct ela_linux_audit_result *result);
int ela_linux_audit_run_rule(const struct ela_linux_audit_rule *rule, enum ela_linux_audit_profile profile,
			     const char *root, struct ela_linux_audit_result *result);

#endif
