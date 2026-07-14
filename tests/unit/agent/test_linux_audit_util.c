// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../../../agent/linux/linux_audit_util.h"
#include "test_harness.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void test_profiles_parse_and_name(void)
{
	enum ela_linux_audit_profile profile;

	ELA_ASSERT_INT_EQ(0, ela_linux_audit_parse_profile("embedded", &profile));
	ELA_ASSERT_INT_EQ(ELA_LINUX_AUDIT_PROFILE_EMBEDDED, profile);
	ELA_ASSERT_STR_EQ("embedded", ela_linux_audit_profile_name(profile));
	ELA_ASSERT_INT_EQ(0, ela_linux_audit_parse_profile("hardened", &profile));
	ELA_ASSERT_INT_EQ(ELA_LINUX_AUDIT_PROFILE_HARDENED, profile);
	ELA_ASSERT_INT_EQ(-1, ela_linux_audit_parse_profile("unknown", &profile));
}

static void test_rule_lookup_and_profile_filter(void)
{
	const struct ela_linux_audit_rule *aslr = ela_linux_audit_find_rule("ELA-LINUX-001");
	const struct ela_linux_audit_rule *bpf = ela_linux_audit_find_rule("ELA-LINUX-008");

	ELA_ASSERT_TRUE(aslr != NULL);
	ELA_ASSERT_TRUE(bpf != NULL);
	ELA_ASSERT_TRUE(ela_linux_audit_rule_enabled(aslr, ELA_LINUX_AUDIT_PROFILE_EMBEDDED));
	ELA_ASSERT_TRUE(ela_linux_audit_rule_enabled(aslr, ELA_LINUX_AUDIT_PROFILE_HARDENED));
	ELA_ASSERT_FALSE(ela_linux_audit_rule_enabled(bpf, ELA_LINUX_AUDIT_PROFILE_EMBEDDED));
	ELA_ASSERT_TRUE(ela_linux_audit_rule_enabled(bpf, ELA_LINUX_AUDIT_PROFILE_HARDENED));
	ELA_ASSERT_TRUE(ela_linux_audit_find_rule("ELA-LINUX-999") == NULL);
}

static void test_embedded_and_hardened_thresholds(void)
{
	const struct ela_linux_audit_rule *rule = ela_linux_audit_find_rule("ELA-LINUX-001");
	struct ela_linux_audit_result result;

	ELA_ASSERT_INT_EQ(0, ela_linux_audit_evaluate(rule, ELA_LINUX_AUDIT_PROFILE_EMBEDDED, "1\n", &result));
	ELA_ASSERT_INT_EQ(ELA_LINUX_AUDIT_PASS, result.status);
	ELA_ASSERT_TRUE(strstr(result.evidence, "expected >= 1") != NULL);

	ELA_ASSERT_INT_EQ(0, ela_linux_audit_evaluate(rule, ELA_LINUX_AUDIT_PROFILE_HARDENED, "1", &result));
	ELA_ASSERT_INT_EQ(ELA_LINUX_AUDIT_FAIL, result.status);
	ELA_ASSERT_TRUE(strstr(result.evidence, "expected >= 2") != NULL);
}

static void test_invalid_value_is_unknown(void)
{
	const struct ela_linux_audit_rule *rule = ela_linux_audit_find_rule("ELA-LINUX-003");
	struct ela_linux_audit_result result;

	ELA_ASSERT_INT_EQ(0, ela_linux_audit_evaluate(rule, ELA_LINUX_AUDIT_PROFILE_EMBEDDED, "not-a-number", &result));
	ELA_ASSERT_INT_EQ(ELA_LINUX_AUDIT_UNKNOWN, result.status);
	ELA_ASSERT_TRUE(strstr(result.evidence, "invalid integer") != NULL);
}

static void test_integer_max_rule(void)
{
	const struct ela_linux_audit_rule *rule = ela_linux_audit_find_rule("ELA-LINUX-014");
	struct ela_linux_audit_result result;

	ELA_ASSERT_INT_EQ(0, ela_linux_audit_evaluate(rule, ELA_LINUX_AUDIT_PROFILE_HARDENED, "0\n", &result));
	ELA_ASSERT_INT_EQ(ELA_LINUX_AUDIT_PASS, result.status);
	ELA_ASSERT_INT_EQ(0, ela_linux_audit_evaluate(rule, ELA_LINUX_AUDIT_PROFILE_HARDENED, "1000", &result));
	ELA_ASSERT_INT_EQ(ELA_LINUX_AUDIT_FAIL, result.status);
}

static void test_unreadable_probe_is_unknown(void)
{
	const struct ela_linux_audit_rule *rule = ela_linux_audit_find_rule("ELA-LINUX-001");
	struct ela_linux_audit_result result;

	ELA_ASSERT_INT_EQ(0, ela_linux_audit_run_rule(rule, ELA_LINUX_AUDIT_PROFILE_EMBEDDED,
						      "/path/that/does/not/exist", &result));
	ELA_ASSERT_INT_EQ(ELA_LINUX_AUDIT_UNKNOWN, result.status);
	ELA_ASSERT_TRUE(strstr(result.evidence, "unable to read") != NULL);
}

static void test_new_sysctl_thresholds(void)
{
	const struct ela_linux_audit_rule *fifos = ela_linux_audit_find_rule("ELA-LINUX-020");
	const struct ela_linux_audit_rule *dumpable = ela_linux_audit_find_rule("ELA-LINUX-022");
	const struct ela_linux_audit_rule *mmap = ela_linux_audit_find_rule("ELA-LINUX-024");
	struct ela_linux_audit_result result;

	ELA_ASSERT_TRUE(fifos != NULL);
	ELA_ASSERT_TRUE(dumpable != NULL);
	ELA_ASSERT_TRUE(mmap != NULL);
	ELA_ASSERT_TRUE(ela_linux_audit_rule_enabled(fifos, ELA_LINUX_AUDIT_PROFILE_EMBEDDED));

	ELA_ASSERT_INT_EQ(0, ela_linux_audit_evaluate(fifos, ELA_LINUX_AUDIT_PROFILE_EMBEDDED, "1\n", &result));
	ELA_ASSERT_INT_EQ(ELA_LINUX_AUDIT_PASS, result.status);
	ELA_ASSERT_INT_EQ(0, ela_linux_audit_evaluate(fifos, ELA_LINUX_AUDIT_PROFILE_HARDENED, "1\n", &result));
	ELA_ASSERT_INT_EQ(ELA_LINUX_AUDIT_FAIL, result.status);

	ELA_ASSERT_INT_EQ(0, ela_linux_audit_evaluate(dumpable, ELA_LINUX_AUDIT_PROFILE_EMBEDDED, "0\n", &result));
	ELA_ASSERT_INT_EQ(ELA_LINUX_AUDIT_PASS, result.status);
	ELA_ASSERT_INT_EQ(0, ela_linux_audit_evaluate(dumpable, ELA_LINUX_AUDIT_PROFILE_EMBEDDED, "2\n", &result));
	ELA_ASSERT_INT_EQ(ELA_LINUX_AUDIT_FAIL, result.status);

	ELA_ASSERT_INT_EQ(0, ela_linux_audit_evaluate(mmap, ELA_LINUX_AUDIT_PROFILE_EMBEDDED, "4096\n", &result));
	ELA_ASSERT_INT_EQ(ELA_LINUX_AUDIT_PASS, result.status);
	ELA_ASSERT_INT_EQ(0, ela_linux_audit_evaluate(mmap, ELA_LINUX_AUDIT_PROFILE_HARDENED, "4096\n", &result));
	ELA_ASSERT_INT_EQ(ELA_LINUX_AUDIT_FAIL, result.status);
}

static int write_probe(const char *root, const char *relative, const char *content)
{
	char path[512];
	FILE *fp;

	if (snprintf(path, sizeof(path), "%s%s", root, relative) >= (int)sizeof(path))
		return -1;
	fp = fopen(path, "w");
	if (!fp)
		return -1;
	fputs(content, fp);
	fclose(fp);
	return 0;
}

static void test_cmdline_forbidden_rules(void)
{
	const struct ela_linux_audit_rule *rule = ela_linux_audit_find_rule("ELA-LINUX-034");
	struct ela_linux_audit_result result;
	char root[] = "/tmp/ela-audit-test-XXXXXX";
	char path[512];

	ELA_ASSERT_TRUE(rule != NULL);
	ELA_ASSERT_TRUE(mkdtemp(root) != NULL);
	snprintf(path, sizeof(path), "%s/proc", root);
	ELA_ASSERT_INT_EQ(0, mkdir(path, 0755));

	ELA_ASSERT_INT_EQ(0, write_probe(root, "/proc/cmdline", "root=/dev/mmcblk0p2 quiet mitigations=off\n"));
	ELA_ASSERT_INT_EQ(0, ela_linux_audit_run_rule(rule, ELA_LINUX_AUDIT_PROFILE_EMBEDDED, root, &result));
	ELA_ASSERT_INT_EQ(ELA_LINUX_AUDIT_FAIL, result.status);
	ELA_ASSERT_TRUE(strstr(result.evidence, "mitigations=off") != NULL);

	ELA_ASSERT_INT_EQ(0, write_probe(root, "/proc/cmdline", "root=/dev/mmcblk0p2 quiet\n"));
	ELA_ASSERT_INT_EQ(0, ela_linux_audit_run_rule(rule, ELA_LINUX_AUDIT_PROFILE_EMBEDDED, root, &result));
	ELA_ASSERT_INT_EQ(ELA_LINUX_AUDIT_PASS, result.status);

	snprintf(path, sizeof(path), "%s/proc/cmdline", root);
	unlink(path);
	snprintf(path, sizeof(path), "%s/proc", root);
	rmdir(path);
	rmdir(root);
}

static void test_mount_absent_uses_expected_fstype(void)
{
	const struct ela_linux_audit_rule *tracefs = ela_linux_audit_find_rule("ELA-LINUX-053");
	const struct ela_linux_audit_rule *debugfs = ela_linux_audit_find_rule("ELA-LINUX-015");
	struct ela_linux_audit_result result;
	char root[] = "/tmp/ela-audit-test-XXXXXX";
	char path[512];

	ELA_ASSERT_TRUE(tracefs != NULL);
	ELA_ASSERT_TRUE(debugfs != NULL);
	ELA_ASSERT_STR_EQ("tracefs", tracefs->expected);
	ELA_ASSERT_TRUE(mkdtemp(root) != NULL);
	snprintf(path, sizeof(path), "%s/proc", root);
	ELA_ASSERT_INT_EQ(0, mkdir(path, 0755));

	ELA_ASSERT_INT_EQ(0, write_probe(root, "/proc/mounts",
					 "proc /proc proc rw 0 0\n"
					 "tracefs /sys/kernel/tracing tracefs rw,nosuid 0 0\n"));
	ELA_ASSERT_INT_EQ(0, ela_linux_audit_run_rule(tracefs, ELA_LINUX_AUDIT_PROFILE_HARDENED, root, &result));
	ELA_ASSERT_INT_EQ(ELA_LINUX_AUDIT_FAIL, result.status);
	ELA_ASSERT_TRUE(strstr(result.evidence, "tracefs mount present") != NULL);
	ELA_ASSERT_INT_EQ(0, ela_linux_audit_run_rule(debugfs, ELA_LINUX_AUDIT_PROFILE_HARDENED, root, &result));
	ELA_ASSERT_INT_EQ(ELA_LINUX_AUDIT_PASS, result.status);
	ELA_ASSERT_TRUE(strstr(result.evidence, "debugfs mount absent") != NULL);

	snprintf(path, sizeof(path), "%s/proc/mounts", root);
	unlink(path);
	snprintf(path, sizeof(path), "%s/proc", root);
	rmdir(path);
	rmdir(root);
}

static void test_status_names(void)
{
	ELA_ASSERT_STR_EQ("pass", ela_linux_audit_status_name(ELA_LINUX_AUDIT_PASS));
	ELA_ASSERT_STR_EQ("fail", ela_linux_audit_status_name(ELA_LINUX_AUDIT_FAIL));
	ELA_ASSERT_STR_EQ("unknown", ela_linux_audit_status_name(ELA_LINUX_AUDIT_UNKNOWN));
	ELA_ASSERT_STR_EQ("not-applicable", ela_linux_audit_status_name(ELA_LINUX_AUDIT_NOT_APPLICABLE));
}

int run_linux_audit_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "profiles_parse_and_name", test_profiles_parse_and_name },
		{ "rule_lookup_and_profile_filter", test_rule_lookup_and_profile_filter },
		{ "embedded_and_hardened_thresholds", test_embedded_and_hardened_thresholds },
		{ "invalid_value_is_unknown", test_invalid_value_is_unknown },
		{ "integer_max_rule", test_integer_max_rule },
		{ "new_sysctl_thresholds", test_new_sysctl_thresholds },
		{ "cmdline_forbidden_rules", test_cmdline_forbidden_rules },
		{ "mount_absent_uses_expected_fstype", test_mount_absent_uses_expected_fstype },
		{ "unreadable_probe_is_unknown", test_unreadable_probe_is_unknown },
		{ "status_names", test_status_names },
	};

	return ela_run_test_suite("linux_audit_util", cases, sizeof(cases) / sizeof(cases[0]));
}
