// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/ssh_parse_util.h"

static void test_ssh_effective_user_prefers_env_then_passwd_then_root(void)
{
	ELA_ASSERT_STR_EQ("ela", ela_ssh_effective_user("ela", "root"));
	ELA_ASSERT_STR_EQ("service", ela_ssh_effective_user("", "service"));
	ELA_ASSERT_STR_EQ("root", ela_ssh_effective_user(NULL, NULL));
}

static void test_ssh_parent_dir_handles_common_paths(void)
{
	char buf[64];

	ELA_ASSERT_INT_EQ(0, ela_ssh_parent_dir("/tmp/file.txt", buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ("/tmp", buf);

	ELA_ASSERT_INT_EQ(0, ela_ssh_parent_dir("relative.txt", buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ(".", buf);

	ELA_ASSERT_INT_EQ(0, ela_ssh_parent_dir("/single", buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ("/", buf);
}

static void test_ssh_parse_port_accepts_valid_and_rejects_invalid_values(void)
{
	uint16_t port = 0;

	ELA_ASSERT_INT_EQ(0, ela_ssh_parse_port("22", &port));
	ELA_ASSERT_INT_EQ(22, port);
	ELA_ASSERT_INT_EQ(-1, ela_ssh_parse_port("0", &port));
	ELA_ASSERT_INT_EQ(-1, ela_ssh_parse_port("65536", &port));
	ELA_ASSERT_INT_EQ(-1, ela_ssh_parse_port("abc", &port));
}

int run_ssh_parse_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "ssh_effective_user_prefers_env_then_passwd_then_root", test_ssh_effective_user_prefers_env_then_passwd_then_root },
		{ "ssh_parent_dir_handles_common_paths", test_ssh_parent_dir_handles_common_paths },
		{ "ssh_parse_port_accepts_valid_and_rejects_invalid_values", test_ssh_parse_port_accepts_valid_and_rejects_invalid_values },
	};

	return ela_run_test_suite("ssh_parse_util", cases, sizeof(cases) / sizeof(cases[0]));
}
