// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/ssh_parse_util.h"

#include <stdint.h>
#include <string.h>

/* =========================================================================
 * ela_ssh_effective_user
 * ====================================================================== */

static void test_effective_user_env_preferred(void)
{
	ELA_ASSERT_STR_EQ("ela", ela_ssh_effective_user("ela", "root"));
}

static void test_effective_user_empty_env_falls_back_to_passwd(void)
{
	ELA_ASSERT_STR_EQ("service", ela_ssh_effective_user("", "service"));
}

static void test_effective_user_null_env_falls_back_to_passwd(void)
{
	ELA_ASSERT_STR_EQ("admin", ela_ssh_effective_user(NULL, "admin"));
}

static void test_effective_user_both_null_returns_root(void)
{
	ELA_ASSERT_STR_EQ("root", ela_ssh_effective_user(NULL, NULL));
}

static void test_effective_user_empty_both_returns_root(void)
{
	ELA_ASSERT_STR_EQ("root", ela_ssh_effective_user("", ""));
}

/* =========================================================================
 * ela_ssh_parent_dir
 * ====================================================================== */

static void test_parent_dir_null_path_returns_minus1(void)
{
	char buf[64];

	ELA_ASSERT_INT_EQ(-1, ela_ssh_parent_dir(NULL, buf, sizeof(buf)));
}

static void test_parent_dir_empty_path_returns_minus1(void)
{
	char buf[64];

	ELA_ASSERT_INT_EQ(-1, ela_ssh_parent_dir("", buf, sizeof(buf)));
}

static void test_parent_dir_null_buf_returns_minus1(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_ssh_parent_dir("/tmp/file", NULL, 64));
}

static void test_parent_dir_small_buf_returns_minus1(void)
{
	char buf[1];

	ELA_ASSERT_INT_EQ(-1, ela_ssh_parent_dir("/tmp/file", buf, sizeof(buf)));
}

static void test_parent_dir_simple(void)
{
	char buf[64];

	ELA_ASSERT_INT_EQ(0, ela_ssh_parent_dir("/tmp/file.txt", buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ("/tmp", buf);
}

static void test_parent_dir_relative_no_slash(void)
{
	char buf[64];

	ELA_ASSERT_INT_EQ(0, ela_ssh_parent_dir("relative.txt", buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ(".", buf);
}

static void test_parent_dir_root_child_returns_slash(void)
{
	char buf[64];

	ELA_ASSERT_INT_EQ(0, ela_ssh_parent_dir("/single", buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ("/", buf);
}

static void test_parent_dir_nested_path(void)
{
	char buf[64];

	ELA_ASSERT_INT_EQ(0, ela_ssh_parent_dir("/a/b/c/file", buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ("/a/b/c", buf);
}

/* =========================================================================
 * ela_ssh_parse_port
 * ====================================================================== */

static void test_parse_port_null_value_returns_minus1(void)
{
	uint16_t port = 0;

	ELA_ASSERT_INT_EQ(-1, ela_ssh_parse_port(NULL, &port));
}

static void test_parse_port_null_out_returns_minus1(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_ssh_parse_port("22", NULL));
}

static void test_parse_port_empty_returns_minus1(void)
{
	uint16_t port = 0;

	ELA_ASSERT_INT_EQ(-1, ela_ssh_parse_port("", &port));
}

static void test_parse_port_valid_22(void)
{
	uint16_t port = 0;

	ELA_ASSERT_INT_EQ(0, ela_ssh_parse_port("22", &port));
	ELA_ASSERT_INT_EQ(22, (int)port);
}

static void test_parse_port_valid_max(void)
{
	uint16_t port = 0;

	ELA_ASSERT_INT_EQ(0, ela_ssh_parse_port("65535", &port));
	ELA_ASSERT_INT_EQ(65535, (int)port);
}

static void test_parse_port_zero_returns_minus1(void)
{
	uint16_t port = 0;

	ELA_ASSERT_INT_EQ(-1, ela_ssh_parse_port("0", &port));
}

static void test_parse_port_overflow_returns_minus1(void)
{
	uint16_t port = 0;

	ELA_ASSERT_INT_EQ(-1, ela_ssh_parse_port("65536", &port));
}

static void test_parse_port_non_numeric_returns_minus1(void)
{
	uint16_t port = 0;

	ELA_ASSERT_INT_EQ(-1, ela_ssh_parse_port("abc", &port));
}

static void test_parse_port_trailing_chars_returns_minus1(void)
{
	uint16_t port = 0;

	ELA_ASSERT_INT_EQ(-1, ela_ssh_parse_port("22z", &port));
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_ssh_parse_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* ela_ssh_effective_user */
		{ "effective_user/env_preferred",       test_effective_user_env_preferred },
		{ "effective_user/empty_env_passwd",    test_effective_user_empty_env_falls_back_to_passwd },
		{ "effective_user/null_env_passwd",     test_effective_user_null_env_falls_back_to_passwd },
		{ "effective_user/both_null",           test_effective_user_both_null_returns_root },
		{ "effective_user/both_empty",          test_effective_user_empty_both_returns_root },
		/* ela_ssh_parent_dir */
		{ "parent_dir/null_path",               test_parent_dir_null_path_returns_minus1 },
		{ "parent_dir/empty_path",              test_parent_dir_empty_path_returns_minus1 },
		{ "parent_dir/null_buf",                test_parent_dir_null_buf_returns_minus1 },
		{ "parent_dir/small_buf",               test_parent_dir_small_buf_returns_minus1 },
		{ "parent_dir/simple",                  test_parent_dir_simple },
		{ "parent_dir/relative",                test_parent_dir_relative_no_slash },
		{ "parent_dir/root_child",              test_parent_dir_root_child_returns_slash },
		{ "parent_dir/nested",                  test_parent_dir_nested_path },
		/* ela_ssh_parse_port */
		{ "parse_port/null_value",              test_parse_port_null_value_returns_minus1 },
		{ "parse_port/null_out",                test_parse_port_null_out_returns_minus1 },
		{ "parse_port/empty",                   test_parse_port_empty_returns_minus1 },
		{ "parse_port/valid_22",                test_parse_port_valid_22 },
		{ "parse_port/valid_max",               test_parse_port_valid_max },
		{ "parse_port/zero",                    test_parse_port_zero_returns_minus1 },
		{ "parse_port/overflow",                test_parse_port_overflow_returns_minus1 },
		{ "parse_port/non_numeric",             test_parse_port_non_numeric_returns_minus1 },
		{ "parse_port/trailing_chars",          test_parse_port_trailing_chars_returns_minus1 },
	};

	return ela_run_test_suite("ssh_parse_util", cases, sizeof(cases) / sizeof(cases[0]));
}
