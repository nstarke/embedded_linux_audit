// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/env/uboot_env_format_util.h"

#include <string.h>

/* =========================================================================
 * ela_uboot_env_detect_output_format
 * ====================================================================== */

static void test_detect_null_returns_txt(void)
{
	ELA_ASSERT_INT_EQ(ELA_UBOOT_ENV_OUTPUT_TXT,
			  ela_uboot_env_detect_output_format(NULL));
}

static void test_detect_empty_returns_txt(void)
{
	ELA_ASSERT_INT_EQ(ELA_UBOOT_ENV_OUTPUT_TXT,
			  ela_uboot_env_detect_output_format(""));
}

static void test_detect_txt_returns_txt(void)
{
	ELA_ASSERT_INT_EQ(ELA_UBOOT_ENV_OUTPUT_TXT,
			  ela_uboot_env_detect_output_format("txt"));
}

static void test_detect_csv_returns_csv(void)
{
	ELA_ASSERT_INT_EQ(ELA_UBOOT_ENV_OUTPUT_CSV,
			  ela_uboot_env_detect_output_format("csv"));
}

static void test_detect_json_returns_json(void)
{
	ELA_ASSERT_INT_EQ(ELA_UBOOT_ENV_OUTPUT_JSON,
			  ela_uboot_env_detect_output_format("json"));
}

static void test_detect_unknown_returns_txt(void)
{
	ELA_ASSERT_INT_EQ(ELA_UBOOT_ENV_OUTPUT_TXT,
			  ela_uboot_env_detect_output_format("xml"));
}

/* =========================================================================
 * ela_uboot_env_http_content_type
 * ====================================================================== */

static void test_content_type_txt(void)
{
	ELA_ASSERT_STR_EQ("text/plain; charset=utf-8",
			  ela_uboot_env_http_content_type(ELA_UBOOT_ENV_OUTPUT_TXT));
}

static void test_content_type_csv(void)
{
	ELA_ASSERT_STR_EQ("text/csv; charset=utf-8",
			  ela_uboot_env_http_content_type(ELA_UBOOT_ENV_OUTPUT_CSV));
}

static void test_content_type_json(void)
{
	ELA_ASSERT_STR_EQ("application/x-ndjson; charset=utf-8",
			  ela_uboot_env_http_content_type(ELA_UBOOT_ENV_OUTPUT_JSON));
}

static void test_content_type_unknown_returns_plain(void)
{
	ELA_ASSERT_STR_EQ("text/plain; charset=utf-8",
			  ela_uboot_env_http_content_type(999));
}

/* =========================================================================
 * ela_uboot_env_trim
 * ====================================================================== */

static void test_trim_null_returns_null(void)
{
	ELA_ASSERT_TRUE(ela_uboot_env_trim(NULL) == NULL);
}

static void test_trim_empty_string(void)
{
	char s[] = "";

	ELA_ASSERT_STR_EQ("", ela_uboot_env_trim(s));
}

static void test_trim_all_whitespace(void)
{
	char s[] = "   \t  ";
	char *r = ela_uboot_env_trim(s);

	ELA_ASSERT_INT_EQ(0, (int)strlen(r));
}

static void test_trim_no_whitespace(void)
{
	char s[] = "hello";

	ELA_ASSERT_STR_EQ("hello", ela_uboot_env_trim(s));
}

static void test_trim_leading_only(void)
{
	char s[] = "   hello";

	ELA_ASSERT_STR_EQ("hello", ela_uboot_env_trim(s));
}

static void test_trim_trailing_only(void)
{
	char s[] = "hello   ";

	ELA_ASSERT_STR_EQ("hello", ela_uboot_env_trim(s));
}

static void test_trim_both_sides(void)
{
	char s[] = " \t bootcmd=run boot \n";

	ELA_ASSERT_STR_EQ("bootcmd=run boot", ela_uboot_env_trim(s));
}

/* =========================================================================
 * ela_uboot_env_valid_var_name
 * ====================================================================== */

static void test_valid_var_name_null(void)
{
	ELA_ASSERT_FALSE(ela_uboot_env_valid_var_name(NULL));
}

static void test_valid_var_name_empty(void)
{
	ELA_ASSERT_FALSE(ela_uboot_env_valid_var_name(""));
}

static void test_valid_var_name_simple(void)
{
	ELA_ASSERT_TRUE(ela_uboot_env_valid_var_name("bootcmd"));
}

static void test_valid_var_name_with_underscore(void)
{
	ELA_ASSERT_TRUE(ela_uboot_env_valid_var_name("boot_targets"));
}

static void test_valid_var_name_with_space(void)
{
	ELA_ASSERT_FALSE(ela_uboot_env_valid_var_name("boot cmd"));
}

static void test_valid_var_name_with_equals(void)
{
	ELA_ASSERT_FALSE(ela_uboot_env_valid_var_name("boot=cmd"));
}

static void test_valid_var_name_with_control_char(void)
{
	ELA_ASSERT_FALSE(ela_uboot_env_valid_var_name("boot\x01cmd"));
}

/* =========================================================================
 * ela_uboot_env_is_sensitive_var
 * ====================================================================== */

static void test_sensitive_var_null(void)
{
	ELA_ASSERT_FALSE(ela_uboot_env_is_sensitive_var(NULL));
}

static void test_sensitive_var_empty(void)
{
	ELA_ASSERT_FALSE(ela_uboot_env_is_sensitive_var(""));
}

static void test_sensitive_var_bootcmd(void)
{
	ELA_ASSERT_TRUE(ela_uboot_env_is_sensitive_var("bootcmd"));
}

static void test_sensitive_var_altbootcmd(void)
{
	ELA_ASSERT_TRUE(ela_uboot_env_is_sensitive_var("altbootcmd"));
}

static void test_sensitive_var_bootargs(void)
{
	ELA_ASSERT_TRUE(ela_uboot_env_is_sensitive_var("bootargs"));
}

static void test_sensitive_var_boot_targets(void)
{
	ELA_ASSERT_TRUE(ela_uboot_env_is_sensitive_var("boot_targets"));
}

static void test_sensitive_var_bootdelay(void)
{
	ELA_ASSERT_TRUE(ela_uboot_env_is_sensitive_var("bootdelay"));
}

static void test_sensitive_var_preboot(void)
{
	ELA_ASSERT_TRUE(ela_uboot_env_is_sensitive_var("preboot"));
}

static void test_sensitive_var_stdin(void)
{
	ELA_ASSERT_TRUE(ela_uboot_env_is_sensitive_var("stdin"));
}

static void test_sensitive_var_stdout(void)
{
	ELA_ASSERT_TRUE(ela_uboot_env_is_sensitive_var("stdout"));
}

static void test_sensitive_var_stderr(void)
{
	ELA_ASSERT_TRUE(ela_uboot_env_is_sensitive_var("stderr"));
}

static void test_sensitive_var_non_sensitive(void)
{
	ELA_ASSERT_FALSE(ela_uboot_env_is_sensitive_var("hostname"));
}

/* =========================================================================
 * ela_uboot_env_has_hint_var
 * ====================================================================== */

static void test_hint_null_data(void)
{
	ELA_ASSERT_FALSE(ela_uboot_env_has_hint_var(NULL, 16, NULL));
}

static void test_hint_zero_len(void)
{
	static const uint8_t d[] = "bootcmd=run boot";

	ELA_ASSERT_FALSE(ela_uboot_env_has_hint_var(d, 0, NULL));
}

static void test_hint_default_bootcmd(void)
{
	static const uint8_t d[] = "bootcmd=run boot\0\0";

	ELA_ASSERT_TRUE(ela_uboot_env_has_hint_var(d, sizeof(d) - 1, NULL));
}

static void test_hint_default_bootargs(void)
{
	static const uint8_t d[] = "bootargs=console=ttyS0\0\0";

	ELA_ASSERT_TRUE(ela_uboot_env_has_hint_var(d, sizeof(d) - 1, NULL));
}

static void test_hint_default_baudrate(void)
{
	static const uint8_t d[] = "baudrate=115200\0\0";

	ELA_ASSERT_TRUE(ela_uboot_env_has_hint_var(d, sizeof(d) - 1, NULL));
}

static void test_hint_default_ethaddr(void)
{
	static const uint8_t d[] = "ethaddr=00:11:22:33:44:55\0\0";

	ELA_ASSERT_TRUE(ela_uboot_env_has_hint_var(d, sizeof(d) - 1, NULL));
}

static void test_hint_default_stdin(void)
{
	static const uint8_t d[] = "stdin=serial\0\0";

	ELA_ASSERT_TRUE(ela_uboot_env_has_hint_var(d, sizeof(d) - 1, NULL));
}

static void test_hint_override_found(void)
{
	static const uint8_t d[] = "foo=bar\0bootargs=console\0\0";

	ELA_ASSERT_TRUE(ela_uboot_env_has_hint_var(d, sizeof(d) - 1, "bootargs="));
}

static void test_hint_override_not_found(void)
{
	static const uint8_t d[] = "foo=bar\0bootargs=console\0\0";

	ELA_ASSERT_FALSE(ela_uboot_env_has_hint_var(d, sizeof(d) - 1, "missing="));
}

static void test_hint_override_empty_uses_defaults(void)
{
	static const uint8_t d[] = "bootcmd=run boot\0\0";

	/* empty string hint_override → falls through to default hints */
	ELA_ASSERT_TRUE(ela_uboot_env_has_hint_var(d, sizeof(d) - 1, ""));
}

static void test_hint_no_match_returns_false(void)
{
	static const uint8_t d[] = "custom=value\0\0";

	ELA_ASSERT_FALSE(ela_uboot_env_has_hint_var(d, sizeof(d) - 1, NULL));
}

/* =========================================================================
 * ela_uboot_env_parse_write_script_line
 * ====================================================================== */

static void test_parse_null_line(void)
{
	char *name, *value;
	bool del;

	ELA_ASSERT_INT_EQ(-1, ela_uboot_env_parse_write_script_line(
		NULL, &name, &value, &del));
}

static void test_parse_null_name_out(void)
{
	char line[] = "bootcmd=run boot";
	char *value;
	bool del;

	ELA_ASSERT_INT_EQ(-1, ela_uboot_env_parse_write_script_line(
		line, NULL, &value, &del));
}

static void test_parse_null_value_out(void)
{
	char line[] = "bootcmd=run boot";
	char *name;
	bool del;

	ELA_ASSERT_INT_EQ(-1, ela_uboot_env_parse_write_script_line(
		line, &name, NULL, &del));
}

static void test_parse_null_delete_out(void)
{
	char line[] = "bootcmd=run boot";
	char *name, *value;

	ELA_ASSERT_INT_EQ(-1, ela_uboot_env_parse_write_script_line(
		line, &name, &value, NULL));
}

static void test_parse_comment_line(void)
{
	char line[] = "# this is a comment";
	char *name, *value;
	bool del;

	ELA_ASSERT_INT_EQ(1, ela_uboot_env_parse_write_script_line(
		line, &name, &value, &del));
}

static void test_parse_empty_line(void)
{
	char line[] = "   ";
	char *name, *value;
	bool del;

	ELA_ASSERT_INT_EQ(1, ela_uboot_env_parse_write_script_line(
		line, &name, &value, &del));
}

static void test_parse_eq_assign(void)
{
	char line[] = "bootcmd=run distro_bootcmd";
	char *name, *value;
	bool del = true;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_parse_write_script_line(
		line, &name, &value, &del));
	ELA_ASSERT_STR_EQ("bootcmd", name);
	ELA_ASSERT_STR_EQ("run distro_bootcmd", value);
	ELA_ASSERT_FALSE(del);
}

static void test_parse_space_assign(void)
{
	char line[] = " baudrate 115200 ";
	char *name, *value;
	bool del = true;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_parse_write_script_line(
		line, &name, &value, &del));
	ELA_ASSERT_STR_EQ("baudrate", name);
	ELA_ASSERT_STR_EQ("115200", value);
	ELA_ASSERT_FALSE(del);
}

static void test_parse_delete_no_value(void)
{
	char line[] = "bootdelay";
	char *name, *value;
	bool del = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_parse_write_script_line(
		line, &name, &value, &del));
	ELA_ASSERT_STR_EQ("bootdelay", name);
	ELA_ASSERT_TRUE(del);
}

static void test_parse_space_delimited_empty_value_deletes(void)
{
	char line[] = "stdin   ";
	char *name, *value;
	bool del = false;

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_parse_write_script_line(
		line, &name, &value, &del));
	ELA_ASSERT_STR_EQ("stdin", name);
	ELA_ASSERT_TRUE(del);
}

/* =========================================================================
 * Suite registration
 * ====================================================================== */

int run_uboot_env_format_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "detect_null_returns_txt",              test_detect_null_returns_txt },
		{ "detect_empty_returns_txt",             test_detect_empty_returns_txt },
		{ "detect_txt_returns_txt",               test_detect_txt_returns_txt },
		{ "detect_csv_returns_csv",               test_detect_csv_returns_csv },
		{ "detect_json_returns_json",             test_detect_json_returns_json },
		{ "detect_unknown_returns_txt",           test_detect_unknown_returns_txt },
		{ "content_type_txt",                     test_content_type_txt },
		{ "content_type_csv",                     test_content_type_csv },
		{ "content_type_json",                    test_content_type_json },
		{ "content_type_unknown_plain",           test_content_type_unknown_returns_plain },
		{ "trim_null",                            test_trim_null_returns_null },
		{ "trim_empty",                           test_trim_empty_string },
		{ "trim_all_whitespace",                  test_trim_all_whitespace },
		{ "trim_no_whitespace",                   test_trim_no_whitespace },
		{ "trim_leading_only",                    test_trim_leading_only },
		{ "trim_trailing_only",                   test_trim_trailing_only },
		{ "trim_both_sides",                      test_trim_both_sides },
		{ "valid_name_null",                      test_valid_var_name_null },
		{ "valid_name_empty",                     test_valid_var_name_empty },
		{ "valid_name_simple",                    test_valid_var_name_simple },
		{ "valid_name_underscore",                test_valid_var_name_with_underscore },
		{ "valid_name_space",                     test_valid_var_name_with_space },
		{ "valid_name_equals",                    test_valid_var_name_with_equals },
		{ "valid_name_control_char",              test_valid_var_name_with_control_char },
		{ "sensitive_null",                       test_sensitive_var_null },
		{ "sensitive_empty",                      test_sensitive_var_empty },
		{ "sensitive_bootcmd",                    test_sensitive_var_bootcmd },
		{ "sensitive_altbootcmd",                 test_sensitive_var_altbootcmd },
		{ "sensitive_bootargs",                   test_sensitive_var_bootargs },
		{ "sensitive_boot_targets",               test_sensitive_var_boot_targets },
		{ "sensitive_bootdelay",                  test_sensitive_var_bootdelay },
		{ "sensitive_preboot",                    test_sensitive_var_preboot },
		{ "sensitive_stdin",                      test_sensitive_var_stdin },
		{ "sensitive_stdout",                     test_sensitive_var_stdout },
		{ "sensitive_stderr",                     test_sensitive_var_stderr },
		{ "sensitive_non_sensitive",              test_sensitive_var_non_sensitive },
		{ "hint_null_data",                       test_hint_null_data },
		{ "hint_zero_len",                        test_hint_zero_len },
		{ "hint_default_bootcmd",                 test_hint_default_bootcmd },
		{ "hint_default_bootargs",                test_hint_default_bootargs },
		{ "hint_default_baudrate",                test_hint_default_baudrate },
		{ "hint_default_ethaddr",                 test_hint_default_ethaddr },
		{ "hint_default_stdin",                   test_hint_default_stdin },
		{ "hint_override_found",                  test_hint_override_found },
		{ "hint_override_not_found",              test_hint_override_not_found },
		{ "hint_override_empty_uses_defaults",    test_hint_override_empty_uses_defaults },
		{ "hint_no_match",                        test_hint_no_match_returns_false },
		{ "parse_null_line",                      test_parse_null_line },
		{ "parse_null_name_out",                  test_parse_null_name_out },
		{ "parse_null_value_out",                 test_parse_null_value_out },
		{ "parse_null_delete_out",                test_parse_null_delete_out },
		{ "parse_comment",                        test_parse_comment_line },
		{ "parse_empty_line",                     test_parse_empty_line },
		{ "parse_eq_assign",                      test_parse_eq_assign },
		{ "parse_space_assign",                   test_parse_space_assign },
		{ "parse_delete_no_value",                test_parse_delete_no_value },
		{ "parse_space_empty_value_deletes",      test_parse_space_delimited_empty_value_deletes },
	};
	return ela_run_test_suite("uboot_env_format_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
