// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/uboot/env/uboot_env_format_util.h"

static void test_uboot_env_output_helpers(void)
{
	ELA_ASSERT_INT_EQ(ELA_UBOOT_ENV_OUTPUT_TXT, ela_uboot_env_detect_output_format(NULL));
	ELA_ASSERT_INT_EQ(ELA_UBOOT_ENV_OUTPUT_CSV, ela_uboot_env_detect_output_format("csv"));
	ELA_ASSERT_INT_EQ(ELA_UBOOT_ENV_OUTPUT_JSON, ela_uboot_env_detect_output_format("json"));
	ELA_ASSERT_STR_EQ("text/plain; charset=utf-8",
			  ela_uboot_env_http_content_type(ELA_UBOOT_ENV_OUTPUT_TXT));
	ELA_ASSERT_STR_EQ("text/csv; charset=utf-8",
			  ela_uboot_env_http_content_type(ELA_UBOOT_ENV_OUTPUT_CSV));
	ELA_ASSERT_STR_EQ("application/x-ndjson; charset=utf-8",
			  ela_uboot_env_http_content_type(ELA_UBOOT_ENV_OUTPUT_JSON));
}

static void test_uboot_env_string_and_name_helpers(void)
{
	char spaced[] = " \t bootcmd=run boot \n";

	ELA_ASSERT_STR_EQ("bootcmd=run boot", ela_uboot_env_trim(spaced));
	ELA_ASSERT_TRUE(ela_uboot_env_valid_var_name("bootcmd"));
	ELA_ASSERT_FALSE(ela_uboot_env_valid_var_name("boot cmd"));
	ELA_ASSERT_FALSE(ela_uboot_env_valid_var_name("boot=cmd"));
	ELA_ASSERT_TRUE(ela_uboot_env_is_sensitive_var("bootcmd"));
	ELA_ASSERT_FALSE(ela_uboot_env_is_sensitive_var("hostname"));
}

static void test_uboot_env_hint_and_script_line_helpers(void)
{
	static const uint8_t env_data[] = "foo=bar\0bootargs=console\0\0";
	char assign_line[] = "bootcmd=run distro_bootcmd";
	char delete_line[] = "bootdelay";
	char spaced_delete_line[] = "stdin   ";
	char spaced_assign_line[] = " baudrate 115200 ";
	char *name = NULL;
	char *value = NULL;
	bool delete_var = false;

	ELA_ASSERT_TRUE(ela_uboot_env_has_hint_var(env_data, sizeof(env_data) - 1, NULL));
	ELA_ASSERT_TRUE(ela_uboot_env_has_hint_var(env_data, sizeof(env_data) - 1, "bootargs="));
	ELA_ASSERT_FALSE(ela_uboot_env_has_hint_var(env_data, sizeof(env_data) - 1, "missing="));

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_parse_write_script_line(assign_line, &name, &value, &delete_var));
	ELA_ASSERT_STR_EQ("bootcmd", name);
	ELA_ASSERT_STR_EQ("run distro_bootcmd", value);
	ELA_ASSERT_FALSE(delete_var);

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_parse_write_script_line(delete_line, &name, &value, &delete_var));
	ELA_ASSERT_STR_EQ("bootdelay", name);
	ELA_ASSERT_TRUE(delete_var);

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_parse_write_script_line(spaced_delete_line, &name, &value, &delete_var));
	ELA_ASSERT_STR_EQ("stdin", name);
	ELA_ASSERT_TRUE(delete_var);

	ELA_ASSERT_INT_EQ(0, ela_uboot_env_parse_write_script_line(spaced_assign_line, &name, &value, &delete_var));
	ELA_ASSERT_STR_EQ("baudrate", name);
	ELA_ASSERT_STR_EQ("115200", value);
	ELA_ASSERT_FALSE(delete_var);
}

int run_uboot_env_format_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "uboot_env_output_helpers", test_uboot_env_output_helpers },
		{ "uboot_env_string_and_name_helpers", test_uboot_env_string_and_name_helpers },
		{ "uboot_env_hint_and_script_line_helpers", test_uboot_env_hint_and_script_line_helpers },
	};

	return ela_run_test_suite("uboot_env_format_util", cases, sizeof(cases) / sizeof(cases[0]));
}
