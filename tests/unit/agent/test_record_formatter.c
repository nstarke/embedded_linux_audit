// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/record_formatter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_fixture(const char *path)
{
	FILE *fp;
	long size;
	char *buf;

	fp = fopen(path, "rb");
	if (!fp)
		return NULL;
	if (fseek(fp, 0, SEEK_END) != 0) {
		fclose(fp);
		return NULL;
	}
	size = ftell(fp);
	if (size < 0) {
		fclose(fp);
		return NULL;
	}
	if (fseek(fp, 0, SEEK_SET) != 0) {
		fclose(fp);
		return NULL;
	}

	buf = calloc((size_t)size + 1, 1);
	if (!buf) {
		fclose(fp);
		return NULL;
	}
	if (size > 0 && fread(buf, 1, (size_t)size, fp) != (size_t)size) {
		fclose(fp);
		free(buf);
		return NULL;
	}
	fclose(fp);
	return buf;
}

static void assert_matches_fixture(const char *fixture_path, const char *actual)
{
	char *expected = read_fixture(fixture_path);

	ELA_ASSERT_TRUE(expected != NULL);
	ELA_ASSERT_STR_EQ(expected, actual);
	free(expected);
}

static void test_arch_formatter_matches_fixtures(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(0, ela_format_arch_record(&out, "txt", "isa", "x86_64"));
	assert_matches_fixture("tests/unit/agent/fixtures/arch.txt", out.data);
	free(out.data);
	out = (struct output_buffer){0};

	ELA_ASSERT_INT_EQ(0, ela_format_arch_record(&out, "csv", "isa", "x86_64"));
	assert_matches_fixture("tests/unit/agent/fixtures/arch.csv", out.data);
	free(out.data);
	out = (struct output_buffer){0};

	ELA_ASSERT_INT_EQ(0, ela_format_arch_record(&out, "json", "isa", "x86_64"));
	assert_matches_fixture("tests/unit/agent/fixtures/arch.json", out.data);
	free(out.data);
}

static void test_execute_formatter_matches_fixtures(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(0, ela_format_execute_command_record(&out, "txt", "echo hi", "ok\n"));
	assert_matches_fixture("tests/unit/agent/fixtures/execute_command.txt", out.data);
	free(out.data);
	out = (struct output_buffer){0};

	ELA_ASSERT_INT_EQ(0, ela_format_execute_command_record(&out, "csv", "echo,hi", "ok"));
	assert_matches_fixture("tests/unit/agent/fixtures/execute_command.csv", out.data);
	free(out.data);
	out = (struct output_buffer){0};

	ELA_ASSERT_INT_EQ(0, ela_format_execute_command_record(&out, "json", "echo hi", "ok"));
	assert_matches_fixture("tests/unit/agent/fixtures/execute_command.json", out.data);
	free(out.data);
}

static void test_efi_formatter_matches_fixtures(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(0, ela_format_efi_var_record(&out, "txt",
						       "12345678-1234-1234-1234-1234567890ab",
						       "Boot0001", 7, 4, "deadbeef"));
	assert_matches_fixture("tests/unit/agent/fixtures/efi_var.txt", out.data);
	free(out.data);
	out = (struct output_buffer){0};

	ELA_ASSERT_INT_EQ(0, ela_format_efi_var_record(&out, "csv",
						       "12345678-1234-1234-1234-1234567890ab",
						       "Boot,0001", 7, 4, "deadbeef"));
	assert_matches_fixture("tests/unit/agent/fixtures/efi_var.csv", out.data);
	free(out.data);
	out = (struct output_buffer){0};

	ELA_ASSERT_INT_EQ(0, ela_format_efi_var_record(&out, "json",
						       "12345678-1234-1234-1234-1234567890ab",
						       "Boot0001", 7, 4, "deadbeef"));
	assert_matches_fixture("tests/unit/agent/fixtures/efi_var.json", out.data);
	free(out.data);
}

int run_record_formatter_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "arch_formatter_matches_fixtures", test_arch_formatter_matches_fixtures },
		{ "execute_formatter_matches_fixtures", test_execute_formatter_matches_fixtures },
		{ "efi_formatter_matches_fixtures", test_efi_formatter_matches_fixtures },
	};

	return ela_run_test_suite("record_formatter", cases, sizeof(cases) / sizeof(cases[0]));
}
