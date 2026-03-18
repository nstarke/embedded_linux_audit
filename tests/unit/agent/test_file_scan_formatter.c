// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/file_scan_formatter.h"

#include <stdio.h>
#include <stdlib.h>

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

static void test_grep_match_formatter_matches_fixture(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(0, ela_format_grep_match_record(&out, "/tmp/test.txt", 7, "needle here"));
	assert_matches_fixture("tests/unit/agent/fixtures/grep.txt", out.data);
	free(out.data);
}

static void test_symlink_formatter_matches_fixtures(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(0, ela_format_symlink_record(&out, "txt", "/tmp/current", "/opt/releases/v1"));
	assert_matches_fixture("tests/unit/agent/fixtures/symlink.txt", out.data);
	free(out.data);
	out = (struct output_buffer){0};

	ELA_ASSERT_INT_EQ(0, ela_format_symlink_record(&out, "csv", "/tmp/current", "/opt/releases,v1"));
	assert_matches_fixture("tests/unit/agent/fixtures/symlink.csv", out.data);
	free(out.data);
	out = (struct output_buffer){0};

	ELA_ASSERT_INT_EQ(0, ela_format_symlink_record(&out, "json", "/tmp/current", "/opt/releases/v1"));
	assert_matches_fixture("tests/unit/agent/fixtures/symlink.json", out.data);
	free(out.data);
}

int run_file_scan_formatter_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "grep_match_formatter_matches_fixture", test_grep_match_formatter_matches_fixture },
		{ "symlink_formatter_matches_fixtures", test_symlink_formatter_matches_fixtures },
	};

	return ela_run_test_suite("file_scan_formatter", cases, sizeof(cases) / sizeof(cases[0]));
}
