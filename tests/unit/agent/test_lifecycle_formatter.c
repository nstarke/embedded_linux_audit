// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/lifecycle_formatter.h"

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

static void test_lifecycle_formatter_matches_fixtures(void)
{
	struct output_buffer out = {0};
	const char *ts = "2026-03-18T12:34:56Z";
	const char *cmd = "linux execute-command echo,hi";

	ELA_ASSERT_INT_EQ(0, ela_format_lifecycle_record(&out, "txt", ts, cmd, "start", 0));
	assert_matches_fixture("tests/unit/agent/fixtures/lifecycle.txt", out.data);
	free(out.data);
	out = (struct output_buffer){0};

	ELA_ASSERT_INT_EQ(0, ela_format_lifecycle_record(&out, "csv", ts, cmd, "start", 0));
	assert_matches_fixture("tests/unit/agent/fixtures/lifecycle.csv", out.data);
	free(out.data);
	out = (struct output_buffer){0};

	ELA_ASSERT_INT_EQ(0, ela_format_lifecycle_record(&out, "json", ts, cmd, "start", 0));
	assert_matches_fixture("tests/unit/agent/fixtures/lifecycle.json", out.data);
	free(out.data);
}

static void test_lifecycle_content_type_matches_format(void)
{
	ELA_ASSERT_STR_EQ("text/plain; charset=utf-8", ela_lifecycle_content_type("txt"));
	ELA_ASSERT_STR_EQ("text/csv; charset=utf-8", ela_lifecycle_content_type("csv"));
	ELA_ASSERT_STR_EQ("application/json; charset=utf-8", ela_lifecycle_content_type("json"));
}

int run_lifecycle_formatter_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "lifecycle_formatter_matches_fixtures", test_lifecycle_formatter_matches_fixtures },
		{ "lifecycle_content_type_matches_format", test_lifecycle_content_type_matches_format },
	};

	return ela_run_test_suite("lifecycle_formatter", cases, sizeof(cases) / sizeof(cases[0]));
}
