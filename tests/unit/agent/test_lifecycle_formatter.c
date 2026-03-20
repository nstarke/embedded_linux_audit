// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/lifecycle_formatter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* -------------------------------------------------------------------------
 * Fixture helpers
 * ---------------------------------------------------------------------- */

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

/* -------------------------------------------------------------------------
 * ela_format_utc_timestamp
 * ---------------------------------------------------------------------- */

static void test_format_utc_timestamp_null_buf(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_format_utc_timestamp(0, NULL, 64));
}

static void test_format_utc_timestamp_zero_buf_size(void)
{
	char buf[64];

	ELA_ASSERT_INT_EQ(-1, ela_format_utc_timestamp(0, buf, 0));
}

static void test_format_utc_timestamp_epoch(void)
{
	char buf[64];

	/* time_t 0 = 1970-01-01T00:00:00Z */
	ELA_ASSERT_INT_EQ(0, ela_format_utc_timestamp((time_t)0, buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ("1970-01-01T00:00:00Z", buf);
}

static void test_format_utc_timestamp_known_time(void)
{
	char buf[64];
	/* 2026-03-18T12:34:56Z = 1773837296 */
	ELA_ASSERT_INT_EQ(0, ela_format_utc_timestamp((time_t)1773837296, buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ("2026-03-18T12:34:56Z", buf);
}

static void test_format_utc_timestamp_buf_too_small(void)
{
	/* "2026-03-18T12:34:56Z" is 20 chars + NUL = 21. A 10-byte buf truncates. */
	char buf[10];

	/* snprintf truncates but returns 0 (no error from format_utc_timestamp),
	 * because snprintf itself succeeds — just the result is truncated. */
	ELA_ASSERT_INT_EQ(0, ela_format_utc_timestamp((time_t)1773837296, buf, sizeof(buf)));
	/* Content is truncated but NUL-terminated */
	ELA_ASSERT_TRUE(buf[sizeof(buf) - 1] == '\0');
}

static void test_format_utc_timestamp_iso8601_format(void)
{
	char buf[64];

	ELA_ASSERT_INT_EQ(0, ela_format_utc_timestamp((time_t)1773837296, buf, sizeof(buf)));
	/* Must end with 'Z' */
	ELA_ASSERT_TRUE(buf[strlen(buf) - 1] == 'Z');
	/* Must contain 'T' separator */
	ELA_ASSERT_TRUE(strchr(buf, 'T') != NULL);
}

/* -------------------------------------------------------------------------
 * ela_format_lifecycle_record — fixture-based tests
 * ---------------------------------------------------------------------- */

static void test_lifecycle_formatter_matches_fixtures(void)
{
	struct output_buffer out = {0};
	const char *ts  = "2026-03-18T12:34:56Z";
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

/* -------------------------------------------------------------------------
 * ela_format_lifecycle_record — null/guard tests
 * ---------------------------------------------------------------------- */

static void test_format_record_null_out(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_format_lifecycle_record(NULL, "txt", "ts", "cmd", "start", 0));
}

static void test_format_record_null_timestamp(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(-1, ela_format_lifecycle_record(&out, "txt", NULL, "cmd", "start", 0));
	free(out.data);
}

static void test_format_record_null_command(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(-1, ela_format_lifecycle_record(&out, "txt", "ts", NULL, "start", 0));
	free(out.data);
}

static void test_format_record_null_phase(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(-1, ela_format_lifecycle_record(&out, "txt", "ts", "cmd", NULL, 0));
	free(out.data);
}

/* -------------------------------------------------------------------------
 * ela_format_lifecycle_record — format-specific content tests
 * ---------------------------------------------------------------------- */

static void test_format_record_txt_content(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(0, ela_format_lifecycle_record(&out, "txt",
		"2026-01-01T00:00:00Z", "pcrread", "end", 42));
	ELA_ASSERT_TRUE(strstr(out.data, "log ") != NULL);
	ELA_ASSERT_TRUE(strstr(out.data, "agent_timestamp=2026-01-01T00:00:00Z") != NULL);
	ELA_ASSERT_TRUE(strstr(out.data, "phase=end") != NULL);
	ELA_ASSERT_TRUE(strstr(out.data, "command=pcrread") != NULL);
	ELA_ASSERT_TRUE(strstr(out.data, "rc=42") != NULL);
	ELA_ASSERT_TRUE(out.data[out.len - 1] == '\n');
	free(out.data);
}

static void test_format_record_csv_content(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(0, ela_format_lifecycle_record(&out, "csv",
		"2026-01-01T00:00:00Z", "getcap", "start", 0));
	ELA_ASSERT_TRUE(strstr(out.data, "\"log\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out.data, "\"2026-01-01T00:00:00Z\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out.data, "\"start\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out.data, "\"getcap\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out.data, "\"0\"") != NULL);
	ELA_ASSERT_TRUE(out.data[out.len - 1] == '\n');
	free(out.data);
}

static void test_format_record_json_content(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(0, ela_format_lifecycle_record(&out, "json",
		"2026-01-01T00:00:00Z", "pcrread", "end", 1));
	ELA_ASSERT_TRUE(strstr(out.data, "\"record\":\"log\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out.data, "\"phase\":\"end\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out.data, "\"command\":\"pcrread\"") != NULL);
	ELA_ASSERT_TRUE(strstr(out.data, "\"rc\":1") != NULL);
	ELA_ASSERT_TRUE(out.data[out.len - 1] == '\n');
	free(out.data);
}

static void test_format_record_null_format_defaults_txt(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(0, ela_format_lifecycle_record(&out, NULL,
		"2026-01-01T00:00:00Z", "cmd", "start", 0));
	ELA_ASSERT_TRUE(strstr(out.data, "log agent_timestamp=") != NULL);
	free(out.data);
}

static void test_format_record_empty_format_defaults_txt(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(0, ela_format_lifecycle_record(&out, "",
		"2026-01-01T00:00:00Z", "cmd", "start", 0));
	ELA_ASSERT_TRUE(strstr(out.data, "log agent_timestamp=") != NULL);
	free(out.data);
}

static void test_format_record_negative_rc(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(0, ela_format_lifecycle_record(&out, "txt",
		"ts", "cmd", "end", -1));
	ELA_ASSERT_TRUE(strstr(out.data, "rc=-1") != NULL);
	free(out.data);
}

/* -------------------------------------------------------------------------
 * ela_lifecycle_content_type
 * ---------------------------------------------------------------------- */

static void test_lifecycle_content_type_matches_format(void)
{
	ELA_ASSERT_STR_EQ("text/plain; charset=utf-8",       ela_lifecycle_content_type("txt"));
	ELA_ASSERT_STR_EQ("text/csv; charset=utf-8",         ela_lifecycle_content_type("csv"));
	ELA_ASSERT_STR_EQ("application/json; charset=utf-8", ela_lifecycle_content_type("json"));
}

static void test_lifecycle_content_type_null_defaults_text(void)
{
	ELA_ASSERT_STR_EQ("text/plain; charset=utf-8", ela_lifecycle_content_type(NULL));
}

static void test_lifecycle_content_type_unknown_defaults_text(void)
{
	ELA_ASSERT_STR_EQ("text/plain; charset=utf-8", ela_lifecycle_content_type("xml"));
	ELA_ASSERT_STR_EQ("text/plain; charset=utf-8", ela_lifecycle_content_type(""));
}

/* -------------------------------------------------------------------------
 * Test suite registration
 * ---------------------------------------------------------------------- */

int run_lifecycle_formatter_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* format_utc_timestamp */
		{ "format_utc_timestamp_null_buf",         test_format_utc_timestamp_null_buf },
		{ "format_utc_timestamp_zero_buf_size",    test_format_utc_timestamp_zero_buf_size },
		{ "format_utc_timestamp_epoch",            test_format_utc_timestamp_epoch },
		{ "format_utc_timestamp_known_time",       test_format_utc_timestamp_known_time },
		{ "format_utc_timestamp_buf_too_small",    test_format_utc_timestamp_buf_too_small },
		{ "format_utc_timestamp_iso8601_format",   test_format_utc_timestamp_iso8601_format },
		/* format_lifecycle_record guards */
		{ "format_record_null_out",                test_format_record_null_out },
		{ "format_record_null_timestamp",          test_format_record_null_timestamp },
		{ "format_record_null_command",            test_format_record_null_command },
		{ "format_record_null_phase",              test_format_record_null_phase },
		/* format_lifecycle_record content */
		{ "format_record_txt_content",             test_format_record_txt_content },
		{ "format_record_csv_content",             test_format_record_csv_content },
		{ "format_record_json_content",            test_format_record_json_content },
		{ "format_record_null_format_defaults",    test_format_record_null_format_defaults_txt },
		{ "format_record_empty_format_defaults",   test_format_record_empty_format_defaults_txt },
		{ "format_record_negative_rc",             test_format_record_negative_rc },
		/* fixture-based round-trip */
		{ "lifecycle_formatter_matches_fixtures",  test_lifecycle_formatter_matches_fixtures },
		/* content_type */
		{ "lifecycle_content_type_matches_format", test_lifecycle_content_type_matches_format },
		{ "lifecycle_content_type_null_default",   test_lifecycle_content_type_null_defaults_text },
		{ "lifecycle_content_type_unknown_default",test_lifecycle_content_type_unknown_defaults_text },
	};

	return ela_run_test_suite("lifecycle_formatter",
				  cases, sizeof(cases) / sizeof(cases[0]));
}
