// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/command_io_util.h"

#include <string.h>
#include <unistd.h>

static void test_execute_command_content_type_matches_format(void)
{
	ELA_ASSERT_STR_EQ("text/plain; charset=utf-8", ela_execute_command_content_type("txt"));
	ELA_ASSERT_STR_EQ("text/csv; charset=utf-8", ela_execute_command_content_type("csv"));
	ELA_ASSERT_STR_EQ("application/json; charset=utf-8", ela_execute_command_content_type("json"));
}

static void test_parse_download_file_args_accepts_valid_inputs(void)
{
	char *argv[] = { "https://ela.example/file.bin", "/tmp/file.bin" };
	const char *url = NULL;
	const char *output = NULL;
	char errbuf[256];

	ELA_ASSERT_INT_EQ(0, ela_parse_download_file_args(2, argv, &url, &output, errbuf, sizeof(errbuf)));
	ELA_ASSERT_STR_EQ(argv[0], url);
	ELA_ASSERT_STR_EQ(argv[1], output);
}

static void test_parse_download_file_args_rejects_bad_inputs(void)
{
	char *argv[] = { "ftp://bad", "/tmp/file.bin", "extra" };
	const char *url = NULL;
	const char *output = NULL;
	char errbuf[256];

	ELA_ASSERT_INT_EQ(-1, ela_parse_download_file_args(3, argv, &url, &output, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "http:// or https://") != NULL);
}

static char mirrored[4096];
static size_t mirrored_len;

static void capture_mirror(const char *data, size_t len)
{
	if (len <= sizeof(mirrored) - mirrored_len) {
		memcpy(mirrored + mirrored_len, data, len);
		mirrored_len += len;
	}
}

static void emit(FILE *stream, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	ela_command_emit_v(stream, fmt, ap, capture_mirror);
	va_end(ap);
}

static void test_command_output_mirrors_stdout_only(void)
{
	FILE *capture = tmpfile();
	FILE *local = tmpfile();
	int saved_stdout;
	char large[2049];
	char readback[4096];
	size_t captured;

	ELA_ASSERT_TRUE(capture != NULL && local != NULL);
	memset(large, 'x', sizeof(large) - 1);
	large[sizeof(large) - 1] = '\0';
	mirrored_len = 0;
	fflush(stdout);
	saved_stdout = dup(STDOUT_FILENO);
	ELA_ASSERT_TRUE(saved_stdout >= 0);
	if (dup2(fileno(capture), STDOUT_FILENO) < 0) {
		close(saved_stdout);
		fclose(capture);
		fclose(local);
		ELA_ASSERT_TRUE(0);
	}
	emit(stdout, "short:%d\n", 42);
	emit(stdout, "%s/%d", large, 7);
	emit(local, "local:%d", 9);
	fflush(stdout);
	dup2(saved_stdout, STDOUT_FILENO);
	close(saved_stdout);
	rewind(capture);
	captured = fread(readback, 1, sizeof(readback), capture);
	fclose(capture);
	ELA_ASSERT_INT_EQ(2059, (int)captured);
	ELA_ASSERT_INT_EQ((int)captured, (int)mirrored_len);
	ELA_ASSERT_TRUE(memcmp(readback, mirrored, captured) == 0);
	ELA_ASSERT_TRUE(memcmp(mirrored, "short:42\n", 9) == 0);
	ELA_ASSERT_TRUE(memcmp(mirrored + 9, large, 2048) == 0);
	ELA_ASSERT_TRUE(memcmp(mirrored + 2057, "/7", 2) == 0);
	rewind(local);
	captured = fread(readback, 1, sizeof(readback) - 1, local);
	readback[captured] = '\0';
	fclose(local);
	ELA_ASSERT_STR_EQ("local:9", readback);
}

int run_command_io_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "command_output/mirrors_stdout_only", test_command_output_mirrors_stdout_only },
		{ "execute_command_content_type_matches_format", test_execute_command_content_type_matches_format },
		{ "parse_download_file_args_accepts_valid_inputs", test_parse_download_file_args_accepts_valid_inputs },
		{ "parse_download_file_args_rejects_bad_inputs", test_parse_download_file_args_rejects_bad_inputs },
	};

	return ela_run_test_suite("command_io_util", cases, sizeof(cases) / sizeof(cases[0]));
}
