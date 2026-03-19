// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../../../agent/linux/linux_download_file_util.h"
#include "test_harness.h"

#include <errno.h>
#include <string.h>

static void test_download_file_prepare_request_accepts_valid_inputs_and_help(void)
{
	struct ela_download_file_env env = {
		.insecure = true,
		.verbose = true,
	};
	struct ela_download_file_request request;
	char errbuf[256];
	char *argv_ok[] = { "download-file", "https://ela.example/file.bin", "/tmp/out.bin" };
	char *argv_help[] = { "download-file", "--help" };

	ELA_ASSERT_INT_EQ(0, ela_download_file_prepare_request(3, argv_ok, &env,
						&request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_FALSE(request.show_help);
	ELA_ASSERT_STR_EQ("https://ela.example/file.bin", request.url);
	ELA_ASSERT_STR_EQ("/tmp/out.bin", request.output_path);
	ELA_ASSERT_TRUE(request.insecure);
	ELA_ASSERT_TRUE(request.verbose);

	ELA_ASSERT_INT_EQ(0, ela_download_file_prepare_request(2, argv_help, &env,
						&request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(request.show_help);
}

static void test_download_file_prepare_request_rejects_invalid_inputs(void)
{
	struct ela_download_file_env env = {0};
	struct ela_download_file_request request;
	char errbuf[256];
	char *argv_missing[] = { "download-file" };
	char *argv_bad_url[] = { "download-file", "ftp://bad", "/tmp/out.bin" };
	char *argv_bad_path[] = { "download-file", "https://ela.example/file.bin", "" };
	char *argv_extra[] = { "download-file", "https://ela.example/file.bin", "/tmp/out.bin", "extra" };

	ELA_ASSERT_INT_EQ(-1, ela_download_file_prepare_request(1, argv_missing, &env,
						&request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "requires a URL") != NULL);

	ELA_ASSERT_INT_EQ(-1, ela_download_file_prepare_request(3, argv_bad_url, &env,
						&request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "http:// or https://") != NULL);

	ELA_ASSERT_INT_EQ(-1, ela_download_file_prepare_request(3, argv_bad_path, &env,
						&request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "non-empty output path") != NULL);

	ELA_ASSERT_INT_EQ(-1, ela_download_file_prepare_request(4, argv_extra, &env,
						&request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Unexpected argument") != NULL);
}

struct fake_download_state {
	int http_rc;
	char http_err[128];
	int stat_rc;
	off_t st_size;
	bool saw_insecure;
	bool saw_verbose;
};

static struct fake_download_state fake_download_state;

static int fake_http_get_to_file(const char *uri, const char *output_path,
				 bool insecure, bool verbose,
				 char *errbuf, size_t errbuf_len)
{
	(void)uri;
	(void)output_path;
	fake_download_state.saw_insecure = insecure;
	fake_download_state.saw_verbose = verbose;
	if (fake_download_state.http_rc < 0 && errbuf && errbuf_len) {
		snprintf(errbuf, errbuf_len, "%s", fake_download_state.http_err);
	}
	return fake_download_state.http_rc;
}

static int fake_stat_success(const char *path, struct stat *st)
{
	(void)path;
	memset(st, 0, sizeof(*st));
	st->st_size = fake_download_state.st_size;
	return fake_download_state.stat_rc;
}

static void test_download_file_run_success_and_summary_formatting(void)
{
	struct ela_download_file_request request = {
		.url = "https://ela.example/file.bin",
		.output_path = "/tmp/out.bin",
		.insecure = true,
		.verbose = true,
	};
	struct ela_download_file_result result;
	struct ela_download_file_ops ops = {
		.http_get_to_file_fn = fake_http_get_to_file,
		.stat_fn = fake_stat_success,
	};
	char errbuf[256];
	char summary[512];

	memset(&fake_download_state, 0, sizeof(fake_download_state));
	fake_download_state.st_size = 25;

	ELA_ASSERT_INT_EQ(0, ela_download_file_run(&request, &ops, &result, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(fake_download_state.saw_insecure);
	ELA_ASSERT_TRUE(fake_download_state.saw_verbose);
	ELA_ASSERT_INT_EQ(25, result.downloaded_bytes);
	ELA_ASSERT_TRUE(result.success);
	ELA_ASSERT_INT_EQ(0, ela_download_file_format_summary(summary, sizeof(summary), &result, &request));
	ELA_ASSERT_TRUE(strstr(summary, "download-file downloaded 25 bytes success=true") != NULL);
	ELA_ASSERT_TRUE(strstr(summary, "url=https://ela.example/file.bin") != NULL);
	ELA_ASSERT_TRUE(strstr(summary, "output=/tmp/out.bin") != NULL);
}

static void test_download_file_run_reports_http_and_stat_failures(void)
{
	struct ela_download_file_request request = {
		.url = "https://ela.example/file.bin",
		.output_path = "/tmp/out.bin",
		.insecure = true,
		.verbose = true,
	};
	struct ela_download_file_result result;
	struct ela_download_file_ops ops = {
		.http_get_to_file_fn = fake_http_get_to_file,
		.stat_fn = fake_stat_success,
	};
	char errbuf[256];
	char summary[512];

	memset(&fake_download_state, 0, sizeof(fake_download_state));
	fake_download_state.http_rc = -1;
	snprintf(fake_download_state.http_err, sizeof(fake_download_state.http_err), "tls failure");
	ELA_ASSERT_INT_EQ(1, ela_download_file_run(&request, &ops, &result, errbuf, sizeof(errbuf)));
	ELA_ASSERT_FALSE(result.success);
	ELA_ASSERT_TRUE(strstr(errbuf, "Failed to download https://ela.example/file.bin to /tmp/out.bin: tls failure") != NULL);
	ELA_ASSERT_INT_EQ(0, ela_download_file_format_summary(summary, sizeof(summary), &result, &request));
	ELA_ASSERT_TRUE(strstr(summary, "download-file downloaded 0 bytes success=false") != NULL);

	memset(&fake_download_state, 0, sizeof(fake_download_state));
	fake_download_state.http_rc = 0;
	fake_download_state.stat_rc = -1;
	errno = ENOENT;
	ELA_ASSERT_INT_EQ(1, ela_download_file_run(&request, &ops, &result, errbuf, sizeof(errbuf)));
	ELA_ASSERT_FALSE(result.success);
	ELA_ASSERT_TRUE(strstr(errbuf, "Downloaded https://ela.example/file.bin but failed to stat /tmp/out.bin") != NULL);
}

int run_linux_download_file_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "download_file_prepare_request_accepts_valid_inputs_and_help", test_download_file_prepare_request_accepts_valid_inputs_and_help },
		{ "download_file_prepare_request_rejects_invalid_inputs", test_download_file_prepare_request_rejects_invalid_inputs },
		{ "download_file_run_success_and_summary_formatting", test_download_file_run_success_and_summary_formatting },
		{ "download_file_run_reports_http_and_stat_failures", test_download_file_run_reports_http_and_stat_failures },
	};

	return ela_run_test_suite("linux_download_file_util",
				  cases, sizeof(cases) / sizeof(cases[0]));
}
