// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/linux/remote_copy_cmd_util.h"

#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <sys/stat.h>

static void test_remote_copy_prepare_request_accepts_flags_and_help(void)
{
	struct ela_remote_copy_env env = {
		.output_tcp = "127.0.0.1:9000",
		.output_http = NULL,
		.output_https = NULL,
		.insecure = true,
		.verbose = true,
	};
	struct ela_remote_copy_request request;
	char errbuf[256];
	char *argv_ok[] = { "remote-copy", "--recursive", "--allow-dev", "--allow-sysfs", "--allow-proc", "--allow-symlinks", "/tmp/file" };
	char *argv_help[] = { "remote-copy", "--help" };

	ELA_ASSERT_INT_EQ(0, ela_remote_copy_prepare_request(7, argv_ok, &env, &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_FALSE(request.show_help);
	ELA_ASSERT_STR_EQ("/tmp/file", request.path);
	ELA_ASSERT_TRUE(request.recursive);
	ELA_ASSERT_TRUE(request.allow_dev);
	ELA_ASSERT_TRUE(request.allow_sysfs);
	ELA_ASSERT_TRUE(request.allow_proc);
	ELA_ASSERT_TRUE(request.allow_symlinks);
	ELA_ASSERT_TRUE(request.insecure);
	ELA_ASSERT_TRUE(request.verbose);
	ELA_ASSERT_STR_EQ("127.0.0.1:9000", request.output_tcp);

	ELA_ASSERT_INT_EQ(0, ela_remote_copy_prepare_request(2, argv_help, &env, &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(request.show_help);
}

static void test_remote_copy_prepare_request_rejects_invalid_inputs(void)
{
	struct ela_remote_copy_env env = {0};
	struct ela_remote_copy_request request;
	char errbuf[256];
	char *argv_missing[] = { "remote-copy" };
	char *argv_relative[] = { "remote-copy", "relative" };
	char *argv_extra[] = { "remote-copy", "/tmp/file", "extra" };

	ELA_ASSERT_INT_EQ(-1, ela_remote_copy_prepare_request(1, argv_missing, &env, &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "requires an absolute file path") != NULL);

	ELA_ASSERT_INT_EQ(-1, ela_remote_copy_prepare_request(2, argv_relative, &env, &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "absolute file path") != NULL);

	ELA_ASSERT_INT_EQ(-1, ela_remote_copy_prepare_request(3, argv_extra, &env, &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Unexpected argument") != NULL);

	env.output_http = "http://ela.example/upload";
	env.output_https = "https://ela.example/upload";
	ELA_ASSERT_INT_EQ(-1, ela_remote_copy_prepare_request(2, argv_relative, &env, &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "absolute file path") != NULL);
}

static void test_remote_copy_validate_request_accepts_valid_http_and_tcp_cases(void)
{
	char errbuf[256];

	ELA_ASSERT_INT_EQ(0, ela_remote_copy_validate_request("/tmp/file", NULL, NULL, "https://ela.example/upload",
							       S_IFREG, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(0, ela_remote_copy_validate_request("/tmp/file", "127.0.0.1:9000", NULL, NULL,
							       S_IFREG, errbuf, sizeof(errbuf)));
}

static void test_remote_copy_validate_request_rejects_invalid_combinations(void)
{
	char errbuf[256];

	ELA_ASSERT_INT_EQ(-1, ela_remote_copy_validate_request("relative", NULL, "http://ela", NULL,
								S_IFREG, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "absolute") != NULL);
	ELA_ASSERT_INT_EQ(-1, ela_remote_copy_validate_request("/tmp/dir", "127.0.0.1:9000", NULL, NULL,
								S_IFDIR, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Directory uploads require --output-http") != NULL);
	ELA_ASSERT_INT_EQ(-1, ela_remote_copy_validate_request("/tmp/link", "127.0.0.1:9000", NULL, NULL,
								S_IFLNK, errbuf, sizeof(errbuf)));
}

static void test_remote_copy_path_and_errno_helpers(void)
{
	char buf[256];

	ELA_ASSERT_INT_EQ(0, ela_remote_copy_format_errno_message(buf, sizeof(buf), "Cannot stat %s: %s\n", "/tmp/missing", ENOENT));
	ELA_ASSERT_TRUE(strstr(buf, "/tmp/missing") != NULL);
	ELA_ASSERT_TRUE(strstr(buf, "No such file") != NULL);
	ELA_ASSERT_INT_EQ(0, ela_remote_copy_join_child_path("/tmp/root", "child", buf, sizeof(buf)));
	ELA_ASSERT_STR_EQ("/tmp/root/child", buf);
	ELA_ASSERT_TRUE(ela_remote_copy_should_recurse(S_IFDIR, true));
	ELA_ASSERT_FALSE(ela_remote_copy_should_recurse(S_IFDIR, false));
	ELA_ASSERT_FALSE(ela_remote_copy_should_recurse(S_IFREG, true));
}

struct fake_remote_copy_exec_state {
	int stat_rc;
	mode_t mode;
	int validate_rc;
	bool path_allowed;
	bool copyable_file;
	int send_tcp_rc;
	int upload_http_rc;
	int format_summary_rc;
	int write_stderr_rc;
	uint64_t upload_copied_files;
	int send_tcp_calls;
	int upload_http_calls;
	int write_stderr_calls;
	bool last_recursive;
	bool last_allow_symlinks;
	char last_output_uri[256];
	char last_output_tcp[128];
	char last_summary[256];
	char validate_errbuf[256];
};

static struct fake_remote_copy_exec_state exec_state;

static int fake_stat_fn(const char *path, struct stat *st)
{
	(void)path;
	if (exec_state.stat_rc != 0)
		return exec_state.stat_rc;
	memset(st, 0, sizeof(*st));
	st->st_mode = exec_state.mode;
	return 0;
}

static int fake_validate_request_fn(const char *path,
				    const char *output_tcp,
				    const char *output_http,
				    const char *output_https,
				    mode_t mode,
				    char *errbuf,
				    size_t errbuf_len)
{
	(void)path;
	(void)output_http;
	(void)output_https;
	(void)mode;
	if (output_tcp)
		snprintf(exec_state.last_output_tcp, sizeof(exec_state.last_output_tcp), "%s", output_tcp);
	if (exec_state.validate_rc != 0 && errbuf && errbuf_len)
		snprintf(errbuf, errbuf_len, "%s", exec_state.validate_errbuf);
	return exec_state.validate_rc;
}

static bool fake_path_is_allowed_fn(const char *path, bool allow_dev, bool allow_sysfs, bool allow_proc)
{
	(void)path;
	(void)allow_dev;
	(void)allow_sysfs;
	(void)allow_proc;
	return exec_state.path_allowed;
}

static bool fake_stat_is_copyable_file_fn(const struct stat *st)
{
	(void)st;
	return exec_state.copyable_file;
}

static int fake_send_file_to_tcp_fn(const char *path, const char *output_tcp, bool verbose)
{
	(void)path;
	(void)verbose;
	exec_state.send_tcp_calls++;
	snprintf(exec_state.last_output_tcp, sizeof(exec_state.last_output_tcp), "%s", output_tcp ? output_tcp : "");
	return exec_state.send_tcp_rc;
}

static int fake_upload_path_http_fn(const char *path,
				    const char *output_uri,
				    bool insecure,
				    bool verbose,
				    bool recursive,
				    bool allow_dev,
				    bool allow_sysfs,
				    bool allow_proc,
				    bool allow_symlinks,
				    uint64_t *copied_files)
{
	(void)path;
	(void)insecure;
	(void)verbose;
	(void)allow_dev;
	(void)allow_sysfs;
	(void)allow_proc;
	exec_state.upload_http_calls++;
	exec_state.last_recursive = recursive;
	exec_state.last_allow_symlinks = allow_symlinks;
	snprintf(exec_state.last_output_uri, sizeof(exec_state.last_output_uri), "%s", output_uri ? output_uri : "");
	if (copied_files)
		*copied_files = exec_state.upload_copied_files;
	return exec_state.upload_http_rc;
}

static int fake_format_summary_fn(char *buf, size_t buf_sz, const char *path, uint64_t copied_files)
{
	if (exec_state.format_summary_rc != 0)
		return exec_state.format_summary_rc;
	snprintf(exec_state.last_summary, sizeof(exec_state.last_summary), "summary %s %" PRIu64 "\n", path, copied_files);
	snprintf(buf, buf_sz, "%s", exec_state.last_summary);
	return 0;
}

static int fake_write_stderr_fn(const char *message)
{
	exec_state.write_stderr_calls++;
	if (exec_state.write_stderr_rc != 0)
		return exec_state.write_stderr_rc;
	snprintf(exec_state.last_summary, sizeof(exec_state.last_summary), "%s", message ? message : "");
	return 0;
}

static void reset_exec_state(void)
{
	memset(&exec_state, 0, sizeof(exec_state));
	exec_state.mode = S_IFREG;
	exec_state.path_allowed = true;
	exec_state.copyable_file = true;
	exec_state.upload_copied_files = 3;
}

static void test_remote_copy_execute_dispatches_tcp_and_http_and_summary(void)
{
	struct ela_remote_copy_request request = {
		.path = "/tmp/file",
		.output_tcp = "127.0.0.1:9000",
		.verbose = true,
	};
	struct ela_remote_copy_execution_result result;
	struct ela_remote_copy_execution_ops ops = {
		.stat_fn = fake_stat_fn,
		.validate_request_fn = fake_validate_request_fn,
		.path_is_allowed_fn = fake_path_is_allowed_fn,
		.stat_is_copyable_file_fn = fake_stat_is_copyable_file_fn,
		.send_file_to_tcp_fn = fake_send_file_to_tcp_fn,
		.upload_path_http_fn = fake_upload_path_http_fn,
		.format_summary_fn = fake_format_summary_fn,
		.write_stderr_fn = fake_write_stderr_fn,
	};
	char errbuf[256];

	reset_exec_state();
	ELA_ASSERT_INT_EQ(0, ela_remote_copy_execute(&request, &ops, &result, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(1, exec_state.send_tcp_calls);
	ELA_ASSERT_INT_EQ(0, exec_state.upload_http_calls);
	ELA_ASSERT_INT_EQ(1, (int)result.copied_files);
	ELA_ASSERT_TRUE(result.emitted_summary);

	reset_exec_state();
	request.output_tcp = NULL;
	request.output_http = "http://ela.example/upload";
	request.output_uri = request.output_http;
	request.recursive = true;
	request.allow_symlinks = true;
	ELA_ASSERT_INT_EQ(0, ela_remote_copy_execute(&request, &ops, &result, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(0, exec_state.send_tcp_calls);
	ELA_ASSERT_INT_EQ(1, exec_state.upload_http_calls);
	ELA_ASSERT_TRUE(exec_state.last_recursive);
	ELA_ASSERT_TRUE(exec_state.last_allow_symlinks);
	ELA_ASSERT_STR_EQ("http://ela.example/upload", exec_state.last_output_uri);
	ELA_ASSERT_INT_EQ(3, (int)result.copied_files);
	ELA_ASSERT_TRUE(result.emitted_summary);
}

static void test_remote_copy_execute_reports_validation_and_dispatch_failures(void)
{
	struct ela_remote_copy_request request = {
		.path = "/tmp/file",
		.output_tcp = "127.0.0.1:9000",
	};
	struct ela_remote_copy_execution_result result;
	struct ela_remote_copy_execution_ops ops = {
		.stat_fn = fake_stat_fn,
		.validate_request_fn = fake_validate_request_fn,
		.path_is_allowed_fn = fake_path_is_allowed_fn,
		.stat_is_copyable_file_fn = fake_stat_is_copyable_file_fn,
		.send_file_to_tcp_fn = fake_send_file_to_tcp_fn,
		.upload_path_http_fn = fake_upload_path_http_fn,
		.format_summary_fn = fake_format_summary_fn,
		.write_stderr_fn = fake_write_stderr_fn,
	};
	char errbuf[256];

	reset_exec_state();
	exec_state.validate_rc = -1;
	snprintf(exec_state.validate_errbuf, sizeof(exec_state.validate_errbuf), "bad request");
	ELA_ASSERT_INT_EQ(2, ela_remote_copy_execute(&request, &ops, &result, errbuf, sizeof(errbuf)));
	ELA_ASSERT_STR_EQ("bad request", errbuf);

	reset_exec_state();
	exec_state.path_allowed = false;
	ELA_ASSERT_INT_EQ(2, ela_remote_copy_execute(&request, &ops, &result, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Refusing to copy restricted path") != NULL);

	reset_exec_state();
	exec_state.copyable_file = false;
	ELA_ASSERT_INT_EQ(1, ela_remote_copy_execute(&request, &ops, &result, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "supported file for TCP transfer") != NULL);

	reset_exec_state();
	exec_state.send_tcp_rc = -1;
	ELA_ASSERT_INT_EQ(1, ela_remote_copy_execute(&request, &ops, &result, errbuf, sizeof(errbuf)));

	reset_exec_state();
	request.output_tcp = NULL;
	request.output_http = "http://ela.example/upload";
	request.output_uri = request.output_http;
	exec_state.upload_http_rc = -1;
	ELA_ASSERT_INT_EQ(1, ela_remote_copy_execute(&request, &ops, &result, errbuf, sizeof(errbuf)));
}

int run_remote_copy_cmd_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "remote_copy_prepare_request_accepts_flags_and_help", test_remote_copy_prepare_request_accepts_flags_and_help },
		{ "remote_copy_prepare_request_rejects_invalid_inputs", test_remote_copy_prepare_request_rejects_invalid_inputs },
		{ "remote_copy_validate_request_accepts_valid_http_and_tcp_cases", test_remote_copy_validate_request_accepts_valid_http_and_tcp_cases },
		{ "remote_copy_validate_request_rejects_invalid_combinations", test_remote_copy_validate_request_rejects_invalid_combinations },
		{ "remote_copy_path_and_errno_helpers", test_remote_copy_path_and_errno_helpers },
		{ "remote_copy_execute_dispatches_tcp_and_http_and_summary", test_remote_copy_execute_dispatches_tcp_and_http_and_summary },
		{ "remote_copy_execute_reports_validation_and_dispatch_failures", test_remote_copy_execute_reports_validation_and_dispatch_failures },
	};

	return ela_run_test_suite("remote_copy_cmd_util", cases, sizeof(cases) / sizeof(cases[0]));
}
