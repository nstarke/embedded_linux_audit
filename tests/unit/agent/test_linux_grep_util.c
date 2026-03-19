// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../../../agent/linux/linux_grep_util.h"
#include "test_harness.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static int fake_parse_http_rc;
static const char *fake_parsed_http;
static const char *fake_parsed_https;
static char fake_parse_http_err[128];
static int fake_connect_tcp_rc;
static char fake_last_tcp_target[128];
static int fake_prepare_lstat_rc;
static mode_t fake_prepare_lstat_mode;

static int fake_parse_http_output_uri(const char *uri,
				      const char **output_http,
				      const char **output_https,
				      char *errbuf,
				      size_t errbuf_len)
{
	(void)uri;
	if (output_http)
		*output_http = fake_parsed_http;
	if (output_https)
		*output_https = fake_parsed_https;
	if (fake_parse_http_rc < 0 && errbuf && errbuf_len)
		snprintf(errbuf, errbuf_len, "%s", fake_parse_http_err);
	return fake_parse_http_rc;
}

static int fake_connect_tcp_ipv4(const char *spec)
{
	snprintf(fake_last_tcp_target, sizeof(fake_last_tcp_target), "%s", spec ? spec : "");
	return fake_connect_tcp_rc;
}

static int fake_prepare_lstat(const char *path, struct stat *st)
{
	(void)path;
	if (fake_prepare_lstat_rc != 0)
		return fake_prepare_lstat_rc;
	memset(st, 0, sizeof(*st));
	st->st_mode = fake_prepare_lstat_mode;
	return 0;
}

static void reset_prepare_fakes(void)
{
	fake_parse_http_rc = 0;
	fake_parsed_http = NULL;
	fake_parsed_https = NULL;
	fake_parse_http_err[0] = '\0';
	fake_connect_tcp_rc = -1;
	fake_last_tcp_target[0] = '\0';
	fake_prepare_lstat_rc = 0;
	fake_prepare_lstat_mode = S_IFDIR | 0755;
}

static void test_grep_prepare_request_accepts_valid_inputs_and_help(void)
{
	struct ela_grep_request request;
	struct ela_grep_prepare_ops ops = {
		.parse_http_output_uri_fn = fake_parse_http_output_uri,
		.connect_tcp_ipv4_fn = fake_connect_tcp_ipv4,
		.lstat_fn = fake_prepare_lstat,
	};
	struct ela_grep_env env = {
		.output_http = "http://ela.example/upload",
		.output_https = NULL,
		.output_tcp = NULL,
		.insecure = true,
	};
	char errbuf[256];
	char *argv_http[] = { "grep", "--search", "needle", "--path", "/tmp/test", "--recursive" };
	char *argv_help[] = { "grep", "--help" };

	reset_prepare_fakes();
	fake_parsed_http = env.output_http;
	ELA_ASSERT_INT_EQ(0, ela_grep_prepare_request(6, argv_http, &env, &ops,
					      &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_FALSE(request.show_help);
	ELA_ASSERT_STR_EQ("needle", request.search);
	ELA_ASSERT_STR_EQ("/tmp/test", request.dir_path);
	ELA_ASSERT_STR_EQ("http://ela.example/upload", request.output_uri);
	ELA_ASSERT_TRUE(request.recursive);
	ELA_ASSERT_TRUE(request.insecure);
	ELA_ASSERT_INT_EQ(-1, request.output_sock);

	reset_prepare_fakes();
	env.output_http = "https://ela.example/upload";
	fake_parsed_https = env.output_http;
	ELA_ASSERT_INT_EQ(0, ela_grep_prepare_request(6, argv_http, &env, &ops,
					      &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_STR_EQ("https://ela.example/upload", request.output_uri);

	reset_prepare_fakes();
	env.output_http = NULL;
	ELA_ASSERT_INT_EQ(0, ela_grep_prepare_request(2, argv_help, &env, &ops,
					      &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(request.show_help);
}

static void test_grep_prepare_request_rejects_invalid_inputs(void)
{
	struct ela_grep_request request;
	struct ela_grep_prepare_ops ops = {
		.parse_http_output_uri_fn = fake_parse_http_output_uri,
		.connect_tcp_ipv4_fn = fake_connect_tcp_ipv4,
		.lstat_fn = fake_prepare_lstat,
	};
	struct ela_grep_env env = {
		.output_http = NULL,
		.output_https = NULL,
		.output_tcp = NULL,
		.insecure = false,
	};
	char errbuf[256];
	char *argv_missing_search[] = { "grep", "--path", "/tmp/test" };
	char *argv_relative[] = { "grep", "--search", "needle", "--path", "tmp/test" };
	char *argv_extra[] = { "grep", "--search", "needle", "--path", "/tmp/test", "extra" };
	char *argv_ok[] = { "grep", "--search", "needle", "--path", "/tmp/test" };

	reset_prepare_fakes();
	ELA_ASSERT_INT_EQ(2, ela_grep_prepare_request(3, argv_missing_search, &env, &ops,
					      &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "grep requires --search") != NULL);

	reset_prepare_fakes();
	ELA_ASSERT_INT_EQ(2, ela_grep_prepare_request(5, argv_relative, &env, &ops,
					      &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "absolute directory path") != NULL);

	reset_prepare_fakes();
	ELA_ASSERT_INT_EQ(2, ela_grep_prepare_request(6, argv_extra, &env, &ops,
					      &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Unexpected argument") != NULL);

	reset_prepare_fakes();
	env.output_http = "ftp://bad";
	snprintf(fake_parse_http_err, sizeof(fake_parse_http_err), "invalid http output");
	fake_parse_http_rc = -1;
	ELA_ASSERT_INT_EQ(2, ela_grep_prepare_request(5, argv_ok, &env, &ops,
					      &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_STR_EQ("invalid http output", errbuf);

	reset_prepare_fakes();
	env.output_http = "http://ela.example/upload";
	env.output_https = "https://ela.example/upload";
	fake_parsed_http = env.output_http;
	ELA_ASSERT_INT_EQ(2, ela_grep_prepare_request(5, argv_ok, &env, &ops,
					      &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Use only one of --output-http or --output-https") != NULL);

	reset_prepare_fakes();
	env.output_http = NULL;
	env.output_https = NULL;
	env.output_tcp = "127.0.0.1:9000";
	fake_connect_tcp_rc = -1;
	ELA_ASSERT_INT_EQ(2, ela_grep_prepare_request(5, argv_ok, &env, &ops,
					      &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Invalid/failed output target") != NULL);
	ELA_ASSERT_STR_EQ("127.0.0.1:9000", fake_last_tcp_target);

	reset_prepare_fakes();
	env.output_tcp = NULL;
	fake_prepare_lstat_rc = -1;
	errno = ENOENT;
	ELA_ASSERT_INT_EQ(1, ela_grep_prepare_request(5, argv_ok, &env, &ops,
					      &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Cannot stat /tmp/test") != NULL);

	reset_prepare_fakes();
	fake_prepare_lstat_mode = S_IFREG | 0644;
	ELA_ASSERT_INT_EQ(2, ela_grep_prepare_request(5, argv_ok, &env, &ops,
					      &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "grep requires a directory path") != NULL);
}

struct fake_run_state {
	int format_calls;
	int send_calls;
	int write_calls;
	int build_upload_uri_calls;
	int http_post_calls;
	int log_calls;
	int close_calls;
	int send_rc;
	int write_rc;
	int format_rc;
	int http_post_rc;
	int log_rc;
	char fopen_fail_path[PATH_MAX];
	char upload_base_uri[256];
	char upload_type[64];
	char upload_file_path[PATH_MAX];
	char upload_uri[256];
	char sent_data[1024];
	size_t sent_data_len;
	char stdout_data[1024];
	size_t stdout_data_len;
	char http_body[1024];
	size_t http_body_len;
	char http_content_type[128];
	char log_message[512];
};

static struct fake_run_state fake_run_state;

static void reset_run_state(void)
{
	memset(&fake_run_state, 0, sizeof(fake_run_state));
	fake_run_state.upload_uri[0] = '\0';
}

static int append_text(char *dst, size_t *dst_len, size_t cap, const char *src, size_t src_len)
{
	if (*dst_len + src_len >= cap)
		return -1;
	memcpy(dst + *dst_len, src, src_len);
	*dst_len += src_len;
	dst[*dst_len] = '\0';
	return 0;
}

static FILE *fake_fopen(const char *path, const char *mode)
{
	if (fake_run_state.fopen_fail_path[0] != '\0' &&
	    strcmp(path, fake_run_state.fopen_fail_path) == 0) {
		errno = EACCES;
		return NULL;
	}
	return fopen(path, mode);
}

static int fake_format_grep_match_record(struct output_buffer *out,
					 const char *path,
					 unsigned long line_no,
					 const char *line)
{
	int n;

	fake_run_state.format_calls++;
	if (fake_run_state.format_rc != 0)
		return fake_run_state.format_rc;

	n = snprintf(NULL, 0, "%s:%lu:%s", path, line_no, line);
	if (n < 0)
		return -1;
	out->data = malloc((size_t)n + 1);
	if (!out->data)
		return -1;
	out->len = (size_t)n;
	snprintf(out->data, out->len + 1, "%s:%lu:%s", path, line_no, line);
	return 0;
}

static int fake_send_all(int sock, const uint8_t *buf, size_t len)
{
	(void)sock;
	fake_run_state.send_calls++;
	if (fake_run_state.send_rc != 0)
		return fake_run_state.send_rc;
	if (len >= sizeof(fake_run_state.sent_data))
		return -1;
	memcpy(fake_run_state.sent_data, buf, len);
	fake_run_state.sent_data[len] = '\0';
	fake_run_state.sent_data_len = len;
	return 0;
}

static int fake_write_stdout(const char *data, size_t len)
{
	fake_run_state.write_calls++;
	if (fake_run_state.write_rc != 0)
		return fake_run_state.write_rc;
	return append_text(fake_run_state.stdout_data, &fake_run_state.stdout_data_len,
			   sizeof(fake_run_state.stdout_data), data, len);
}

static char *fake_build_upload_uri(const char *base_uri, const char *upload_type, const char *file_path)
{
	fake_run_state.build_upload_uri_calls++;
	snprintf(fake_run_state.upload_base_uri, sizeof(fake_run_state.upload_base_uri), "%s", base_uri ? base_uri : "");
	snprintf(fake_run_state.upload_type, sizeof(fake_run_state.upload_type), "%s", upload_type ? upload_type : "");
	snprintf(fake_run_state.upload_file_path, sizeof(fake_run_state.upload_file_path), "%s", file_path ? file_path : "");
	if (!fake_run_state.upload_uri[0])
		snprintf(fake_run_state.upload_uri, sizeof(fake_run_state.upload_uri), "%s/%s", base_uri, upload_type);
	return strdup(fake_run_state.upload_uri);
}

static int fake_http_post(const char *uri, const uint8_t *data, size_t len,
			  const char *content_type, bool insecure, bool verbose,
			  char *errbuf, size_t errbuf_len)
{
	(void)insecure;
	(void)verbose;
	fake_run_state.http_post_calls++;
	snprintf(fake_run_state.upload_uri, sizeof(fake_run_state.upload_uri), "%s", uri ? uri : "");
	snprintf(fake_run_state.http_content_type, sizeof(fake_run_state.http_content_type), "%s",
		 content_type ? content_type : "");
	if (len < sizeof(fake_run_state.http_body)) {
		memcpy(fake_run_state.http_body, data, len);
		fake_run_state.http_body[len] = '\0';
		fake_run_state.http_body_len = len;
	}
	if (fake_run_state.http_post_rc != 0 && errbuf && errbuf_len)
		snprintf(errbuf, errbuf_len, "upload failed");
	return fake_run_state.http_post_rc;
}

static int fake_http_post_log_message(const char *base_uri, const char *message,
				      bool insecure, bool verbose,
				      char *errbuf, size_t errbuf_len)
{
	(void)base_uri;
	(void)insecure;
	(void)verbose;
	fake_run_state.log_calls++;
	snprintf(fake_run_state.log_message, sizeof(fake_run_state.log_message), "%s", message ? message : "");
	if (fake_run_state.log_rc != 0 && errbuf && errbuf_len)
		snprintf(errbuf, errbuf_len, "log post failed");
	return fake_run_state.log_rc;
}

static int fake_close(int fd)
{
	(void)fd;
	fake_run_state.close_calls++;
	return 0;
}

static void write_file(const char *path, const char *content)
{
	FILE *fp = fopen(path, "w");

	ELA_ASSERT_TRUE(fp != NULL);
	ELA_ASSERT_TRUE(fputs(content, fp) >= 0);
	ELA_ASSERT_INT_EQ(0, fclose(fp));
}

static void cleanup_test_tree(const char *root)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/root.txt", root);
	unlink(path);
	snprintf(path, sizeof(path), "%s/unreadable.txt", root);
	unlink(path);
	snprintf(path, sizeof(path), "%s/sub/child.txt", root);
	unlink(path);
	snprintf(path, sizeof(path), "%s/sub", root);
	rmdir(path);
	rmdir(root);
}

static void join_path(char *buf, size_t buf_len, const char *dir, const char *name)
{
	size_t dir_len = strlen(dir);
	size_t name_len = strlen(name);

	ELA_ASSERT_TRUE(dir_len + 1 + name_len < buf_len);
	memcpy(buf, dir, dir_len);
	buf[dir_len] = '/';
	memcpy(buf + dir_len + 1, name, name_len);
	buf[dir_len + 1 + name_len] = '\0';
}

static void create_test_tree(char *root_buf, size_t root_buf_len,
			     char *root_file_buf, size_t root_file_buf_len,
			     char *child_file_buf, size_t child_file_buf_len)
{
	char template[] = "/tmp/ela-grep-unit-XXXXXX";
	char *created_root;
	char subdir[PATH_MAX];

	created_root = mkdtemp(template);
	ELA_ASSERT_TRUE(created_root != NULL);
	snprintf(root_buf, root_buf_len, "%s", created_root);

	join_path(root_file_buf, root_file_buf_len, root_buf, "root.txt");
	write_file(root_file_buf, "first line\nneedle root\n");

	join_path(subdir, sizeof(subdir), root_buf, "sub");
	ELA_ASSERT_INT_EQ(0, mkdir(subdir, 0700));

	join_path(child_file_buf, child_file_buf_len, subdir, "child.txt");
	write_file(child_file_buf, "needle child\n");
}

static struct ela_grep_run_ops fake_run_ops = {
	.fopen_fn = fake_fopen,
	.getline_fn = getline,
	.fclose_fn = fclose,
	.lstat_fn = lstat,
	.format_grep_match_record_fn = fake_format_grep_match_record,
	.send_all_fn = fake_send_all,
	.append_output_fn = output_buffer_append_len,
	.write_stdout_fn = fake_write_stdout,
	.build_upload_uri_fn = fake_build_upload_uri,
	.http_post_fn = fake_http_post,
	.http_post_log_message_fn = fake_http_post_log_message,
	.close_fn = fake_close,
};

static void test_grep_run_honors_recursive_policy_and_stdout_branch(void)
{
	struct ela_grep_request request = {
		.search = "needle",
		.recursive = false,
		.insecure = false,
		.output_sock = -1,
	};
	char root[PATH_MAX];
	char root_file[PATH_MAX];
	char child_file[PATH_MAX];

	create_test_tree(root, sizeof(root), root_file, sizeof(root_file), child_file, sizeof(child_file));
	request.dir_path = root;

	reset_run_state();
	ELA_ASSERT_INT_EQ(0, ela_grep_run(&request, &fake_run_ops, NULL, 0));
	ELA_ASSERT_INT_EQ(1, fake_run_state.format_calls);
	ELA_ASSERT_INT_EQ(1, fake_run_state.write_calls);
	ELA_ASSERT_TRUE(strstr(fake_run_state.stdout_data, root_file) != NULL);
	ELA_ASSERT_TRUE(strstr(fake_run_state.stdout_data, child_file) == NULL);

	request.recursive = true;
	reset_run_state();
	ELA_ASSERT_INT_EQ(0, ela_grep_run(&request, &fake_run_ops, NULL, 0));
	ELA_ASSERT_INT_EQ(2, fake_run_state.format_calls);
	ELA_ASSERT_TRUE(strstr(fake_run_state.stdout_data, root_file) != NULL);
	ELA_ASSERT_TRUE(strstr(fake_run_state.stdout_data, child_file) != NULL);

	cleanup_test_tree(root);
}

static void test_grep_run_uses_tcp_and_http_output_branches(void)
{
	struct ela_grep_request request = {
		.search = "needle",
		.output_uri = NULL,
		.recursive = false,
		.insecure = true,
		.output_sock = 9,
	};
	char root[PATH_MAX];
	char root_file[PATH_MAX];
	char child_file[PATH_MAX];
	char errbuf[256];

	create_test_tree(root, sizeof(root), root_file, sizeof(root_file), child_file, sizeof(child_file));
	request.dir_path = root;

	reset_run_state();
	ELA_ASSERT_INT_EQ(0, ela_grep_run(&request, &fake_run_ops, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(1, fake_run_state.send_calls);
	ELA_ASSERT_INT_EQ(1, fake_run_state.write_calls);
	ELA_ASSERT_INT_EQ(0, fake_run_state.http_post_calls);
	ELA_ASSERT_TRUE(strstr(fake_run_state.sent_data, root_file) != NULL);
	ELA_ASSERT_TRUE(strstr(fake_run_state.stdout_data, root_file) != NULL);
	ELA_ASSERT_INT_EQ(1, fake_run_state.close_calls);

	request.output_sock = -1;
	request.output_uri = "https://ela.example/upload";
	reset_run_state();
	snprintf(fake_run_state.upload_uri, sizeof(fake_run_state.upload_uri),
		 "https://ela.example/upload/grep");
	ELA_ASSERT_INT_EQ(0, ela_grep_run(&request, &fake_run_ops, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(1, fake_run_state.build_upload_uri_calls);
	ELA_ASSERT_INT_EQ(1, fake_run_state.http_post_calls);
	ELA_ASSERT_STR_EQ("https://ela.example/upload", fake_run_state.upload_base_uri);
	ELA_ASSERT_STR_EQ("grep", fake_run_state.upload_type);
	ELA_ASSERT_STR_EQ(root, fake_run_state.upload_file_path);
	ELA_ASSERT_STR_EQ("text/plain; charset=utf-8", fake_run_state.http_content_type);
	ELA_ASSERT_TRUE(strstr(fake_run_state.http_body, root_file) != NULL);

	cleanup_test_tree(root);
}

static void test_grep_run_reports_file_read_errors_and_continues(void)
{
	struct ela_grep_request request = {
		.search = "needle",
		.recursive = false,
		.insecure = true,
		.output_sock = -1,
		.output_uri = "https://ela.example/upload",
	};
	char root[PATH_MAX];
	char root_file[PATH_MAX];
	char child_file[PATH_MAX];
	char unreadable_file[PATH_MAX];
	char errbuf[256];

	create_test_tree(root, sizeof(root), root_file, sizeof(root_file), child_file, sizeof(child_file));
	join_path(unreadable_file, sizeof(unreadable_file), root, "unreadable.txt");
	write_file(unreadable_file, "needle hidden\n");
	request.dir_path = root;

	reset_run_state();
	snprintf(fake_run_state.upload_uri, sizeof(fake_run_state.upload_uri),
		 "https://ela.example/upload/grep");
	snprintf(fake_run_state.fopen_fail_path, sizeof(fake_run_state.fopen_fail_path), "%s", unreadable_file);
	ELA_ASSERT_INT_EQ(0, ela_grep_run(&request, &fake_run_ops, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(1, fake_run_state.log_calls);
	ELA_ASSERT_TRUE(strstr(fake_run_state.log_message, "Cannot read file") != NULL);
	ELA_ASSERT_TRUE(strstr(fake_run_state.log_message, unreadable_file) != NULL);
	ELA_ASSERT_INT_EQ(1, fake_run_state.http_post_calls);
	ELA_ASSERT_TRUE(strstr(fake_run_state.http_body, root_file) != NULL);
	ELA_ASSERT_TRUE(strstr(fake_run_state.http_body, unreadable_file) == NULL);

	cleanup_test_tree(root);
}

int run_linux_grep_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "grep_prepare_request_accepts_valid_inputs_and_help", test_grep_prepare_request_accepts_valid_inputs_and_help },
		{ "grep_prepare_request_rejects_invalid_inputs", test_grep_prepare_request_rejects_invalid_inputs },
		{ "grep_run_honors_recursive_policy_and_stdout_branch", test_grep_run_honors_recursive_policy_and_stdout_branch },
		{ "grep_run_uses_tcp_and_http_output_branches", test_grep_run_uses_tcp_and_http_output_branches },
		{ "grep_run_reports_file_read_errors_and_continues", test_grep_run_reports_file_read_errors_and_continues },
	};

	return ela_run_test_suite("linux_grep_util",
				  cases, sizeof(cases) / sizeof(cases[0]));
}
