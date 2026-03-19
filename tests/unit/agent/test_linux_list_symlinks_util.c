// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../../../agent/linux/linux_list_symlinks_util.h"
#include "test_harness.h"

#include <errno.h>
#include <limits.h>
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

static void test_list_symlinks_prepare_request_accepts_defaults_and_help(void)
{
	struct ela_list_symlinks_request request;
	struct ela_list_symlinks_prepare_ops ops = {
		.parse_http_output_uri_fn = fake_parse_http_output_uri,
		.connect_tcp_ipv4_fn = fake_connect_tcp_ipv4,
		.lstat_fn = fake_prepare_lstat,
	};
	struct ela_list_symlinks_env env = {
		.output_format = "json",
		.output_http = "http://ela.example/upload",
		.insecure = true,
	};
	char errbuf[256];
	char *argv_full[] = { "list-symlinks", "--recursive", "/tmp/tree" };
	char *argv_help[] = { "list-symlinks", "--help" };
	char *argv_default[] = { "list-symlinks" };

	reset_prepare_fakes();
	fake_parsed_http = env.output_http;
	ELA_ASSERT_INT_EQ(0, ela_list_symlinks_prepare_request(3, argv_full, &env, &ops,
					       &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_FALSE(request.show_help);
	ELA_ASSERT_TRUE(request.recursive);
	ELA_ASSERT_STR_EQ("/tmp/tree", request.dir_path);
	ELA_ASSERT_STR_EQ("json", request.output_format);
	ELA_ASSERT_STR_EQ("http://ela.example/upload", request.output_uri);
	ELA_ASSERT_TRUE(request.insecure);

	reset_prepare_fakes();
	env.output_format = NULL;
	ELA_ASSERT_INT_EQ(0, ela_list_symlinks_prepare_request(1, argv_default, &env, &ops,
					       &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_STR_EQ("/", request.dir_path);
	ELA_ASSERT_STR_EQ("txt", request.output_format);

	reset_prepare_fakes();
	ELA_ASSERT_INT_EQ(0, ela_list_symlinks_prepare_request(2, argv_help, &env, &ops,
					       &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(request.show_help);
}

static void test_list_symlinks_prepare_request_rejects_invalid_inputs(void)
{
	struct ela_list_symlinks_request request;
	struct ela_list_symlinks_prepare_ops ops = {
		.parse_http_output_uri_fn = fake_parse_http_output_uri,
		.connect_tcp_ipv4_fn = fake_connect_tcp_ipv4,
		.lstat_fn = fake_prepare_lstat,
	};
	struct ela_list_symlinks_env env = {0};
	char errbuf[256];
	char *argv_relative[] = { "list-symlinks", "tmp/tree" };
	char *argv_extra[] = { "list-symlinks", "/tmp/tree", "extra" };
	char *argv_ok[] = { "list-symlinks", "/tmp/tree" };

	reset_prepare_fakes();
	ELA_ASSERT_INT_EQ(2, ela_list_symlinks_prepare_request(2, argv_relative, &env, &ops,
					       &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "absolute directory path") != NULL);

	reset_prepare_fakes();
	ELA_ASSERT_INT_EQ(2, ela_list_symlinks_prepare_request(3, argv_extra, &env, &ops,
					       &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Unexpected argument") != NULL);

	reset_prepare_fakes();
	env.output_format = "yaml";
	ELA_ASSERT_INT_EQ(2, ela_list_symlinks_prepare_request(2, argv_ok, &env, &ops,
					       &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Invalid output format") != NULL);

	reset_prepare_fakes();
	env.output_format = "txt";
	env.output_http = "ftp://bad";
	snprintf(fake_parse_http_err, sizeof(fake_parse_http_err), "invalid http output");
	fake_parse_http_rc = -1;
	ELA_ASSERT_INT_EQ(2, ela_list_symlinks_prepare_request(2, argv_ok, &env, &ops,
					       &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_STR_EQ("invalid http output", errbuf);

	reset_prepare_fakes();
	env.output_http = "http://ela.example/upload";
	env.output_https = "https://ela.example/upload";
	fake_parsed_http = env.output_http;
	ELA_ASSERT_INT_EQ(2, ela_list_symlinks_prepare_request(2, argv_ok, &env, &ops,
					       &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Use only one of --output-http or --output-https") != NULL);

	reset_prepare_fakes();
	env.output_http = NULL;
	env.output_https = NULL;
	env.output_tcp = "127.0.0.1:9000";
	ELA_ASSERT_INT_EQ(2, ela_list_symlinks_prepare_request(2, argv_ok, &env, &ops,
					       &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Invalid/failed output target") != NULL);
	ELA_ASSERT_STR_EQ("127.0.0.1:9000", fake_last_tcp_target);

	reset_prepare_fakes();
	env.output_tcp = NULL;
	fake_prepare_lstat_rc = -1;
	errno = ENOENT;
	ELA_ASSERT_INT_EQ(1, ela_list_symlinks_prepare_request(2, argv_ok, &env, &ops,
					       &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Cannot stat /tmp/tree") != NULL);

	reset_prepare_fakes();
	fake_prepare_lstat_mode = S_IFREG | 0644;
	ELA_ASSERT_INT_EQ(2, ela_list_symlinks_prepare_request(2, argv_ok, &env, &ops,
					       &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "list-symlinks requires a directory path") != NULL);
}

struct fake_run_state {
	int format_calls;
	int send_calls;
	int write_calls;
	int build_upload_uri_calls;
	int http_post_calls;
	int close_calls;
	int send_rc;
	int http_post_rc;
	char sent_data[2048];
	size_t sent_data_len;
	char stdout_data[2048];
	size_t stdout_data_len;
	char upload_base_uri[256];
	char upload_type[64];
	char upload_file_path[PATH_MAX];
	char upload_uri[256];
	char http_body[2048];
	char http_content_type[128];
	char format_used[16];
	char last_link_path[PATH_MAX];
	char last_target_path[PATH_MAX];
};

static struct fake_run_state fake_run_state;

static void reset_run_state(void)
{
	memset(&fake_run_state, 0, sizeof(fake_run_state));
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

static int fake_format_symlink_record(struct output_buffer *out,
				      const char *format,
				      const char *link_path,
				      const char *target_path)
{
	int n;

	fake_run_state.format_calls++;
	snprintf(fake_run_state.format_used, sizeof(fake_run_state.format_used), "%s", format ? format : "");
	snprintf(fake_run_state.last_link_path, sizeof(fake_run_state.last_link_path), "%s", link_path ? link_path : "");
	snprintf(fake_run_state.last_target_path, sizeof(fake_run_state.last_target_path), "%s", target_path ? target_path : "");

	n = snprintf(NULL, 0, "%s|%s|%s\n", format, link_path, target_path);
	if (n < 0)
		return -1;
	out->data = malloc((size_t)n + 1);
	if (!out->data)
		return -1;
	out->len = (size_t)n;
	snprintf(out->data, out->len + 1, "%s|%s|%s\n", format, link_path, target_path);
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
	return append_text(fake_run_state.stdout_data, &fake_run_state.stdout_data_len,
			   sizeof(fake_run_state.stdout_data), data, len);
}

static char *fake_build_upload_uri(const char *base_uri, const char *upload_type, const char *file_path)
{
	fake_run_state.build_upload_uri_calls++;
	snprintf(fake_run_state.upload_base_uri, sizeof(fake_run_state.upload_base_uri), "%s", base_uri ? base_uri : "");
	snprintf(fake_run_state.upload_type, sizeof(fake_run_state.upload_type), "%s", upload_type ? upload_type : "");
	snprintf(fake_run_state.upload_file_path, sizeof(fake_run_state.upload_file_path), "%s", file_path ? file_path : "");
	snprintf(fake_run_state.upload_uri, sizeof(fake_run_state.upload_uri), "%s/%s", base_uri, upload_type);
	return strdup(fake_run_state.upload_uri);
}

static const char *fake_content_type(const char *format, const char *default_content_type)
{
	(void)default_content_type;
	if (format && !strcmp(format, "json"))
		return "application/json; charset=utf-8";
	if (format && !strcmp(format, "csv"))
		return "text/csv; charset=utf-8";
	return "text/plain; charset=utf-8";
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
	(void)message;
	(void)insecure;
	(void)verbose;
	(void)errbuf;
	(void)errbuf_len;
	return 0;
}

static int fake_close(int fd)
{
	(void)fd;
	fake_run_state.close_calls++;
	return 0;
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

static void cleanup_test_tree(const char *root)
{
	char path[PATH_MAX];
	char subdir[PATH_MAX];

	join_path(path, sizeof(path), root, "link-top");
	unlink(path);
	join_path(subdir, sizeof(subdir), root, "sub");
	join_path(path, sizeof(path), subdir, "link-nested");
	unlink(path);
	rmdir(subdir);
	rmdir(root);
}

static void create_test_tree(char *root_buf, size_t root_buf_len,
			     char *top_link_buf, size_t top_link_buf_len,
			     char *nested_link_buf, size_t nested_link_buf_len)
{
	char template[] = "/tmp/ela-list-symlinks-unit-XXXXXX";
	char *created_root;
	char subdir[PATH_MAX];

	created_root = mkdtemp(template);
	ELA_ASSERT_TRUE(created_root != NULL);
	snprintf(root_buf, root_buf_len, "%s", created_root);

	join_path(top_link_buf, top_link_buf_len, root_buf, "link-top");
	ELA_ASSERT_INT_EQ(0, symlink("target-top", top_link_buf));

	join_path(subdir, sizeof(subdir), root_buf, "sub");
	ELA_ASSERT_INT_EQ(0, mkdir(subdir, 0700));

	join_path(nested_link_buf, nested_link_buf_len, subdir, "link-nested");
	ELA_ASSERT_INT_EQ(0, symlink("../target-nested", nested_link_buf));
}

static struct ela_list_symlinks_run_ops fake_run_ops = {
	.lstat_fn = lstat,
	.readlink_fn = readlink,
	.format_symlink_record_fn = fake_format_symlink_record,
	.send_all_fn = fake_send_all,
	.append_output_fn = output_buffer_append_len,
	.write_stdout_fn = fake_write_stdout,
	.build_upload_uri_fn = fake_build_upload_uri,
	.content_type_fn = fake_content_type,
	.http_post_fn = fake_http_post,
	.http_post_log_message_fn = fake_http_post_log_message,
	.close_fn = fake_close,
};

static void test_list_symlinks_run_honors_recursive_traversal_and_formatting(void)
{
	struct ela_list_symlinks_request request = {
		.output_format = "csv",
		.output_sock = -1,
		.recursive = false,
	};
	char root[PATH_MAX];
	char top_link[PATH_MAX];
	char nested_link[PATH_MAX];

	create_test_tree(root, sizeof(root), top_link, sizeof(top_link), nested_link, sizeof(nested_link));
	request.dir_path = root;

	reset_run_state();
	ELA_ASSERT_INT_EQ(0, ela_list_symlinks_run(&request, &fake_run_ops, NULL, 0));
	ELA_ASSERT_INT_EQ(1, fake_run_state.format_calls);
	ELA_ASSERT_STR_EQ("csv", fake_run_state.format_used);
	ELA_ASSERT_STR_EQ(top_link, fake_run_state.last_link_path);
	ELA_ASSERT_STR_EQ("target-top", fake_run_state.last_target_path);
	ELA_ASSERT_TRUE(strstr(fake_run_state.stdout_data, top_link) != NULL);
	ELA_ASSERT_TRUE(strstr(fake_run_state.stdout_data, nested_link) == NULL);

	reset_run_state();
	request.recursive = true;
	ELA_ASSERT_INT_EQ(0, ela_list_symlinks_run(&request, &fake_run_ops, NULL, 0));
	ELA_ASSERT_INT_EQ(2, fake_run_state.format_calls);
	ELA_ASSERT_TRUE(strstr(fake_run_state.stdout_data, top_link) != NULL);
	ELA_ASSERT_TRUE(strstr(fake_run_state.stdout_data, nested_link) != NULL);

	cleanup_test_tree(root);
}

static void test_list_symlinks_run_supports_tcp_and_http_outputs(void)
{
	struct ela_list_symlinks_request request = {
		.output_format = "json",
		.output_sock = 8,
		.recursive = false,
	};
	char root[PATH_MAX];
	char top_link[PATH_MAX];
	char nested_link[PATH_MAX];
	char errbuf[256];

	create_test_tree(root, sizeof(root), top_link, sizeof(top_link), nested_link, sizeof(nested_link));
	request.dir_path = root;

	reset_run_state();
	ELA_ASSERT_INT_EQ(0, ela_list_symlinks_run(&request, &fake_run_ops, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(1, fake_run_state.send_calls);
	ELA_ASSERT_INT_EQ(1, fake_run_state.write_calls);
	ELA_ASSERT_TRUE(strstr(fake_run_state.sent_data, top_link) != NULL);
	ELA_ASSERT_INT_EQ(1, fake_run_state.close_calls);

	reset_run_state();
	request.output_sock = -1;
	request.output_uri = "https://ela.example/upload";
	ELA_ASSERT_INT_EQ(0, ela_list_symlinks_run(&request, &fake_run_ops, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(1, fake_run_state.build_upload_uri_calls);
	ELA_ASSERT_INT_EQ(1, fake_run_state.http_post_calls);
	ELA_ASSERT_STR_EQ("https://ela.example/upload", fake_run_state.upload_base_uri);
	ELA_ASSERT_STR_EQ("symlink-list", fake_run_state.upload_type);
	ELA_ASSERT_STR_EQ(root, fake_run_state.upload_file_path);
	ELA_ASSERT_STR_EQ("application/json; charset=utf-8", fake_run_state.http_content_type);
	ELA_ASSERT_TRUE(strstr(fake_run_state.http_body, top_link) != NULL);

	cleanup_test_tree(root);
}

static void test_list_symlinks_run_reports_tcp_and_http_failures(void)
{
	struct ela_list_symlinks_request request = {
		.output_format = "txt",
		.output_sock = 8,
		.recursive = false,
	};
	char root[PATH_MAX];
	char top_link[PATH_MAX];
	char nested_link[PATH_MAX];
	char errbuf[256];

	create_test_tree(root, sizeof(root), top_link, sizeof(top_link), nested_link, sizeof(nested_link));
	request.dir_path = root;

	reset_run_state();
	fake_run_state.send_rc = -1;
	ELA_ASSERT_INT_EQ(1, ela_list_symlinks_run(&request, &fake_run_ops, errbuf, sizeof(errbuf)));

	reset_run_state();
	request.output_sock = -1;
	request.output_uri = "https://ela.example/upload";
	fake_run_state.http_post_rc = -1;
	ELA_ASSERT_INT_EQ(1, ela_list_symlinks_run(&request, &fake_run_ops, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Failed HTTP(S) POST") != NULL);
	ELA_ASSERT_TRUE(strstr(errbuf, "upload failed") != NULL);

	cleanup_test_tree(root);
}

int run_linux_list_symlinks_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "list_symlinks_prepare_request_accepts_defaults_and_help", test_list_symlinks_prepare_request_accepts_defaults_and_help },
		{ "list_symlinks_prepare_request_rejects_invalid_inputs", test_list_symlinks_prepare_request_rejects_invalid_inputs },
		{ "list_symlinks_run_honors_recursive_traversal_and_formatting", test_list_symlinks_run_honors_recursive_traversal_and_formatting },
		{ "list_symlinks_run_supports_tcp_and_http_outputs", test_list_symlinks_run_supports_tcp_and_http_outputs },
		{ "list_symlinks_run_reports_tcp_and_http_failures", test_list_symlinks_run_reports_tcp_and_http_failures },
	};

	return ela_run_test_suite("linux_list_symlinks_util",
				  cases, sizeof(cases) / sizeof(cases[0]));
}
