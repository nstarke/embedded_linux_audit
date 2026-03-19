// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../../../agent/linux/linux_list_files_util.h"
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

static int fake_parse_permissions_rc;
static int fake_parse_http_rc;
static const char *fake_parsed_http;
static const char *fake_parsed_https;
static char fake_parse_http_err[128];
static int fake_connect_tcp_rc;
static char fake_last_tcp_target[128];
static int fake_prepare_lstat_rc;
static mode_t fake_prepare_lstat_mode;

static int fake_parse_permissions_filter(const char *spec, struct permissions_filter *filter)
{
	(void)spec;
	if (fake_parse_permissions_rc == 0)
		memset(filter, 0, sizeof(*filter));
	return fake_parse_permissions_rc;
}

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
	fake_parse_permissions_rc = 0;
	fake_parse_http_rc = 0;
	fake_parsed_http = NULL;
	fake_parsed_https = NULL;
	fake_parse_http_err[0] = '\0';
	fake_connect_tcp_rc = -1;
	fake_last_tcp_target[0] = '\0';
	fake_prepare_lstat_rc = 0;
	fake_prepare_lstat_mode = S_IFDIR | 0755;
}

static void test_list_files_prepare_request_accepts_defaults_and_filters(void)
{
	struct ela_list_files_request request;
	struct ela_list_files_prepare_ops ops = {
		.parse_permissions_filter_fn = fake_parse_permissions_filter,
		.parse_http_output_uri_fn = fake_parse_http_output_uri,
		.connect_tcp_ipv4_fn = fake_connect_tcp_ipv4,
		.lstat_fn = fake_prepare_lstat,
	};
	struct ela_list_files_env env = {
		.output_http = "http://ela.example/upload",
		.insecure = true,
	};
	char errbuf[256];
	char user_spec[32];
	char group_spec[32];
	char *argv_full[] = {
		"list-files", "--recursive", "--suid-only", "--permissions", "4755",
		"--user", user_spec, "--group", group_spec, "/tmp/tree"
	};
	char *argv_default[] = { "list-files" };

	snprintf(user_spec, sizeof(user_spec), "%u", (unsigned)getuid());
	snprintf(group_spec, sizeof(group_spec), "%u", (unsigned)getgid());

	reset_prepare_fakes();
	fake_parsed_http = env.output_http;
	ELA_ASSERT_INT_EQ(0, ela_list_files_prepare_request(10, argv_full, &env, &ops,
					      &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_STR_EQ("/tmp/tree", request.dir_path);
	ELA_ASSERT_TRUE(request.recursive);
	ELA_ASSERT_TRUE(request.filters.suid_only);
	ELA_ASSERT_TRUE(request.filters.user_set);
	ELA_ASSERT_TRUE(request.filters.group_set);
	ELA_ASSERT_INT_EQ((int)getuid(), (int)request.filters.uid);
	ELA_ASSERT_INT_EQ((int)getgid(), (int)request.filters.gid);
	ELA_ASSERT_STR_EQ("http://ela.example/upload", request.output_uri);
	ELA_ASSERT_TRUE(request.insecure);

	reset_prepare_fakes();
	ELA_ASSERT_INT_EQ(0, ela_list_files_prepare_request(1, argv_default, &env, &ops,
					      &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_STR_EQ("/", request.dir_path);
}

static void test_list_files_prepare_request_rejects_invalid_inputs(void)
{
	struct ela_list_files_request request;
	struct ela_list_files_prepare_ops ops = {
		.parse_permissions_filter_fn = fake_parse_permissions_filter,
		.parse_http_output_uri_fn = fake_parse_http_output_uri,
		.connect_tcp_ipv4_fn = fake_connect_tcp_ipv4,
		.lstat_fn = fake_prepare_lstat,
	};
	struct ela_list_files_env env = {0};
	char errbuf[256];
	char *argv_relative[] = { "list-files", "tmp/tree" };
	char *argv_extra[] = { "list-files", "/tmp/tree", "extra" };
	char *argv_permissions[] = { "list-files", "--permissions", "bad", "/tmp/tree" };
	char *argv_user[] = { "list-files", "--user", "definitely-no-such-user-ela", "/tmp/tree" };
	char *argv_group[] = { "list-files", "--group", "definitely-no-such-group-ela", "/tmp/tree" };
	char *argv_ok[] = { "list-files", "/tmp/tree" };

	reset_prepare_fakes();
	ELA_ASSERT_INT_EQ(2, ela_list_files_prepare_request(2, argv_relative, &env, &ops,
					      &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "absolute directory path") != NULL);

	reset_prepare_fakes();
	ELA_ASSERT_INT_EQ(2, ela_list_files_prepare_request(3, argv_extra, &env, &ops,
					      &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Unexpected argument") != NULL);

	reset_prepare_fakes();
	fake_parse_permissions_rc = -1;
	ELA_ASSERT_INT_EQ(2, ela_list_files_prepare_request(4, argv_permissions, &env, &ops,
					      &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Invalid --permissions value") != NULL);

	reset_prepare_fakes();
	ELA_ASSERT_INT_EQ(2, ela_list_files_prepare_request(4, argv_user, &env, &ops,
					      &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Invalid --user value") != NULL);

	reset_prepare_fakes();
	ELA_ASSERT_INT_EQ(2, ela_list_files_prepare_request(4, argv_group, &env, &ops,
					      &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Invalid --group value") != NULL);

	reset_prepare_fakes();
	env.output_http = "ftp://bad";
	snprintf(fake_parse_http_err, sizeof(fake_parse_http_err), "invalid http output");
	fake_parse_http_rc = -1;
	ELA_ASSERT_INT_EQ(2, ela_list_files_prepare_request(2, argv_ok, &env, &ops,
					      &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_STR_EQ("invalid http output", errbuf);

	reset_prepare_fakes();
	env.output_http = "http://ela.example/upload";
	env.output_https = "https://ela.example/upload";
	fake_parsed_http = env.output_http;
	ELA_ASSERT_INT_EQ(2, ela_list_files_prepare_request(2, argv_ok, &env, &ops,
					      &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Use only one of --output-http or --output-https") != NULL);

	reset_prepare_fakes();
	env.output_http = NULL;
	env.output_https = NULL;
	env.output_tcp = "127.0.0.1:9000";
	ELA_ASSERT_INT_EQ(2, ela_list_files_prepare_request(2, argv_ok, &env, &ops,
					      &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Invalid/failed output target") != NULL);

	reset_prepare_fakes();
	env.output_tcp = NULL;
	fake_prepare_lstat_rc = -1;
	errno = ENOENT;
	ELA_ASSERT_INT_EQ(1, ela_list_files_prepare_request(2, argv_ok, &env, &ops,
					      &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Cannot stat /tmp/tree") != NULL);

	reset_prepare_fakes();
	fake_prepare_lstat_mode = S_IFREG | 0644;
	ELA_ASSERT_INT_EQ(2, ela_list_files_prepare_request(2, argv_ok, &env, &ops,
					      &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "list-files requires a directory path") != NULL);
}

struct fake_run_state {
	int send_calls;
	int write_calls;
	int build_upload_uri_calls;
	int http_post_calls;
	int close_calls;
	int send_rc;
	int write_rc;
	char sent_data[1024];
	size_t sent_data_len;
	char stdout_data[1024];
	size_t stdout_data_len;
	char upload_base_uri[256];
	char upload_type[64];
	char upload_file_path[PATH_MAX];
	char upload_uri[256];
	char http_body[1024];
	char http_content_type[128];
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
	snprintf(fake_run_state.upload_uri, sizeof(fake_run_state.upload_uri), "%s/%s", base_uri, upload_type);
	return strdup(fake_run_state.upload_uri);
}

static int fake_http_post(const char *uri, const uint8_t *data, size_t len,
			  const char *content_type, bool insecure, bool verbose,
			  char *errbuf, size_t errbuf_len)
{
	(void)insecure;
	(void)verbose;
	(void)errbuf;
	(void)errbuf_len;
	fake_run_state.http_post_calls++;
	snprintf(fake_run_state.upload_uri, sizeof(fake_run_state.upload_uri), "%s", uri ? uri : "");
	snprintf(fake_run_state.http_content_type, sizeof(fake_run_state.http_content_type), "%s",
		 content_type ? content_type : "");
	if (len < sizeof(fake_run_state.http_body)) {
		memcpy(fake_run_state.http_body, data, len);
		fake_run_state.http_body[len] = '\0';
	}
	return 0;
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

static void write_file(const char *path)
{
	FILE *fp = fopen(path, "w");

	ELA_ASSERT_TRUE(fp != NULL);
	ELA_ASSERT_TRUE(fputs("x\n", fp) >= 0);
	ELA_ASSERT_INT_EQ(0, fclose(fp));
}

static void cleanup_test_tree(const char *root)
{
	char path[PATH_MAX];
	char sub[PATH_MAX];

	join_path(path, sizeof(path), root, "plain.txt");
	unlink(path);
	join_path(path, sizeof(path), root, "suid.txt");
	unlink(path);
	join_path(sub, sizeof(sub), root, "sub");
	join_path(path, sizeof(path), sub, "nested.txt");
	unlink(path);
	rmdir(sub);
	rmdir(root);
}

static void create_test_tree(char *root_buf, size_t root_buf_len,
			     char *plain_buf, size_t plain_buf_len,
			     char *suid_buf, size_t suid_buf_len,
			     char *nested_buf, size_t nested_buf_len)
{
	char template[] = "/tmp/ela-list-files-unit-XXXXXX";
	char *created_root;
	char subdir[PATH_MAX];

	created_root = mkdtemp(template);
	ELA_ASSERT_TRUE(created_root != NULL);
	snprintf(root_buf, root_buf_len, "%s", created_root);

	join_path(plain_buf, plain_buf_len, root_buf, "plain.txt");
	write_file(plain_buf);
	ELA_ASSERT_INT_EQ(0, chmod(plain_buf, 0644));

	join_path(suid_buf, suid_buf_len, root_buf, "suid.txt");
	write_file(suid_buf);
	ELA_ASSERT_INT_EQ(0, chmod(suid_buf, 04755));

	join_path(subdir, sizeof(subdir), root_buf, "sub");
	ELA_ASSERT_INT_EQ(0, mkdir(subdir, 0700));

	join_path(nested_buf, nested_buf_len, subdir, "nested.txt");
	write_file(nested_buf);
	ELA_ASSERT_INT_EQ(0, chmod(nested_buf, 0644));
}

static struct ela_list_files_run_ops fake_run_ops = {
	.lstat_fn = lstat,
	.send_all_fn = fake_send_all,
	.append_output_fn = output_buffer_append,
	.write_stdout_fn = fake_write_stdout,
	.build_upload_uri_fn = fake_build_upload_uri,
	.http_post_fn = fake_http_post,
	.http_post_log_message_fn = fake_http_post_log_message,
	.close_fn = fake_close,
};

static void test_list_files_run_applies_filters_and_recursion(void)
{
	struct ela_list_files_request request = {
		.recursive = false,
		.output_sock = -1,
	};
	char root[PATH_MAX];
	char plain[PATH_MAX];
	char suid[PATH_MAX];
	char nested[PATH_MAX];

	create_test_tree(root, sizeof(root), plain, sizeof(plain), suid, sizeof(suid), nested, sizeof(nested));
	request.dir_path = root;

	reset_run_state();
	request.filters.suid_only = true;
	ELA_ASSERT_INT_EQ(0, ela_list_files_run(&request, &fake_run_ops, NULL, 0));
	ELA_ASSERT_TRUE(strstr(fake_run_state.stdout_data, suid) != NULL);
	ELA_ASSERT_TRUE(strstr(fake_run_state.stdout_data, plain) == NULL);

	reset_run_state();
	memset(&request.filters, 0, sizeof(request.filters));
	request.filters.user_set = true;
	request.filters.uid = getuid();
	request.filters.group_set = true;
	request.filters.gid = getgid();
	ELA_ASSERT_INT_EQ(0, ela_list_files_run(&request, &fake_run_ops, NULL, 0));
	ELA_ASSERT_TRUE(strstr(fake_run_state.stdout_data, plain) != NULL);

	reset_run_state();
	memset(&request.filters, 0, sizeof(request.filters));
	request.recursive = true;
	ELA_ASSERT_INT_EQ(0, ela_list_files_run(&request, &fake_run_ops, NULL, 0));
	ELA_ASSERT_TRUE(strstr(fake_run_state.stdout_data, nested) != NULL);

	cleanup_test_tree(root);
}

static void test_list_files_run_supports_tcp_and_http_outputs(void)
{
	struct ela_list_files_request request = {
		.recursive = false,
		.output_uri = NULL,
		.output_sock = 7,
	};
	char root[PATH_MAX];
	char plain[PATH_MAX];
	char suid[PATH_MAX];
	char nested[PATH_MAX];
	char errbuf[256];

	create_test_tree(root, sizeof(root), plain, sizeof(plain), suid, sizeof(suid), nested, sizeof(nested));
	request.dir_path = root;

	reset_run_state();
	ELA_ASSERT_INT_EQ(0, ela_list_files_run(&request, &fake_run_ops, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(2, fake_run_state.send_calls);
	ELA_ASSERT_INT_EQ(2, fake_run_state.write_calls);
	ELA_ASSERT_TRUE(strstr(fake_run_state.sent_data, "\n") != NULL);
	ELA_ASSERT_INT_EQ(1, fake_run_state.close_calls);

	reset_run_state();
	request.output_sock = -1;
	request.output_uri = "https://ela.example/upload";
	ELA_ASSERT_INT_EQ(0, ela_list_files_run(&request, &fake_run_ops, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(1, fake_run_state.build_upload_uri_calls);
	ELA_ASSERT_INT_EQ(1, fake_run_state.http_post_calls);
	ELA_ASSERT_STR_EQ("https://ela.example/upload", fake_run_state.upload_base_uri);
	ELA_ASSERT_STR_EQ("file-list", fake_run_state.upload_type);
	ELA_ASSERT_STR_EQ(root, fake_run_state.upload_file_path);
	ELA_ASSERT_STR_EQ("text/plain; charset=utf-8", fake_run_state.http_content_type);
	ELA_ASSERT_TRUE(strstr(fake_run_state.http_body, plain) != NULL);
	ELA_ASSERT_TRUE(strstr(fake_run_state.http_body, suid) != NULL);

	cleanup_test_tree(root);
}

int run_linux_list_files_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "list_files_prepare_request_accepts_defaults_and_filters", test_list_files_prepare_request_accepts_defaults_and_filters },
		{ "list_files_prepare_request_rejects_invalid_inputs", test_list_files_prepare_request_rejects_invalid_inputs },
		{ "list_files_run_applies_filters_and_recursion", test_list_files_run_applies_filters_and_recursion },
		{ "list_files_run_supports_tcp_and_http_outputs", test_list_files_run_supports_tcp_and_http_outputs },
	};

	return ela_run_test_suite("linux_list_files_util",
				  cases, sizeof(cases) / sizeof(cases[0]));
}
