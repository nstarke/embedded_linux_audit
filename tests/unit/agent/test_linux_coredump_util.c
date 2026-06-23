// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../../../agent/linux/linux_coredump_util.h"
#include "test_harness.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct fake_state {
	char writes[8][512];
	char write_paths[8][128];
	unsigned int write_modes[8];
	int write_count;
	char config_text[1800];
	const char *stdin_data;
	size_t stdin_off;
	char file_path[512];
	unsigned char file_data[256];
	size_t file_len;
	char upload_uri[256];
	char posted_uri[256];
	char posted_type[64];
	unsigned char posted_data[256];
	size_t posted_len;
	bool posted_insecure;
	char api_key[128];
	time_t fake_time;
	int mkdir_count;
	int chmod_count;
	int post_calls;
};

static struct fake_state g;

static void reset_fake_state(void)
{
	memset(&g, 0, sizeof(g));
	g.stdin_data = "";
	g.fake_time = 456;
	snprintf(g.upload_uri, sizeof(g.upload_uri), "http://api/upload/coredump");
}

static int fake_mkdir(const char *path, unsigned int mode)
{
	(void)path;
	(void)mode;
	g.mkdir_count++;
	return 0;
}

static int fake_chmod(const char *path, unsigned int mode)
{
	(void)path;
	(void)mode;
	g.chmod_count++;
	return 0;
}

static int fake_write_text_file(const char *path, const char *text, unsigned int mode)
{
	int idx = g.write_count++;

	if (idx >= 8)
		return -1;
	snprintf(g.write_paths[idx], sizeof(g.write_paths[idx]), "%s", path);
	snprintf(g.writes[idx], sizeof(g.writes[idx]), "%s", text);
	g.write_modes[idx] = mode;
	return 0;
}

static int fake_read_text_file(const char *path, char *buf, size_t buf_len)
{
	if (!strcmp(path, "/proc/123/comm")) {
		snprintf(buf, buf_len, "crasher\n");
		return 0;
	}
	snprintf(buf, buf_len, "%s", g.config_text);
	return 0;
}

static ssize_t fake_read(int fd, void *buf, size_t count)
{
	size_t remaining;
	size_t n;

	(void)fd;
	remaining = strlen(g.stdin_data) - g.stdin_off;
	if (!remaining)
		return 0;
	n = remaining < count ? remaining : count;
	memcpy(buf, g.stdin_data + g.stdin_off, n);
	g.stdin_off += n;
	return (ssize_t)n;
}

static ssize_t fake_write(int fd, const void *buf, size_t count)
{
	(void)fd;
	if (g.file_len + count > sizeof(g.file_data))
		return -1;
	memcpy(g.file_data + g.file_len, buf, count);
	g.file_len += count;
	return (ssize_t)count;
}

static int fake_open_file(const char *path, int flags, unsigned int mode)
{
	(void)flags;
	(void)mode;
	snprintf(g.file_path, sizeof(g.file_path), "%s", path);
	return 99;
}

static int fake_close(int fd)
{
	(void)fd;
	return 0;
}

static time_t fake_time(time_t *tloc)
{
	if (tloc)
		*tloc = g.fake_time;
	return g.fake_time;
}

static char *fake_build_upload_uri(const char *base_uri, const char *upload_type,
				   const char *file_path)
{
	if (strcmp("http://api/upload", base_uri ? base_uri : "") ||
	    strcmp("coredump", upload_type ? upload_type : "") ||
	    strstr(file_path ? file_path : "", "/tmp/core.") == NULL)
		return NULL;
	return strdup(g.upload_uri);
}

static int fake_http_post(const char *uri, const uint8_t *data, size_t len,
			  const char *content_type, bool insecure, bool verbose,
			  char *errbuf, size_t errbuf_len)
{
	(void)verbose;
	(void)errbuf;
	(void)errbuf_len;
	g.post_calls++;
	snprintf(g.posted_uri, sizeof(g.posted_uri), "%s", uri ? uri : "");
	snprintf(g.posted_type, sizeof(g.posted_type), "%s", content_type ? content_type : "");
	if (len > sizeof(g.posted_data))
		return -1;
	memcpy(g.posted_data, data, len);
	g.posted_len = len;
	g.posted_insecure = insecure;
	return 0;
}

static void fake_api_key_init(const char *api_key)
{
	snprintf(g.api_key, sizeof(g.api_key), "%s", api_key ? api_key : "");
}

static const struct ela_coredump_ops fake_ops = {
	.mkdir_fn = fake_mkdir,
	.chmod_fn = fake_chmod,
	.write_text_file_fn = fake_write_text_file,
	.read_text_file_fn = fake_read_text_file,
	.read_fn = fake_read,
	.write_fn = fake_write,
	.open_file_fn = fake_open_file,
	.close_fn = fake_close,
	.time_fn = fake_time,
	.build_upload_uri_fn = fake_build_upload_uri,
	.http_post_fn = fake_http_post,
	.api_key_init_fn = fake_api_key_init,
};

static void test_build_core_pattern_uses_pipe_collector(void)
{
	char pattern[256];

	ELA_ASSERT_INT_EQ(0, ela_coredump_build_core_pattern("/bin/ela", "/tmp",
							     pattern, sizeof(pattern)));
	ELA_ASSERT_STR_EQ("|/bin/ela linux coredump collect --output-dir /tmp --pid %p --signal %s",
			  pattern);
	ELA_ASSERT_INT_EQ(-1, ela_coredump_build_core_pattern("relative", "/tmp",
							      pattern, sizeof(pattern)));
	ELA_ASSERT_INT_EQ(-1, ela_coredump_build_core_pattern("/path with/ela", "/tmp",
							      pattern, sizeof(pattern)));
}

static void test_configure_writes_kernel_prerequisites_and_upload_config(void)
{
	struct ela_coredump_config_request request = {
		.collector_path = "/bin/ela",
		.output_dir = "/tmp",
		.config_path = "/tmp/ela-coredump.conf",
		.output_uri = "http://api/upload",
		.api_key = "secret",
		.insecure = true,
	};
	char errbuf[128];

	reset_fake_state();
	ELA_ASSERT_INT_EQ(0, ela_coredump_configure(&request, &fake_ops, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(1, g.mkdir_count);
	ELA_ASSERT_INT_EQ(1, g.chmod_count);
	ELA_ASSERT_STR_EQ("/proc/sys/kernel/core_pattern", g.write_paths[0]);
	ELA_ASSERT_TRUE(strstr(g.writes[0], "|/bin/ela linux coredump collect") != NULL);
	ELA_ASSERT_STR_EQ("/proc/sys/kernel/core_uses_pid", g.write_paths[1]);
	ELA_ASSERT_STR_EQ("1\n", g.writes[1]);
	ELA_ASSERT_STR_EQ("/proc/sys/fs/suid_dumpable", g.write_paths[2]);
	ELA_ASSERT_STR_EQ("2\n", g.writes[2]);
	ELA_ASSERT_STR_EQ("/tmp/ela-coredump.conf", g.write_paths[3]);
	ELA_ASSERT_TRUE(strstr(g.writes[3], "output_uri=http://api/upload") != NULL);
	ELA_ASSERT_TRUE(strstr(g.writes[3], "api_key=secret") != NULL);
	ELA_ASSERT_INT_EQ(0600, (int)g.write_modes[3]);
}

static void test_disable_restores_non_collector_settings(void)
{
	char errbuf[128];

	reset_fake_state();
	ELA_ASSERT_INT_EQ(0, ela_coredump_disable("/tmp/ela-coredump.conf", &fake_ops,
						  errbuf, sizeof(errbuf)));
	ELA_ASSERT_STR_EQ("/proc/sys/kernel/core_pattern", g.write_paths[0]);
	ELA_ASSERT_STR_EQ("core\n", g.writes[0]);
	ELA_ASSERT_STR_EQ("/proc/sys/kernel/core_uses_pid", g.write_paths[1]);
	ELA_ASSERT_STR_EQ("1\n", g.writes[1]);
	ELA_ASSERT_STR_EQ("/proc/sys/fs/suid_dumpable", g.write_paths[2]);
	ELA_ASSERT_STR_EQ("0\n", g.writes[2]);
	ELA_ASSERT_STR_EQ("/tmp/ela-coredump.conf", g.write_paths[3]);
	ELA_ASSERT_STR_EQ("", g.writes[3]);
}

static void test_collect_writes_core_and_posts_binary_upload(void)
{
	struct ela_coredump_collect_request request = {
		.output_dir = "/tmp",
		.config_path = "/tmp/ela-coredump.conf",
		.pid = "123",
		.signal = "11",
	};
	char path[512];
	char errbuf[128];

	reset_fake_state();
	g.stdin_data = "COREBYTES";
	snprintf(g.config_text, sizeof(g.config_text),
		 "output_uri=http://api/upload\ninsecure=1\napi_key=secret\n");

	ELA_ASSERT_INT_EQ(0, ela_coredump_collect(&request, &fake_ops, path, sizeof(path),
						  errbuf, sizeof(errbuf)));
	ELA_ASSERT_STR_EQ("/tmp/core.crasher.123.456", path);
	ELA_ASSERT_STR_EQ("/tmp/core.crasher.123.456", g.file_path);
	ELA_ASSERT_INT_EQ(9, (int)g.file_len);
	ELA_ASSERT_TRUE(memcmp(g.file_data, "COREBYTES", 9) == 0);
	ELA_ASSERT_INT_EQ(1, g.post_calls);
	ELA_ASSERT_STR_EQ("http://api/upload/coredump", g.posted_uri);
	ELA_ASSERT_STR_EQ("application/octet-stream", g.posted_type);
	ELA_ASSERT_TRUE(g.posted_insecure);
	ELA_ASSERT_STR_EQ("secret", g.api_key);
	ELA_ASSERT_INT_EQ(9, (int)g.posted_len);
	ELA_ASSERT_TRUE(memcmp(g.posted_data, "COREBYTES", 9) == 0);
}

static void test_collect_without_pid_uses_unknown_name_and_current_time(void)
{
	struct ela_coredump_collect_request request = {
		.output_dir = "/tmp",
	};
	char path[512];
	char errbuf[128];

	reset_fake_state();
	g.stdin_data = "X";
	g.fake_time = 99;
	g.config_text[0] = '\0';

	ELA_ASSERT_INT_EQ(0, ela_coredump_collect(&request, &fake_ops, path, sizeof(path),
						  errbuf, sizeof(errbuf)));
	ELA_ASSERT_STR_EQ("/tmp/core.unknown.unknown.99", path);
	ELA_ASSERT_INT_EQ(0, g.post_calls);
}

static void test_collect_without_config_only_writes_file(void)
{
	struct ela_coredump_collect_request request = {
		.output_dir = "/tmp",
		.pid = "7",
		.signal = "6",
		.timestamp = "8",
		.exe_name = "bad/name",
	};
	char path[512];
	char errbuf[128];

	reset_fake_state();
	g.stdin_data = "X";
	g.fake_time = 8;
	g.config_text[0] = '\0';

	ELA_ASSERT_INT_EQ(0, ela_coredump_collect(&request, &fake_ops, path, sizeof(path),
						  errbuf, sizeof(errbuf)));
	ELA_ASSERT_STR_EQ("/tmp/core.bad_name.7.8", path);
	ELA_ASSERT_INT_EQ(0, g.post_calls);
}

int run_linux_coredump_util_tests(void)
{
	const struct ela_test_case cases[] = {
		{ "build_core_pattern_uses_pipe_collector", test_build_core_pattern_uses_pipe_collector },
		{ "configure_writes_kernel_prerequisites_and_upload_config", test_configure_writes_kernel_prerequisites_and_upload_config },
		{ "disable_restores_non_collector_settings", test_disable_restores_non_collector_settings },
		{ "collect_writes_core_and_posts_binary_upload", test_collect_writes_core_and_posts_binary_upload },
		{ "collect_without_pid_uses_unknown_name_and_current_time", test_collect_without_pid_uses_unknown_name_and_current_time },
		{ "collect_without_config_only_writes_file", test_collect_without_config_only_writes_file },
	};

	return ela_run_test_suite("linux_coredump_util", cases, sizeof(cases) / sizeof(cases[0]));
}
