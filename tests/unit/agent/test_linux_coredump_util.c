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

	/* failure-injection switches (default 0 == no failure) */
	int mkdir_fail;
	int chmod_fail;
	int open_fail;
	int read_fail;
	int write_fail;
	int close_fail;
	int post_fail;
	int build_uri_fail;
	int read_text_fail;
	const char *write_fail_path;
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
	if (g.mkdir_fail)
		return -1;
	return 0;
}

static int fake_chmod(const char *path, unsigned int mode)
{
	(void)path;
	(void)mode;
	g.chmod_count++;
	if (g.chmod_fail)
		return -1;
	return 0;
}

static int fake_write_text_file(const char *path, const char *text, unsigned int mode)
{
	int idx = g.write_count++;

	if (g.write_fail_path && !strcmp(g.write_fail_path, path))
		return -1;
	if (idx >= 8)
		return -1;
	snprintf(g.write_paths[idx], sizeof(g.write_paths[idx]), "%s", path);
	snprintf(g.writes[idx], sizeof(g.writes[idx]), "%s", text);
	g.write_modes[idx] = mode;
	return 0;
}

static int fake_read_text_file(const char *path, char *buf, size_t buf_len)
{
	if (g.read_text_fail)
		return -1;
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
	if (g.read_fail) {
		errno = EIO;
		return -1;
	}
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
	if (g.write_fail) {
		errno = EIO;
		return -1;
	}
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
	if (g.open_fail)
		return -1;
	snprintf(g.file_path, sizeof(g.file_path), "%s", path);
	return 99;
}

static int fake_close(int fd)
{
	(void)fd;
	if (g.close_fail)
		return -1;
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
	if (g.build_uri_fail)
		return NULL;
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
	g.post_calls++;
	if (g.post_fail) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "post failed");
		return -1;
	}
	(void)errbuf;
	(void)errbuf_len;
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

static void test_build_core_pattern_rejects_bad_args(void)
{
	char pattern[256];
	char tiny[8];

	/* NULL / empty inputs */
	ELA_ASSERT_INT_EQ(-1, ela_coredump_build_core_pattern(NULL, "/tmp", pattern, sizeof(pattern)));
	ELA_ASSERT_INT_EQ(-1, ela_coredump_build_core_pattern("/bin/ela", NULL, pattern, sizeof(pattern)));
	ELA_ASSERT_INT_EQ(-1, ela_coredump_build_core_pattern("/bin/ela", "/tmp", NULL, sizeof(pattern)));
	ELA_ASSERT_INT_EQ(-1, ela_coredump_build_core_pattern("/bin/ela", "/tmp", pattern, 0));
	/* relative output_dir / spaces in output_dir */
	ELA_ASSERT_INT_EQ(-1, ela_coredump_build_core_pattern("/bin/ela", "rel", pattern, sizeof(pattern)));
	ELA_ASSERT_INT_EQ(-1, ela_coredump_build_core_pattern("/bin/ela", "/has space", pattern, sizeof(pattern)));
	/* output buffer too small to hold the formatted pattern */
	ELA_ASSERT_INT_EQ(-1, ela_coredump_build_core_pattern("/bin/ela", "/tmp", tiny, sizeof(tiny)));
}

/* ------------------------------------------------------------------ *
 * ela_coredump_write_config — guards and failure paths
 * ------------------------------------------------------------------ */

static void test_write_config_null_request_fails(void)
{
	char errbuf[128];

	reset_fake_state();
	ELA_ASSERT_INT_EQ(-1, ela_coredump_write_config(NULL, &fake_ops, errbuf, sizeof(errbuf)));
}

static void test_write_config_empty_uri_is_noop(void)
{
	struct ela_coredump_config_request request = {
		.collector_path = "/bin/ela",
		.output_uri = "",
	};
	char errbuf[128];

	reset_fake_state();
	ELA_ASSERT_INT_EQ(0, ela_coredump_write_config(&request, &fake_ops, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(0, g.write_count);
}

static void test_write_config_value_too_long_fails(void)
{
	static char huge[2048];
	struct ela_coredump_config_request request = {
		.config_path = "/tmp/ela-coredump.conf",
		.api_key = "k",
	};
	char errbuf[128];

	reset_fake_state();
	memset(huge, 'a', sizeof(huge) - 1);
	huge[sizeof(huge) - 1] = '\0';
	request.output_uri = huge;

	ELA_ASSERT_INT_EQ(-1, ela_coredump_write_config(&request, &fake_ops, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "config value too long") != NULL);
}

static void test_write_config_write_failure_reports_error(void)
{
	struct ela_coredump_config_request request = {
		.config_path = "/tmp/ela-coredump.conf",
		.output_uri = "http://api/upload",
	};
	char errbuf[128];

	reset_fake_state();
	g.write_fail_path = "/tmp/ela-coredump.conf";
	ELA_ASSERT_INT_EQ(-1, ela_coredump_write_config(&request, &fake_ops, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "failed to write collector config") != NULL);
}

/* ------------------------------------------------------------------ *
 * ela_coredump_read_config — guard, read failure, and parsing
 * ------------------------------------------------------------------ */

static void test_read_config_null_out_fails(void)
{
	char errbuf[128];

	reset_fake_state();
	ELA_ASSERT_INT_EQ(-1, ela_coredump_read_config("/tmp/ela-coredump.conf", &fake_ops, NULL,
						       errbuf, sizeof(errbuf)));
}

static void test_read_config_read_failure_yields_empty(void)
{
	struct ela_coredump_config_file out;
	char errbuf[128];

	reset_fake_state();
	g.read_text_fail = 1;
	ELA_ASSERT_INT_EQ(0, ela_coredump_read_config("/tmp/ela-coredump.conf", &fake_ops, &out,
						      errbuf, sizeof(errbuf)));
	ELA_ASSERT_STR_EQ("", out.output_uri);
	ELA_ASSERT_STR_EQ("", out.api_key);
	ELA_ASSERT_FALSE(out.insecure);
}

static void test_read_config_parses_all_fields(void)
{
	struct ela_coredump_config_file out;
	char errbuf[128];

	reset_fake_state();
	snprintf(g.config_text, sizeof(g.config_text),
		 "output_uri=http://api/upload\napi_key=topsecret\ninsecure=true\n");
	ELA_ASSERT_INT_EQ(0, ela_coredump_read_config("/tmp/ela-coredump.conf", &fake_ops, &out,
						      errbuf, sizeof(errbuf)));
	ELA_ASSERT_STR_EQ("http://api/upload", out.output_uri);
	ELA_ASSERT_STR_EQ("topsecret", out.api_key);
	ELA_ASSERT_TRUE(out.insecure);
}

/* ------------------------------------------------------------------ *
 * ela_coredump_configure — guard and failure paths
 * ------------------------------------------------------------------ */

static void test_configure_null_request_fails(void)
{
	char errbuf[128];

	reset_fake_state();
	ELA_ASSERT_INT_EQ(-1, ela_coredump_configure(NULL, &fake_ops, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "collector path is required") != NULL);
}

static void test_configure_missing_collector_path_fails(void)
{
	struct ela_coredump_config_request request = { .collector_path = "" };
	char errbuf[128];

	reset_fake_state();
	ELA_ASSERT_INT_EQ(-1, ela_coredump_configure(&request, &fake_ops, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "collector path is required") != NULL);
}

static void test_configure_bad_collector_path_fails_pattern(void)
{
	struct ela_coredump_config_request request = {
		.collector_path = "relative/ela",
		.output_dir = "/tmp",
	};
	char errbuf[128];

	reset_fake_state();
	ELA_ASSERT_INT_EQ(-1, ela_coredump_configure(&request, &fake_ops, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "failed to build core_pattern") != NULL);
}

static void test_configure_mkdir_failure_reports_error(void)
{
	struct ela_coredump_config_request request = {
		.collector_path = "/bin/ela",
		.output_dir = "/tmp",
	};
	char errbuf[128];

	reset_fake_state();
	g.mkdir_fail = 1;
	ELA_ASSERT_INT_EQ(-1, ela_coredump_configure(&request, &fake_ops, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "failed to create output directory") != NULL);
}

static void test_configure_chmod_failure_reports_error(void)
{
	struct ela_coredump_config_request request = {
		.collector_path = "/bin/ela",
		.output_dir = "/tmp",
	};
	char errbuf[128];

	reset_fake_state();
	g.chmod_fail = 1;
	ELA_ASSERT_INT_EQ(-1, ela_coredump_configure(&request, &fake_ops, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "failed to chmod output directory") != NULL);
}

static void test_configure_core_pattern_write_failure_reports_error(void)
{
	struct ela_coredump_config_request request = {
		.collector_path = "/bin/ela",
		.output_dir = "/tmp",
	};
	char errbuf[128];

	reset_fake_state();
	g.write_fail_path = "/proc/sys/kernel/core_pattern";
	ELA_ASSERT_INT_EQ(-1, ela_coredump_configure(&request, &fake_ops, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "failed to write /proc/sys/kernel/core_pattern") != NULL);
}

/* ------------------------------------------------------------------ *
 * ela_coredump_disable — failure path
 * ------------------------------------------------------------------ */

static void test_disable_core_pattern_write_failure_reports_error(void)
{
	char errbuf[128];

	reset_fake_state();
	g.write_fail_path = "/proc/sys/kernel/core_pattern";
	ELA_ASSERT_INT_EQ(-1, ela_coredump_disable("/tmp/ela-coredump.conf", &fake_ops,
						   errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "failed to write /proc/sys/kernel/core_pattern") != NULL);
}

/* ------------------------------------------------------------------ *
 * ela_coredump_collect — guard and failure paths
 * ------------------------------------------------------------------ */

static void test_collect_null_request_fails(void)
{
	char path[512];
	char errbuf[128];

	reset_fake_state();
	ELA_ASSERT_INT_EQ(-1, ela_coredump_collect(NULL, &fake_ops, path, sizeof(path),
						   errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "collect request is required") != NULL);
}

static void test_collect_output_path_too_long_fails(void)
{
	static char big_dir[600];
	struct ela_coredump_collect_request request = {
		.pid = "1",
		.timestamp = "2",
		.exe_name = "x",
	};
	char path[512];
	char errbuf[128];

	reset_fake_state();
	big_dir[0] = '/';
	memset(big_dir + 1, 'a', sizeof(big_dir) - 2);
	big_dir[sizeof(big_dir) - 1] = '\0';
	request.output_dir = big_dir;

	ELA_ASSERT_INT_EQ(-1, ela_coredump_collect(&request, &fake_ops, path, sizeof(path),
						   errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "output path too long") != NULL);
}

static void test_collect_mkdir_failure_reports_error(void)
{
	struct ela_coredump_collect_request request = {
		.output_dir = "/tmp", .pid = "1", .timestamp = "2", .exe_name = "x",
	};
	char path[512];
	char errbuf[128];

	reset_fake_state();
	g.mkdir_fail = 1;
	ELA_ASSERT_INT_EQ(-1, ela_coredump_collect(&request, &fake_ops, path, sizeof(path),
						   errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "failed to create output directory") != NULL);
}

static void test_collect_open_failure_reports_error(void)
{
	struct ela_coredump_collect_request request = {
		.output_dir = "/tmp", .pid = "1", .timestamp = "2", .exe_name = "x",
	};
	char path[512];
	char errbuf[128];

	reset_fake_state();
	g.open_fail = 1;
	ELA_ASSERT_INT_EQ(-1, ela_coredump_collect(&request, &fake_ops, path, sizeof(path),
						   errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "failed to open output file") != NULL);
}

static void test_collect_read_failure_reports_error(void)
{
	struct ela_coredump_collect_request request = {
		.output_dir = "/tmp", .pid = "1", .timestamp = "2", .exe_name = "x",
	};
	char path[512];
	char errbuf[128];

	reset_fake_state();
	g.stdin_data = "data";
	g.read_fail = 1;
	ELA_ASSERT_INT_EQ(-1, ela_coredump_collect(&request, &fake_ops, path, sizeof(path),
						   errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "failed to read core stream") != NULL);
}

static void test_collect_write_failure_reports_error(void)
{
	struct ela_coredump_collect_request request = {
		.output_dir = "/tmp", .pid = "1", .timestamp = "2", .exe_name = "x",
	};
	char path[512];
	char errbuf[128];

	reset_fake_state();
	g.stdin_data = "data";
	g.write_fail = 1;
	ELA_ASSERT_INT_EQ(-1, ela_coredump_collect(&request, &fake_ops, path, sizeof(path),
						   errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "failed to write output file") != NULL);
}

static void test_collect_close_failure_reports_error(void)
{
	struct ela_coredump_collect_request request = {
		.output_dir = "/tmp", .pid = "1", .timestamp = "2", .exe_name = "x",
	};
	char path[512];
	char errbuf[128];

	reset_fake_state();
	g.stdin_data = "data";
	g.close_fail = 1;
	ELA_ASSERT_INT_EQ(-1, ela_coredump_collect(&request, &fake_ops, path, sizeof(path),
						   errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "failed to close output file") != NULL);
}

static void test_collect_build_upload_uri_failure_reports_error(void)
{
	struct ela_coredump_collect_request request = {
		.output_dir = "/tmp", .config_path = "/tmp/ela-coredump.conf",
		.pid = "1", .timestamp = "2", .exe_name = "x",
	};
	char path[512];
	char errbuf[128];

	reset_fake_state();
	g.stdin_data = "data";
	g.build_uri_fail = 1;
	snprintf(g.config_text, sizeof(g.config_text),
		 "output_uri=http://api/upload\ninsecure=0\napi_key=k\n");
	ELA_ASSERT_INT_EQ(-1, ela_coredump_collect(&request, &fake_ops, path, sizeof(path),
						   errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "failed to build upload URI") != NULL);
}

static void test_collect_http_post_failure_reports_error(void)
{
	struct ela_coredump_collect_request request = {
		.output_dir = "/tmp", .config_path = "/tmp/ela-coredump.conf",
		.pid = "1", .timestamp = "2", .exe_name = "x",
	};
	char path[512];
	char errbuf[128];

	reset_fake_state();
	g.stdin_data = "data";
	g.post_fail = 1;
	snprintf(g.config_text, sizeof(g.config_text),
		 "output_uri=http://api/upload\ninsecure=0\napi_key=k\n");
	ELA_ASSERT_INT_EQ(-1, ela_coredump_collect(&request, &fake_ops, path, sizeof(path),
						   errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(1, g.post_calls);
}

int run_linux_coredump_util_tests(void)
{
	const struct ela_test_case cases[] = {
		{ "build_core_pattern_uses_pipe_collector", test_build_core_pattern_uses_pipe_collector },
		{ "build_core_pattern_rejects_bad_args", test_build_core_pattern_rejects_bad_args },
		{ "configure_writes_kernel_prerequisites_and_upload_config", test_configure_writes_kernel_prerequisites_and_upload_config },
		{ "disable_restores_non_collector_settings", test_disable_restores_non_collector_settings },
		{ "collect_writes_core_and_posts_binary_upload", test_collect_writes_core_and_posts_binary_upload },
		{ "collect_without_pid_uses_unknown_name_and_current_time", test_collect_without_pid_uses_unknown_name_and_current_time },
		{ "collect_without_config_only_writes_file", test_collect_without_config_only_writes_file },
		/* write_config */
		{ "write_config_null_request_fails", test_write_config_null_request_fails },
		{ "write_config_empty_uri_is_noop", test_write_config_empty_uri_is_noop },
		{ "write_config_value_too_long_fails", test_write_config_value_too_long_fails },
		{ "write_config_write_failure_reports_error", test_write_config_write_failure_reports_error },
		/* read_config */
		{ "read_config_null_out_fails", test_read_config_null_out_fails },
		{ "read_config_read_failure_yields_empty", test_read_config_read_failure_yields_empty },
		{ "read_config_parses_all_fields", test_read_config_parses_all_fields },
		/* configure */
		{ "configure_null_request_fails", test_configure_null_request_fails },
		{ "configure_missing_collector_path_fails", test_configure_missing_collector_path_fails },
		{ "configure_bad_collector_path_fails_pattern", test_configure_bad_collector_path_fails_pattern },
		{ "configure_mkdir_failure_reports_error", test_configure_mkdir_failure_reports_error },
		{ "configure_chmod_failure_reports_error", test_configure_chmod_failure_reports_error },
		{ "configure_core_pattern_write_failure_reports_error", test_configure_core_pattern_write_failure_reports_error },
		/* disable */
		{ "disable_core_pattern_write_failure_reports_error", test_disable_core_pattern_write_failure_reports_error },
		/* collect failure paths */
		{ "collect_null_request_fails", test_collect_null_request_fails },
		{ "collect_output_path_too_long_fails", test_collect_output_path_too_long_fails },
		{ "collect_mkdir_failure_reports_error", test_collect_mkdir_failure_reports_error },
		{ "collect_open_failure_reports_error", test_collect_open_failure_reports_error },
		{ "collect_read_failure_reports_error", test_collect_read_failure_reports_error },
		{ "collect_write_failure_reports_error", test_collect_write_failure_reports_error },
		{ "collect_close_failure_reports_error", test_collect_close_failure_reports_error },
		{ "collect_build_upload_uri_failure_reports_error", test_collect_build_upload_uri_failure_reports_error },
		{ "collect_http_post_failure_reports_error", test_collect_http_post_failure_reports_error },
	};

	return ela_run_test_suite("linux_coredump_util", cases, sizeof(cases) / sizeof(cases[0]));
}
