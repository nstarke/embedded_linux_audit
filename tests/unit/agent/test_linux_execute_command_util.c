// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../../../agent/linux/linux_execute_command_util.h"
#include "test_harness.h"

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int fake_parse_http_rc;
static const char *fake_parsed_http;
static const char *fake_parsed_https;
static char fake_parse_http_err[128];
static int fake_connect_tcp_rc;
static char fake_last_tcp_target[128];

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
	if (fake_parse_http_rc < 0 && errbuf && errbuf_len) {
		snprintf(errbuf, errbuf_len, "%s", fake_parse_http_err);
	}
	return fake_parse_http_rc;
}

static int fake_connect_tcp_ipv4(const char *spec)
{
	snprintf(fake_last_tcp_target, sizeof(fake_last_tcp_target), "%s", spec ? spec : "");
	return fake_connect_tcp_rc;
}

static void reset_prepare_fakes(void)
{
	fake_parse_http_rc = 0;
	fake_parsed_http = NULL;
	fake_parsed_https = NULL;
	fake_parse_http_err[0] = '\0';
	fake_connect_tcp_rc = -1;
	fake_last_tcp_target[0] = '\0';
}

static void test_prepare_request_resolves_http_https_and_branching(void)
{
	struct ela_execute_command_request request;
	struct ela_execute_command_prepare_ops ops = {
		.parse_http_output_uri_fn = fake_parse_http_output_uri,
		.connect_tcp_ipv4_fn = fake_connect_tcp_ipv4,
	};
	struct ela_execute_command_env env = {
		.output_format = NULL,
		.output_http = "http://ela.example/upload",
		.output_https = NULL,
		.output_tcp = NULL,
		.insecure = true,
	};
	char errbuf[256];
	char *argv_http[] = { "execute-command", "echo hi" };

	reset_prepare_fakes();
	fake_parsed_http = env.output_http;
	ELA_ASSERT_INT_EQ(0, ela_execute_command_prepare_request(2, argv_http, &env, true, &ops,
						 &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_FALSE(request.show_help);
	ELA_ASSERT_STR_EQ("echo hi", request.command);
	ELA_ASSERT_STR_EQ("txt", request.output_format);
	ELA_ASSERT_STR_EQ("http://ela.example/upload", request.output_uri);
	ELA_ASSERT_TRUE(request.insecure);
	ELA_ASSERT_TRUE(ela_execute_command_should_run_interactive(&request, false) == false);

	reset_prepare_fakes();
	env.output_http = "https://ela.example/upload";
	fake_parsed_https = env.output_http;
	ELA_ASSERT_INT_EQ(0, ela_execute_command_prepare_request(2, argv_http, &env, true, &ops,
						 &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_STR_EQ("https://ela.example/upload", request.output_uri);

	reset_prepare_fakes();
	env.output_http = NULL;
	env.output_https = NULL;
	env.output_tcp = NULL;
	ELA_ASSERT_INT_EQ(0, ela_execute_command_prepare_request(2, argv_http, &env, true, &ops,
						 &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(ela_execute_command_should_run_interactive(&request, true));
}

static void test_prepare_request_rejects_invalid_inputs(void)
{
	struct ela_execute_command_request request;
	struct ela_execute_command_prepare_ops ops = {
		.parse_http_output_uri_fn = fake_parse_http_output_uri,
		.connect_tcp_ipv4_fn = fake_connect_tcp_ipv4,
	};
	struct ela_execute_command_env env = {
		.output_format = "yaml",
		.output_http = NULL,
		.output_https = NULL,
		.output_tcp = NULL,
		.insecure = false,
	};
	char errbuf[256];
	char *argv_missing[] = { "execute-command" };
	char *argv_extra[] = { "execute-command", "echo hi", "extra" };
	char *argv_ok[] = { "execute-command", "echo hi" };

	reset_prepare_fakes();
	ELA_ASSERT_INT_EQ(-1, ela_execute_command_prepare_request(1, argv_missing, &env, false, &ops,
						  &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "requires a command string") != NULL);

	reset_prepare_fakes();
	env.output_format = "txt";
	ELA_ASSERT_INT_EQ(-1, ela_execute_command_prepare_request(3, argv_extra, &env, false, &ops,
						  &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Unexpected argument") != NULL);

	reset_prepare_fakes();
	env.output_format = "yaml";
	ELA_ASSERT_INT_EQ(-1, ela_execute_command_prepare_request(2, argv_ok, &env, false, &ops,
						  &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Invalid output format") != NULL);

	reset_prepare_fakes();
	env.output_format = "txt";
	env.output_http = "ftp://bad";
	snprintf(fake_parse_http_err, sizeof(fake_parse_http_err), "invalid http output");
	fake_parse_http_rc = -1;
	ELA_ASSERT_INT_EQ(-1, ela_execute_command_prepare_request(2, argv_ok, &env, false, &ops,
						  &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_STR_EQ("invalid http output", errbuf);

	reset_prepare_fakes();
	env.output_http = "http://ela.example/upload";
	env.output_https = "https://ela.example/upload";
	fake_parsed_http = env.output_http;
	ELA_ASSERT_INT_EQ(-1, ela_execute_command_prepare_request(2, argv_ok, &env, false, &ops,
						  &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Use only one of --output-http or --output-https") != NULL);

	reset_prepare_fakes();
	env.output_http = NULL;
	env.output_https = NULL;
	env.output_tcp = "127.0.0.1:9000";
	fake_connect_tcp_rc = -1;
	ELA_ASSERT_INT_EQ(-1, ela_execute_command_prepare_request(2, argv_ok, &env, false, &ops,
						  &request, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Invalid/failed output target") != NULL);
}

struct fake_capture_state {
	FILE *popen_result;
	int fread_calls;
	const char *chunk1;
	size_t chunk1_len;
	size_t chunk2_len;
	int ferror_value;
	int append_rc;
	int format_rc;
	const char *formatted_text;
	int write_stdout_rc;
	int send_all_rc;
	char *upload_uri;
	const char *content_type;
	int http_post_rc;
	char http_post_err[128];
	int pclose_status;
	int close_calls;
	int send_calls;
	int http_post_calls;
	char sent_uri[256];
	char sent_content_type[128];
	char sent_body[256];
	size_t sent_body_len;
};

static struct fake_capture_state capture_state;

static void reset_capture_state(void)
{
	memset(&capture_state, 0, sizeof(capture_state));
	capture_state.popen_result = (FILE *)0x1;
	capture_state.chunk1 = "raw-output";
	capture_state.chunk1_len = strlen(capture_state.chunk1);
	capture_state.formatted_text = "formatted-output";
	capture_state.content_type = "application/json; charset=utf-8";
	capture_state.pclose_status = 0;
}

static FILE *fake_popen(const char *command, const char *mode)
{
	(void)command;
	(void)mode;
	return capture_state.popen_result;
}

static size_t fake_fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	size_t cap = size * nmemb;
	(void)stream;
	capture_state.fread_calls++;
	if (capture_state.fread_calls == 1 && capture_state.chunk1_len > 0) {
		memcpy(ptr, capture_state.chunk1, capture_state.chunk1_len < cap ? capture_state.chunk1_len : cap);
		return capture_state.chunk1_len < cap ? capture_state.chunk1_len : cap;
	}
	if (capture_state.fread_calls == 2 && capture_state.chunk2_len > 0) {
		memset(ptr, 'x', capture_state.chunk2_len < cap ? capture_state.chunk2_len : cap);
		return capture_state.chunk2_len < cap ? capture_state.chunk2_len : cap;
	}
	return 0;
}

static int fake_ferror(FILE *stream)
{
	(void)stream;
	return capture_state.ferror_value;
}

static int fake_pclose(FILE *stream)
{
	(void)stream;
	return capture_state.pclose_status;
}

static int fake_append_output(struct output_buffer *buf, const char *data, size_t len)
{
	if (capture_state.append_rc != 0)
		return capture_state.append_rc;
	return output_buffer_append_len(buf, data, len);
}

static int fake_format_record(struct output_buffer *out,
			      const char *output_format,
			      const char *command,
			      const char *raw_text)
{
	(void)output_format;
	(void)command;
	(void)raw_text;
	if (capture_state.format_rc != 0)
		return capture_state.format_rc;
	return output_buffer_append_len(out, capture_state.formatted_text,
					strlen(capture_state.formatted_text));
}

static int fake_write_stdout(const char *data, size_t len)
{
	(void)data;
	(void)len;
	return capture_state.write_stdout_rc;
}

static int fake_send_all(int sock, const uint8_t *buf, size_t len)
{
	(void)sock;
	capture_state.send_calls++;
	snprintf(capture_state.sent_body, sizeof(capture_state.sent_body), "%.*s", (int)len, buf);
	capture_state.sent_body_len = len;
	return capture_state.send_all_rc;
}

static char *fake_build_upload_uri(const char *base_uri, const char *upload_type, const char *file_path)
{
	(void)upload_type;
	(void)file_path;
	if (!capture_state.upload_uri)
		return NULL;
	return strdup(base_uri ? capture_state.upload_uri : capture_state.upload_uri);
}

static const char *fake_content_type(const char *output_format)
{
	(void)output_format;
	return capture_state.content_type;
}

static int fake_http_post(const char *uri, const uint8_t *data, size_t len,
			  const char *content_type, bool insecure, bool verbose,
			  char *errbuf, size_t errbuf_len)
{
	(void)insecure;
	(void)verbose;
	capture_state.http_post_calls++;
	snprintf(capture_state.sent_uri, sizeof(capture_state.sent_uri), "%s", uri ? uri : "");
	snprintf(capture_state.sent_content_type, sizeof(capture_state.sent_content_type), "%s",
		 content_type ? content_type : "");
	snprintf(capture_state.sent_body, sizeof(capture_state.sent_body), "%.*s", (int)len, data);
	capture_state.sent_body_len = len;
	if (capture_state.http_post_rc < 0 && errbuf && errbuf_len) {
		snprintf(errbuf, errbuf_len, "%s", capture_state.http_post_err);
	}
	return capture_state.http_post_rc;
}

static int fake_close(int fd)
{
	(void)fd;
	capture_state.close_calls++;
	return 0;
}

static void test_run_capture_successfully_sends_tcp_and_http_output(void)
{
	struct ela_execute_command_request request = {
		.command = "echo hi",
		.output_format = "json",
		.output_tcp = "127.0.0.1:9000",
		.output_uri = "http://ela.example/upload",
		.insecure = true,
		.output_sock = 77,
	};
	struct ela_execute_command_capture_ops ops = {
		.popen_fn = fake_popen,
		.fread_fn = fake_fread,
		.ferror_fn = fake_ferror,
		.pclose_fn = fake_pclose,
		.append_output_fn = fake_append_output,
		.format_record_fn = fake_format_record,
		.write_stdout_fn = fake_write_stdout,
		.send_all_fn = fake_send_all,
		.build_upload_uri_fn = fake_build_upload_uri,
		.content_type_fn = fake_content_type,
		.http_post_fn = fake_http_post,
		.close_fn = fake_close,
	};
	char errbuf[256];

	reset_capture_state();
	capture_state.upload_uri = "http://ela.example/upload/cmd";
	ELA_ASSERT_INT_EQ(0, ela_execute_command_run_capture(&request, &ops, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(1, capture_state.send_calls);
	ELA_ASSERT_INT_EQ(1, capture_state.http_post_calls);
	ELA_ASSERT_STR_EQ("http://ela.example/upload/cmd", capture_state.sent_uri);
	ELA_ASSERT_STR_EQ("application/json; charset=utf-8", capture_state.sent_content_type);
	ELA_ASSERT_STR_EQ("formatted-output", capture_state.sent_body);
	ELA_ASSERT_INT_EQ(1, capture_state.close_calls);
}

static void test_run_capture_reports_failure_paths(void)
{
	struct ela_execute_command_request request = {
		.command = "echo hi",
		.output_format = "json",
		.output_tcp = "127.0.0.1:9000",
		.output_uri = "http://ela.example/upload",
		.insecure = false,
		.output_sock = 77,
	};
	struct ela_execute_command_capture_ops ops = {
		.popen_fn = fake_popen,
		.fread_fn = fake_fread,
		.ferror_fn = fake_ferror,
		.pclose_fn = fake_pclose,
		.append_output_fn = fake_append_output,
		.format_record_fn = fake_format_record,
		.write_stdout_fn = fake_write_stdout,
		.send_all_fn = fake_send_all,
		.build_upload_uri_fn = fake_build_upload_uri,
		.content_type_fn = fake_content_type,
		.http_post_fn = fake_http_post,
		.close_fn = fake_close,
	};
	char errbuf[256];

	reset_capture_state();
	capture_state.popen_result = NULL;
	ELA_ASSERT_INT_EQ(1, ela_execute_command_run_capture(&request, &ops, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Failed to execute command") != NULL);

	reset_capture_state();
	capture_state.append_rc = -1;
	ELA_ASSERT_INT_EQ(1, ela_execute_command_run_capture(&request, &ops, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Out of memory") != NULL);

	reset_capture_state();
	capture_state.format_rc = -1;
	ELA_ASSERT_INT_EQ(1, ela_execute_command_run_capture(&request, &ops, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Failed to format command output") != NULL);

	reset_capture_state();
	capture_state.write_stdout_rc = -1;
	ELA_ASSERT_INT_EQ(1, ela_execute_command_run_capture(&request, &ops, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Failed to write formatted command output") != NULL);

	reset_capture_state();
	capture_state.send_all_rc = -1;
	ELA_ASSERT_INT_EQ(1, ela_execute_command_run_capture(&request, &ops, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Failed sending bytes") != NULL);

	reset_capture_state();
	capture_state.upload_uri = NULL;
	request.output_sock = -1;
	ELA_ASSERT_INT_EQ(1, ela_execute_command_run_capture(&request, &ops, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Unable to build upload URI") != NULL);

	reset_capture_state();
	request.output_sock = -1;
	capture_state.upload_uri = "http://ela.example/upload/cmd";
	capture_state.http_post_rc = -1;
	snprintf(capture_state.http_post_err, sizeof(capture_state.http_post_err), "post failed");
	ELA_ASSERT_INT_EQ(1, ela_execute_command_run_capture(&request, &ops, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Failed HTTP(S) POST to http://ela.example/upload/cmd: post failed") != NULL);

	reset_capture_state();
	request.output_uri = NULL;
	request.output_sock = -1;
	capture_state.pclose_status = 3 << 8;
	ELA_ASSERT_INT_EQ(1, ela_execute_command_run_capture(&request, &ops, errbuf, sizeof(errbuf)));
}

#ifdef __linux__
struct fake_interactive_state {
	pid_t forkpty_rc;
	int master_fd;
	int waitpid_calls;
	int waitpid_wnohang_status;
	int waitpid_blocking_status;
	int select_rc;
	int select_sets_stdin;
	int select_sets_master;
	ssize_t stdin_read_rc;
	ssize_t master_read_rc;
	int close_calls;
};

static struct fake_interactive_state interactive_state;

static void reset_interactive_state(void)
{
	memset(&interactive_state, 0, sizeof(interactive_state));
	interactive_state.forkpty_rc = 123;
	interactive_state.master_fd = 55;
	interactive_state.stdin_read_rc = 0;
	interactive_state.master_read_rc = 0;
}

static void fake_flush(void) {}

static pid_t fake_forkpty(int *master_fd, char *name, const void *termios_p, const void *winsize_p)
{
	(void)name;
	(void)termios_p;
	(void)winsize_p;
	if (master_fd)
		*master_fd = interactive_state.master_fd;
	return interactive_state.forkpty_rc;
}

static pid_t fake_waitpid(pid_t pid, int *status, int options)
{
	(void)pid;
	interactive_state.waitpid_calls++;
	if (options == WNOHANG) {
		if (status)
			*status = interactive_state.waitpid_wnohang_status;
		return interactive_state.waitpid_wnohang_status ? interactive_state.forkpty_rc : 0;
	}
	if (status)
		*status = interactive_state.waitpid_blocking_status;
	return interactive_state.forkpty_rc;
}

static int fake_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
		       struct timeval *timeout)
{
	(void)nfds;
	(void)writefds;
	(void)exceptfds;
	(void)timeout;
	if (readfds) {
		FD_ZERO(readfds);
		if (interactive_state.select_sets_stdin)
			FD_SET(STDIN_FILENO, readfds);
		if (interactive_state.select_sets_master)
			FD_SET(interactive_state.master_fd, readfds);
	}
	return interactive_state.select_rc;
}

static ssize_t fake_read(int fd, void *buf, size_t len)
{
	(void)buf;
	(void)len;
	if (fd == STDIN_FILENO)
		return interactive_state.stdin_read_rc;
	if (fd == interactive_state.master_fd)
		return interactive_state.master_read_rc;
	return -1;
}

static ssize_t fake_write(int fd, const void *buf, size_t len)
{
	(void)fd;
	(void)buf;
	return (ssize_t)len;
}

static int fake_close_interactive(int fd)
{
	(void)fd;
	interactive_state.close_calls++;
	return 0;
}

static int fake_exec_shell(const char *command)
{
	(void)command;
	return -1;
}

static void test_run_interactive_helper_handles_exit_signal_and_eof_paths(void)
{
	struct ela_execute_command_interactive_ops ops = {
		.flush_stdout_fn = fake_flush,
		.flush_stderr_fn = fake_flush,
		.forkpty_fn = fake_forkpty,
		.waitpid_fn = fake_waitpid,
		.select_fn = fake_select,
		.read_fn = fake_read,
		.write_fn = fake_write,
		.close_fn = fake_close_interactive,
		.exec_shell_fn = fake_exec_shell,
	};

	reset_interactive_state();
	interactive_state.waitpid_wnohang_status = 7 << 8;
	ELA_ASSERT_INT_EQ(7, ela_execute_command_run_interactive_with_ops("sh", &ops));

	reset_interactive_state();
	interactive_state.waitpid_wnohang_status = SIGTERM;
	ELA_ASSERT_INT_EQ(143, ela_execute_command_run_interactive_with_ops("sh", &ops));

	reset_interactive_state();
	interactive_state.forkpty_rc = -1;
	ELA_ASSERT_INT_EQ(1, ela_execute_command_run_interactive_with_ops("sh", &ops));

	reset_interactive_state();
	interactive_state.select_rc = 1;
	interactive_state.select_sets_stdin = 1;
	interactive_state.stdin_read_rc = 0;
	interactive_state.waitpid_blocking_status = 0;
	ELA_ASSERT_INT_EQ(0, ela_execute_command_run_interactive_with_ops("sh", &ops));

	reset_interactive_state();
	interactive_state.select_rc = 1;
	interactive_state.select_sets_master = 1;
	interactive_state.master_read_rc = 0;
	interactive_state.waitpid_blocking_status = 0;
	ELA_ASSERT_INT_EQ(0, ela_execute_command_run_interactive_with_ops("sh", &ops));
}
#endif

int run_linux_execute_command_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "prepare_request_resolves_http_https_and_branching", test_prepare_request_resolves_http_https_and_branching },
		{ "prepare_request_rejects_invalid_inputs", test_prepare_request_rejects_invalid_inputs },
		{ "run_capture_successfully_sends_tcp_and_http_output", test_run_capture_successfully_sends_tcp_and_http_output },
		{ "run_capture_reports_failure_paths", test_run_capture_reports_failure_paths },
#ifdef __linux__
		{ "run_interactive_helper_handles_exit_signal_and_eof_paths", test_run_interactive_helper_handles_exit_signal_and_eof_paths },
#endif
	};

	return ela_run_test_suite("linux_execute_command_util",
				  cases, sizeof(cases) / sizeof(cases[0]));
}
