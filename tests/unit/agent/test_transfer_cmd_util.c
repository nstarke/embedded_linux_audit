// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../../../agent/transfer/transfer_cmd_util.h"
#include "test_harness.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

/* =========================================================================
 * Fake WebSocket state and callbacks
 * ====================================================================== */

struct fake_ws_state {
	int initial_connect_rc;
	int reconnect_connect_rc;
	int interactive_rc;
	int interactive_rc_after_reconnect;
	int fork_result;
	int reconnect_success_on_attempt;
	int connect_calls;
	int interactive_calls;
	int close_calls;
	int close_parent_calls;
	int sleep_calls;
	int stderr_calls;
	char stdout_msg[256];
	char stderr_msg[512];
};

static struct fake_ws_state fake_ws_state;

static int fake_is_ws_url(const char *url)
{
	return url && (!strncmp(url, "ws://", 5) || !strncmp(url, "wss://", 6));
}

static int fake_ws_connect(const char *base_url, int insecure, struct ela_ws_conn *ws_out)
{
	(void)base_url;
	(void)insecure;
	(void)ws_out;
	fake_ws_state.connect_calls++;
	if (fake_ws_state.connect_calls == 1)
		return fake_ws_state.initial_connect_rc;
	if (fake_ws_state.reconnect_success_on_attempt > 0 &&
	    fake_ws_state.connect_calls == fake_ws_state.reconnect_success_on_attempt) {
		return 0;
	}
	return fake_ws_state.reconnect_connect_rc;
}

static void fake_ws_close_parent_fd(const struct ela_ws_conn *ws)
{
	(void)ws;
	fake_ws_state.close_parent_calls++;
}

static void fake_ws_close(struct ela_ws_conn *ws)
{
	(void)ws;
	fake_ws_state.close_calls++;
}

static int fake_ws_run_interactive(struct ela_ws_conn *ws, const char *prog)
{
	(void)ws;
	(void)prog;
	fake_ws_state.interactive_calls++;
	if (fake_ws_state.interactive_calls > 1)
		return fake_ws_state.interactive_rc_after_reconnect;
	return fake_ws_state.interactive_rc;
}

static pid_t fake_ws_fork(void)
{
	return fake_ws_state.fork_result;
}

static pid_t fake_setsid(void)
{
	return 1;
}

static unsigned int fake_sleep(unsigned int seconds)
{
	(void)seconds;
	fake_ws_state.sleep_calls++;
	return 0;
}

static int fake_ws_stdout(const char *message)
{
	snprintf(fake_ws_state.stdout_msg, sizeof(fake_ws_state.stdout_msg),
		 "%s", message ? message : "");
	return 0;
}

static int fake_ws_stderr(const char *message)
{
	fake_ws_state.stderr_calls++;
	if (message)
		strncat(fake_ws_state.stderr_msg, message,
			sizeof(fake_ws_state.stderr_msg) - strlen(fake_ws_state.stderr_msg) - 1);
	return 0;
}

static void reset_ws_state(void)
{
	memset(&fake_ws_state, 0, sizeof(fake_ws_state));
	fake_ws_state.initial_connect_rc = 0;
	fake_ws_state.reconnect_connect_rc = 0;
	fake_ws_state.interactive_rc = ELA_WS_EXIT_CLEAN;
	fake_ws_state.interactive_rc_after_reconnect = ELA_WS_EXIT_CLEAN;
	fake_ws_state.fork_result = 1234;
}

static struct ela_transfer_ws_ops make_ws_ops(void)
{
	struct ela_transfer_ws_ops ops = {
		.is_ws_url_fn            = fake_is_ws_url,
		.ws_connect_fn           = fake_ws_connect,
		.ws_close_parent_fd_fn   = fake_ws_close_parent_fd,
		.ws_close_fn             = fake_ws_close,
		.ws_run_interactive_fn   = fake_ws_run_interactive,
		.fork_fn                 = fake_ws_fork,
		.setsid_fn               = fake_setsid,
		.sleep_fn                = fake_sleep,
		.write_stdout_fn         = fake_ws_stdout,
		.write_stderr_fn         = fake_ws_stderr,
	};
	return ops;
}

/* =========================================================================
 * Fake TCP state and callbacks
 * ====================================================================== */

struct fake_tcp_state {
	int connect_rc;
	int fork_result;
	int child_rc;
	int close_calls;
	char stdout_msg[256];
};

static struct fake_tcp_state fake_tcp_state;

static int fake_connect_tcp_any(const char *spec)
{
	(void)spec;
	return fake_tcp_state.connect_rc;
}

static pid_t fake_tcp_fork(void)
{
	return fake_tcp_state.fork_result;
}

static int fake_tcp_close(int fd)
{
	(void)fd;
	fake_tcp_state.close_calls++;
	return 0;
}

static int fake_tcp_stdout(const char *message)
{
	snprintf(fake_tcp_state.stdout_msg, sizeof(fake_tcp_state.stdout_msg),
		 "%s", message ? message : "");
	return 0;
}

static int fake_run_child_session(const struct ela_transfer_request *request,
				  int sock,
				  const struct ela_transfer_tcp_child_ops *child_ops)
{
	(void)request;
	(void)sock;
	(void)child_ops;
	return fake_tcp_state.child_rc;
}

static void reset_tcp_state(void)
{
	memset(&fake_tcp_state, 0, sizeof(fake_tcp_state));
	fake_tcp_state.connect_rc  = 7;
	fake_tcp_state.fork_result = 4321;
}

static struct ela_transfer_tcp_ops make_tcp_ops(void)
{
	struct ela_transfer_tcp_ops ops = {
		.connect_tcp_any_fn  = fake_connect_tcp_any,
		.fork_fn             = fake_tcp_fork,
		.setsid_fn           = fake_setsid,
		.close_fn            = fake_tcp_close,
		.write_stdout_fn     = fake_tcp_stdout,
		.write_stderr_fn     = fake_ws_stderr,
		.run_child_session_fn = fake_run_child_session,
		.child_ops           = NULL,
	};
	return ops;
}

/* =========================================================================
 * Fake child state and callbacks
 * ====================================================================== */

struct fake_child_state {
	int open_rc;
	int send_rc;
	int interactive_rc;
	int interactive_calls;
	int read_call;
	int dup2_calls;
	int close_calls;
	int read_error;   /* if set, first read returns -1 */
	int dup2_fail;    /* if set, dup2 always returns -1 */
};

static struct fake_child_state fake_child_state;

static int fake_open_self(const char *path, int flags)
{
	(void)path;
	(void)flags;
	return fake_child_state.open_rc;
}

static ssize_t fake_read_binary(int fd, void *buf, size_t count)
{
	(void)fd;
	(void)count;
	fake_child_state.read_call++;
	if (fake_child_state.read_error)
		return -1;
	if (fake_child_state.read_call == 1) {
		memcpy(buf, "abcd", 4);
		return 4;
	}
	return 0;
}

static int fake_send_binary(int sock, const uint8_t *buf, size_t len)
{
	(void)sock;
	(void)buf;
	(void)len;
	return fake_child_state.send_rc;
}

static int fake_dup2(int oldfd, int newfd)
{
	(void)oldfd;
	(void)newfd;
	fake_child_state.dup2_calls++;
	if (fake_child_state.dup2_fail)
		return -1;
	return 0;
}

static int fake_close_child(int fd)
{
	(void)fd;
	fake_child_state.close_calls++;
	return 0;
}

static int fake_interactive_loop(const char *prog)
{
	(void)prog;
	fake_child_state.interactive_calls++;
	return fake_child_state.interactive_rc;
}

static void reset_child_state(void)
{
	memset(&fake_child_state, 0, sizeof(fake_child_state));
	fake_child_state.open_rc       = 9;
	fake_child_state.interactive_rc = 6;
}

static struct ela_transfer_tcp_child_ops make_child_ops(void)
{
	struct ela_transfer_tcp_child_ops ops = {
		.open_fn             = fake_open_self,
		.read_fn             = fake_read_binary,
		.send_all_fn         = fake_send_binary,
		.dup2_fn             = fake_dup2,
		.close_fn            = fake_close_child,
		.interactive_loop_fn = fake_interactive_loop,
	};
	return ops;
}

/* =========================================================================
 * ela_transfer_run_ws tests
 * ====================================================================== */

static void test_run_ws_null_request(void)
{
	struct ela_transfer_ws_ops ws_ops = make_ws_ops();
	struct ela_transfer_result result;
	char errbuf[256];

	reset_ws_state();
	ELA_ASSERT_INT_EQ(1, ela_transfer_run_ws(NULL, &ws_ops, &result, errbuf, sizeof(errbuf)));
}

static void test_run_ws_null_target(void)
{
	struct ela_transfer_request request = {
		.prog          = "transfer",
		.self_exe_path = "/proc/self/exe",
		.options       = { .target = NULL },
	};
	struct ela_transfer_ws_ops ws_ops = make_ws_ops();
	struct ela_transfer_result result;
	char errbuf[256];

	reset_ws_state();
	ELA_ASSERT_INT_EQ(1, ela_transfer_run_ws(&request, &ws_ops, &result, errbuf, sizeof(errbuf)));
}

static void test_run_ws_connect_failure(void)
{
	struct ela_transfer_request request = {
		.prog          = "transfer",
		.self_exe_path = "/proc/self/exe",
		.options       = { .target = "wss://ela.example/ws", .retry_attempts = 3 },
	};
	struct ela_transfer_ws_ops ws_ops = make_ws_ops();
	struct ela_transfer_result result;
	char errbuf[256] = { 0 };

	reset_ws_state();
	fake_ws_state.initial_connect_rc = -1;
	ELA_ASSERT_INT_EQ(1, ela_transfer_run_ws(&request, &ws_ops, &result,
						 errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "failed to connect") != NULL);
	ELA_ASSERT_INT_EQ(0, fake_ws_state.fork_result == -1 ? 0 : fake_ws_state.close_parent_calls);
}

static void test_run_ws_fork_failure(void)
{
	struct ela_transfer_request request = {
		.prog          = "transfer",
		.self_exe_path = "/proc/self/exe",
		.options       = { .target = "wss://ela.example/ws", .retry_attempts = 3 },
	};
	struct ela_transfer_ws_ops ws_ops = make_ws_ops();
	struct ela_transfer_result result;
	char errbuf[256] = { 0 };

	reset_ws_state();
	fake_ws_state.fork_result = -1;
	ELA_ASSERT_INT_EQ(1, ela_transfer_run_ws(&request, &ws_ops, &result,
						 errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "fork failed") != NULL);
	ELA_ASSERT_INT_EQ(1, fake_ws_state.close_parent_calls);
}

static void test_run_ws_retry_attempts_zero_no_retry(void)
{
	struct ela_transfer_request request = {
		.prog          = "transfer",
		.self_exe_path = "/proc/self/exe",
		.options       = { .target = "ws://ela.example/ws", .retry_attempts = 0 },
	};
	struct ela_transfer_ws_ops ws_ops = make_ws_ops();
	struct ela_transfer_result result;
	char errbuf[256];

	reset_ws_state();
	fake_ws_state.fork_result   = 0;
	fake_ws_state.interactive_rc = 42; /* non-clean, non-ELA_WS_EXIT_CLEAN */
	ELA_ASSERT_INT_EQ(1, ela_transfer_run_ws(&request, &ws_ops, &result,
						 errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(0, fake_ws_state.sleep_calls);
	ELA_ASSERT_INT_EQ(1, fake_ws_state.interactive_calls);
}

static void test_run_ws_null_result_no_crash(void)
{
	struct ela_transfer_request request = {
		.prog          = "transfer",
		.self_exe_path = "/proc/self/exe",
		.options       = { .target = "wss://ela.example/ws", .retry_attempts = 1 },
	};
	struct ela_transfer_ws_ops ws_ops = make_ws_ops();
	char errbuf[256];

	reset_ws_state();
	/* parent path — result=NULL must not crash */
	ELA_ASSERT_INT_EQ(0, ela_transfer_run_ws(&request, &ws_ops, NULL,
						 errbuf, sizeof(errbuf)));
}

static void test_run_ws_null_errbuf_no_crash(void)
{
	struct ela_transfer_request request = {
		.prog          = "transfer",
		.self_exe_path = "/proc/self/exe",
		.options       = { .target = "wss://ela.example/ws", .retry_attempts = 1 },
	};
	struct ela_transfer_ws_ops ws_ops = make_ws_ops();
	struct ela_transfer_result result;

	reset_ws_state();
	fake_ws_state.initial_connect_rc = -1;
	/* errbuf=NULL must not crash when connect fails */
	ELA_ASSERT_INT_EQ(1, ela_transfer_run_ws(&request, &ws_ops, &result, NULL, 0));
}

/* =========================================================================
 * ela_transfer_run_ws — existing parent/child/retry paths
 * ====================================================================== */

static void test_transfer_execute_ws_parent_and_clean_child_paths(void)
{
	struct ela_transfer_request request = {
		.prog          = "transfer",
		.self_exe_path = "/proc/self/exe",
		.options = {
			.target         = "wss://ela.example/ws",
			.insecure       = 1,
			.retry_attempts = 3,
		},
	};
	struct ela_transfer_result result;
	struct ela_transfer_ws_ops ws_ops = make_ws_ops();
	char errbuf[256];

	reset_ws_state();
	ELA_ASSERT_INT_EQ(0, ela_transfer_execute(&request, &ws_ops, NULL, &result,
						  errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(result.started);
	ELA_ASSERT_TRUE(result.used_websocket);
	ELA_ASSERT_INT_EQ(1234, result.started_pid);
	ELA_ASSERT_TRUE(strstr(fake_ws_state.stdout_msg, "Transfer started") != NULL);
	ELA_ASSERT_INT_EQ(1, fake_ws_state.close_parent_calls);

	reset_ws_state();
	fake_ws_state.fork_result = 0;
	ELA_ASSERT_INT_EQ(0, ela_transfer_execute(&request, &ws_ops, NULL, &result,
						  errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(result.used_websocket);
	ELA_ASSERT_INT_EQ(0, result.exit_code);
	ELA_ASSERT_INT_EQ(1, fake_ws_state.interactive_calls);
	ELA_ASSERT_INT_EQ(1, fake_ws_state.close_calls);
}

static void test_transfer_execute_ws_retry_and_exhaustion_paths(void)
{
	struct ela_transfer_request request = {
		.prog          = "transfer",
		.self_exe_path = "/proc/self/exe",
		.options = {
			.target         = "ws://ela.example/ws",
			.insecure       = 0,
			.retry_attempts = 2,
		},
	};
	struct ela_transfer_result result;
	struct ela_transfer_ws_ops ws_ops = make_ws_ops();
	char errbuf[256];

	reset_ws_state();
	fake_ws_state.fork_result          = 0;
	fake_ws_state.interactive_rc       = 0;
	fake_ws_state.reconnect_connect_rc = -1;
	ELA_ASSERT_INT_EQ(1, ela_transfer_execute(&request, &ws_ops, NULL, &result,
						  errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(3, fake_ws_state.connect_calls);
	ELA_ASSERT_INT_EQ(2, fake_ws_state.sleep_calls);
	ELA_ASSERT_TRUE(strstr(fake_ws_state.stderr_msg, "max retry attempts") != NULL);
	ELA_ASSERT_INT_EQ(1, result.exit_code);

	reset_ws_state();
	fake_ws_state.fork_result                  = 0;
	fake_ws_state.interactive_rc               = 0;
	fake_ws_state.interactive_rc_after_reconnect = ELA_WS_EXIT_CLEAN;
	fake_ws_state.reconnect_connect_rc         = -1;
	fake_ws_state.reconnect_success_on_attempt = 2;
	ELA_ASSERT_INT_EQ(0, ela_transfer_execute(&request, &ws_ops, NULL, &result,
						  errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(2, fake_ws_state.connect_calls);
	ELA_ASSERT_INT_EQ(1, fake_ws_state.sleep_calls);
	ELA_ASSERT_INT_EQ(1, result.reconnect_attempts);
}

/* =========================================================================
 * ela_transfer_run_tcp tests
 * ====================================================================== */

static void test_run_tcp_null_request(void)
{
	struct ela_transfer_tcp_ops tcp_ops = make_tcp_ops();
	struct ela_transfer_result result;
	char errbuf[256];

	reset_tcp_state();
	ELA_ASSERT_INT_EQ(1, ela_transfer_run_tcp(NULL, &tcp_ops, &result, errbuf, sizeof(errbuf)));
}

static void test_run_tcp_null_target(void)
{
	struct ela_transfer_request request = {
		.prog          = "transfer",
		.self_exe_path = "/proc/self/exe",
		.options       = { .target = NULL },
	};
	struct ela_transfer_tcp_ops tcp_ops = make_tcp_ops();
	struct ela_transfer_result result;
	char errbuf[256];

	reset_tcp_state();
	ELA_ASSERT_INT_EQ(1, ela_transfer_run_tcp(&request, &tcp_ops, &result,
						  errbuf, sizeof(errbuf)));
}

static void test_run_tcp_fork_failure(void)
{
	struct ela_transfer_request request = {
		.prog          = "transfer",
		.self_exe_path = "/proc/self/exe",
		.options       = { .target = "host:9000" },
	};
	struct ela_transfer_tcp_ops tcp_ops = make_tcp_ops();
	struct ela_transfer_result result;
	char errbuf[256] = { 0 };

	reset_tcp_state();
	fake_tcp_state.fork_result = -1;
	ELA_ASSERT_INT_EQ(1, ela_transfer_run_tcp(&request, &tcp_ops, &result,
						  errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "fork failed") != NULL);
	ELA_ASSERT_INT_EQ(1, fake_tcp_state.close_calls); /* sock closed before returning */
}

static void test_run_tcp_null_result_no_crash(void)
{
	struct ela_transfer_request request = {
		.prog          = "transfer",
		.self_exe_path = "/proc/self/exe",
		.options       = { .target = "host:9000" },
	};
	struct ela_transfer_tcp_ops tcp_ops = make_tcp_ops();
	char errbuf[256];

	reset_tcp_state();
	/* parent path (fork_result=4321) with result=NULL must not crash */
	ELA_ASSERT_INT_EQ(0, ela_transfer_run_tcp(&request, &tcp_ops, NULL, errbuf, sizeof(errbuf)));
}

static void test_run_tcp_null_errbuf_no_crash(void)
{
	struct ela_transfer_request request = {
		.prog          = "transfer",
		.self_exe_path = "/proc/self/exe",
		.options       = { .target = "host:9000" },
	};
	struct ela_transfer_tcp_ops tcp_ops = make_tcp_ops();
	struct ela_transfer_result result;

	reset_tcp_state();
	fake_tcp_state.connect_rc = -1;
	/* errbuf=NULL must not crash on connect failure */
	ELA_ASSERT_INT_EQ(1, ela_transfer_run_tcp(&request, &tcp_ops, &result, NULL, 0));
}

/* =========================================================================
 * ela_transfer_run_tcp — existing parent/failure paths
 * ====================================================================== */

static void test_transfer_execute_tcp_parent_and_failure_paths(void)
{
	struct ela_transfer_request request = {
		.prog          = "transfer",
		.self_exe_path = "/proc/self/exe",
		.options = {
			.target         = "host:9000",
			.retry_attempts = 1,
		},
	};
	struct ela_transfer_result result;
	struct ela_transfer_ws_ops ws_ops = { .is_ws_url_fn = fake_is_ws_url };
	struct ela_transfer_tcp_ops tcp_ops = make_tcp_ops();
	char errbuf[256];

	reset_tcp_state();
	ELA_ASSERT_INT_EQ(0, ela_transfer_execute(&request, &ws_ops, &tcp_ops, &result,
						  errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(result.started);
	ELA_ASSERT_INT_EQ(4321, result.started_pid);
	ELA_ASSERT_TRUE(strstr(fake_tcp_state.stdout_msg, "Transfer started") != NULL);
	ELA_ASSERT_INT_EQ(1, fake_tcp_state.close_calls);

	reset_tcp_state();
	fake_tcp_state.connect_rc = -1;
	ELA_ASSERT_INT_EQ(1, ela_transfer_execute(&request, &ws_ops, &tcp_ops, &result,
						  errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "failed to connect") != NULL);

	reset_tcp_state();
	fake_tcp_state.fork_result = 0;
	fake_tcp_state.child_rc    = 5;
	ELA_ASSERT_INT_EQ(5, ela_transfer_execute(&request, &ws_ops, &tcp_ops, &result,
						  errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(5, result.exit_code);
}

/* =========================================================================
 * ela_transfer_run_tcp_child tests
 * ====================================================================== */

static void test_run_tcp_child_null_request(void)
{
	struct ela_transfer_tcp_child_ops child_ops = make_child_ops();

	reset_child_state();
	ELA_ASSERT_INT_EQ(1, ela_transfer_run_tcp_child(NULL, 11, &child_ops));
}

static void test_run_tcp_child_null_exe_path(void)
{
	struct ela_transfer_request request = {
		.prog          = "transfer",
		.self_exe_path = NULL,
	};
	struct ela_transfer_tcp_child_ops child_ops = make_child_ops();

	reset_child_state();
	ELA_ASSERT_INT_EQ(1, ela_transfer_run_tcp_child(&request, 11, &child_ops));
}

static void test_run_tcp_child_open_failure(void)
{
	struct ela_transfer_request request = {
		.prog          = "transfer",
		.self_exe_path = "/proc/self/exe",
	};
	struct ela_transfer_tcp_child_ops child_ops = make_child_ops();

	reset_child_state();
	fake_child_state.open_rc = -1;
	ELA_ASSERT_INT_EQ(1, ela_transfer_run_tcp_child(&request, 11, &child_ops));
	ELA_ASSERT_INT_EQ(0, fake_child_state.read_call);
}

static void test_run_tcp_child_read_error(void)
{
	struct ela_transfer_request request = {
		.prog          = "transfer",
		.self_exe_path = "/proc/self/exe",
	};
	struct ela_transfer_tcp_child_ops child_ops = make_child_ops();

	reset_child_state();
	fake_child_state.read_error = 1;
	ELA_ASSERT_INT_EQ(1, ela_transfer_run_tcp_child(&request, 11, &child_ops));
	ELA_ASSERT_INT_EQ(1, fake_child_state.read_call);
	/* both fd and sock should be closed on read error */
	ELA_ASSERT_INT_EQ(2, fake_child_state.close_calls);
}

static void test_run_tcp_child_dup2_failure(void)
{
	struct ela_transfer_request request = {
		.prog          = "transfer",
		.self_exe_path = "/proc/self/exe",
	};
	struct ela_transfer_tcp_child_ops child_ops = make_child_ops();

	reset_child_state();
	fake_child_state.dup2_fail = 1;
	ELA_ASSERT_INT_EQ(1, ela_transfer_run_tcp_child(&request, 11, &child_ops));
	ELA_ASSERT_INT_EQ(0, fake_child_state.interactive_calls); /* loop never called */
}

static void test_transfer_run_tcp_child_handles_success_and_send_failure(void)
{
	struct ela_transfer_request request = {
		.prog          = "transfer",
		.self_exe_path = "/proc/self/exe",
	};
	struct ela_transfer_tcp_child_ops child_ops = make_child_ops();

	reset_child_state();
	ELA_ASSERT_INT_EQ(6, ela_transfer_run_tcp_child(&request, 11, &child_ops));
	ELA_ASSERT_INT_EQ(2, fake_child_state.read_call);
	ELA_ASSERT_INT_EQ(3, fake_child_state.dup2_calls);

	reset_child_state();
	fake_child_state.send_rc = -1;
	ELA_ASSERT_INT_EQ(1, ela_transfer_run_tcp_child(&request, 11, &child_ops));
}

/* =========================================================================
 * ela_transfer_execute guard tests
 * ====================================================================== */

static void test_execute_null_request(void)
{
	struct ela_transfer_ws_ops ws_ops = make_ws_ops();
	struct ela_transfer_result result;
	char errbuf[256];

	ELA_ASSERT_INT_EQ(1, ela_transfer_execute(NULL, &ws_ops, NULL, &result,
						  errbuf, sizeof(errbuf)));
}

static void test_execute_null_target(void)
{
	struct ela_transfer_request request = {
		.prog          = "transfer",
		.self_exe_path = "/proc/self/exe",
		.options       = { .target = NULL },
	};
	struct ela_transfer_ws_ops ws_ops = make_ws_ops();
	struct ela_transfer_result result;
	char errbuf[256];

	ELA_ASSERT_INT_EQ(1, ela_transfer_execute(&request, &ws_ops, NULL, &result,
						  errbuf, sizeof(errbuf)));
}

static void test_execute_routes_to_tcp_for_non_ws_url(void)
{
	struct ela_transfer_request request = {
		.prog          = "transfer",
		.self_exe_path = "/proc/self/exe",
		.options       = { .target = "host:9000" },
	};
	struct ela_transfer_ws_ops ws_ops  = { .is_ws_url_fn = fake_is_ws_url };
	struct ela_transfer_tcp_ops tcp_ops = make_tcp_ops();
	struct ela_transfer_result result;
	char errbuf[256];

	reset_tcp_state();
	reset_ws_state();
	ELA_ASSERT_INT_EQ(0, ela_transfer_execute(&request, &ws_ops, &tcp_ops, &result,
						  errbuf, sizeof(errbuf)));
	/* TCP parent path was taken: PID recorded, WS connect never called */
	ELA_ASSERT_INT_EQ(4321, result.started_pid);
	ELA_ASSERT_INT_EQ(0, fake_ws_state.connect_calls);
}

static void test_execute_routes_to_ws_for_ws_url(void)
{
	struct ela_transfer_request request = {
		.prog          = "transfer",
		.self_exe_path = "/proc/self/exe",
		.options       = { .target = "wss://ela.example/ws", .retry_attempts = 1 },
	};
	struct ela_transfer_ws_ops ws_ops = make_ws_ops();
	struct ela_transfer_result result;
	char errbuf[256];

	reset_ws_state();
	reset_tcp_state();
	ELA_ASSERT_INT_EQ(0, ela_transfer_execute(&request, &ws_ops, NULL, &result,
						  errbuf, sizeof(errbuf)));
	/* WS parent path: connect was called, TCP connect was NOT */
	ELA_ASSERT_INT_EQ(1, fake_ws_state.connect_calls);
	ELA_ASSERT_INT_EQ(0, fake_tcp_state.close_calls);
}

static void test_execute_null_result_no_crash(void)
{
	struct ela_transfer_request request = {
		.prog          = "transfer",
		.self_exe_path = "/proc/self/exe",
		.options       = { .target = "wss://ela.example/ws", .retry_attempts = 1 },
	};
	struct ela_transfer_ws_ops ws_ops = make_ws_ops();
	char errbuf[256];

	reset_ws_state();
	ELA_ASSERT_INT_EQ(0, ela_transfer_execute(&request, &ws_ops, NULL, NULL,
						  errbuf, sizeof(errbuf)));
}

/* =========================================================================
 * Test suite registration
 * ====================================================================== */

int run_transfer_cmd_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* run_ws guards */
		{ "run_ws_null_request",                    test_run_ws_null_request },
		{ "run_ws_null_target",                     test_run_ws_null_target },
		{ "run_ws_connect_failure",                 test_run_ws_connect_failure },
		{ "run_ws_fork_failure",                    test_run_ws_fork_failure },
		{ "run_ws_retry_attempts_zero_no_retry",    test_run_ws_retry_attempts_zero_no_retry },
		{ "run_ws_null_result_no_crash",            test_run_ws_null_result_no_crash },
		{ "run_ws_null_errbuf_no_crash",            test_run_ws_null_errbuf_no_crash },
		/* run_ws happy/retry paths */
		{ "ws_parent_and_clean_child_paths",        test_transfer_execute_ws_parent_and_clean_child_paths },
		{ "ws_retry_and_exhaustion_paths",          test_transfer_execute_ws_retry_and_exhaustion_paths },
		/* run_tcp guards */
		{ "run_tcp_null_request",                   test_run_tcp_null_request },
		{ "run_tcp_null_target",                    test_run_tcp_null_target },
		{ "run_tcp_fork_failure",                   test_run_tcp_fork_failure },
		{ "run_tcp_null_result_no_crash",           test_run_tcp_null_result_no_crash },
		{ "run_tcp_null_errbuf_no_crash",           test_run_tcp_null_errbuf_no_crash },
		/* run_tcp happy/failure paths */
		{ "tcp_parent_and_failure_paths",           test_transfer_execute_tcp_parent_and_failure_paths },
		/* run_tcp_child guards */
		{ "run_tcp_child_null_request",             test_run_tcp_child_null_request },
		{ "run_tcp_child_null_exe_path",            test_run_tcp_child_null_exe_path },
		{ "run_tcp_child_open_failure",             test_run_tcp_child_open_failure },
		{ "run_tcp_child_read_error",               test_run_tcp_child_read_error },
		{ "run_tcp_child_dup2_failure",             test_run_tcp_child_dup2_failure },
		/* run_tcp_child happy/send-failure paths */
		{ "run_tcp_child_success_and_send_failure", test_transfer_run_tcp_child_handles_success_and_send_failure },
		/* execute guards */
		{ "execute_null_request",                   test_execute_null_request },
		{ "execute_null_target",                    test_execute_null_target },
		{ "execute_routes_to_tcp",                  test_execute_routes_to_tcp_for_non_ws_url },
		{ "execute_routes_to_ws",                   test_execute_routes_to_ws_for_ws_url },
		{ "execute_null_result_no_crash",           test_execute_null_result_no_crash },
	};

	return ela_run_test_suite("transfer_cmd_util",
				  cases, sizeof(cases) / sizeof(cases[0]));
}
