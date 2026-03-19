// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/lifecycle_util.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* =========================================================================
 * Fake I/O state and callbacks
 * ====================================================================== */

struct fake_lifecycle_state {
	/* time */
	time_t fixed_time;

	/* write (stderr echo) */
	int    write_calls;
	size_t write_len;
	char   write_buf[4096];

	/* TCP */
	int  tcp_connect_rc;
	int  tcp_connect_calls;
	char tcp_connect_spec[256];
	int  tcp_send_calls;
	size_t tcp_send_len;
	int  tcp_close_calls;

	/* HTTP */
	char *upload_uri_to_return; /* strdup'd by fake; caller sets */
	int   build_uri_calls;
	char  build_uri_base[256];
	char  build_uri_type[64];
	int   http_post_calls;
	char  http_post_uri[256];
	size_t http_post_len;
	bool  http_post_insecure;
	int   http_post_rc;
};

static struct fake_lifecycle_state g;

static void reset_state(void)
{
	free(g.upload_uri_to_return);
	memset(&g, 0, sizeof(g));
	g.fixed_time      = (time_t)1773837296; /* 2026-03-18T12:34:56Z */
	g.tcp_connect_rc  = -1;                 /* no TCP by default */
	g.http_post_rc    = 0;
}

static time_t fake_time(time_t *t)
{
	if (t)
		*t = g.fixed_time;
	return g.fixed_time;
}

static ssize_t fake_write(int fd, const void *buf, size_t len)
{
	(void)fd;
	g.write_calls++;
	g.write_len += len;
	if (len > 0 && len < sizeof(g.write_buf) - g.write_len)
		strncat(g.write_buf, (const char *)buf, len);
	return (ssize_t)len;
}

static int fake_connect_tcp(const char *spec)
{
	g.tcp_connect_calls++;
	if (spec)
		snprintf(g.tcp_connect_spec, sizeof(g.tcp_connect_spec), "%s", spec);
	return g.tcp_connect_rc;
}

static int fake_send_all(int sock, const uint8_t *buf, size_t len)
{
	(void)sock;
	(void)buf;
	g.tcp_send_calls++;
	g.tcp_send_len += len;
	return 0;
}

static int fake_close(int fd)
{
	(void)fd;
	g.tcp_close_calls++;
	return 0;
}

static char *fake_build_upload_uri(const char *base, const char *type, const char *path)
{
	(void)path;
	g.build_uri_calls++;
	if (base)
		snprintf(g.build_uri_base, sizeof(g.build_uri_base), "%s", base);
	if (type)
		snprintf(g.build_uri_type, sizeof(g.build_uri_type), "%s", type);
	if (!g.upload_uri_to_return)
		return NULL;
	return strdup(g.upload_uri_to_return);
}

static int fake_http_post(const char *uri, const uint8_t *data, size_t len,
			  const char *ct, bool insecure, bool verbose,
			  char *errbuf, size_t errbuf_len)
{
	(void)data; (void)ct; (void)verbose; (void)errbuf; (void)errbuf_len;
	g.http_post_calls++;
	if (uri)
		snprintf(g.http_post_uri, sizeof(g.http_post_uri), "%s", uri);
	g.http_post_len      = len;
	g.http_post_insecure = insecure;
	return g.http_post_rc;
}

static struct ela_lifecycle_io_ops make_ops(void)
{
	struct ela_lifecycle_io_ops ops = {
		.time_fn             = fake_time,
		.write_fn            = fake_write,
		.connect_tcp_fn      = fake_connect_tcp,
		.send_all_fn         = fake_send_all,
		.close_fn            = fake_close,
		.build_upload_uri_fn = fake_build_upload_uri,
		.http_post_fn        = fake_http_post,
	};
	return ops;
}

/* =========================================================================
 * ela_emit_lifecycle_event_ex — null / guard tests
 * ====================================================================== */

static void test_emit_null_command(void)
{
	struct ela_lifecycle_io_ops ops = make_ops();

	reset_state();
	ELA_ASSERT_INT_EQ(-1, ela_emit_lifecycle_event_ex(&ops, "txt", NULL, NULL, NULL,
							  false, NULL, "start", 0));
}

static void test_emit_null_phase(void)
{
	struct ela_lifecycle_io_ops ops = make_ops();

	reset_state();
	ELA_ASSERT_INT_EQ(-1, ela_emit_lifecycle_event_ex(&ops, "txt", NULL, NULL, NULL,
							  false, "cmd", NULL, 0));
}

/* =========================================================================
 * ela_emit_lifecycle_event_ex — txt format
 * ====================================================================== */

static void test_emit_txt_writes_to_stderr(void)
{
	struct ela_lifecycle_io_ops ops = make_ops();

	reset_state();
	ELA_ASSERT_INT_EQ(0, ela_emit_lifecycle_event_ex(&ops, "txt", NULL, NULL, NULL,
							 false, "pcrread", "start", 0));
	ELA_ASSERT_INT_EQ(1, g.write_calls);
	ELA_ASSERT_TRUE(strstr(g.write_buf, "log ") != NULL);
	ELA_ASSERT_TRUE(strstr(g.write_buf, "phase=start") != NULL);
	ELA_ASSERT_TRUE(strstr(g.write_buf, "command=pcrread") != NULL);
}

static void test_emit_txt_includes_fixed_timestamp(void)
{
	struct ela_lifecycle_io_ops ops = make_ops();

	reset_state();
	ELA_ASSERT_INT_EQ(0, ela_emit_lifecycle_event_ex(&ops, "txt", NULL, NULL, NULL,
							 false, "getcap", "end", 1));
	ELA_ASSERT_TRUE(strstr(g.write_buf, "2026-03-18T12:34:56Z") != NULL);
	ELA_ASSERT_TRUE(strstr(g.write_buf, "rc=1") != NULL);
}

static void test_emit_txt_null_format_defaults_txt(void)
{
	struct ela_lifecycle_io_ops ops = make_ops();

	reset_state();
	ELA_ASSERT_INT_EQ(0, ela_emit_lifecycle_event_ex(&ops, NULL, NULL, NULL, NULL,
							 false, "cmd", "start", 0));
	ELA_ASSERT_INT_EQ(1, g.write_calls);
}

/* =========================================================================
 * ela_emit_lifecycle_event_ex — csv/json do NOT write to stderr
 * ====================================================================== */

static void test_emit_csv_no_stderr_write(void)
{
	struct ela_lifecycle_io_ops ops = make_ops();

	reset_state();
	ELA_ASSERT_INT_EQ(0, ela_emit_lifecycle_event_ex(&ops, "csv", NULL, NULL, NULL,
							 false, "getcap", "start", 0));
	ELA_ASSERT_INT_EQ(0, g.write_calls);
}

static void test_emit_json_no_stderr_write(void)
{
	struct ela_lifecycle_io_ops ops = make_ops();

	reset_state();
	ELA_ASSERT_INT_EQ(0, ela_emit_lifecycle_event_ex(&ops, "json", NULL, NULL, NULL,
							 false, "pcrread", "end", 0));
	ELA_ASSERT_INT_EQ(0, g.write_calls);
}

/* =========================================================================
 * ela_emit_lifecycle_event_ex — TCP output
 * ====================================================================== */

static void test_emit_tcp_connect_and_send(void)
{
	struct ela_lifecycle_io_ops ops = make_ops();

	reset_state();
	g.tcp_connect_rc = 7; /* valid socket fd */
	ELA_ASSERT_INT_EQ(0, ela_emit_lifecycle_event_ex(&ops, "txt", "host:9000",
							 NULL, NULL, false,
							 "getcap", "start", 0));
	ELA_ASSERT_INT_EQ(1, g.tcp_connect_calls);
	ELA_ASSERT_STR_EQ("host:9000", g.tcp_connect_spec);
	ELA_ASSERT_INT_EQ(1, g.tcp_send_calls);
	ELA_ASSERT_TRUE(g.tcp_send_len > 0);
	ELA_ASSERT_INT_EQ(1, g.tcp_close_calls);
}

static void test_emit_tcp_connect_fail_continues(void)
{
	struct ela_lifecycle_io_ops ops = make_ops();

	reset_state();
	g.tcp_connect_rc = -1;
	ELA_ASSERT_INT_EQ(0, ela_emit_lifecycle_event_ex(&ops, "txt", "host:9000",
							 NULL, NULL, false,
							 "cmd", "start", 0));
	ELA_ASSERT_INT_EQ(1, g.tcp_connect_calls);
	ELA_ASSERT_INT_EQ(0, g.tcp_send_calls);
	ELA_ASSERT_INT_EQ(0, g.tcp_close_calls);
}

static void test_emit_no_tcp_when_empty_spec(void)
{
	struct ela_lifecycle_io_ops ops = make_ops();

	reset_state();
	ELA_ASSERT_INT_EQ(0, ela_emit_lifecycle_event_ex(&ops, "txt", "",
							 NULL, NULL, false,
							 "cmd", "start", 0));
	ELA_ASSERT_INT_EQ(0, g.tcp_connect_calls);
}

/* =========================================================================
 * ela_emit_lifecycle_event_ex — HTTP output
 * ====================================================================== */

static void test_emit_http_post(void)
{
	struct ela_lifecycle_io_ops ops = make_ops();

	reset_state();
	g.upload_uri_to_return = strdup("http://ela.example/log");
	ELA_ASSERT_INT_EQ(0, ela_emit_lifecycle_event_ex(&ops, "txt", NULL,
							 "http://ela.example",
							 NULL, false,
							 "pcrread", "start", 0));
	ELA_ASSERT_INT_EQ(1, g.build_uri_calls);
	ELA_ASSERT_STR_EQ("http://ela.example", g.build_uri_base);
	ELA_ASSERT_STR_EQ("log", g.build_uri_type);
	ELA_ASSERT_INT_EQ(1, g.http_post_calls);
	ELA_ASSERT_STR_EQ("http://ela.example/log", g.http_post_uri);
	ELA_ASSERT_TRUE(g.http_post_len > 0);
}

static void test_emit_https_used_when_http_absent(void)
{
	struct ela_lifecycle_io_ops ops = make_ops();

	reset_state();
	g.upload_uri_to_return = strdup("https://ela.example/log");
	ELA_ASSERT_INT_EQ(0, ela_emit_lifecycle_event_ex(&ops, "txt", NULL,
							 NULL,
							 "https://ela.example",
							 false, "cmd", "start", 0));
	ELA_ASSERT_INT_EQ(1, g.build_uri_calls);
	ELA_ASSERT_STR_EQ("https://ela.example", g.build_uri_base);
}

static void test_emit_http_takes_precedence_over_https(void)
{
	struct ela_lifecycle_io_ops ops = make_ops();

	reset_state();
	g.upload_uri_to_return = strdup("http://ela.example/log");
	ELA_ASSERT_INT_EQ(0, ela_emit_lifecycle_event_ex(&ops, "txt", NULL,
							 "http://ela.example",
							 "https://ela.example",
							 false, "cmd", "start", 0));
	ELA_ASSERT_STR_EQ("http://ela.example", g.build_uri_base);
}

static void test_emit_build_uri_fail_continues(void)
{
	struct ela_lifecycle_io_ops ops = make_ops();

	reset_state();
	/* upload_uri_to_return is NULL → build_upload_uri_fn returns NULL */
	ELA_ASSERT_INT_EQ(0, ela_emit_lifecycle_event_ex(&ops, "txt", NULL,
							 "http://ela.example",
							 NULL, false,
							 "cmd", "start", 0));
	ELA_ASSERT_INT_EQ(1, g.build_uri_calls);
	ELA_ASSERT_INT_EQ(0, g.http_post_calls);
}

static void test_emit_http_post_fail_continues(void)
{
	struct ela_lifecycle_io_ops ops = make_ops();

	reset_state();
	g.upload_uri_to_return = strdup("http://ela.example/log");
	g.http_post_rc         = -1;
	ELA_ASSERT_INT_EQ(0, ela_emit_lifecycle_event_ex(&ops, "txt", NULL,
							 "http://ela.example",
							 NULL, false,
							 "cmd", "start", 0));
	ELA_ASSERT_INT_EQ(1, g.http_post_calls);
}

static void test_emit_insecure_propagated_to_http_post(void)
{
	struct ela_lifecycle_io_ops ops = make_ops();

	reset_state();
	g.upload_uri_to_return = strdup("https://ela.example/log");
	ELA_ASSERT_INT_EQ(0, ela_emit_lifecycle_event_ex(&ops, "txt", NULL,
							 NULL,
							 "https://ela.example",
							 true, "cmd", "start", 0));
	ELA_ASSERT_TRUE(g.http_post_insecure);
}

/* =========================================================================
 * ela_emit_lifecycle_event_ex — combined TCP + HTTP
 * ====================================================================== */

static void test_emit_tcp_and_http_together(void)
{
	struct ela_lifecycle_io_ops ops = make_ops();

	reset_state();
	g.tcp_connect_rc       = 5;
	g.upload_uri_to_return = strdup("http://ela.example/log");
	ELA_ASSERT_INT_EQ(0, ela_emit_lifecycle_event_ex(&ops, "csv", "host:9000",
							 "http://ela.example",
							 NULL, false,
							 "getcap", "end", 0));
	ELA_ASSERT_INT_EQ(1, g.tcp_send_calls);
	ELA_ASSERT_INT_EQ(1, g.http_post_calls);
	/* csv format: no stderr write */
	ELA_ASSERT_INT_EQ(0, g.write_calls);
}

/* =========================================================================
 * ela_emit_lifecycle_event_ex — no output targets
 * ====================================================================== */

static void test_emit_no_outputs_still_succeeds(void)
{
	struct ela_lifecycle_io_ops ops = make_ops();

	reset_state();
	ELA_ASSERT_INT_EQ(0, ela_emit_lifecycle_event_ex(&ops, "json", NULL, NULL, NULL,
							 false, "pcrread", "start", 0));
	ELA_ASSERT_INT_EQ(0, g.tcp_connect_calls);
	ELA_ASSERT_INT_EQ(0, g.build_uri_calls);
	ELA_ASSERT_INT_EQ(0, g.write_calls);
}

/* =========================================================================
 * ela_emit_lifecycle_event_ex — rc values
 * ====================================================================== */

static void test_emit_rc_zero_and_nonzero(void)
{
	struct ela_lifecycle_io_ops ops = make_ops();

	reset_state();
	ELA_ASSERT_INT_EQ(0, ela_emit_lifecycle_event_ex(&ops, "txt", NULL, NULL, NULL,
							 false, "cmd", "end", 0));
	ELA_ASSERT_TRUE(strstr(g.write_buf, "rc=0") != NULL);

	reset_state();
	ELA_ASSERT_INT_EQ(0, ela_emit_lifecycle_event_ex(&ops, "txt", NULL, NULL, NULL,
							 false, "cmd", "end", 99));
	ELA_ASSERT_TRUE(strstr(g.write_buf, "rc=99") != NULL);
}

/* =========================================================================
 * Test suite registration
 * ====================================================================== */

int run_lifecycle_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		/* guards */
		{ "emit_null_command",                   test_emit_null_command },
		{ "emit_null_phase",                     test_emit_null_phase },
		/* txt format */
		{ "emit_txt_writes_to_stderr",           test_emit_txt_writes_to_stderr },
		{ "emit_txt_includes_fixed_timestamp",   test_emit_txt_includes_fixed_timestamp },
		{ "emit_txt_null_format_defaults_txt",   test_emit_txt_null_format_defaults_txt },
		/* csv/json — no stderr write */
		{ "emit_csv_no_stderr_write",            test_emit_csv_no_stderr_write },
		{ "emit_json_no_stderr_write",           test_emit_json_no_stderr_write },
		/* TCP */
		{ "emit_tcp_connect_and_send",           test_emit_tcp_connect_and_send },
		{ "emit_tcp_connect_fail_continues",     test_emit_tcp_connect_fail_continues },
		{ "emit_no_tcp_when_empty_spec",         test_emit_no_tcp_when_empty_spec },
		/* HTTP */
		{ "emit_http_post",                      test_emit_http_post },
		{ "emit_https_when_http_absent",         test_emit_https_used_when_http_absent },
		{ "emit_http_takes_precedence",          test_emit_http_takes_precedence_over_https },
		{ "emit_build_uri_fail_continues",       test_emit_build_uri_fail_continues },
		{ "emit_http_post_fail_continues",       test_emit_http_post_fail_continues },
		{ "emit_insecure_propagated",            test_emit_insecure_propagated_to_http_post },
		/* combined */
		{ "emit_tcp_and_http_together",          test_emit_tcp_and_http_together },
		/* no outputs */
		{ "emit_no_outputs_still_succeeds",      test_emit_no_outputs_still_succeeds },
		/* rc values */
		{ "emit_rc_zero_and_nonzero",            test_emit_rc_zero_and_nonzero },
	};

	return ela_run_test_suite("lifecycle_util",
				  cases, sizeof(cases) / sizeof(cases[0]));
}
