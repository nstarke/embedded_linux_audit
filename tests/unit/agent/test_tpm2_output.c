// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"

int run_tpm2_output_tests(void);

#if defined(ELA_HAS_TPM2)

#include "../../../agent/tpm2/tpm2_output.h"

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* -----------------------------------------------------------------------
 * Stubs for the network sinks referenced by tpm2_output.c.  Linking the real
 * implementations would drag the TCP/HTTP/TLS stack (and OpenSSL/curl) into
 * the lightweight unit-test binary, so we provide controllable replacements.
 *
 * Only ela_connect_tcp_ipv4() is exercised by these tests (via
 * tpm2_output_init); the others are referenced solely by the LCOV-excluded
 * tpm2_output_flush() and exist here just to satisfy the linker.
 * --------------------------------------------------------------------- */

static int g_connect_fd = -1; /* value returned by the connect stub */

int ela_connect_tcp_ipv4(const char *spec)
{
	(void)spec;
	return g_connect_fd;
}

int ela_send_all(int sock, const uint8_t *buf, size_t len)
{
	(void)sock;
	(void)buf;
	(void)len;
	return 0;
}

char *ela_http_build_upload_uri(const char *base_uri, const char *upload_type,
				const char *file_path)
{
	(void)base_uri;
	(void)upload_type;
	(void)file_path;
	return NULL;
}

int ela_http_post(const char *uri, const uint8_t *data, size_t len,
		  const char *content_type, bool insecure, bool verbose,
		  char *errbuf, size_t errbuf_len)
{
	(void)uri;
	(void)data;
	(void)len;
	(void)content_type;
	(void)insecure;
	(void)verbose;
	if (errbuf && errbuf_len)
		errbuf[0] = '\0';
	return 0;
}

/* --------------------------------------------------------------------- */

static void clear_output_env(void)
{
	unsetenv("ELA_OUTPUT_FORMAT");
	unsetenv("ELA_OUTPUT_TCP");
	unsetenv("ELA_OUTPUT_HTTP");
	unsetenv("ELA_OUTPUT_HTTPS");
	unsetenv("ELA_OUTPUT_INSECURE");
	g_connect_fd = -1;
}

/* -----------------------------------------------------------------------
 * tpm2_output_init
 * --------------------------------------------------------------------- */

static void test_init_default_format_txt(void)
{
	struct tpm2_output_ctx ctx;

	clear_output_env();
	ELA_ASSERT_INT_EQ(0, tpm2_output_init(&ctx));
	ELA_ASSERT_STR_EQ("txt", ctx.format);
	ELA_ASSERT_INT_EQ(-1, ctx.output_sock);
	ELA_ASSERT_FALSE(ctx.insecure);
	tpm2_output_free(&ctx);
}

static void test_init_explicit_formats(void)
{
	struct tpm2_output_ctx ctx;

	clear_output_env();
	setenv("ELA_OUTPUT_FORMAT", "json", 1);
	ELA_ASSERT_INT_EQ(0, tpm2_output_init(&ctx));
	ELA_ASSERT_STR_EQ("json", ctx.format);
	tpm2_output_free(&ctx);

	clear_output_env();
	setenv("ELA_OUTPUT_FORMAT", "csv", 1);
	ELA_ASSERT_INT_EQ(0, tpm2_output_init(&ctx));
	ELA_ASSERT_STR_EQ("csv", ctx.format);
	tpm2_output_free(&ctx);

	clear_output_env();
}

static void test_init_invalid_format_returns_2(void)
{
	struct tpm2_output_ctx ctx;

	clear_output_env();
	setenv("ELA_OUTPUT_FORMAT", "xml", 1);
	ELA_ASSERT_INT_EQ(2, tpm2_output_init(&ctx));
	tpm2_output_free(&ctx);
	clear_output_env();
}

static void test_init_insecure_flag(void)
{
	struct tpm2_output_ctx ctx;

	clear_output_env();
	setenv("ELA_OUTPUT_INSECURE", "1", 1);
	ELA_ASSERT_INT_EQ(0, tpm2_output_init(&ctx));
	ELA_ASSERT_TRUE(ctx.insecure);
	tpm2_output_free(&ctx);

	clear_output_env();
	setenv("ELA_OUTPUT_INSECURE", "0", 1);
	ELA_ASSERT_INT_EQ(0, tpm2_output_init(&ctx));
	ELA_ASSERT_FALSE(ctx.insecure);
	tpm2_output_free(&ctx);

	clear_output_env();
}

static void test_init_http_uri_sets_output_uri(void)
{
	struct tpm2_output_ctx ctx;

	clear_output_env();
	setenv("ELA_OUTPUT_HTTP", "http://example.com:8080/", 1);
	ELA_ASSERT_INT_EQ(0, tpm2_output_init(&ctx));
	ELA_ASSERT_STR_EQ("http://example.com:8080/", ctx.output_uri);
	tpm2_output_free(&ctx);
	clear_output_env();
}

static void test_init_https_via_http_env_sets_output_uri(void)
{
	struct tpm2_output_ctx ctx;

	/* A https:// value passed through ELA_OUTPUT_HTTP is parsed into the
	 * https output slot. */
	clear_output_env();
	setenv("ELA_OUTPUT_HTTP", "https://example.com/", 1);
	ELA_ASSERT_INT_EQ(0, tpm2_output_init(&ctx));
	ELA_ASSERT_STR_EQ("https://example.com/", ctx.output_uri);
	tpm2_output_free(&ctx);
	clear_output_env();
}

static void test_init_https_env_sets_output_uri(void)
{
	struct tpm2_output_ctx ctx;

	clear_output_env();
	setenv("ELA_OUTPUT_HTTPS", "https://secure.example/", 1);
	ELA_ASSERT_INT_EQ(0, tpm2_output_init(&ctx));
	ELA_ASSERT_STR_EQ("https://secure.example/", ctx.output_uri);
	tpm2_output_free(&ctx);
	clear_output_env();
}

static void test_init_bad_http_uri_returns_2(void)
{
	struct tpm2_output_ctx ctx;

	clear_output_env();
	setenv("ELA_OUTPUT_HTTP", "ftp://example.com/", 1);
	ELA_ASSERT_INT_EQ(2, tpm2_output_init(&ctx));
	tpm2_output_free(&ctx);
	clear_output_env();
}

static void test_init_http_and_https_conflict_returns_2(void)
{
	struct tpm2_output_ctx ctx;

	clear_output_env();
	setenv("ELA_OUTPUT_HTTP", "http://example.com/", 1);
	setenv("ELA_OUTPUT_HTTPS", "https://example.com/", 1);
	ELA_ASSERT_INT_EQ(2, tpm2_output_init(&ctx));
	tpm2_output_free(&ctx);
	clear_output_env();
}

static void test_init_tcp_connect_failure_returns_2(void)
{
	struct tpm2_output_ctx ctx;

	clear_output_env();
	setenv("ELA_OUTPUT_TCP", "192.0.2.1:9000", 1);
	g_connect_fd = -1; /* connect stub fails */
	ELA_ASSERT_INT_EQ(2, tpm2_output_init(&ctx));
	tpm2_output_free(&ctx);
	clear_output_env();
}

static void test_init_tcp_connect_success(void)
{
	struct tpm2_output_ctx ctx;

	clear_output_env();
	setenv("ELA_OUTPUT_TCP", "192.0.2.1:9000", 1);
	g_connect_fd = open("/dev/null", O_WRONLY); /* a real, closeable fd */
	ELA_ASSERT_TRUE(g_connect_fd >= 0);
	ELA_ASSERT_INT_EQ(0, tpm2_output_init(&ctx));
	ELA_ASSERT_INT_EQ(g_connect_fd, ctx.output_sock);
	tpm2_output_free(&ctx); /* closes the socket */
	ELA_ASSERT_INT_EQ(-1, ctx.output_sock);
	clear_output_env();
}

/* -----------------------------------------------------------------------
 * tpm2_output_kv
 * --------------------------------------------------------------------- */

static void test_kv_rejects_null_args(void)
{
	struct tpm2_output_ctx ctx;

	clear_output_env();
	ELA_ASSERT_INT_EQ(0, tpm2_output_init(&ctx));

	ELA_ASSERT_INT_EQ(-1, tpm2_output_kv(NULL, "k", "v"));
	ELA_ASSERT_INT_EQ(-1, tpm2_output_kv(&ctx, NULL, "v"));
	ELA_ASSERT_INT_EQ(-1, tpm2_output_kv(&ctx, "k", NULL));

	tpm2_output_free(&ctx);
	clear_output_env();
}

static void test_kv_appends_to_buffer(void)
{
	struct tpm2_output_ctx ctx;

	clear_output_env();
	ELA_ASSERT_INT_EQ(0, tpm2_output_init(&ctx)); /* txt format */

	ELA_ASSERT_INT_EQ(0, tpm2_output_kv(&ctx, "manufacturer", "IBM"));
	ELA_ASSERT_TRUE(ctx.buf.data != NULL);
	ELA_ASSERT_TRUE(ctx.buf.len > 0);
	/* txt format renders "key: value\n" */
	ELA_ASSERT_TRUE(strstr(ctx.buf.data, "manufacturer") != NULL);
	ELA_ASSERT_TRUE(strstr(ctx.buf.data, "IBM") != NULL);

	tpm2_output_free(&ctx);
	clear_output_env();
}

/* -----------------------------------------------------------------------
 * tpm2_output_free
 * --------------------------------------------------------------------- */

static void test_free_null_no_crash(void)
{
	tpm2_output_free(NULL);
	ELA_ASSERT_TRUE(1);
}

static void test_free_resets_context(void)
{
	struct tpm2_output_ctx ctx;

	clear_output_env();
	ELA_ASSERT_INT_EQ(0, tpm2_output_init(&ctx));
	ELA_ASSERT_INT_EQ(0, tpm2_output_kv(&ctx, "k", "v"));

	tpm2_output_free(&ctx);
	ELA_ASSERT_TRUE(ctx.buf.data == NULL);
	ELA_ASSERT_TRUE(ctx.buf.len == 0);
	ELA_ASSERT_TRUE(ctx.buf.cap == 0);
	clear_output_env();
}

int run_tpm2_output_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "init/default_txt",          test_init_default_format_txt },
		{ "init/explicit_formats",     test_init_explicit_formats },
		{ "init/invalid_format",       test_init_invalid_format_returns_2 },
		{ "init/insecure_flag",        test_init_insecure_flag },
		{ "init/http_uri",             test_init_http_uri_sets_output_uri },
		{ "init/https_via_http_env",   test_init_https_via_http_env_sets_output_uri },
		{ "init/https_env",            test_init_https_env_sets_output_uri },
		{ "init/bad_http_uri",         test_init_bad_http_uri_returns_2 },
		{ "init/http_https_conflict",  test_init_http_and_https_conflict_returns_2 },
		{ "init/tcp_connect_failure",  test_init_tcp_connect_failure_returns_2 },
		{ "init/tcp_connect_success",  test_init_tcp_connect_success },
		{ "kv/rejects_null_args",      test_kv_rejects_null_args },
		{ "kv/appends_to_buffer",      test_kv_appends_to_buffer },
		{ "free/null_no_crash",        test_free_null_no_crash },
		{ "free/resets_context",       test_free_resets_context },
	};

	return ela_run_test_suite("tpm2_output", cases, sizeof(cases) / sizeof(cases[0]));
}

#else /* !ELA_HAS_TPM2 */

int run_tpm2_output_tests(void)
{
	return 0;
}

#endif /* ELA_HAS_TPM2 */
