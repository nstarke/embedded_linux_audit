// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/orom/orom_pull_cmd_util.h"

#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * ela_orom_build_tcp_header
 * ---------------------------------------------------------------------- */

static void test_orom_tcp_header_normal(void)
{
	char hdr[64];
	int n;

	n = ela_orom_build_tcp_header(hdr, sizeof(hdr),
				      "/sys/bus/pci/devices/0000:00:01.0/rom",
				      4096);
	ELA_ASSERT_TRUE(n > 0);
	ELA_ASSERT_STR_EQ("OROM /sys/bus/pci/devices/0000:00:01.0/rom 4096\n", hdr);
}

static void test_orom_tcp_header_zero_len(void)
{
	char hdr[64];
	int n;

	n = ela_orom_build_tcp_header(hdr, sizeof(hdr), "somefile", 0);
	ELA_ASSERT_TRUE(n > 0);
	ELA_ASSERT_STR_EQ("OROM somefile 0\n", hdr);
}

static void test_orom_tcp_header_rejects_overflow(void)
{
	char hdr[8]; /* too small for any real path */

	ELA_ASSERT_INT_EQ(-1, ela_orom_build_tcp_header(hdr, sizeof(hdr),
							"a_long_name", 99));
}

static void test_orom_tcp_header_rejects_null_hdr(void)
{
	ELA_ASSERT_INT_EQ(-1, ela_orom_build_tcp_header(NULL, 64, "name", 1));
}

static void test_orom_tcp_header_rejects_zero_buf_sz(void)
{
	char hdr[64];

	ELA_ASSERT_INT_EQ(-1, ela_orom_build_tcp_header(hdr, 0, "name", 1));
}

static void test_orom_tcp_header_rejects_null_name(void)
{
	char hdr[64];

	ELA_ASSERT_INT_EQ(-1, ela_orom_build_tcp_header(hdr, sizeof(hdr), NULL, 1));
}

/* -------------------------------------------------------------------------
 * ela_orom_build_http_payload
 * ---------------------------------------------------------------------- */

static void test_orom_http_payload_normal(void)
{
	const uint8_t data[] = { 0x55, 0xAA, 0x01 };
	uint8_t *out = NULL;
	size_t out_len = 0;

	ELA_ASSERT_INT_EQ(0, ela_orom_build_http_payload("romfile",
							 data, sizeof(data),
							 &out, &out_len));
	ELA_ASSERT_TRUE(out != NULL);
	/* "romfile\n" + 3 bytes = 11 bytes */
	ELA_ASSERT_INT_EQ(11, (int)out_len);
	ELA_ASSERT_INT_EQ(0, memcmp(out, "romfile\n", 8));
	ELA_ASSERT_INT_EQ(0x55, out[8]);
	ELA_ASSERT_INT_EQ(0xAA, out[9]);
	ELA_ASSERT_INT_EQ(0x01, out[10]);
	free(out);
}

static void test_orom_http_payload_zero_data(void)
{
	uint8_t *out = NULL;
	size_t out_len = 0;

	ELA_ASSERT_INT_EQ(0, ela_orom_build_http_payload("foo", NULL, 0,
							 &out, &out_len));
	ELA_ASSERT_TRUE(out != NULL);
	/* "foo\n" = 4 bytes */
	ELA_ASSERT_INT_EQ(4, (int)out_len);
	ELA_ASSERT_INT_EQ(0, memcmp(out, "foo\n", 4));
	free(out);
}

static void test_orom_http_payload_rejects_null_name(void)
{
	uint8_t *out = NULL;
	size_t out_len = 0;

	ELA_ASSERT_INT_EQ(-1, ela_orom_build_http_payload(NULL, NULL, 0,
							  &out, &out_len));
}

static void test_orom_http_payload_rejects_null_out(void)
{
	const uint8_t data[] = { 0x01 };
	size_t out_len = 0;

	ELA_ASSERT_INT_EQ(-1, ela_orom_build_http_payload("name", data, 1,
							  NULL, &out_len));
}

static void test_orom_http_payload_rejects_null_out_len(void)
{
	const uint8_t data[] = { 0x01 };
	uint8_t *out = NULL;

	ELA_ASSERT_INT_EQ(-1, ela_orom_build_http_payload("name", data, 1,
							  &out, NULL));
}

static void test_orom_http_payload_rejects_null_data_with_len(void)
{
	uint8_t *out = NULL;
	size_t out_len = 0;

	ELA_ASSERT_INT_EQ(-1, ela_orom_build_http_payload("name", NULL, 5,
							  &out, &out_len));
}

/* -------------------------------------------------------------------------
 * ela_orom_parse_args
 * ---------------------------------------------------------------------- */

static void test_orom_parse_args_too_few_args(void)
{
	char *argv[] = { "prog", NULL };
	struct ela_orom_parsed_args out;

	ELA_ASSERT_INT_EQ(2, ela_orom_parse_args(1, argv, "efi", NULL,
						 &out, NULL, 0));
}

static void test_orom_parse_args_help_action(void)
{
	char *argv_help[] = { "prog", "help", NULL };
	char *argv_h[]    = { "prog", "-h", NULL };
	char *argv_long[] = { "prog", "--help", NULL };
	struct ela_orom_parsed_args out;

	ELA_ASSERT_INT_EQ(1, ela_orom_parse_args(2, argv_help, "efi", NULL,
						 &out, NULL, 0));
	ELA_ASSERT_INT_EQ(1, ela_orom_parse_args(2, argv_h, "efi", NULL,
						 &out, NULL, 0));
	ELA_ASSERT_INT_EQ(1, ela_orom_parse_args(2, argv_long, "efi", NULL,
						 &out, NULL, 0));
}

static void test_orom_parse_args_unknown_action(void)
{
	char *argv[] = { "prog", "frobnicate", NULL };
	struct ela_orom_parsed_args out;
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(2, ela_orom_parse_args(2, argv, "efi", NULL,
						 &out, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "frobnicate") != NULL);
}

static void test_orom_parse_args_list_no_flags(void)
{
	char *argv[] = { "prog", "list", NULL };
	struct ela_orom_parsed_args out;

	ELA_ASSERT_INT_EQ(0, ela_orom_parse_args(2, argv, "efi", NULL,
						 &out, NULL, 0));
	ELA_ASSERT_STR_EQ("list", out.action);
	ELA_ASSERT_TRUE(out.output_tcp == NULL);
	ELA_ASSERT_TRUE(out.output_uri == NULL);
}

static void test_orom_parse_args_pull_missing_output(void)
{
	char *argv[] = { "prog", "pull", NULL };
	struct ela_orom_parsed_args out;
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(2, ela_orom_parse_args(2, argv, "efi", NULL,
						 &out, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "pull requires") != NULL);
}

static void test_orom_parse_args_pull_with_tcp(void)
{
	char *argv[] = { "prog", "pull", "--output-tcp", "1.2.3.4:9000", NULL };
	struct ela_orom_parsed_args out;

	ELA_ASSERT_INT_EQ(0, ela_orom_parse_args(4, argv, "efi", NULL,
						 &out, NULL, 0));
	ELA_ASSERT_STR_EQ("pull", out.action);
	ELA_ASSERT_STR_EQ("1.2.3.4:9000", out.output_tcp);
}

static void test_orom_parse_args_pull_with_http(void)
{
	char *argv[] = { "prog", "pull", "--output-http",
			 "http://1.2.3.4:8080/upload", NULL };
	struct ela_orom_parsed_args out;

	ELA_ASSERT_INT_EQ(0, ela_orom_parse_args(4, argv, "bios", NULL,
						 &out, NULL, 0));
	ELA_ASSERT_STR_EQ("pull", out.action);
	ELA_ASSERT_TRUE(out.output_uri != NULL);
}

static void test_orom_parse_args_pull_with_https(void)
{
	char *argv[] = { "prog", "pull", "--output-http",
			 "https://1.2.3.4:8443/upload", NULL };
	struct ela_orom_parsed_args out;

	ELA_ASSERT_INT_EQ(0, ela_orom_parse_args(4, argv, "efi", NULL,
						 &out, NULL, 0));
	ELA_ASSERT_STR_EQ("pull", out.action);
	ELA_ASSERT_TRUE(out.output_uri != NULL);
}

static void test_orom_parse_args_invalid_http_scheme(void)
{
	char *argv[] = { "prog", "pull", "--output-http",
			 "ftp://bad/path", NULL };
	struct ela_orom_parsed_args out;
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(2, ela_orom_parse_args(4, argv, "efi", NULL,
						 &out, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Invalid") != NULL);
}

static void test_orom_parse_args_extra_positional_arg(void)
{
	char *argv[] = { "prog", "list", "extra", NULL };
	struct ela_orom_parsed_args out;
	char errbuf[128] = { 0 };

	ELA_ASSERT_INT_EQ(2, ela_orom_parse_args(3, argv, "efi", NULL,
						 &out, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "unexpected argument") != NULL);
}

static void test_orom_parse_args_help_flag_after_action(void)
{
	char *argv[] = { "prog", "list", "--help", NULL };
	struct ela_orom_parsed_args out;

	ELA_ASSERT_INT_EQ(1, ela_orom_parse_args(3, argv, "efi", NULL,
						 &out, NULL, 0));
}

static void test_orom_parse_args_env_tcp_satisfies_pull(void)
{
	char *argv[] = { "prog", "pull", NULL };
	struct ela_orom_env env = { 0 };
	struct ela_orom_parsed_args out;

	env.output_tcp = "1.2.3.4:9000";

	ELA_ASSERT_INT_EQ(0, ela_orom_parse_args(2, argv, "efi", &env,
						 &out, NULL, 0));
	ELA_ASSERT_STR_EQ("pull", out.action);
	ELA_ASSERT_STR_EQ("1.2.3.4:9000", out.output_tcp);
}

static void test_orom_parse_args_env_verbose_and_insecure(void)
{
	char *argv[] = { "prog", "list", NULL };
	struct ela_orom_env env = { 0 };
	struct ela_orom_parsed_args out;

	env.verbose  = "1";
	env.insecure = "1";

	ELA_ASSERT_INT_EQ(0, ela_orom_parse_args(2, argv, "efi", &env,
						 &out, NULL, 0));
	ELA_ASSERT_TRUE(out.verbose);
	ELA_ASSERT_TRUE(out.insecure);
}

static void test_orom_parse_args_env_verbose_off(void)
{
	char *argv[] = { "prog", "list", NULL };
	struct ela_orom_env env = { 0 };
	struct ela_orom_parsed_args out;

	env.verbose = "0";

	ELA_ASSERT_INT_EQ(0, ela_orom_parse_args(2, argv, "efi", &env,
						 &out, NULL, 0));
	ELA_ASSERT_FALSE(out.verbose);
}

static void test_orom_parse_args_env_fmt_csv(void)
{
	char *argv[] = { "prog", "list", NULL };
	struct ela_orom_env env = { 0 };
	struct ela_orom_parsed_args out;

	env.output_fmt = "csv";

	ELA_ASSERT_INT_EQ(0, ela_orom_parse_args(2, argv, "efi", &env,
						 &out, NULL, 0));
	ELA_ASSERT_INT_EQ(OROM_FMT_CSV, (int)out.fmt);
}

static void test_orom_parse_args_unknown_flag(void)
{
	char *argv[] = { "prog", "list", "--unknown", NULL };
	struct ela_orom_parsed_args out;

	ELA_ASSERT_INT_EQ(2, ela_orom_parse_args(3, argv, "efi", NULL,
						 &out, NULL, 0));
}

int run_orom_pull_cmd_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "orom_tcp_header_normal",                  test_orom_tcp_header_normal },
		{ "orom_tcp_header_zero_len",                test_orom_tcp_header_zero_len },
		{ "orom_tcp_header_rejects_overflow",        test_orom_tcp_header_rejects_overflow },
		{ "orom_tcp_header_rejects_null_hdr",        test_orom_tcp_header_rejects_null_hdr },
		{ "orom_tcp_header_rejects_zero_buf_sz",     test_orom_tcp_header_rejects_zero_buf_sz },
		{ "orom_tcp_header_rejects_null_name",       test_orom_tcp_header_rejects_null_name },
		{ "orom_http_payload_normal",                test_orom_http_payload_normal },
		{ "orom_http_payload_zero_data",             test_orom_http_payload_zero_data },
		{ "orom_http_payload_rejects_null_name",     test_orom_http_payload_rejects_null_name },
		{ "orom_http_payload_rejects_null_out",      test_orom_http_payload_rejects_null_out },
		{ "orom_http_payload_rejects_null_out_len",  test_orom_http_payload_rejects_null_out_len },
		{ "orom_http_payload_rejects_null_data_len", test_orom_http_payload_rejects_null_data_with_len },
		{ "orom_parse_args_too_few_args",            test_orom_parse_args_too_few_args },
		{ "orom_parse_args_help_action",             test_orom_parse_args_help_action },
		{ "orom_parse_args_unknown_action",          test_orom_parse_args_unknown_action },
		{ "orom_parse_args_list_no_flags",           test_orom_parse_args_list_no_flags },
		{ "orom_parse_args_pull_missing_output",     test_orom_parse_args_pull_missing_output },
		{ "orom_parse_args_pull_with_tcp",           test_orom_parse_args_pull_with_tcp },
		{ "orom_parse_args_pull_with_http",          test_orom_parse_args_pull_with_http },
		{ "orom_parse_args_pull_with_https",         test_orom_parse_args_pull_with_https },
		{ "orom_parse_args_invalid_http_scheme",     test_orom_parse_args_invalid_http_scheme },
		{ "orom_parse_args_extra_positional_arg",    test_orom_parse_args_extra_positional_arg },
		{ "orom_parse_args_help_flag_after_action",  test_orom_parse_args_help_flag_after_action },
		{ "orom_parse_args_env_tcp_satisfies_pull",  test_orom_parse_args_env_tcp_satisfies_pull },
		{ "orom_parse_args_env_verbose_and_insecure", test_orom_parse_args_env_verbose_and_insecure },
		{ "orom_parse_args_env_verbose_off",         test_orom_parse_args_env_verbose_off },
		{ "orom_parse_args_env_fmt_csv",             test_orom_parse_args_env_fmt_csv },
		{ "orom_parse_args_unknown_flag",            test_orom_parse_args_unknown_flag },
	};

	return ela_run_test_suite("orom_pull_cmd_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
