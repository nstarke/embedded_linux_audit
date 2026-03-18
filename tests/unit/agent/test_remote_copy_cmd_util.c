// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/linux/remote_copy_cmd_util.h"

#include <string.h>
#include <sys/stat.h>

static void test_remote_copy_validate_request_accepts_valid_http_and_tcp_cases(void)
{
	char errbuf[256];

	ELA_ASSERT_INT_EQ(0, ela_remote_copy_validate_request("/tmp/file", NULL, NULL, "https://ela.example/upload",
							       S_IFREG, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(0, ela_remote_copy_validate_request("/tmp/file", "127.0.0.1:9000", NULL, NULL,
							       S_IFREG, errbuf, sizeof(errbuf)));
}

static void test_remote_copy_validate_request_rejects_invalid_combinations(void)
{
	char errbuf[256];

	ELA_ASSERT_INT_EQ(-1, ela_remote_copy_validate_request("relative", NULL, "http://ela", NULL,
								S_IFREG, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "absolute") != NULL);
	ELA_ASSERT_INT_EQ(-1, ela_remote_copy_validate_request("/tmp/dir", "127.0.0.1:9000", NULL, NULL,
								S_IFDIR, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Directory uploads require --output-http") != NULL);
	ELA_ASSERT_INT_EQ(-1, ela_remote_copy_validate_request("/tmp/link", "127.0.0.1:9000", NULL, NULL,
								S_IFLNK, errbuf, sizeof(errbuf)));
}

int run_remote_copy_cmd_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "remote_copy_validate_request_accepts_valid_http_and_tcp_cases", test_remote_copy_validate_request_accepts_valid_http_and_tcp_cases },
		{ "remote_copy_validate_request_rejects_invalid_combinations", test_remote_copy_validate_request_rejects_invalid_combinations },
	};

	return ela_run_test_suite("remote_copy_cmd_util", cases, sizeof(cases) / sizeof(cases[0]));
}
