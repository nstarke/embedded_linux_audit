// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/linux/linux_pcap_cmd_util.h"

#include <stdint.h>

static void test_pcap_global_header_uses_classic_pcap_defaults(void)
{
	struct ela_pcap_file_header hdr;

	ELA_ASSERT_INT_EQ(0, ela_pcap_make_global_header(1, 65535, &hdr));
	ELA_ASSERT_INT_EQ(ELA_PCAP_MAGIC_USEC, hdr.magic);
	ELA_ASSERT_INT_EQ(ELA_PCAP_VERSION_MAJOR, hdr.version_major);
	ELA_ASSERT_INT_EQ(ELA_PCAP_VERSION_MINOR, hdr.version_minor);
	ELA_ASSERT_INT_EQ(0, hdr.thiszone);
	ELA_ASSERT_INT_EQ(0, hdr.sigfigs);
	ELA_ASSERT_INT_EQ(65535, hdr.snaplen);
	ELA_ASSERT_INT_EQ(1, hdr.linktype);
	ELA_ASSERT_INT_EQ(24, sizeof(hdr));
}

static void test_pcap_global_header_rejects_invalid_values(void)
{
	struct ela_pcap_file_header hdr;

	ELA_ASSERT_INT_EQ(-1, ela_pcap_make_global_header(1, 65535, NULL));
	ELA_ASSERT_INT_EQ(-1, ela_pcap_make_global_header(-1, 65535, &hdr));
	ELA_ASSERT_INT_EQ(-1, ela_pcap_make_global_header(1, 0, &hdr));
}

static void test_pcap_record_header_copies_timestamp_and_lengths(void)
{
	struct timeval ts;
	struct ela_pcap_record_header rec;

	ts.tv_sec = 42;
	ts.tv_usec = 123456;

	ELA_ASSERT_INT_EQ(0, ela_pcap_make_record_header(&ts, 64, 128, &rec));
	ELA_ASSERT_INT_EQ(42, rec.ts_sec);
	ELA_ASSERT_INT_EQ(123456, rec.ts_usec);
	ELA_ASSERT_INT_EQ(64, rec.caplen);
	ELA_ASSERT_INT_EQ(128, rec.len);
	ELA_ASSERT_INT_EQ(16, sizeof(rec));
}

static void test_pcap_record_header_rejects_invalid_values(void)
{
	struct timeval ts;
	struct ela_pcap_record_header rec;

	ts.tv_sec = 1;
	ts.tv_usec = 2;

	ELA_ASSERT_INT_EQ(-1, ela_pcap_make_record_header(NULL, 1, 1, &rec));
	ELA_ASSERT_INT_EQ(-1, ela_pcap_make_record_header(&ts, 1, 1, NULL));
	ELA_ASSERT_INT_EQ(-1, ela_pcap_make_record_header(&ts, 2, 1, &rec));
}

static void test_pcap_ws_url_derives_endpoint_from_http_authority(void)
{
	char url[128];

	ELA_ASSERT_INT_EQ(0, ela_pcap_build_ws_url("http://127.0.0.1:5000/upload",
						   "aa:bb:cc:dd:ee:ff",
						   url,
						   sizeof(url)));
	ELA_ASSERT_STR_EQ("ws://127.0.0.1:5000/pcap/aa:bb:cc:dd:ee:ff", url);

	ELA_ASSERT_INT_EQ(0, ela_pcap_build_ws_url("https://agent.example.test/api?x=1",
						   "00:11:22:33:44:55",
						   url,
						   sizeof(url)));
	ELA_ASSERT_STR_EQ("wss://agent.example.test/pcap/00:11:22:33:44:55", url);
}

static void test_pcap_ws_url_rejects_invalid_or_too_small_inputs(void)
{
	char url[16];

	ELA_ASSERT_INT_EQ(-1, ela_pcap_build_ws_url(NULL, "aa:bb", url, sizeof(url)));
	ELA_ASSERT_INT_EQ(-1, ela_pcap_build_ws_url("ftp://host", "aa:bb", url, sizeof(url)));
	ELA_ASSERT_INT_EQ(-1, ela_pcap_build_ws_url("http:///path", "aa:bb", url, sizeof(url)));
	ELA_ASSERT_INT_EQ(-1, ela_pcap_build_ws_url("http://host", "", url, sizeof(url)));
	ELA_ASSERT_INT_EQ(-1, ela_pcap_build_ws_url("http://host", "aa:bb", url, 4));
}

int run_linux_pcap_cmd_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "pcap_global_header_uses_classic_pcap_defaults", test_pcap_global_header_uses_classic_pcap_defaults },
		{ "pcap_global_header_rejects_invalid_values", test_pcap_global_header_rejects_invalid_values },
		{ "pcap_record_header_copies_timestamp_and_lengths", test_pcap_record_header_copies_timestamp_and_lengths },
		{ "pcap_record_header_rejects_invalid_values", test_pcap_record_header_rejects_invalid_values },
		{ "pcap_ws_url_derives_endpoint_from_http_authority", test_pcap_ws_url_derives_endpoint_from_http_authority },
		{ "pcap_ws_url_rejects_invalid_or_too_small_inputs", test_pcap_ws_url_rejects_invalid_or_too_small_inputs },
	};

	return ela_run_test_suite("linux_pcap_cmd_util", cases, sizeof(cases) / sizeof(cases[0]));
}
