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

static void put_u16(uint8_t *p, uint16_t v, int little_endian)
{
	if (little_endian) {
		p[0] = (uint8_t)v;
		p[1] = (uint8_t)(v >> 8);
	} else {
		p[0] = (uint8_t)(v >> 8);
		p[1] = (uint8_t)v;
	}
}

static void put_u32(uint8_t *p, uint32_t v, int little_endian)
{
	if (little_endian) {
		p[0] = (uint8_t)v;
		p[1] = (uint8_t)(v >> 8);
		p[2] = (uint8_t)(v >> 16);
		p[3] = (uint8_t)(v >> 24);
	} else {
		p[0] = (uint8_t)(v >> 24);
		p[1] = (uint8_t)(v >> 16);
		p[2] = (uint8_t)(v >> 8);
		p[3] = (uint8_t)v;
	}
}

static void build_global_header(uint8_t *buf, int little_endian)
{
	put_u32(buf + 0, ELA_PCAP_MAGIC_USEC, little_endian);
	put_u16(buf + 4, ELA_PCAP_VERSION_MAJOR, little_endian);
	put_u16(buf + 6, ELA_PCAP_VERSION_MINOR, little_endian);
	put_u32(buf + 8, 0, little_endian);
	put_u32(buf + 12, 0, little_endian);
	put_u32(buf + 16, 65535, little_endian);
	put_u32(buf + 20, 1, little_endian);
}

static void build_record_header(uint8_t *buf, int little_endian)
{
	put_u32(buf + 0, 42, little_endian);
	put_u32(buf + 4, 123456, little_endian);
	put_u32(buf + 8, 64, little_endian);
	put_u32(buf + 12, 128, little_endian);
}

/*
 * Parsing must normalize fields to host byte order regardless of the file's
 * on-disk endianness, so a little-endian and a big-endian header that encode
 * the same values must parse identically. One of the two always exercises the
 * byte-swap path on any host.
 */
static void test_pcap_parse_global_header_normalizes_either_endianness(void)
{
	uint8_t buf[24];
	struct ela_pcap_file_header hdr;
	int endian;

	for (endian = 0; endian <= 1; endian++) {
		int needs_swap = -1;

		build_global_header(buf, endian);
		ELA_ASSERT_INT_EQ(0, ela_pcap_parse_global_header(buf, sizeof(buf),
								  &hdr, &needs_swap));
		ELA_ASSERT_INT_EQ(ELA_PCAP_VERSION_MAJOR, hdr.version_major);
		ELA_ASSERT_INT_EQ(ELA_PCAP_VERSION_MINOR, hdr.version_minor);
		ELA_ASSERT_INT_EQ(0, hdr.thiszone);
		ELA_ASSERT_INT_EQ(0, hdr.sigfigs);
		ELA_ASSERT_INT_EQ(65535, hdr.snaplen);
		ELA_ASSERT_INT_EQ(1, hdr.linktype);
		ELA_ASSERT_INT_EQ(1, hdr.magic == ELA_PCAP_MAGIC_USEC ||
				     hdr.magic == ELA_PCAP_MAGIC_USEC_SWAPPED);
		ELA_ASSERT_INT_EQ(1, needs_swap == 0 || needs_swap == 1);
	}
}

static void test_pcap_parse_global_header_rejects_bad_or_short_input(void)
{
	uint8_t buf[24];
	struct ela_pcap_file_header hdr;
	int needs_swap = 0;

	build_global_header(buf, 1);
	ELA_ASSERT_INT_EQ(-1, ela_pcap_parse_global_header(NULL, sizeof(buf), &hdr, &needs_swap));
	ELA_ASSERT_INT_EQ(-1, ela_pcap_parse_global_header(buf, sizeof(buf), NULL, &needs_swap));
	ELA_ASSERT_INT_EQ(-1, ela_pcap_parse_global_header(buf, sizeof(buf), &hdr, NULL));
	ELA_ASSERT_INT_EQ(-1, ela_pcap_parse_global_header(buf, 23, &hdr, &needs_swap));

	/* Corrupt the magic so it matches none of the recognized values. */
	buf[0] = 0x00;
	buf[1] = 0x00;
	buf[2] = 0x00;
	buf[3] = 0x00;
	ELA_ASSERT_INT_EQ(-1, ela_pcap_parse_global_header(buf, sizeof(buf), &hdr, &needs_swap));
}

static void test_pcap_parse_record_header_normalizes_either_endianness(void)
{
	uint8_t ghdr[24];
	uint8_t rhdr[16];
	struct ela_pcap_file_header file_hdr;
	struct ela_pcap_record_header rec;
	int endian;

	for (endian = 0; endian <= 1; endian++) {
		int needs_swap = -1;

		build_global_header(ghdr, endian);
		ELA_ASSERT_INT_EQ(0, ela_pcap_parse_global_header(ghdr, sizeof(ghdr),
								  &file_hdr, &needs_swap));
		build_record_header(rhdr, endian);
		ELA_ASSERT_INT_EQ(0, ela_pcap_parse_record_header(rhdr, sizeof(rhdr),
								  needs_swap, &rec));
		ELA_ASSERT_INT_EQ(42, rec.ts_sec);
		ELA_ASSERT_INT_EQ(123456, rec.ts_usec);
		ELA_ASSERT_INT_EQ(64, rec.caplen);
		ELA_ASSERT_INT_EQ(128, rec.len);
	}
}

static void test_pcap_parse_record_header_rejects_invalid_input(void)
{
	uint8_t rhdr[16];
	struct ela_pcap_record_header rec;

	build_record_header(rhdr, 1);
	ELA_ASSERT_INT_EQ(-1, ela_pcap_parse_record_header(NULL, sizeof(rhdr), 0, &rec));
	ELA_ASSERT_INT_EQ(-1, ela_pcap_parse_record_header(rhdr, sizeof(rhdr), 0, NULL));
	ELA_ASSERT_INT_EQ(-1, ela_pcap_parse_record_header(rhdr, 15, 0, &rec));

	/* caplen (offset 8) greater than len (offset 12) is rejected. */
	put_u32(rhdr + 8, 200, 1);
	put_u32(rhdr + 12, 100, 1);
	ELA_ASSERT_INT_EQ(-1, ela_pcap_parse_record_header(rhdr, sizeof(rhdr), 0, &rec));
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
		{ "pcap_parse_global_header_normalizes_either_endianness", test_pcap_parse_global_header_normalizes_either_endianness },
		{ "pcap_parse_global_header_rejects_bad_or_short_input", test_pcap_parse_global_header_rejects_bad_or_short_input },
		{ "pcap_parse_record_header_normalizes_either_endianness", test_pcap_parse_record_header_normalizes_either_endianness },
		{ "pcap_parse_record_header_rejects_invalid_input", test_pcap_parse_record_header_rejects_invalid_input },
	};

	return ela_run_test_suite("linux_pcap_cmd_util", cases, sizeof(cases) / sizeof(cases[0]));
}
