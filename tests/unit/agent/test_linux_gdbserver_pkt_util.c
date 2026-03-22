// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/linux/linux_gdbserver_pkt_util.h"

#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>

/* =========================================================================
 * ela_gdb_parse_thread_id
 * ====================================================================== */

static void test_parse_thread_id_plain(void)
{
	pid_t pid = 99, tid = 99;
	int n;

	/* plain hex TID, no multiprocess prefix */
	n = ela_gdb_parse_thread_id("1a", &pid, &tid);
	ELA_ASSERT_INT_EQ(2, n);
	ELA_ASSERT_INT_EQ(0,  (int)pid);
	ELA_ASSERT_INT_EQ(26, (int)tid);
}

static void test_parse_thread_id_multiprocess(void)
{
	pid_t pid = 0, tid = 0;
	int n;

	/* p<pid>.<tid> multiprocess form */
	n = ela_gdb_parse_thread_id("p1234.5678", &pid, &tid);
	ELA_ASSERT_INT_EQ(10, n);
	ELA_ASSERT_INT_EQ(0x1234, (int)pid);
	ELA_ASSERT_INT_EQ(0x5678, (int)tid);
}

static void test_parse_thread_id_null_outputs(void)
{
	/* Both output pointers NULL — should not crash */
	int n = ela_gdb_parse_thread_id("ff", NULL, NULL);

	ELA_ASSERT_INT_EQ(2, n);
}

static void test_parse_thread_id_null_input(void)
{
	pid_t pid, tid;

	ELA_ASSERT_INT_EQ(-1, ela_gdb_parse_thread_id(NULL, &pid, &tid));
}

static void test_parse_thread_id_empty(void)
{
	pid_t pid, tid;

	ELA_ASSERT_INT_EQ(-1, ela_gdb_parse_thread_id("", &pid, &tid));
}

static void test_parse_thread_id_p_no_dot(void)
{
	pid_t pid, tid;

	/* 'p' prefix but missing dot — invalid */
	ELA_ASSERT_INT_EQ(-1, ela_gdb_parse_thread_id("p1234", &pid, &tid));
}

static void test_parse_thread_id_multiprocess_only_pid(void)
{
	pid_t pid = 0, tid = 0;
	int n;

	n = ela_gdb_parse_thread_id("pff.1", &pid, &tid);
	ELA_ASSERT_INT_EQ(5, n);
	ELA_ASSERT_INT_EQ(0xff, (int)pid);
	ELA_ASSERT_INT_EQ(1,    (int)tid);
}

static void test_parse_thread_id_plain_1(void)
{
	pid_t pid = 99, tid = 0;
	int n;

	n = ela_gdb_parse_thread_id("1", &pid, &tid);
	ELA_ASSERT_INT_EQ(1, n);
	ELA_ASSERT_INT_EQ(0, (int)pid);
	ELA_ASSERT_INT_EQ(1, (int)tid);
}

/* =========================================================================
 * ela_gdb_rsp_binary_unescape
 * ====================================================================== */

static void test_binary_unescape_plain(void)
{
	const char src[] = "abc";
	uint8_t dst[4];
	int n;

	n = ela_gdb_rsp_binary_unescape(src, sizeof(src) - 1, dst, 3);
	ELA_ASSERT_INT_EQ(3, n);
	ELA_ASSERT_INT_EQ('a', (int)dst[0]);
	ELA_ASSERT_INT_EQ('b', (int)dst[1]);
	ELA_ASSERT_INT_EQ('c', (int)dst[2]);
}

static void test_binary_unescape_escape_sequence(void)
{
	/* 0x7d 0x5d decodes to 0x5d ^ 0x20 = 0x7d (the escape byte itself) */
	const uint8_t src[] = { 0x7d, 0x5d };
	uint8_t dst[2];
	int n;

	n = ela_gdb_rsp_binary_unescape((const char *)src, 2, dst, 1);
	ELA_ASSERT_INT_EQ(1, n);
	ELA_ASSERT_INT_EQ(0x7d, (int)dst[0]);
}

static void test_binary_unescape_escape_hash(void)
{
	/* '#' (0x23) is escaped as 0x7d 0x03; 0x03 ^ 0x20 = 0x23 */
	const uint8_t src[] = { 0x7d, 0x03 };
	uint8_t dst[2];
	int n;

	n = ela_gdb_rsp_binary_unescape((const char *)src, 2, dst, 1);
	ELA_ASSERT_INT_EQ(1, n);
	ELA_ASSERT_INT_EQ('#', (int)dst[0]);
}

static void test_binary_unescape_src_exhausted(void)
{
	/* max_src too small to produce expected bytes */
	const char src[] = "ab";
	uint8_t dst[4];

	ELA_ASSERT_INT_EQ(-1,
		ela_gdb_rsp_binary_unescape(src, 2, dst, 3));
}

static void test_binary_unescape_escape_at_end(void)
{
	/* escape byte (0x7d) at end with no following byte — should fail */
	const uint8_t src[] = { 0x7d };
	uint8_t dst[2];

	ELA_ASSERT_INT_EQ(-1,
		ela_gdb_rsp_binary_unescape((const char *)src, 1, dst, 1));
}

static void test_binary_unescape_zero_expected(void)
{
	/* requesting 0 output bytes should always succeed immediately */
	const char src[] = "xyz";
	uint8_t dst[4];
	int n;

	n = ela_gdb_rsp_binary_unescape(src, sizeof(src) - 1, dst, 0);
	ELA_ASSERT_INT_EQ(0, n);
}

static void test_binary_unescape_mixed(void)
{
	/* 'A' 0x7d 0x04 'B'  → 'A' '$' 'B'  (0x04^0x20=0x24='$') */
	const uint8_t src[] = { 'A', 0x7d, 0x04, 'B' };
	uint8_t dst[4];
	int n;

	n = ela_gdb_rsp_binary_unescape((const char *)src, 4, dst, 3);
	ELA_ASSERT_INT_EQ(3, n);
	ELA_ASSERT_INT_EQ('A',  (int)dst[0]);
	ELA_ASSERT_INT_EQ('$',  (int)dst[1]);
	ELA_ASSERT_INT_EQ('B',  (int)dst[2]);
}

/* =========================================================================
 * ela_gdb_vfile_encode_stat
 * ====================================================================== */

/*
 * Helper: read a 32-bit big-endian value from buf at offset off.
 */
static uint32_t read_be32(const uint8_t *buf, size_t off)
{
	return ((uint32_t)buf[off]   << 24) |
	       ((uint32_t)buf[off+1] << 16) |
	       ((uint32_t)buf[off+2] <<  8) |
	        (uint32_t)buf[off+3];
}

static uint64_t read_be64(const uint8_t *buf, size_t off)
{
	return ((uint64_t)read_be32(buf, off) << 32) |
	        (uint64_t)read_be32(buf, off + 4);
}

static void test_vfile_encode_stat_zeroes_buffer(void)
{
	struct stat st;
	uint8_t buf[64];

	memset(&st, 0, sizeof(st));
	memset(buf, 0xff, sizeof(buf));
	ela_gdb_vfile_encode_stat(buf, &st);

	/* All fields zero → whole buffer should be zero */
	ELA_ASSERT_TRUE(read_be64(buf, 28) == 0); /* st_size */
	ELA_ASSERT_TRUE(read_be32(buf, 52) == 0); /* st_atime */
}

static void test_vfile_encode_stat_dev(void)
{
	struct stat st;
	uint8_t buf[64];

	memset(&st, 0, sizeof(st));
	st.st_dev = 0x12345678u;
	ela_gdb_vfile_encode_stat(buf, &st);
	ELA_ASSERT_TRUE(read_be32(buf, 0) == 0x12345678u);
}

static void test_vfile_encode_stat_mode(void)
{
	struct stat st;
	uint8_t buf[64];

	memset(&st, 0, sizeof(st));
	st.st_mode = 0100755u; /* regular file, rwxr-xr-x */
	ela_gdb_vfile_encode_stat(buf, &st);
	ELA_ASSERT_TRUE(read_be32(buf, 8) == 0100755u);
}

static void test_vfile_encode_stat_size(void)
{
	struct stat st;
	uint8_t buf[64];

	memset(&st, 0, sizeof(st));
	st.st_size = UINT64_C(0x0102030405060708);
	ela_gdb_vfile_encode_stat(buf, &st);
	ELA_ASSERT_TRUE(read_be64(buf, 28) == UINT64_C(0x0102030405060708));
}

static void test_vfile_encode_stat_timestamps(void)
{
	struct stat st;
	uint8_t buf[64];

	memset(&st, 0, sizeof(st));
	st.st_atime = 0xaabbccdd;
	st.st_mtime = 0x11223344;
	st.st_ctime = 0xdeadbeef;
	ela_gdb_vfile_encode_stat(buf, &st);
	ELA_ASSERT_TRUE(read_be32(buf, 52) == 0xaabbccddu);
	ELA_ASSERT_TRUE(read_be32(buf, 56) == 0x11223344u);
	ELA_ASSERT_TRUE(read_be32(buf, 60) == 0xdeadbeefu);
}

/* =========================================================================
 * ela_gdb_vfile_flags_to_linux
 * ====================================================================== */

static void test_vfile_flags_rdonly(void)
{
	/* GDB O_RDONLY = 0 */
	ELA_ASSERT_INT_EQ(0, ela_gdb_vfile_flags_to_linux(0));
}

static void test_vfile_flags_wronly(void)
{
	/* GDB O_WRONLY = 1; Linux O_WRONLY = 1 */
	ELA_ASSERT_INT_EQ(1, ela_gdb_vfile_flags_to_linux(1));
}

static void test_vfile_flags_rdwr(void)
{
	/* GDB O_RDWR = 2; Linux O_RDWR = 2 */
	ELA_ASSERT_INT_EQ(2, ela_gdb_vfile_flags_to_linux(2));
}

static void test_vfile_flags_append(void)
{
	int lflags = ela_gdb_vfile_flags_to_linux(0x008);

	ELA_ASSERT_TRUE((lflags & O_APPEND) != 0);
}

static void test_vfile_flags_creat(void)
{
	int lflags = ela_gdb_vfile_flags_to_linux(0x200);

	ELA_ASSERT_TRUE((lflags & O_CREAT) != 0);
}

static void test_vfile_flags_trunc(void)
{
	int lflags = ela_gdb_vfile_flags_to_linux(0x400);

	ELA_ASSERT_TRUE((lflags & O_TRUNC) != 0);
}

static void test_vfile_flags_excl(void)
{
	int lflags = ela_gdb_vfile_flags_to_linux(0x800);

	ELA_ASSERT_TRUE((lflags & O_EXCL) != 0);
}

static void test_vfile_flags_combined(void)
{
	/* GDB O_WRONLY | O_CREAT | O_TRUNC = 0x601 */
	int lflags = ela_gdb_vfile_flags_to_linux(0x601);

	ELA_ASSERT_TRUE((lflags & 1) != 0);       /* O_WRONLY */
	ELA_ASSERT_TRUE((lflags & O_CREAT) != 0);
	ELA_ASSERT_TRUE((lflags & O_TRUNC) != 0);
}

/* =========================================================================
 * Test suite registration
 * ====================================================================== */

int run_linux_gdbserver_pkt_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "parse_thread_id/plain",             test_parse_thread_id_plain },
		{ "parse_thread_id/multiprocess",      test_parse_thread_id_multiprocess },
		{ "parse_thread_id/null_outputs",      test_parse_thread_id_null_outputs },
		{ "parse_thread_id/null_input",        test_parse_thread_id_null_input },
		{ "parse_thread_id/empty",             test_parse_thread_id_empty },
		{ "parse_thread_id/p_no_dot",          test_parse_thread_id_p_no_dot },
		{ "parse_thread_id/mp_only_pid",       test_parse_thread_id_multiprocess_only_pid },
		{ "parse_thread_id/plain_1",           test_parse_thread_id_plain_1 },
		{ "rsp_binary_unescape/plain",         test_binary_unescape_plain },
		{ "rsp_binary_unescape/escape_self",   test_binary_unescape_escape_sequence },
		{ "rsp_binary_unescape/escape_hash",   test_binary_unescape_escape_hash },
		{ "rsp_binary_unescape/src_exhausted", test_binary_unescape_src_exhausted },
		{ "rsp_binary_unescape/escape_at_end", test_binary_unescape_escape_at_end },
		{ "rsp_binary_unescape/zero_expected", test_binary_unescape_zero_expected },
		{ "rsp_binary_unescape/mixed",         test_binary_unescape_mixed },
		{ "vfile_encode_stat/zeroes_buffer",   test_vfile_encode_stat_zeroes_buffer },
		{ "vfile_encode_stat/dev",             test_vfile_encode_stat_dev },
		{ "vfile_encode_stat/mode",            test_vfile_encode_stat_mode },
		{ "vfile_encode_stat/size",            test_vfile_encode_stat_size },
		{ "vfile_encode_stat/timestamps",      test_vfile_encode_stat_timestamps },
		{ "vfile_flags_to_linux/rdonly",       test_vfile_flags_rdonly },
		{ "vfile_flags_to_linux/wronly",       test_vfile_flags_wronly },
		{ "vfile_flags_to_linux/rdwr",         test_vfile_flags_rdwr },
		{ "vfile_flags_to_linux/append",       test_vfile_flags_append },
		{ "vfile_flags_to_linux/creat",        test_vfile_flags_creat },
		{ "vfile_flags_to_linux/trunc",        test_vfile_flags_trunc },
		{ "vfile_flags_to_linux/excl",         test_vfile_flags_excl },
		{ "vfile_flags_to_linux/combined",     test_vfile_flags_combined },
	};

	return ela_run_test_suite("linux_gdbserver_pkt_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
