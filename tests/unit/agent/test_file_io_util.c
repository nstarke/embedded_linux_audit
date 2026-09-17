// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/file_io_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void test_write_all_binary_and_errors(void)
{
	FILE *fp = tmpfile();
	const unsigned char payload[] = { 'a', 0, 'b', 255 };
	unsigned char readback[sizeof(payload)];

	ELA_ASSERT_TRUE(fp != NULL);
	ELA_ASSERT_INT_EQ(0, ela_write_all(fileno(fp), payload, sizeof(payload)));
	rewind(fp);
	ELA_ASSERT_INT_EQ((int)sizeof(payload), (int)fread(readback, 1, sizeof(readback), fp));
	ELA_ASSERT_TRUE(memcmp(readback, payload, sizeof(payload)) == 0);
	fclose(fp);
	ELA_ASSERT_INT_EQ(-1, ela_write_all(-1, payload, sizeof(payload)));
	ELA_ASSERT_INT_EQ(0, ela_write_all(-1, NULL, 0));
}

static void test_readlink_basename_and_truncation(void)
{
	char directory[] = "/tmp/ela-file-io-XXXXXX";
	char link[128];
	char out[32];

	ELA_ASSERT_TRUE(mkdtemp(directory) != NULL);
	snprintf(link, sizeof(link), "%s/driver", directory);
	ELA_ASSERT_INT_EQ(0, symlink("../../drivers/example", link));
	ELA_ASSERT_INT_EQ(0, ela_readlink_basename(link, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("example", out);
	ELA_ASSERT_INT_EQ(0, ela_readlink_basename(link, out, 4));
	ELA_ASSERT_STR_EQ("exa", out);
	ELA_ASSERT_INT_EQ(0, ela_readlink_basename(link, out, 1));
	ELA_ASSERT_STR_EQ("", out);
	ELA_ASSERT_INT_EQ(-1, ela_readlink_basename(link, out, 0));
	unlink(link);
	ELA_ASSERT_INT_EQ(-1, ela_readlink_basename(link, out, sizeof(out)));
	rmdir(directory);
}

int run_file_io_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "write-all/binary-and-errors", test_write_all_binary_and_errors },
		{ "readlink/basename-and-truncation", test_readlink_basename_and_truncation },
	};

	return ela_run_test_suite("file_io_util", cases, sizeof(cases) / sizeof(cases[0]));
}
