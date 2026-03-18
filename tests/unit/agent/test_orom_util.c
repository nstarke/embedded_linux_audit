// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_harness.h"
#include "../../../agent/util/orom_util.h"

#include <stdio.h>
#include <stdlib.h>

static char *read_fixture(const char *path)
{
	FILE *fp;
	long size;
	char *buf;

	fp = fopen(path, "rb");
	if (!fp)
		return NULL;
	if (fseek(fp, 0, SEEK_END) != 0) {
		fclose(fp);
		return NULL;
	}
	size = ftell(fp);
	if (size < 0) {
		fclose(fp);
		return NULL;
	}
	if (fseek(fp, 0, SEEK_SET) != 0) {
		fclose(fp);
		return NULL;
	}
	buf = calloc((size_t)size + 1, 1);
	if (!buf) {
		fclose(fp);
		return NULL;
	}
	if (size > 0 && fread(buf, 1, (size_t)size, fp) != (size_t)size) {
		fclose(fp);
		free(buf);
		return NULL;
	}
	fclose(fp);
	return buf;
}

static void assert_matches_fixture(const char *fixture_path, const char *actual)
{
	char *expected = read_fixture(fixture_path);

	ELA_ASSERT_TRUE(expected != NULL);
	ELA_ASSERT_STR_EQ(expected, actual);
	free(expected);
}

static void test_orom_detect_output_format_and_mode_matching(void)
{
	uint8_t rom[64] = {0};

	rom[8] = 'P'; rom[9] = 'C'; rom[10] = 'I'; rom[11] = 'R';
	rom[0x1c] = 0x03;

	ELA_ASSERT_INT_EQ(OROM_FMT_TXT, ela_orom_detect_output_format(NULL));
	ELA_ASSERT_INT_EQ(OROM_FMT_JSON, ela_orom_detect_output_format("json"));
	ELA_ASSERT_FALSE(ela_orom_rom_matches_mode(rom, sizeof(rom), "bios"));
	ELA_ASSERT_TRUE(ela_orom_rom_matches_mode(rom, sizeof(rom), "efi"));
}

static void test_orom_formatter_matches_fixtures(void)
{
	struct output_buffer out = {0};

	ELA_ASSERT_INT_EQ(0, ela_orom_format_record(&out, OROM_FMT_TXT, "efi", "orom_list", "/sys/bus/pci/devices/0000:00:01.0/rom", 4096, "match", "true"));
	assert_matches_fixture("tests/unit/agent/fixtures/orom.txt", out.data);
	free(out.data);
	out = (struct output_buffer){0};

	ELA_ASSERT_INT_EQ(0, ela_orom_format_record(&out, OROM_FMT_CSV, "efi", "orom_list", "/sys/bus/pci/devices/0000:00:01.0/rom", 4096, "match", "true"));
	assert_matches_fixture("tests/unit/agent/fixtures/orom.csv", out.data);
	free(out.data);
	out = (struct output_buffer){0};

	ELA_ASSERT_INT_EQ(0, ela_orom_format_record(&out, OROM_FMT_JSON, "efi", "orom_list", "/sys/bus/pci/devices/0000:00:01.0/rom", 4096, "match", "true"));
	assert_matches_fixture("tests/unit/agent/fixtures/orom.json", out.data);
	free(out.data);
}

int run_orom_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "orom_detect_output_format_and_mode_matching", test_orom_detect_output_format_and_mode_matching },
		{ "orom_formatter_matches_fixtures", test_orom_formatter_matches_fixtures },
	};

	return ela_run_test_suite("orom_util", cases, sizeof(cases) / sizeof(cases[0]));
}
