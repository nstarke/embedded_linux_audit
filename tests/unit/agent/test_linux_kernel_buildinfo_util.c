// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../../../agent/linux/linux_kernel_buildinfo_util.h"
#include "test_harness.h"

#include <string.h>

static void test_config_candidate_ordering(void)
{
	char out[256];

	ELA_ASSERT_INT_EQ(0, ela_kernel_buildinfo_config_candidate(
		NULL, "6.1.0-rpi7-rpi-v8", 0, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("/proc/config.gz", out);

	ELA_ASSERT_INT_EQ(0, ela_kernel_buildinfo_config_candidate(
		NULL, "6.1.0-rpi7-rpi-v8", 1, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("/boot/config-6.1.0-rpi7-rpi-v8", out);

	ELA_ASSERT_INT_EQ(0, ela_kernel_buildinfo_config_candidate(
		NULL, "6.1.0-rpi7-rpi-v8", 2, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("/proc/config", out);

	ELA_ASSERT_INT_EQ(-1, ela_kernel_buildinfo_config_candidate(
		NULL, "6.1.0", 3, out, sizeof(out)));
}

static void test_config_candidate_with_root_prefix(void)
{
	char out[256];

	ELA_ASSERT_INT_EQ(0, ela_kernel_buildinfo_config_candidate(
		"/tmp/fixture", "3.12.19-rt30", 0, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("/tmp/fixture/proc/config.gz", out);

	ELA_ASSERT_INT_EQ(0, ela_kernel_buildinfo_config_candidate(
		"/tmp/fixture", "3.12.19-rt30", 1, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("/tmp/fixture/boot/config-3.12.19-rt30", out);
}

static void test_config_candidate_rejects_bad_input(void)
{
	char out[256];
	char tiny[8];

	/* /boot/config-<release> requires a release string. */
	ELA_ASSERT_INT_EQ(-1, ela_kernel_buildinfo_config_candidate(
		NULL, NULL, 1, out, sizeof(out)));
	ELA_ASSERT_INT_EQ(-1, ela_kernel_buildinfo_config_candidate(
		NULL, "", 1, out, sizeof(out)));
	/* Candidates 0 and 2 do not need the release. */
	ELA_ASSERT_INT_EQ(0, ela_kernel_buildinfo_config_candidate(
		NULL, NULL, 0, out, sizeof(out)));
	ELA_ASSERT_INT_EQ(0, ela_kernel_buildinfo_config_candidate(
		NULL, NULL, 2, out, sizeof(out)));

	ELA_ASSERT_INT_EQ(-1, ela_kernel_buildinfo_config_candidate(
		NULL, "6.1.0", 0, NULL, 0));
	ELA_ASSERT_INT_EQ(-1, ela_kernel_buildinfo_config_candidate(
		NULL, "6.1.0", 0, tiny, sizeof(tiny)));
}

static void test_config_is_gz(void)
{
	ELA_ASSERT_TRUE(ela_kernel_buildinfo_config_is_gz("/proc/config.gz"));
	ELA_ASSERT_TRUE(!ela_kernel_buildinfo_config_is_gz("/proc/config"));
	ELA_ASSERT_TRUE(!ela_kernel_buildinfo_config_is_gz("/boot/config-6.1.0"));
	ELA_ASSERT_TRUE(!ela_kernel_buildinfo_config_is_gz(".gz"));
	ELA_ASSERT_TRUE(!ela_kernel_buildinfo_config_is_gz(""));
	ELA_ASSERT_TRUE(!ela_kernel_buildinfo_config_is_gz(NULL));
}

static void test_tool_candidate_walks_path_then_fallbacks(void)
{
	char out[256];

	/* PATH entries come first, in order, skipping empty segments. */
	ELA_ASSERT_INT_EQ(0, ela_kernel_buildinfo_tool_candidate(
		"/opt/bin::/usr/local/bin", "modprobe", 0, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("/opt/bin/modprobe", out);
	ELA_ASSERT_INT_EQ(0, ela_kernel_buildinfo_tool_candidate(
		"/opt/bin::/usr/local/bin", "modprobe", 1, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("/usr/local/bin/modprobe", out);

	/* Then the conventional sbin/bin locations. */
	ELA_ASSERT_INT_EQ(0, ela_kernel_buildinfo_tool_candidate(
		"/opt/bin::/usr/local/bin", "modprobe", 2, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("/sbin/modprobe", out);
	ELA_ASSERT_INT_EQ(0, ela_kernel_buildinfo_tool_candidate(
		"/opt/bin::/usr/local/bin", "modprobe", 5, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("/usr/bin/modprobe", out);

	/* Past the last fallback: done. */
	ELA_ASSERT_INT_EQ(-1, ela_kernel_buildinfo_tool_candidate(
		"/opt/bin::/usr/local/bin", "modprobe", 6, out, sizeof(out)));
}

static void test_tool_candidate_without_path(void)
{
	char out[256];

	/* NULL or empty PATH: fallbacks only. */
	ELA_ASSERT_INT_EQ(0, ela_kernel_buildinfo_tool_candidate(
		NULL, "modprobe", 0, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("/sbin/modprobe", out);
	ELA_ASSERT_INT_EQ(0, ela_kernel_buildinfo_tool_candidate(
		"", "modprobe", 3, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("/usr/bin/modprobe", out);
	ELA_ASSERT_INT_EQ(-1, ela_kernel_buildinfo_tool_candidate(
		NULL, "modprobe", 4, out, sizeof(out)));
}

static void test_tool_candidate_rejects_bad_input(void)
{
	char out[256];
	char tiny[4];

	ELA_ASSERT_INT_EQ(-1, ela_kernel_buildinfo_tool_candidate(
		"/bin", NULL, 0, out, sizeof(out)));
	ELA_ASSERT_INT_EQ(-1, ela_kernel_buildinfo_tool_candidate(
		"/bin", "", 0, out, sizeof(out)));
	ELA_ASSERT_INT_EQ(-1, ela_kernel_buildinfo_tool_candidate(
		"/bin", "modprobe", 0, NULL, 0));
	ELA_ASSERT_INT_EQ(-1, ela_kernel_buildinfo_tool_candidate(
		"/bin", "modprobe", 0, tiny, sizeof(tiny)));
}

static void test_trim_line(void)
{
	char lf[] = "Linux version 6.1.0\n";
	char crlf[] = "Linux version 6.1.0\r\n";
	char bare[] = "Linux version 6.1.0";
	char empty[] = "";

	ELA_ASSERT_STR_EQ("Linux version 6.1.0", ela_kernel_buildinfo_trim_line(lf));
	ELA_ASSERT_STR_EQ("Linux version 6.1.0", ela_kernel_buildinfo_trim_line(crlf));
	ELA_ASSERT_STR_EQ("Linux version 6.1.0", ela_kernel_buildinfo_trim_line(bare));
	ELA_ASSERT_STR_EQ("", ela_kernel_buildinfo_trim_line(empty));
	ELA_ASSERT_TRUE(ela_kernel_buildinfo_trim_line(NULL) == NULL);
}

static struct ela_kernel_buildinfo sample_info(void)
{
	struct ela_kernel_buildinfo info;

	memset(&info, 0, sizeof(info));
	snprintf(info.kernel_release, sizeof(info.kernel_release),
		 "3.12.19-rt30");
	snprintf(info.proc_version, sizeof(info.proc_version),
		 "Linux version 3.12.19-rt30 (gcc version 4.8.2) #1 SMP");
	snprintf(info.vermagic, sizeof(info.vermagic),
		 "3.12.19-rt30 SMP mod_unload ARMv7");
	snprintf(info.module_path, sizeof(info.module_path),
		 "/lib/modules/demo.ko");
	info.isa = "arm32";
	info.bits = "32";
	info.endianness = "little";
	snprintf(info.config_source, sizeof(info.config_source),
		 "/proc/config.gz");
	info.config_available = true;
	info.config_compressed = true;
	return info;
}

static void test_format_payload_json(void)
{
	struct ela_kernel_buildinfo info = sample_info();
	char out[2048];

	ELA_ASSERT_INT_EQ(0, ela_kernel_buildinfo_format_payload(
		"json", &info, out, sizeof(out)));
	ELA_ASSERT_STR_EQ(
		"{\"record\":\"module_buildinfo\","
		"\"kernel_release\":\"3.12.19-rt30\","
		"\"proc_version\":\"Linux version 3.12.19-rt30 (gcc version 4.8.2) #1 SMP\","
		"\"vermagic\":\"3.12.19-rt30 SMP mod_unload ARMv7\","
		"\"module_path\":\"/lib/modules/demo.ko\","
		"\"isa\":\"arm32\","
		"\"bits\":\"32\","
		"\"endianness\":\"little\","
		"\"config_source\":\"/proc/config.gz\","
		"\"config_available\":true,\"config_compressed\":true}\n",
		out);
}

static void test_format_payload_json_missing_fields_are_null(void)
{
	struct ela_kernel_buildinfo info;
	char out[2048];

	memset(&info, 0, sizeof(info));
	snprintf(info.kernel_release, sizeof(info.kernel_release), "6.1.0");
	info.isa = "x86_64";

	ELA_ASSERT_INT_EQ(0, ela_kernel_buildinfo_format_payload(
		"json", &info, out, sizeof(out)));
	ELA_ASSERT_STR_EQ(
		"{\"record\":\"module_buildinfo\","
		"\"kernel_release\":\"6.1.0\","
		"\"proc_version\":null,"
		"\"vermagic\":null,"
		"\"module_path\":null,"
		"\"isa\":\"x86_64\","
		"\"bits\":null,"
		"\"endianness\":null,"
		"\"config_source\":null,"
		"\"config_available\":false,\"config_compressed\":false}\n",
		out);
}

static void test_format_payload_json_escapes(void)
{
	struct ela_kernel_buildinfo info;
	char out[2048];

	memset(&info, 0, sizeof(info));
	snprintf(info.proc_version, sizeof(info.proc_version),
		 "Linux \"vendor\\build\"\ttest");

	ELA_ASSERT_INT_EQ(0, ela_kernel_buildinfo_format_payload(
		"json", &info, out, sizeof(out)));
	ELA_ASSERT_TRUE(strstr(out,
		"\"proc_version\":\"Linux \\\"vendor\\\\build\\\"\\ttest\"") != NULL);
}

static void test_format_payload_csv_and_text(void)
{
	struct ela_kernel_buildinfo info = sample_info();
	char out[2048];

	ELA_ASSERT_INT_EQ(0, ela_kernel_buildinfo_format_payload(
		"csv", &info, out, sizeof(out)));
	ELA_ASSERT_STR_EQ(
		"\"3.12.19-rt30\","
		"\"Linux version 3.12.19-rt30 (gcc version 4.8.2) #1 SMP\","
		"\"3.12.19-rt30 SMP mod_unload ARMv7\","
		"\"/lib/modules/demo.ko\",\"arm32\",\"32\",\"little\","
		"\"/proc/config.gz\",true,true\n",
		out);

	ELA_ASSERT_INT_EQ(0, ela_kernel_buildinfo_format_payload(
		NULL, &info, out, sizeof(out)));
	ELA_ASSERT_STR_EQ(
		"kernel_release=3.12.19-rt30 "
		"vermagic=3.12.19-rt30 SMP mod_unload ARMv7 "
		"module_path=/lib/modules/demo.ko isa=arm32 "
		"bits=32 endianness=little "
		"config_source=/proc/config.gz "
		"config_available=true config_compressed=true\n",
		out);
}

static void test_format_payload_rejects_bad_args(void)
{
	struct ela_kernel_buildinfo info = sample_info();
	char out[2048];
	char tiny[16];

	ELA_ASSERT_INT_EQ(-1, ela_kernel_buildinfo_format_payload(
		"json", NULL, out, sizeof(out)));
	ELA_ASSERT_INT_EQ(-1, ela_kernel_buildinfo_format_payload(
		"json", &info, NULL, 0));
	ELA_ASSERT_INT_EQ(-1, ela_kernel_buildinfo_format_payload(
		"json", &info, tiny, sizeof(tiny)));
	ELA_ASSERT_INT_EQ(-1, ela_kernel_buildinfo_format_payload(
		"csv", &info, tiny, sizeof(tiny)));
	ELA_ASSERT_INT_EQ(-1, ela_kernel_buildinfo_format_payload(
		NULL, &info, tiny, sizeof(tiny)));
}

int run_linux_kernel_buildinfo_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "config_candidate/ordering", test_config_candidate_ordering },
		{ "config_candidate/root_prefix", test_config_candidate_with_root_prefix },
		{ "config_candidate/bad_input", test_config_candidate_rejects_bad_input },
		{ "config/is_gz", test_config_is_gz },
		{ "tool_candidate/path_then_fallbacks", test_tool_candidate_walks_path_then_fallbacks },
		{ "tool_candidate/no_path", test_tool_candidate_without_path },
		{ "tool_candidate/bad_input", test_tool_candidate_rejects_bad_input },
		{ "trim_line", test_trim_line },
		{ "format/json", test_format_payload_json },
		{ "format/json_nulls", test_format_payload_json_missing_fields_are_null },
		{ "format/json_escapes", test_format_payload_json_escapes },
		{ "format/csv_text", test_format_payload_csv_and_text },
		{ "format/bad_args", test_format_payload_rejects_bad_args },
	};

	return ela_run_test_suite("linux_kernel_buildinfo_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
