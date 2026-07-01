// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../../../agent/linux/linux_kernel_module_util.h"
#include "test_harness.h"

#include <string.h>

static void test_parse_proc_modules_line_with_dependencies(void)
{
	struct ela_kernel_module_record rec;

	ELA_ASSERT_INT_EQ(0, ela_kernel_module_parse_proc_line(
		"usb_storage 77824 1 uas,usbcore Live 0xffffffffc08b0000\n", &rec));
	ELA_ASSERT_STR_EQ("usb_storage", rec.name);
	ELA_ASSERT_INT_EQ(77824, rec.size);
	ELA_ASSERT_INT_EQ(1, rec.refcount);
	ELA_ASSERT_STR_EQ("uas,usbcore", rec.dependencies);
	ELA_ASSERT_STR_EQ("Live", rec.state);
	ELA_ASSERT_STR_EQ("0xffffffffc08b0000", rec.address);
}

static void test_parse_proc_modules_line_without_dependencies(void)
{
	struct ela_kernel_module_record rec;

	ELA_ASSERT_INT_EQ(0, ela_kernel_module_parse_proc_line(
		"dummy 16384 0 - Live 0x0000000000000000\n", &rec));
	ELA_ASSERT_STR_EQ("dummy", rec.name);
	ELA_ASSERT_STR_EQ("", rec.dependencies);
}

static void test_parse_proc_modules_line_rejects_bad_input(void)
{
	struct ela_kernel_module_record rec;

	ELA_ASSERT_INT_EQ(-1, ela_kernel_module_parse_proc_line(NULL, &rec));
	ELA_ASSERT_INT_EQ(-1, ela_kernel_module_parse_proc_line("too few fields", &rec));
	ELA_ASSERT_INT_EQ(-1, ela_kernel_module_parse_proc_line(
		"a 1 0 - Live 0x0 trailing\n", &rec));
}

static void test_prepare_list_load_unload_requests(void)
{
	struct ela_kernel_module_request req;
	char errbuf[256];
	char *list_argv[] = { "modules", "list" };
	char *load_argv[] = {
		"modules", "load", "--force", "/tmp/demo.ko", "debug=1", "name=demo"
	};
	char *unload_argv[] = { "modules", "unload", "demo" };
	char *vermagic_argv[] = { "modules", "vermagic", "/tmp/demo.ko" };
	char *vermagic_search_argv[] = { "modules", "vermagic" };

	ELA_ASSERT_INT_EQ(0, ela_kernel_module_prepare_request(
		2, list_argv, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(ELA_KERNEL_MODULE_ACTION_LIST, req.action);

	ELA_ASSERT_INT_EQ(0, ela_kernel_module_prepare_request(
		6, load_argv, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(ELA_KERNEL_MODULE_ACTION_LOAD, req.action);
	ELA_ASSERT_STR_EQ("/tmp/demo.ko", req.module_path);
	ELA_ASSERT_STR_EQ("debug=1 name=demo", req.params);
	ELA_ASSERT_TRUE(req.force_vermagic);
	ELA_ASSERT_INT_EQ(ELA_MODULE_INIT_IGNORE_VERMAGIC,
			  ela_kernel_module_load_flags(&req));

	ELA_ASSERT_INT_EQ(0, ela_kernel_module_prepare_request(
		3, unload_argv, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(ELA_KERNEL_MODULE_ACTION_UNLOAD, req.action);
	ELA_ASSERT_STR_EQ("demo", req.module_name);

	ELA_ASSERT_INT_EQ(0, ela_kernel_module_prepare_request(
		3, vermagic_argv, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(ELA_KERNEL_MODULE_ACTION_VERMAGIC, req.action);
	ELA_ASSERT_STR_EQ("/tmp/demo.ko", req.module_path);

	/* vermagic with no path is valid: module_path stays NULL so the command
	 * discovers a .ko under the module tree at runtime. */
	ELA_ASSERT_INT_EQ(0, ela_kernel_module_prepare_request(
		2, vermagic_search_argv, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(ELA_KERNEL_MODULE_ACTION_VERMAGIC, req.action);
	ELA_ASSERT_TRUE(req.module_path == NULL);
}

static void test_prepare_rejects_invalid_requests(void)
{
	struct ela_kernel_module_request req;
	char errbuf[256];
	char *load_missing[] = { "modules", "load" };
	char *unload_missing[] = { "modules", "unload" };
	char *unload_extra[] = { "modules", "unload", "demo", "extra" };
	char *vermagic_extra[] = { "modules", "vermagic", "/tmp/demo.ko", "extra" };
	char *unknown[] = { "modules", "reload", "demo" };

	ELA_ASSERT_INT_EQ(2, ela_kernel_module_prepare_request(
		2, load_missing, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "requires a module path") != NULL);

	ELA_ASSERT_INT_EQ(2, ela_kernel_module_prepare_request(
		2, unload_missing, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "exactly one module name") != NULL);

	ELA_ASSERT_INT_EQ(2, ela_kernel_module_prepare_request(
		4, unload_extra, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "exactly one module name") != NULL);

	ELA_ASSERT_INT_EQ(2, ela_kernel_module_prepare_request(
		4, vermagic_extra, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "at most one module path") != NULL);

	ELA_ASSERT_INT_EQ(2, ela_kernel_module_prepare_request(
		3, unknown, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Unknown modules action") != NULL);
}

static void test_prepare_help(void)
{
	struct ela_kernel_module_request req;
	char errbuf[256];
	char *argv_top[] = { "modules", "--help" };
	char *argv_load[] = { "modules", "load", "--help" };
	char *argv_vermagic[] = { "modules", "vermagic", "--help" };

	ELA_ASSERT_INT_EQ(0, ela_kernel_module_prepare_request(
		2, argv_top, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(req.show_help);

	ELA_ASSERT_INT_EQ(0, ela_kernel_module_prepare_request(
		3, argv_load, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(req.show_help);

	ELA_ASSERT_INT_EQ(0, ela_kernel_module_prepare_request(
		3, argv_vermagic, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(req.show_help);
}

static void test_extract_vermagic(void)
{
	static const unsigned char blob[] =
		"\x7f""ELF"
		"license=GPL\0"
		"vermagic=6.1.0 SMP preempt mod_unload aarch64\0"
		"name=demo\0";
	char out[128];

	ELA_ASSERT_INT_EQ(0, ela_kernel_module_extract_vermagic(
		blob, sizeof(blob) - 1U, out, sizeof(out)));
	ELA_ASSERT_STR_EQ("6.1.0 SMP preempt mod_unload aarch64", out);
}

static void test_extract_vermagic_rejects_invalid_inputs(void)
{
	static const unsigned char no_vermagic[] = "license=GPL\0name=demo\0";
	static const unsigned char unterminated[] = "prefix\0vermagic=unterminated";
	char out[8];

	ELA_ASSERT_INT_EQ(-1, ela_kernel_module_extract_vermagic(NULL, 0, out, sizeof(out)));
	ELA_ASSERT_INT_EQ(-1, ela_kernel_module_extract_vermagic(no_vermagic,
		sizeof(no_vermagic) - 1U, out, sizeof(out)));
	ELA_ASSERT_INT_EQ(-1, ela_kernel_module_extract_vermagic(unterminated,
		sizeof(unterminated) - 1U, out, sizeof(out)));
	ELA_ASSERT_INT_EQ(-1, ela_kernel_module_extract_vermagic(
		(const unsigned char *)"vermagic=too-long\0", 18, out, sizeof(out)));
}

static void test_has_ko_suffix(void)
{
	ELA_ASSERT_TRUE(ela_kernel_module_has_ko_suffix("demo.ko"));
	ELA_ASSERT_TRUE(ela_kernel_module_has_ko_suffix("/lib/modules/6.1.0/kernel/foo.ko"));
	ELA_ASSERT_TRUE(!ela_kernel_module_has_ko_suffix("demo.ko.xz"));
	ELA_ASSERT_TRUE(!ela_kernel_module_has_ko_suffix("demo.o"));
	ELA_ASSERT_TRUE(!ela_kernel_module_has_ko_suffix(".ko"));
	ELA_ASSERT_TRUE(!ela_kernel_module_has_ko_suffix("ko"));
	ELA_ASSERT_TRUE(!ela_kernel_module_has_ko_suffix(""));
	ELA_ASSERT_TRUE(!ela_kernel_module_has_ko_suffix(NULL));
}

int run_linux_kernel_module_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "parse/with_dependencies", test_parse_proc_modules_line_with_dependencies },
		{ "parse/without_dependencies", test_parse_proc_modules_line_without_dependencies },
		{ "parse/bad_input", test_parse_proc_modules_line_rejects_bad_input },
		{ "prepare/actions", test_prepare_list_load_unload_requests },
		{ "prepare/invalid", test_prepare_rejects_invalid_requests },
		{ "prepare/help", test_prepare_help },
		{ "extract/vermagic", test_extract_vermagic },
		{ "extract/invalid", test_extract_vermagic_rejects_invalid_inputs },
		{ "vermagic/ko_suffix", test_has_ko_suffix },
	};

	return ela_run_test_suite("linux_kernel_module_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
