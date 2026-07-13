// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "../../../agent/linux/linux_physmem_util.h"
#include "test_harness.h"

#include <string.h>

static void test_parse_u64(void)
{
	uint64_t value;

	ELA_ASSERT_INT_EQ(0, ela_physmem_parse_u64("0x1000", &value));
	ELA_ASSERT_TRUE(value == 0x1000ULL);
	ELA_ASSERT_INT_EQ(0, ela_physmem_parse_u64("4096", &value));
	ELA_ASSERT_TRUE(value == 4096ULL);
	ELA_ASSERT_INT_EQ(0, ela_physmem_parse_u64("0xfffff000", &value));
	ELA_ASSERT_TRUE(value == 0xfffff000ULL);
	ELA_ASSERT_INT_EQ(0, ela_physmem_parse_u64("0xFEDC0000", &value));
	ELA_ASSERT_TRUE(value == 0xFEDC0000ULL);

	ELA_ASSERT_INT_EQ(-1, ela_physmem_parse_u64("", &value));
	ELA_ASSERT_INT_EQ(-1, ela_physmem_parse_u64(NULL, &value));
	ELA_ASSERT_INT_EQ(-1, ela_physmem_parse_u64("0x", &value));
	ELA_ASSERT_INT_EQ(-1, ela_physmem_parse_u64("12junk", &value));
	ELA_ASSERT_INT_EQ(-1, ela_physmem_parse_u64("0x1_000", &value));
}

static void test_decode_hex(void)
{
	unsigned char out[8];

	ELA_ASSERT_INT_EQ(4, ela_physmem_decode_hex("deadbeef", out, sizeof(out)));
	ELA_ASSERT_TRUE(out[0] == 0xde && out[1] == 0xad &&
			out[2] == 0xbe && out[3] == 0xef);

	ELA_ASSERT_INT_EQ(4, ela_physmem_decode_hex("de:ad:be:ef", out, sizeof(out)));
	ELA_ASSERT_TRUE(out[3] == 0xef);

	ELA_ASSERT_INT_EQ(2, ela_physmem_decode_hex("AB cd", out, sizeof(out)));
	ELA_ASSERT_TRUE(out[0] == 0xab && out[1] == 0xcd);

	ELA_ASSERT_INT_EQ(-1, ela_physmem_decode_hex("", out, sizeof(out)));
	ELA_ASSERT_INT_EQ(-1, ela_physmem_decode_hex("abc", out, sizeof(out)));
	ELA_ASSERT_INT_EQ(-1, ela_physmem_decode_hex("zz", out, sizeof(out)));
	ELA_ASSERT_INT_EQ(-1, ela_physmem_decode_hex(NULL, out, sizeof(out)));
	/* overflow of the destination */
	ELA_ASSERT_INT_EQ(-1, ela_physmem_decode_hex("00112233445566778899",
						     out, sizeof(out)));
}

static void test_prepare_memread(void)
{
	struct ela_physmem_request req;
	char errbuf[256];
	char *read_argv[] = { "memread", "0x1000", "256" };
	char *read_uncached[] = { "memread", "--uncached", "0x1000", "16" };
	char *read_help[] = { "memread", "--help" };

	ELA_ASSERT_INT_EQ(0, ela_physmem_prepare_request(
		3, read_argv, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(ELA_PHYSMEM_ACTION_READ, req.action);
	ELA_ASSERT_TRUE(req.phys_addr == 0x1000ULL);
	ELA_ASSERT_TRUE(req.length == 256ULL);
	ELA_ASSERT_TRUE(!req.uncached);

	ELA_ASSERT_INT_EQ(0, ela_physmem_prepare_request(
		4, read_uncached, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(req.uncached);
	ELA_ASSERT_TRUE(req.phys_addr == 0x1000ULL);

	ELA_ASSERT_INT_EQ(0, ela_physmem_prepare_request(
		2, read_help, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(req.show_help);
}

static void test_prepare_memwrite(void)
{
	struct ela_physmem_request req;
	char errbuf[256];
	char *write_argv[] = { "memwrite", "0xfedc0000", "deadbeef" };

	ELA_ASSERT_INT_EQ(0, ela_physmem_prepare_request(
		3, write_argv, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(ELA_PHYSMEM_ACTION_WRITE, req.action);
	ELA_ASSERT_TRUE(req.phys_addr == 0xfedc0000ULL);
	ELA_ASSERT_STR_EQ("deadbeef", req.hex_data);
}

static void test_prepare_rejects_invalid(void)
{
	struct ela_physmem_request req;
	char errbuf[256];
	char *missing_len[] = { "memread", "0x1000" };
	char *extra[] = { "memread", "0x1000", "16", "extra" };
	char *bad_addr[] = { "memread", "nope", "16" };
	char *zero_len[] = { "memread", "0x1000", "0" };
	char *bad_opt[] = { "memread", "--wat", "0x1000", "16" };
	char *unknown[] = { "memfrob", "0x1000", "16" };

	ELA_ASSERT_INT_EQ(2, ela_physmem_prepare_request(
		2, missing_len, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "requires an address and a length") != NULL);

	ELA_ASSERT_INT_EQ(2, ela_physmem_prepare_request(
		4, extra, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(2, ela_physmem_prepare_request(
		3, bad_addr, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Invalid physical address") != NULL);
	ELA_ASSERT_INT_EQ(2, ela_physmem_prepare_request(
		3, zero_len, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Invalid read length") != NULL);
	ELA_ASSERT_INT_EQ(2, ela_physmem_prepare_request(
		4, bad_opt, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Unknown physmem option") != NULL);
	ELA_ASSERT_INT_EQ(2, ela_physmem_prepare_request(
		3, unknown, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Unknown physmem action") != NULL);
}

static void test_format_dump_line(void)
{
	static const unsigned char data[] =
		"\x00\x01Hello, world!\x7f\xffTRAILING";
	char line[128];

	ELA_ASSERT_INT_EQ(0, ela_physmem_format_dump_line(
		0x1000, data, 0, 16, line, sizeof(line)));
	ELA_ASSERT_STR_EQ(
		"0000000000001000  00 01 48 65 6c 6c 6f 2c  20 77 6f 72 6c 64 21 7f "
		" |..Hello, world!.|\n",
		line);

	/* Short tail line pads hex and ascii columns. */
	ELA_ASSERT_INT_EQ(0, ela_physmem_format_dump_line(
		0x1000, data, 16, 3, line, sizeof(line)));
	ELA_ASSERT_TRUE(strstr(line, "0000000000001010") == line);
	ELA_ASSERT_TRUE(strstr(line, "|.TR             |") != NULL);

	ELA_ASSERT_INT_EQ(-1, ela_physmem_format_dump_line(
		0, data, 0, 0, line, sizeof(line)));
	ELA_ASSERT_INT_EQ(-1, ela_physmem_format_dump_line(
		0, data, 0, 17, line, sizeof(line)));
	ELA_ASSERT_INT_EQ(-1, ela_physmem_format_dump_line(
		0, NULL, 0, 16, line, sizeof(line)));
}

static void test_value_fits_width(void)
{
	ELA_ASSERT_TRUE(ela_physmem_value_fits_width(0xff, 1));
	ELA_ASSERT_TRUE(!ela_physmem_value_fits_width(0x100, 1));
	ELA_ASSERT_TRUE(ela_physmem_value_fits_width(0xffff, 2));
	ELA_ASSERT_TRUE(!ela_physmem_value_fits_width(0x10000, 2));
	ELA_ASSERT_TRUE(ela_physmem_value_fits_width(0xffffffffULL, 4));
	ELA_ASSERT_TRUE(!ela_physmem_value_fits_width(0x100000000ULL, 4));
	ELA_ASSERT_TRUE(ela_physmem_value_fits_width(0xffffffffffffffffULL, 8));
}

static void test_prepare_mmio(void)
{
	struct ela_mmio_request req;
	char errbuf[256];
	char *read_argv[] = { "mmio", "read", "0xfe000000", "4" };
	char *write_argv[] = { "mmio", "write", "0xfe000000", "4", "0xdeadbeef" };
	char *help_argv[] = { "mmio", "--help" };
	char *misaligned[] = { "mmio", "read", "0xfe000002", "4" };
	char *bad_width[] = { "mmio", "read", "0xfe000000", "3" };
	char *too_big[] = { "mmio", "write", "0xfe000000", "1", "0x100" };
	char *missing_value[] = { "mmio", "write", "0xfe000000", "4" };
	char *unknown[] = { "mmio", "poke", "0xfe000000", "4" };

	ELA_ASSERT_INT_EQ(0, ela_mmio_prepare_request(
		4, read_argv, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(!req.write);
	ELA_ASSERT_TRUE(req.phys_addr == 0xfe000000ULL);
	ELA_ASSERT_INT_EQ(4, req.width);

	ELA_ASSERT_INT_EQ(0, ela_mmio_prepare_request(
		5, write_argv, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(req.write);
	ELA_ASSERT_TRUE(req.value == 0xdeadbeefULL);

	ELA_ASSERT_INT_EQ(0, ela_mmio_prepare_request(
		2, help_argv, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(req.show_help);

	ELA_ASSERT_INT_EQ(2, ela_mmio_prepare_request(
		4, misaligned, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "width-aligned") != NULL);
	ELA_ASSERT_INT_EQ(2, ela_mmio_prepare_request(
		4, bad_width, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(2, ela_mmio_prepare_request(
		5, too_big, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "does not fit") != NULL);
	ELA_ASSERT_INT_EQ(2, ela_mmio_prepare_request(
		4, missing_value, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(2, ela_mmio_prepare_request(
		4, unknown, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Unknown mmio action") != NULL);
}

static void test_parse_bdf(void)
{
	uint32_t domain;
	uint8_t bus;
	uint8_t device;
	uint8_t function;

	ELA_ASSERT_INT_EQ(0, ela_pci_parse_bdf("00:1f.3", &domain, &bus,
						&device, &function));
	ELA_ASSERT_INT_EQ(0, domain);
	ELA_ASSERT_INT_EQ(0x00, bus);
	ELA_ASSERT_INT_EQ(0x1f, device);
	ELA_ASSERT_INT_EQ(3, function);

	ELA_ASSERT_INT_EQ(0, ela_pci_parse_bdf("0001:02:03.4", &domain, &bus,
						&device, &function));
	ELA_ASSERT_INT_EQ(1, domain);
	ELA_ASSERT_INT_EQ(2, bus);
	ELA_ASSERT_INT_EQ(3, device);
	ELA_ASSERT_INT_EQ(4, function);

	ELA_ASSERT_INT_EQ(-1, ela_pci_parse_bdf("", &domain, &bus, &device, &function));
	ELA_ASSERT_INT_EQ(-1, ela_pci_parse_bdf("garbage", &domain, &bus, &device, &function));
	ELA_ASSERT_INT_EQ(-1, ela_pci_parse_bdf("00:1f", &domain, &bus, &device, &function));
	ELA_ASSERT_INT_EQ(-1, ela_pci_parse_bdf("00:20.0", &domain, &bus, &device, &function));
	ELA_ASSERT_INT_EQ(-1, ela_pci_parse_bdf("00:1f.8", &domain, &bus, &device, &function));
	ELA_ASSERT_INT_EQ(-1, ela_pci_parse_bdf("00:1f.3x", &domain, &bus, &device, &function));
	ELA_ASSERT_INT_EQ(-1, ela_pci_parse_bdf(NULL, &domain, &bus, &device, &function));
}

static void test_prepare_ioport(void)
{
	struct ela_ioport_request req;
	char errbuf[256];
	char *read_argv[] = { "ioport", "read", "0x80", "1" };
	char *write_argv[] = { "ioport", "write", "0xcf8", "4", "0x80000000" };
	char *help_argv[] = { "ioport", "--help" };
	char *bad_port[] = { "ioport", "read", "0x10000", "1" };
	char *bad_width[] = { "ioport", "read", "0x80", "8" };
	char *too_big[] = { "ioport", "write", "0x80", "1", "0x100" };
	char *unknown[] = { "ioport", "poke", "0x80", "1" };

	ELA_ASSERT_INT_EQ(0, ela_ioport_prepare_request(
		4, read_argv, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(!req.write);
	ELA_ASSERT_INT_EQ(0x80, req.port);
	ELA_ASSERT_INT_EQ(1, req.width);
	ELA_ASSERT_INT_EQ(0, ela_ioport_prepare_request(
		5, write_argv, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(req.write);
	ELA_ASSERT_INT_EQ(0xcf8, req.port);
	ELA_ASSERT_TRUE(req.value == 0x80000000U);
	ELA_ASSERT_INT_EQ(0, ela_ioport_prepare_request(
		2, help_argv, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(req.show_help);
	ELA_ASSERT_INT_EQ(2, ela_ioport_prepare_request(
		4, bad_port, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(2, ela_ioport_prepare_request(
		4, bad_width, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(2, ela_ioport_prepare_request(
		5, too_big, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "does not fit") != NULL);
	ELA_ASSERT_INT_EQ(2, ela_ioport_prepare_request(
		4, unknown, &req, errbuf, sizeof(errbuf)));
}

static void test_prepare_pci(void)
{
	struct ela_pci_request req;
	char errbuf[256];
	char *read_argv[] = { "pci", "read", "00:1f.3", "0x10", "4" };
	char *write_argv[] = { "pci", "write", "0000:00:1f.3", "0x4", "2", "0x0107" };
	char *bad_bdf[] = { "pci", "read", "nope", "0", "4" };
	char *bad_offset[] = { "pci", "read", "00:1f.3", "4096", "4" };
	char *misaligned[] = { "pci", "read", "00:1f.3", "0x2", "4" };
	char *bad_width[] = { "pci", "read", "00:1f.3", "0", "8" };
	char *too_big[] = { "pci", "write", "00:1f.3", "0", "1", "0x1ff" };

	ELA_ASSERT_INT_EQ(0, ela_pci_prepare_request(
		5, read_argv, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(!req.write);
	ELA_ASSERT_INT_EQ(0x1f, req.device);
	ELA_ASSERT_INT_EQ(0x10, req.offset);
	ELA_ASSERT_INT_EQ(4, req.width);

	ELA_ASSERT_INT_EQ(0, ela_pci_prepare_request(
		6, write_argv, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(req.write);
	ELA_ASSERT_INT_EQ(0x0107, req.value);
	ELA_ASSERT_INT_EQ(2, req.width);

	ELA_ASSERT_INT_EQ(2, ela_pci_prepare_request(
		5, bad_bdf, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Invalid PCI address") != NULL);
	ELA_ASSERT_INT_EQ(2, ela_pci_prepare_request(
		5, bad_offset, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(2, ela_pci_prepare_request(
		5, misaligned, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(2, ela_pci_prepare_request(
		5, bad_width, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(2, ela_pci_prepare_request(
		6, too_big, &req, errbuf, sizeof(errbuf)));
}

static void test_prepare_physctl(void)
{
	struct ela_physctl_request req;
	char errbuf[256];
	char *alloc_argv[] = { "physmem", "alloc", "4096" };
	char *alloc_max[] = { "physmem", "alloc", "65536", "0xffffffff" };
	char *free_argv[] = { "physmem", "free", "0x1000000" };
	char *va2pa_argv[] = { "physmem", "va2pa", "0xffff000012345678" };
	char *alloc_zero[] = { "physmem", "alloc", "0" };
	char *free_missing[] = { "physmem", "free" };
	char *unknown[] = { "physmem", "defrag" };

	ELA_ASSERT_INT_EQ(0, ela_physctl_prepare_request(
		3, alloc_argv, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(ELA_PHYSCTL_ACTION_ALLOC, req.action);
	ELA_ASSERT_TRUE(req.length == 4096ULL);
	ELA_ASSERT_TRUE(req.max_phys_addr == 0);

	ELA_ASSERT_INT_EQ(0, ela_physctl_prepare_request(
		4, alloc_max, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(req.max_phys_addr == 0xffffffffULL);

	ELA_ASSERT_INT_EQ(0, ela_physctl_prepare_request(
		3, free_argv, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(ELA_PHYSCTL_ACTION_FREE, req.action);
	ELA_ASSERT_TRUE(req.addr == 0x1000000ULL);

	ELA_ASSERT_INT_EQ(0, ela_physctl_prepare_request(
		3, va2pa_argv, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(ELA_PHYSCTL_ACTION_VA2PA, req.action);
	ELA_ASSERT_TRUE(req.addr == 0xffff000012345678ULL);

	ELA_ASSERT_INT_EQ(2, ela_physctl_prepare_request(
		3, alloc_zero, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(2, ela_physctl_prepare_request(
		2, free_missing, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_INT_EQ(2, ela_physctl_prepare_request(
		2, unknown, &req, errbuf, sizeof(errbuf)));
	ELA_ASSERT_TRUE(strstr(errbuf, "Unknown physmem action") != NULL);
}

int run_linux_physmem_util_tests(void)
{
	static const struct ela_test_case cases[] = {
		{ "parse/u64", test_parse_u64 },
		{ "parse/hex_data", test_decode_hex },
		{ "prepare/memread", test_prepare_memread },
		{ "prepare/memwrite", test_prepare_memwrite },
		{ "prepare/invalid", test_prepare_rejects_invalid },
		{ "format/dump_line", test_format_dump_line },
		{ "width/value_fits", test_value_fits_width },
		{ "prepare/mmio", test_prepare_mmio },
		{ "prepare/ioport", test_prepare_ioport },
		{ "parse/bdf", test_parse_bdf },
		{ "prepare/pci", test_prepare_pci },
		{ "prepare/physctl", test_prepare_physctl },
	};

	return ela_run_test_suite("linux_physmem_util", cases,
				  sizeof(cases) / sizeof(cases[0]));
}
