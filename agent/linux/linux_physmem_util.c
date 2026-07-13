// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "linux_physmem_util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void set_err(char *errbuf, size_t errbuf_len, const char *msg)
{
	if (errbuf && errbuf_len)
		snprintf(errbuf, errbuf_len, "%s", msg ? msg : "");
}

int ela_physmem_parse_u64(const char *text, uint64_t *out)
{
	char *end = NULL;
	unsigned long long value;

	if (!text || !*text || !out)
		return -1;

	errno = 0;
	value = strtoull(text, &end, 0); /* base 0: 0x hex, 0 octal, decimal */
	if (errno != 0 || !end || *end != '\0')
		return -1;

	*out = (uint64_t)value;
	return 0;
}

static int hex_nibble(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

int ela_physmem_decode_hex(const char *hex, unsigned char *out, size_t out_len)
{
	size_t count = 0;
	size_t i = 0;

	if (!hex || !out)
		return -1;

	while (hex[i]) {
		int hi;
		int lo;

		/* Permit byte separators for readability. */
		if (hex[i] == ':' || hex[i] == ' ') {
			i++;
			continue;
		}
		hi = hex_nibble(hex[i]);
		if (hi < 0 || !hex[i + 1])
			return -1;
		lo = hex_nibble(hex[i + 1]);
		if (lo < 0)
			return -1;
		if (count >= out_len)
			return -1;
		out[count++] = (unsigned char)((hi << 4) | lo);
		i += 2;
	}

	return count ? (int)count : -1;
}

int ela_physmem_prepare_request(int argc, char **argv,
				struct ela_physmem_request *request,
				char *errbuf, size_t errbuf_len)
{
	int i;
	int positional = 0;
	const char *pos_args[2] = { NULL, NULL };

	if (!request) {
		set_err(errbuf, errbuf_len, "internal error: null physmem request");
		return 2;
	}

	memset(request, 0, sizeof(*request));

	if (argc < 1 || !argv || !argv[0]) {
		set_err(errbuf, errbuf_len, "missing physmem command");
		return 2;
	}

	if (!strcmp(argv[0], "memread"))
		request->action = ELA_PHYSMEM_ACTION_READ;
	else if (!strcmp(argv[0], "memwrite"))
		request->action = ELA_PHYSMEM_ACTION_WRITE;
	else {
		set_err(errbuf, errbuf_len, "Unknown physmem action");
		return 2;
	}

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			request->show_help = true;
			return 0;
		}
		if (!strcmp(argv[i], "--uncached")) {
			request->uncached = true;
			continue;
		}
		if (argv[i][0] == '-') {
			set_err(errbuf, errbuf_len, "Unknown physmem option");
			return 2;
		}
		if (positional >= 2) {
			set_err(errbuf, errbuf_len,
				request->action == ELA_PHYSMEM_ACTION_READ
				? "memread takes exactly an address and a length"
				: "memwrite takes exactly an address and hex bytes");
			return 2;
		}
		pos_args[positional++] = argv[i];
	}

	if (positional != 2) {
		set_err(errbuf, errbuf_len,
			request->action == ELA_PHYSMEM_ACTION_READ
			? "memread requires an address and a length"
			: "memwrite requires an address and hex bytes");
		return 2;
	}

	if (ela_physmem_parse_u64(pos_args[0], &request->phys_addr) != 0) {
		set_err(errbuf, errbuf_len, "Invalid physical address");
		return 2;
	}

	if (request->action == ELA_PHYSMEM_ACTION_READ) {
		if (ela_physmem_parse_u64(pos_args[1], &request->length) != 0 ||
		    request->length == 0) {
			set_err(errbuf, errbuf_len, "Invalid read length");
			return 2;
		}
	} else {
		request->hex_data = pos_args[1];
	}

	return 0;
}

bool ela_physmem_value_fits_width(uint64_t value, uint32_t width)
{
	if (width >= 8)
		return true;
	return value <= ((1ULL << (width * 8)) - 1ULL);
}

int ela_mmio_prepare_request(int argc, char **argv,
			     struct ela_mmio_request *request,
			     char *errbuf, size_t errbuf_len)
{
	uint64_t width;

	if (!request) {
		set_err(errbuf, errbuf_len, "internal error: null mmio request");
		return 2;
	}

	memset(request, 0, sizeof(*request));

	if (argc < 2 || !argv || !argv[0] || !argv[1] ||
	    !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ||
	    !strcmp(argv[1], "help")) {
		request->show_help = true;
		return argc >= 2 ? 0 : 2;
	}

	if (!strcmp(argv[1], "read"))
		request->write = false;
	else if (!strcmp(argv[1], "write"))
		request->write = true;
	else {
		set_err(errbuf, errbuf_len, "Unknown mmio action");
		return 2;
	}

	if (argc >= 3 && (!strcmp(argv[2], "-h") || !strcmp(argv[2], "--help"))) {
		request->show_help = true;
		return 0;
	}

	if (argc != (request->write ? 5 : 4)) {
		set_err(errbuf, errbuf_len, request->write
			? "mmio write requires an address, a width, and a value"
			: "mmio read requires an address and a width");
		return 2;
	}

	if (ela_physmem_parse_u64(argv[2], &request->phys_addr) != 0) {
		set_err(errbuf, errbuf_len, "Invalid mmio address");
		return 2;
	}
	if (ela_physmem_parse_u64(argv[3], &width) != 0 ||
	    (width != 1 && width != 2 && width != 4 && width != 8)) {
		set_err(errbuf, errbuf_len, "Width must be 1, 2, 4, or 8");
		return 2;
	}
	request->width = (uint32_t)width;
	if (request->phys_addr & (request->width - 1)) {
		set_err(errbuf, errbuf_len, "Address must be width-aligned");
		return 2;
	}

	if (request->write) {
		if (ela_physmem_parse_u64(argv[4], &request->value) != 0) {
			set_err(errbuf, errbuf_len, "Invalid mmio value");
			return 2;
		}
		if (!ela_physmem_value_fits_width(request->value, request->width)) {
			set_err(errbuf, errbuf_len, "Value does not fit the access width");
			return 2;
		}
	}

	return 0;
}

int ela_ioport_prepare_request(int argc, char **argv,
			       struct ela_ioport_request *request,
			       char *errbuf, size_t errbuf_len)
{
	uint64_t port;
	uint64_t width;
	uint64_t value = 0;

	if (!request) {
		set_err(errbuf, errbuf_len, "internal error: null ioport request");
		return 2;
	}
	memset(request, 0, sizeof(*request));

	if (argc < 2 || !argv || !argv[0] || !argv[1] ||
	    !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ||
	    !strcmp(argv[1], "help")) {
		request->show_help = true;
		return argc >= 2 ? 0 : 2;
	}
	if (!strcmp(argv[1], "read"))
		request->write = false;
	else if (!strcmp(argv[1], "write"))
		request->write = true;
	else {
		set_err(errbuf, errbuf_len, "Unknown ioport action");
		return 2;
	}

	if (argc >= 3 && (!strcmp(argv[2], "-h") || !strcmp(argv[2], "--help"))) {
		request->show_help = true;
		return 0;
	}
	if (argc != (request->write ? 5 : 4)) {
		set_err(errbuf, errbuf_len, request->write
			? "ioport write requires a port, a width, and a value"
			: "ioport read requires a port and a width");
		return 2;
	}
	if (ela_physmem_parse_u64(argv[2], &port) != 0 || port > 0xffff) {
		set_err(errbuf, errbuf_len, "I/O port must be between 0 and 0xffff");
		return 2;
	}
	if (ela_physmem_parse_u64(argv[3], &width) != 0 ||
	    (width != 1 && width != 2 && width != 4)) {
		set_err(errbuf, errbuf_len, "Width must be 1, 2, or 4");
		return 2;
	}
	if (request->write) {
		if (ela_physmem_parse_u64(argv[4], &value) != 0) {
			set_err(errbuf, errbuf_len, "Invalid ioport value");
			return 2;
		}
		if (!ela_physmem_value_fits_width(value, (uint32_t)width)) {
			set_err(errbuf, errbuf_len, "Value does not fit the access width");
			return 2;
		}
	}

	request->port = (uint32_t)port;
	request->width = (uint32_t)width;
	request->value = (uint32_t)value;
	return 0;
}

int ela_pci_parse_bdf(const char *text, uint32_t *domain, uint8_t *bus,
		      uint8_t *device, uint8_t *function)
{
	unsigned int dom = 0;
	unsigned int b = 0;
	unsigned int d = 0;
	unsigned int f = 0;
	int matched;
	char extra;

	if (!text || !domain || !bus || !device || !function)
		return -1;

	/* Try dddd:bb:dd.f first, then bb:dd.f (domain 0). */
	matched = sscanf(text, "%4x:%2x:%2x.%1x%c", &dom, &b, &d, &f, &extra);
	if (matched != 4) {
		dom = 0;
		matched = sscanf(text, "%2x:%2x.%1x%c", &b, &d, &f, &extra);
		if (matched != 3)
			return -1;
	}

	if (b > 0xff || d > 31 || f > 7)
		return -1;

	*domain = dom;
	*bus = (uint8_t)b;
	*device = (uint8_t)d;
	*function = (uint8_t)f;
	return 0;
}

int ela_pci_prepare_request(int argc, char **argv,
			    struct ela_pci_request *request,
			    char *errbuf, size_t errbuf_len)
{
	uint64_t offset;
	uint64_t width;

	if (!request) {
		set_err(errbuf, errbuf_len, "internal error: null pci request");
		return 2;
	}

	memset(request, 0, sizeof(*request));

	if (argc < 2 || !argv || !argv[0] || !argv[1] ||
	    !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ||
	    !strcmp(argv[1], "help")) {
		request->show_help = true;
		return argc >= 2 ? 0 : 2;
	}

	if (!strcmp(argv[1], "read"))
		request->write = false;
	else if (!strcmp(argv[1], "write"))
		request->write = true;
	else {
		set_err(errbuf, errbuf_len, "Unknown pci action");
		return 2;
	}

	if (argc >= 3 && (!strcmp(argv[2], "-h") || !strcmp(argv[2], "--help"))) {
		request->show_help = true;
		return 0;
	}

	if (argc != (request->write ? 6 : 5)) {
		set_err(errbuf, errbuf_len, request->write
			? "pci write requires a bdf, an offset, a width, and a value"
			: "pci read requires a bdf, an offset, and a width");
		return 2;
	}

	if (ela_pci_parse_bdf(argv[2], &request->domain, &request->bus,
			      &request->device, &request->function) != 0) {
		set_err(errbuf, errbuf_len,
			"Invalid PCI address; use [domain:]bus:device.function (hex)");
		return 2;
	}

	if (ela_physmem_parse_u64(argv[3], &offset) != 0 || offset >= 4096) {
		set_err(errbuf, errbuf_len, "Invalid config offset (0-4095)");
		return 2;
	}
	if (ela_physmem_parse_u64(argv[4], &width) != 0 ||
	    (width != 1 && width != 2 && width != 4)) {
		set_err(errbuf, errbuf_len, "Width must be 1, 2, or 4");
		return 2;
	}
	if (offset & (width - 1)) {
		set_err(errbuf, errbuf_len, "Offset must be width-aligned");
		return 2;
	}
	request->offset = (uint32_t)offset;
	request->width = (uint32_t)width;

	if (request->write) {
		uint64_t value;

		if (ela_physmem_parse_u64(argv[5], &value) != 0 ||
		    !ela_physmem_value_fits_width(value, request->width)) {
			set_err(errbuf, errbuf_len, "Invalid value for the access width");
			return 2;
		}
		request->value = (uint32_t)value;
	}

	return 0;
}

int ela_physctl_prepare_request(int argc, char **argv,
				struct ela_physctl_request *request,
				char *errbuf, size_t errbuf_len)
{
	if (!request) {
		set_err(errbuf, errbuf_len, "internal error: null physmem request");
		return 2;
	}

	memset(request, 0, sizeof(*request));

	if (argc < 2 || !argv || !argv[0] || !argv[1] ||
	    !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ||
	    !strcmp(argv[1], "help")) {
		request->show_help = true;
		return argc >= 2 ? 0 : 2;
	}

	if (argc >= 3 && (!strcmp(argv[2], "-h") || !strcmp(argv[2], "--help"))) {
		request->show_help = true;
		return 0;
	}

	if (!strcmp(argv[1], "alloc")) {
		request->action = ELA_PHYSCTL_ACTION_ALLOC;
		if (argc != 3 && argc != 4) {
			set_err(errbuf, errbuf_len,
				"physmem alloc requires a byte length and an optional max phys addr");
			return 2;
		}
		if (ela_physmem_parse_u64(argv[2], &request->length) != 0 ||
		    request->length == 0) {
			set_err(errbuf, errbuf_len, "Invalid allocation length");
			return 2;
		}
		if (argc == 4 &&
		    ela_physmem_parse_u64(argv[3], &request->max_phys_addr) != 0) {
			set_err(errbuf, errbuf_len, "Invalid max phys addr");
			return 2;
		}
		return 0;
	}

	if (!strcmp(argv[1], "free") || !strcmp(argv[1], "va2pa")) {
		request->action = !strcmp(argv[1], "free")
			? ELA_PHYSCTL_ACTION_FREE : ELA_PHYSCTL_ACTION_VA2PA;
		if (argc != 3) {
			set_err(errbuf, errbuf_len,
				request->action == ELA_PHYSCTL_ACTION_FREE
				? "physmem free requires a physical address"
				: "physmem va2pa requires a kernel virtual address");
			return 2;
		}
		if (ela_physmem_parse_u64(argv[2], &request->addr) != 0) {
			set_err(errbuf, errbuf_len, "Invalid address");
			return 2;
		}
		return 0;
	}

	set_err(errbuf, errbuf_len, "Unknown physmem action");
	return 2;
}

int ela_physmem_format_dump_line(uint64_t base_addr, const unsigned char *data,
				 size_t off, size_t len,
				 char *out, size_t out_len)
{
	char hex[16 * 3 + 2];
	char ascii[17];
	size_t i;
	size_t pos = 0;
	int n;

	if (!data || !out || !out_len || len == 0 || len > 16)
		return -1;

	for (i = 0; i < 16; i++) {
		if (i < len) {
			n = snprintf(hex + pos, sizeof(hex) - pos, "%02x%s",
				     data[off + i], i == 7 ? "  " : " ");
			ascii[i] = (data[off + i] >= 0x20 && data[off + i] < 0x7f)
				? (char)data[off + i] : '.';
		} else {
			n = snprintf(hex + pos, sizeof(hex) - pos, "  %s",
				     i == 7 ? "  " : " ");
			ascii[i] = ' ';
		}
		if (n < 0 || (size_t)n >= sizeof(hex) - pos)
			return -1;
		pos += (size_t)n;
	}
	ascii[16] = '\0';

	n = snprintf(out, out_len, "%016llx  %s |%s|\n",
		     (unsigned long long)(base_addr + off), hex, ascii);
	return (n >= 0 && (size_t)n < out_len) ? 0 : -1;
}
