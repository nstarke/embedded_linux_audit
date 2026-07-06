// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_LINUX_PHYSMEM_UTIL_H
#define ELA_LINUX_PHYSMEM_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum ela_physmem_action {
	ELA_PHYSMEM_ACTION_NONE = 0,
	ELA_PHYSMEM_ACTION_READ,
	ELA_PHYSMEM_ACTION_WRITE,
};

/* A parsed memread/memwrite invocation. For writes, `hex_data` points at the
 * caller's argv hex string (validated but not yet decoded). */
struct ela_physmem_request {
	enum ela_physmem_action action;
	uint64_t phys_addr;
	uint64_t length;
	bool uncached;
	const char *hex_data;
	bool show_help;
};

/* A parsed `mmio read|write` invocation (single device-width access). */
struct ela_mmio_request {
	bool write;
	uint64_t phys_addr;
	uint32_t width;
	uint64_t value;
	bool show_help;
};

/* A parsed `pci read|write` invocation (config space access). */
struct ela_pci_request {
	bool write;
	uint32_t domain;
	uint8_t bus;
	uint8_t device;
	uint8_t function;
	uint32_t offset;
	uint32_t width;
	uint32_t value;
	bool show_help;
};

/* A parsed `physmem alloc|free|va2pa` invocation. */
enum ela_physctl_action {
	ELA_PHYSCTL_ACTION_NONE = 0,
	ELA_PHYSCTL_ACTION_ALLOC,
	ELA_PHYSCTL_ACTION_FREE,
	ELA_PHYSCTL_ACTION_VA2PA,
};

struct ela_physctl_request {
	enum ela_physctl_action action;
	uint64_t length;        /* alloc */
	uint64_t max_phys_addr; /* alloc: 0 = unconstrained */
	uint64_t addr;          /* free: phys; va2pa: virt */
	bool show_help;
};

/* Parse `mmio read <addr> <width>` / `mmio write <addr> <width> <value>`.
 * Widths are 1/2/4/8; values must fit the width. Returns 0 or 2 (usage). */
int ela_mmio_prepare_request(int argc, char **argv,
			     struct ela_mmio_request *request,
			     char *errbuf, size_t errbuf_len);

/* Parse a PCI address written as [domain:]bus:device.function (hex fields,
 * e.g. "00:1f.3" or "0000:00:1f.3"). Returns 0 on success. */
int ela_pci_parse_bdf(const char *text, uint32_t *domain, uint8_t *bus,
		      uint8_t *device, uint8_t *function);

/* Parse `pci read <bdf> <offset> <width>` /
 * `pci write <bdf> <offset> <width> <value>`. Widths are 1/2/4. */
int ela_pci_prepare_request(int argc, char **argv,
			    struct ela_pci_request *request,
			    char *errbuf, size_t errbuf_len);

/* Parse `physmem alloc <bytes> [max-phys-addr]` / `physmem free <phys>` /
 * `physmem va2pa <virt>`. */
int ela_physctl_prepare_request(int argc, char **argv,
				struct ela_physctl_request *request,
				char *errbuf, size_t errbuf_len);

/* True when `value` fits in `width` bytes (width 8 always fits). */
bool ela_physmem_value_fits_width(uint64_t value, uint32_t width);

/* Parse `memread <addr> <length> [--uncached]` /
 * `memwrite <addr> <hex-bytes> [--uncached]` argv. Addresses and lengths
 * accept 0x-prefixed hex or decimal. Returns 0 on success, 2 on usage errors
 * (message in errbuf). */
int ela_physmem_prepare_request(int argc, char **argv,
				struct ela_physmem_request *request,
				char *errbuf, size_t errbuf_len);

/* Parse a u64 that is either decimal or 0x-hex. Returns 0 on success. */
int ela_physmem_parse_u64(const char *text, uint64_t *out);

/* Decode a hex string ("deadbeef" or "de:ad:be:ef") into out. Returns the
 * decoded byte count, or -1 on invalid input or overflow of out_len. */
int ela_physmem_decode_hex(const char *hex, unsigned char *out, size_t out_len);

/* Format one 16-byte hexdump line (offset, hex bytes, ASCII gutter) for the
 * bytes at data[off..off+len). Returns 0 on success. */
int ela_physmem_format_dump_line(uint64_t base_addr, const unsigned char *data,
				 size_t off, size_t len,
				 char *out, size_t out_len);

#endif
