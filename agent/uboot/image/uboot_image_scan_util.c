// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "uboot_image_scan_util.h"
#include "uboot_image_format_util.h"
#include "uboot_image_internal.h"

#include "embedded_linux_audit_cmd.h"

#include <string.h>

bool ela_uboot_image_validate_fit_header(const uint8_t *p,
					 uint64_t abs_off,
					 uint64_t dev_size)
{
	uint32_t totalsize        = ela_read_be32(p + 4);
	uint32_t off_dt_struct    = ela_read_be32(p + 8);
	uint32_t off_dt_strings   = ela_read_be32(p + 12);
	uint32_t off_mem_rsvmap   = ela_read_be32(p + 16);
	uint32_t version          = ela_read_be32(p + 20);
	uint32_t last_comp_version = ela_read_be32(p + 24);
	uint32_t size_dt_strings  = ela_read_be32(p + 32);
	uint32_t size_dt_struct   = ela_read_be32(p + 36);

	if (totalsize < FIT_MIN_TOTAL_SIZE || totalsize > FIT_MAX_TOTAL_SIZE)
		return false;
	if (abs_off + totalsize > dev_size)
		return false;

	if (off_mem_rsvmap < 40 || off_mem_rsvmap >= totalsize)
		return false;
	if (off_dt_struct >= totalsize || off_dt_strings >= totalsize)
		return false;
	if (size_dt_struct == 0 || size_dt_strings == 0)
		return false;
	if ((uint64_t)off_dt_struct + size_dt_struct > totalsize)
		return false;
	if ((uint64_t)off_dt_strings + size_dt_strings > totalsize)
		return false;

	if (version < 16 || version > 17)
		return false;
	if (last_comp_version > version)
		return false;

	return true;
}

bool ela_uboot_image_validate_uimage_header(const uint8_t *p,
					    uint64_t abs_off,
					    uint64_t dev_size,
					    const uint32_t *crc32_table)
{
	uint8_t hdr[UIMAGE_HDR_SIZE];
	uint32_t header_crc;
	uint32_t calc_crc;
	uint32_t data_size;

	memcpy(hdr, p, sizeof(hdr));
	header_crc = ela_read_be32(hdr + 4);
	hdr[4] = hdr[5] = hdr[6] = hdr[7] = 0;
	calc_crc = ela_crc32_calc(crc32_table, hdr, sizeof(hdr));
	if (calc_crc != header_crc)
		return false;

	data_size = ela_read_be32(p + 12);
	if (data_size == 0 || data_size > UIMAGE_MAX_DATA_SIZE)
		return false;
	if (abs_off + UIMAGE_HDR_SIZE + data_size > dev_size)
		return false;

	return true;
}

bool ela_uboot_image_fit_find_load_address(const uint8_t *blob,
					   size_t blob_size,
					   uint32_t *addr_out,
					   uint64_t *uboot_off_out,
					   bool *uboot_off_found_out)
{
	enum { FDT_BEGIN_NODE = 1, FDT_END_NODE = 2, FDT_PROP = 3, FDT_NOP = 4, FDT_END = 9 };
	enum { MAX_DEPTH = 64 };
	uint32_t off_dt_struct;
	uint32_t off_dt_strings;
	uint32_t total_size;
	uint32_t size_dt_struct;
	uint32_t size_dt_strings;
	const uint8_t *p;
	const uint8_t *end;
	const char *strings;
	const char *node_stack[MAX_DEPTH];
	int depth = -1;
	bool load_found = false;
	uint32_t load_value = 0;
	bool in_image_node = false;
	int image_depth = -1;
	bool image_name_uboot = false;
	bool image_desc_uboot = false;
	bool image_type_firmware = false;
	bool image_payload_off_found = false;
	uint64_t image_payload_off = 0;
	bool chosen_uboot_off = false;
	uint64_t chosen_uboot_off_val = 0;

	if (uboot_off_found_out)
		*uboot_off_found_out = false;
	if (uboot_off_out)
		*uboot_off_out = 0;

	if (!blob || blob_size < 40 || !addr_out)
		return false;

	total_size      = ela_read_be32(blob + 4);
	off_dt_struct   = ela_read_be32(blob + 8);
	off_dt_strings  = ela_read_be32(blob + 12);
	size_dt_strings = ela_read_be32(blob + 32);
	size_dt_struct  = ela_read_be32(blob + 36);

	if ((uint64_t)off_dt_struct + size_dt_struct > blob_size)
		return false;
	if ((uint64_t)off_dt_strings + size_dt_strings > blob_size)
		return false;

	p       = blob + off_dt_struct;
	end     = p + size_dt_struct;
	strings = (const char *)blob + off_dt_strings;

	while (p + 4 <= end) {
		uint32_t token = ela_read_be32(p);
		p += 4;

		switch (token) {
		case FDT_BEGIN_NODE: {
			const uint8_t *name_start = p;
			const char *name;
			while (p < end && *p)
				p++;
			if (p >= end)
				return false;
			name = (const char *)name_start;
			p++;
			p = name_start + ela_uboot_image_align_up_4((size_t)(p - name_start));

			if (depth + 1 >= MAX_DEPTH)
				return false;
			depth++;
			node_stack[depth] = name;

			if (depth == 2 && !strcmp(node_stack[1], "images")) {
				in_image_node = true;
				image_depth = depth;
				image_name_uboot = ela_uboot_image_str_contains_token_ci(name, "u-boot");
				image_desc_uboot = false;
				image_type_firmware = false;
				image_payload_off_found = false;
				image_payload_off = 0;
			}
			break;
		}
		case FDT_END_NODE:
			if (depth < 0)
				return false;
			if (in_image_node && depth == image_depth) {
				bool is_uboot_candidate = image_name_uboot || image_desc_uboot || image_type_firmware;
				if (!chosen_uboot_off && is_uboot_candidate && image_payload_off_found) {
					chosen_uboot_off = true;
					chosen_uboot_off_val = image_payload_off;
				}
				in_image_node = false;
				image_depth = -1;
			}
			depth--;
			break;
		case FDT_NOP:
			break;
		case FDT_END:
			if (load_found)
				*addr_out = load_value;
			if (chosen_uboot_off && uboot_off_found_out)
				*uboot_off_found_out = true;
			if (chosen_uboot_off && uboot_off_out)
				*uboot_off_out = chosen_uboot_off_val;
			return load_found;
		case FDT_PROP: {
			uint32_t len;
			uint32_t nameoff;
			const char *name;
			const uint8_t *data;

			if (p + 8 > end)
				return false;
			len     = ela_read_be32(p);
			nameoff = ela_read_be32(p + 4);
			p += 8;
			if (nameoff >= size_dt_strings)
				return false;
			if ((uint64_t)(end - p) < len)
				return false;

			name = strings + nameoff;
			data = p;
			if (!strcmp(name, "load") && len >= 4 && !load_found) {
				load_value = ela_read_be32(data);
				if (len >= 8 && load_value == 0)
					load_value = ela_read_be32(data + 4);
				load_found = true;
			}

			if (in_image_node) {
				if (!strcmp(name, "description") && len > 0)
					image_desc_uboot = ela_uboot_image_str_contains_token_ci((const char *)data, "u-boot");

				if (!strcmp(name, "type") && len > 0 &&
				    !strcasecmp((const char *)data, "firmware"))
					image_type_firmware = true;

				if (!strcmp(name, "data") && len > 0) {
					image_payload_off_found = true;
					image_payload_off = (uint64_t)(data - blob);
				}

				if (!strcmp(name, "data-position") && len >= 4) {
					uint64_t pos = ela_read_be32(data);
					if (len >= 8 && pos == 0)
						pos = ela_read_be32(data + 4);
					image_payload_off_found = true;
					image_payload_off = pos;
				}

				if (!strcmp(name, "data-offset") && len >= 4) {
					uint64_t ext_off = ela_read_be32(data);
					if (len >= 8 && ext_off == 0)
						ext_off = ela_read_be32(data + 4);
					image_payload_off_found = true;
					image_payload_off = (uint64_t)total_size + ext_off;
				}
			}

			p += ela_uboot_image_align_up_4((size_t)len);
			break;
		}
		default:
			return false;
		}
	}

	if (load_found)
		*addr_out = load_value;
	if (chosen_uboot_off && uboot_off_found_out)
		*uboot_off_found_out = true;
	if (chosen_uboot_off && uboot_off_out)
		*uboot_off_out = chosen_uboot_off_val;

	return load_found;
}
