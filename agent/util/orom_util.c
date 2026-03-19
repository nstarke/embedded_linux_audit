// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "orom_util.h"

#include <json.h>
#include <stdio.h>
#include <string.h>

enum orom_output_format ela_orom_detect_output_format(const char *format)
{
	if (format && !strcmp(format, "csv"))
		return OROM_FMT_CSV;
	if (format && !strcmp(format, "json"))
		return OROM_FMT_JSON;
	return OROM_FMT_TXT;
}

bool ela_orom_rom_matches_mode(const uint8_t *buf, size_t len, const char *fw_mode)
{
	bool want_efi;
	bool saw_any = false;
	size_t i;

	if (!buf || !fw_mode || len < 0x1c)
		return false;

	want_efi = !strcmp(fw_mode, "efi");
	for (i = 0; i + 0x18 < len; i++) {
		if (i + 4 > len)
			break;
		if (memcmp(buf + i, "PCIR", 4))
			continue;
		saw_any = true;
		if (i + 0x15 >= len)
			continue;
		if (want_efi && buf[i + 0x14] == 0x03)
			return true;
		if (!want_efi && buf[i + 0x14] == 0x00)
			return true;
	}

	return !saw_any;
}

int ela_orom_format_record(struct output_buffer *out,
			   enum orom_output_format fmt,
			   const char *fw_mode,
			   const char *record,
			   const char *rom_path,
			   size_t size,
			   const char *type,
			   const char *value)
{
	char size_s[32];

	if (!out || !fw_mode)
		return -1;

	snprintf(size_s, sizeof(size_s), "%zu", size);

	if (fmt == OROM_FMT_CSV) {
		if (csv_write_to_buf(out, record ? record : "") != 0 ||
		    output_buffer_append(out, ",") != 0 ||
		    csv_write_to_buf(out, fw_mode) != 0 ||
		    output_buffer_append(out, ",") != 0 ||
		    csv_write_to_buf(out, rom_path ? rom_path : "") != 0 ||
		    output_buffer_append(out, ",") != 0 ||
		    csv_write_to_buf(out, size_s) != 0 ||
		    output_buffer_append(out, ",") != 0 ||
		    csv_write_to_buf(out, type ? type : "") != 0 ||
		    output_buffer_append(out, ",") != 0 ||
		    csv_write_to_buf(out, value ? value : "") != 0 ||
		    output_buffer_append(out, "\n") != 0)
			return -1;
		return 0;
	}

	if (fmt == OROM_FMT_JSON) {
		json_object *obj = json_object_new_object();
		const char *js;
		if (!obj)
			return -1;
		json_object_object_add(obj, "record", json_object_new_string(record ? record : ""));
		json_object_object_add(obj, "mode", json_object_new_string(fw_mode));
		if (rom_path)
			json_object_object_add(obj, "rom_path", json_object_new_string(rom_path));
		json_object_object_add(obj, "size", json_object_new_uint64((uint64_t)size));
		if (type)
			json_object_object_add(obj, "type", json_object_new_string(type));
		if (value)
			json_object_object_add(obj, "value", json_object_new_string(value));
		js = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
		if (output_buffer_append(out, js) != 0 || output_buffer_append(out, "\n") != 0) {
			json_object_put(obj);
			return -1;
		}
		json_object_put(obj);
		return 0;
	}

	if (output_buffer_append(out, "orom ") != 0 ||
	    output_buffer_append(out, record ? record : "record") != 0 ||
	    output_buffer_append(out, " mode=") != 0 ||
	    output_buffer_append(out, fw_mode) != 0 ||
	    output_buffer_append(out, " rom=") != 0 ||
	    output_buffer_append(out, rom_path ? rom_path : "") != 0 ||
	    output_buffer_append(out, " size=") != 0 ||
	    output_buffer_append(out, size_s) != 0 ||
	    output_buffer_append(out, " ") != 0 ||
	    output_buffer_append(out, type ? type : "type") != 0 ||
	    output_buffer_append(out, "=") != 0 ||
	    output_buffer_append(out, value ? value : "") != 0 ||
	    output_buffer_append(out, "\n") != 0)
		return -1;

	return 0;
}
