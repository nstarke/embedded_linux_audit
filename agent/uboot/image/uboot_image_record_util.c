// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "uboot_image_record_util.h"

#include "../../util/str_util.h"

#include <csv.h>
#include <json.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int append_csv_field(char **out, size_t *len, size_t *cap, const char *value)
{
	const char *in = value ? value : "";
	size_t in_len = strlen(in);
	size_t buf_len = (in_len * 2U) + 3U;
	char *buf = malloc(buf_len);
	size_t written;
	int rc;

	if (!buf)
		return -1;

	written = csv_write(buf, buf_len, in, in_len);
	rc = append_bytes(out, len, cap, buf, written);
	free(buf);
	return rc;
}

int ela_uboot_image_format_record(enum uboot_output_format fmt,
				  bool *csv_header_emitted,
				  const char *record,
				  const char *dev,
				  uint64_t off,
				  const char *type,
				  const char *value,
				  char **out)
{
	char off_s[32];
	char *buf = NULL;
	size_t len = 0;
	size_t cap = 0;

	if (!out)
		return -1;
	*out = NULL;

	if (fmt == FW_OUTPUT_TXT)
		return 0;

	snprintf(off_s, sizeof(off_s), "0x%jx", (uintmax_t)off);

	if (fmt == FW_OUTPUT_CSV) {
		if (csv_header_emitted && !*csv_header_emitted) {
			if (append_text(&buf, &len, &cap, "record,device,offset,type,value\n") != 0)
				goto fail;
			*csv_header_emitted = true;
		}
		if (append_csv_field(&buf, &len, &cap, record ? record : "") != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, dev ? dev : "") != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, off_s) != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, type ? type : "") != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, value ? value : "") != 0 ||
		    append_text(&buf, &len, &cap, "\n") != 0)
			goto fail;
		*out = buf;
		return 0;
	}

	if (fmt == FW_OUTPUT_JSON) {
		json_object *obj = json_object_new_object();
		const char *json_s;

		if (!obj)
			return -1;
		json_object_object_add(obj, "record", json_object_new_string(record ? record : ""));
		if (dev)
			json_object_object_add(obj, "device", json_object_new_string(dev));
		json_object_object_add(obj, "offset", json_object_new_uint64(off));
		json_object_object_add(obj, "type", json_object_new_string(type ? type : ""));
		if (value)
			json_object_object_add(obj, "value", json_object_new_string(value));
		json_s = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
		if (append_text(&buf, &len, &cap, json_s) != 0 ||
		    append_text(&buf, &len, &cap, "\n") != 0) {
			json_object_put(obj);
			goto fail;
		}
		json_object_put(obj);
		*out = buf;
		return 0;
	}

	return -1;

fail:
	free(buf);
	return -1;
}

int ela_uboot_image_format_verbose(enum uboot_output_format fmt,
				   bool verbose,
				   bool *csv_header_emitted,
				   const char *dev,
				   uint64_t off,
				   const char *msg,
				   char **out)
{
	if (!out)
		return -1;
	*out = NULL;

	if (!verbose || !msg)
		return 0;

	if (fmt == FW_OUTPUT_TXT) {
		size_t len = strlen(msg) + 2U;
		char *buf = malloc(len);

		if (!buf)
			return -1;
		snprintf(buf, len, "%s\n", msg);
		*out = buf;
		return 0;
	}

	return ela_uboot_image_format_record(fmt, csv_header_emitted,
					     "verbose", dev ? dev : "", off, "log", msg, out);
}

int ela_uboot_image_format_signature(enum uboot_output_format fmt,
				     bool *csv_header_emitted,
				     const char *dev,
				     uint64_t off,
				     const char *kind,
				     char **out)
{
	if (!out)
		return -1;
	*out = NULL;

	if (fmt == FW_OUTPUT_TXT) {
		size_t len = snprintf(NULL, 0,
				      "candidate image signature: %s offset=0x%jx type=%s\n",
				      dev ? dev : "", (uintmax_t)off, kind ? kind : "") + 1U;
		char *buf = malloc(len);

		if (!buf)
			return -1;
		snprintf(buf, len, "candidate image signature: %s offset=0x%jx type=%s\n",
			 dev ? dev : "", (uintmax_t)off, kind ? kind : "");
		*out = buf;
		return 0;
	}

	return ela_uboot_image_format_record(fmt, csv_header_emitted,
					     "image_signature", dev, off, kind, NULL, out);
}

bool ela_uboot_image_matches_text_pattern(const uint8_t *buf,
					  size_t buf_len,
					  size_t pos,
					  const char *pattern)
{
	size_t pattern_len;

	if (!buf || !pattern)
		return false;

	pattern_len = strlen(pattern);
	if (pattern_len == 0 || pos + pattern_len > buf_len)
		return false;

	return memcmp(buf + pos, pattern, pattern_len) == 0;
}

const char *ela_uboot_image_classify_signature_kind(bool uimage_valid,
						    bool fit_valid,
						    bool text_match)
{
	if (uimage_valid)
		return "uImage";
	if (fit_valid)
		return "FIT";
	if (text_match)
		return "U-Boot-text";
	return NULL;
}
