// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "file_scan_formatter.h"

#include <json.h>
#include <stdio.h>
#include <string.h>

int ela_format_grep_match_record(struct output_buffer *out,
				 const char *path,
				 unsigned long line_no,
				 const char *line)
{
	char prefix[4096 + 64];
	int n;

	if (!out || !path || !line)
		return -1;

	n = snprintf(prefix, sizeof(prefix), "%s:%lu:", path, line_no);
	if (n < 0 || (size_t)n >= sizeof(prefix))
		return -1;

	if (output_buffer_append(out, prefix) != 0 || output_buffer_append(out, line) != 0)
		return -1;
	if (out->len == 0 || out->data[out->len - 1] != '\n') {
		if (output_buffer_append(out, "\n") != 0)
			return -1;
	}

	return 0;
}

int ela_format_symlink_record(struct output_buffer *out,
			      const char *format,
			      const char *link_path,
			      const char *target_path)
{
	const char *fmt = (format && *format) ? format : "txt";

	if (!out || !link_path || !target_path)
		return -1;

	if (!strcmp(fmt, "txt")) {
		if (output_buffer_append(out, link_path) != 0 ||
		    output_buffer_append(out, " -> ") != 0 ||
		    output_buffer_append(out, target_path) != 0 ||
		    output_buffer_append(out, "\n") != 0)
			return -1;
		return 0;
	}

	if (!strcmp(fmt, "csv")) {
		if (csv_write_to_buf(out, link_path) != 0 ||
		    output_buffer_append(out, ",") != 0 ||
		    csv_write_to_buf(out, target_path) != 0 ||
		    output_buffer_append(out, "\n") != 0)
			return -1;
		return 0;
	}

	if (!strcmp(fmt, "json")) {
		json_object *obj;
		const char *js;

		obj = json_object_new_object();
		if (!obj)
			return -1;
		json_object_object_add(obj, "link_path", json_object_new_string(link_path));
		json_object_object_add(obj, "location_path", json_object_new_string(target_path));
		js = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
		if (output_buffer_append(out, js) != 0 || output_buffer_append(out, "\n") != 0) {
			json_object_put(obj);
			return -1;
		}
		json_object_put(obj);
		return 0;
	}

	return -1;
}

const char *ela_output_format_content_type(const char *format,
					   const char *default_content_type)
{
	if (format && !strcmp(format, "csv"))
		return "text/csv; charset=utf-8";
	if (format && !strcmp(format, "json"))
		return "application/x-ndjson; charset=utf-8";
	return default_content_type;
}
