// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "tpm2_output_format_util.h"

#include "../embedded_linux_audit_cmd.h"

#include <json.h>
#include <string.h>

int ela_tpm2_is_valid_output_format(const char *format)
{
	return format &&
	       (!strcmp(format, "txt") ||
		!strcmp(format, "csv") ||
		!strcmp(format, "json"));
}

const char *ela_tpm2_output_content_type(const char *format)
{
	if (format && !strcmp(format, "csv"))
		return "text/csv; charset=utf-8";
	if (format && !strcmp(format, "json"))
		return "application/json; charset=utf-8";
	return "text/plain; charset=utf-8";
}

int ela_tpm2_format_kv_record(struct output_buffer *buf,
			      const char *format,
			      const char *key,
			      const char *value)
{
	if (!buf || !key || !value || !ela_tpm2_is_valid_output_format(format))
		return -1;

	if (!strcmp(format, "txt")) {
		if (output_buffer_append(buf, key) != 0 ||
		    output_buffer_append(buf, ": ") != 0 ||
		    output_buffer_append(buf, value) != 0 ||
		    output_buffer_append(buf, "\n") != 0)
			return -1;
		return 0;
	}

	if (!strcmp(format, "csv")) {
		if (csv_write_to_buf(buf, key) != 0 ||
		    output_buffer_append(buf, ",") != 0 ||
		    csv_write_to_buf(buf, value) != 0 ||
		    output_buffer_append(buf, "\n") != 0)
			return -1;
		return 0;
	}

	{
		json_object *obj = json_object_new_object();
		const char *json;
		int err;

		if (!obj)
			return -1;
		json_object_object_add(obj, "key", json_object_new_string(key));
		json_object_object_add(obj, "value", json_object_new_string(value));
		json = json_object_to_json_string_ext(obj,
				JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
		err = output_buffer_append(buf, json);
		if (err == 0)
			err = output_buffer_append(buf, "\n");
		json_object_put(obj);
		return err;
	}
}
