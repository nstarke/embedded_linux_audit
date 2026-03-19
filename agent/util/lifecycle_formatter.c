// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "lifecycle_formatter.h"

#include "str_util.h"

#include <json.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int ela_format_utc_timestamp(time_t now, char *buf, size_t buf_size)
{
	struct tm tm_now;

	if (!buf || buf_size == 0)
		return -1;
	if (gmtime_r(&now, &tm_now) == NULL)
		return -1;
	snprintf(buf, buf_size, "%04d-%02d-%02dT%02d:%02d:%02dZ",
		 (int)(tm_now.tm_year + 1900), (int)(tm_now.tm_mon + 1),
		 (int)tm_now.tm_mday, (int)tm_now.tm_hour,
		 (int)tm_now.tm_min, (int)tm_now.tm_sec);
	return 0;
}

int ela_format_lifecycle_record(struct output_buffer *out,
				const char *format,
				const char *agent_timestamp,
				const char *command,
				const char *phase,
				int rc)
{
	char rc_buf[32];
	const char *fmt = (format && *format) ? format : "txt";

	if (!out || !agent_timestamp || !command || !phase)
		return -1;

	snprintf(rc_buf, sizeof(rc_buf), "%d", rc);

	if (!strcmp(fmt, "json")) {
		json_object *obj;
		const char *js;

		obj = json_object_new_object();
		if (!obj)
			return -1;
		json_object_object_add(obj, "record", json_object_new_string("log"));
		json_object_object_add(obj, "agent_timestamp", json_object_new_string(agent_timestamp));
		json_object_object_add(obj, "phase", json_object_new_string(phase));
		json_object_object_add(obj, "command", json_object_new_string(command));
		json_object_object_add(obj, "rc", json_object_new_int(rc));
		js = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
		if (output_buffer_append(out, js) != 0 || output_buffer_append(out, "\n") != 0) {
			json_object_put(obj);
			return -1;
		}
		json_object_put(obj);
		return 0;
	}

	if (!strcmp(fmt, "csv")) {
		if (csv_write_to_buf(out, "log") != 0 ||
		    output_buffer_append(out, ",") != 0 ||
		    csv_write_to_buf(out, agent_timestamp) != 0 ||
		    output_buffer_append(out, ",") != 0 ||
		    csv_write_to_buf(out, phase) != 0 ||
		    output_buffer_append(out, ",") != 0 ||
		    csv_write_to_buf(out, command) != 0 ||
		    output_buffer_append(out, ",") != 0 ||
		    csv_write_to_buf(out, rc_buf) != 0 ||
		    output_buffer_append(out, "\n") != 0)
			return -1;
		return 0;
	}

	if (output_buffer_append(out, "log agent_timestamp=") != 0 ||
	    output_buffer_append(out, agent_timestamp) != 0 ||
	    output_buffer_append(out, " phase=") != 0 ||
	    output_buffer_append(out, phase) != 0 ||
	    output_buffer_append(out, " command=") != 0 ||
	    output_buffer_append(out, command) != 0 ||
	    output_buffer_append(out, " rc=") != 0 ||
	    output_buffer_append(out, rc_buf) != 0 ||
	    output_buffer_append(out, "\n") != 0)
		return -1;

	return 0;
}

const char *ela_lifecycle_content_type(const char *format)
{
	if (format && !strcmp(format, "json"))
		return "application/json; charset=utf-8";
	if (format && !strcmp(format, "csv"))
		return "text/csv; charset=utf-8";
	return "text/plain; charset=utf-8";
}
