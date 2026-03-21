// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "record_formatter.h"

#include <json.h>
#include <stdio.h>
#include <string.h>

int ela_format_arch_record(struct output_buffer *out,
			   const char *format,
			   const char *subcommand,
			   const char *value)
{
	if (!out || !format || !subcommand || !value)
		return -1;

	if (!strcmp(format, "json")) {
		json_object *obj = json_object_new_object();
		const char *js;
		int err;

		if (!obj)
			return -1;
		json_object_object_add(obj, "record", json_object_new_string("arch"));
		json_object_object_add(obj, "subcommand", json_object_new_string(subcommand));
		json_object_object_add(obj, "value", json_object_new_string(value));
		js = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
		err = output_buffer_append(out, js);
		if (err == 0)
			err = output_buffer_append(out, "\n");
		json_object_put(obj);
		return err;
	}

	if (!strcmp(format, "csv")) {
		/* coverity[copy_paste_error] */
		if (csv_write_to_buf(out, value) != 0 || output_buffer_append(out, "\n") != 0)
			return -1;
		return 0;
	}

	if (!strcmp(format, "txt")) {
		if (output_buffer_append(out, value) != 0 || output_buffer_append(out, "\n") != 0)
			return -1;
		return 0;
	}

	return -1;
}

int ela_format_execute_command_record(struct output_buffer *out,
				      const char *format,
				      const char *command,
				      const char *command_output)
{
	if (!out || !format || !command || !command_output)
		return -1;

	if (!strcmp(format, "txt")) {
		if (output_buffer_append(out, command) != 0 ||
		    output_buffer_append(out, "\n") != 0 ||
		    output_buffer_append(out, command_output) != 0)
			return -1;
		return 0;
	}

	if (!strcmp(format, "csv")) {
		if (csv_write_to_buf(out, command) != 0 ||
		    output_buffer_append(out, ",") != 0 ||
		    csv_write_to_buf(out, command_output) != 0 ||
		    output_buffer_append(out, "\n") != 0)
			return -1;
		return 0;
	}

	if (!strcmp(format, "json")) {
		json_object *obj;
		const char *js;
		int err;

		obj = json_object_new_object();
		if (!obj)
			return -1;
		json_object_object_add(obj, "command", json_object_new_string(command));
		json_object_object_add(obj, "output", json_object_new_string(command_output));
		js = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
		err = output_buffer_append(out, js);
		if (err == 0)
			err = output_buffer_append(out, "\n");
		json_object_put(obj);
		return err;
	}

	return -1;
}

int ela_format_efi_var_record(struct output_buffer *out,
			      const char *format,
			      const char *guid_str,
			      const char *name,
			      uint32_t attributes,
			      size_t data_size,
			      const char *hex_data)
{
	char attr_buf[32];
	char size_buf[32];

	if (!out || !format || !guid_str || !name || !hex_data)
		return -1;

	snprintf(attr_buf, sizeof(attr_buf), "0x%08x", attributes);
	snprintf(size_buf, sizeof(size_buf), "%zu", data_size);

	if (!strcmp(format, "txt")) {
		if (output_buffer_append(out, "guid=") != 0 ||
		    output_buffer_append(out, guid_str) != 0 ||
		    output_buffer_append(out, " name=") != 0 ||
		    output_buffer_append(out, name) != 0 ||
		    output_buffer_append(out, " attributes=") != 0 ||
		    output_buffer_append(out, attr_buf) != 0 ||
		    output_buffer_append(out, " size=") != 0 ||
		    output_buffer_append(out, size_buf) != 0 ||
		    output_buffer_append(out, " data_hex=") != 0 ||
		    output_buffer_append(out, hex_data) != 0 ||
		    output_buffer_append(out, "\n") != 0)
			return -1;
		return 0;
	}

	if (!strcmp(format, "csv")) {
		if (csv_write_to_buf(out, guid_str) != 0 ||
		    output_buffer_append(out, ",") != 0 ||
		    csv_write_to_buf(out, name) != 0 ||
		    output_buffer_append(out, ",") != 0 ||
		    csv_write_to_buf(out, attr_buf) != 0 ||
		    output_buffer_append(out, ",") != 0 ||
		    csv_write_to_buf(out, size_buf) != 0 ||
		    output_buffer_append(out, ",") != 0 ||
		    csv_write_to_buf(out, hex_data) != 0 ||
		    output_buffer_append(out, "\n") != 0)
			return -1;
		return 0;
	}

	if (!strcmp(format, "json")) {
		json_object *obj = json_object_new_object();
		const char *js;
		int err;

		if (!obj)
			return -1;
		json_object_object_add(obj, "record", json_object_new_string("efi_var"));
		json_object_object_add(obj, "guid", json_object_new_string(guid_str));
		json_object_object_add(obj, "name", json_object_new_string(name));
		json_object_object_add(obj, "attributes", json_object_new_uint64((uint64_t)attributes));
		json_object_object_add(obj, "size", json_object_new_uint64((uint64_t)data_size));
		json_object_object_add(obj, "data_hex", json_object_new_string(hex_data));
		js = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
		err = output_buffer_append(out, js);
		if (err == 0)
			err = output_buffer_append(out, "\n");
		json_object_put(obj);
		return err;
	}

	return -1;
}
