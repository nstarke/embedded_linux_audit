// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "linux_process_watch_util.h"

#include <csv.h>
#include <json.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

bool ela_process_watch_needle_is_valid(const char *needle)
{
	if (!needle || !*needle)
		return false;
	if (strlen(needle) > ELA_PROCESS_WATCH_NEEDLE_MAX)
		return false;
	/* Newlines and tabs are reserved as state-file delimiters */
	if (strchr(needle, '\n') || strchr(needle, '\r') || strchr(needle, '\t'))
		return false;
	return true;
}

int ela_process_watch_state_parse_line(const char *line,
					char *needle_out, size_t needle_sz,
					char *pids_out, size_t pids_sz)
{
	const char *tab;
	const char *end;
	size_t needle_len;
	size_t pids_len;

	if (!line || !needle_out || needle_sz < 2 || !pids_out || pids_sz < 1)
		return -1;

	tab = strchr(line, '\t');
	if (!tab)
		return -1;

	needle_len = (size_t)(tab - line);
	if (needle_len == 0 || needle_len >= needle_sz)
		return -1;

	/* pids: everything after the tab up to the first newline or NUL */
	end = tab + 1;
	while (*end && *end != '\n' && *end != '\r')
		end++;

	pids_len = (size_t)(end - (tab + 1));
	if (pids_len >= pids_sz)
		return -1;

	memcpy(needle_out, line, needle_len);
	needle_out[needle_len] = '\0';
	memcpy(pids_out, tab + 1, pids_len);
	pids_out[pids_len] = '\0';
	return 0;
}

int ela_process_watch_state_format_line(const char *needle, const char *pids,
					 char *out, size_t out_sz)
{
	int n;

	if (!needle || !*needle || !pids || !out || out_sz < 4)
		return -1;

	n = snprintf(out, out_sz, "%s\t%s\n", needle, pids);
	return (n > 0 && (size_t)n < out_sz) ? 0 : -1;
}

bool ela_process_watch_pids_equal(const char *a, const char *b)
{
	if (!a)
		a = "";
	if (!b)
		b = "";
	return strcmp(a, b) == 0;
}

/*
 * Internal helper: build one txt/csv/json record with up to two named fields.
 * field2_name/field2_val may both be NULL to omit the second field.
 */
static int format_record(const char *record_type,
			  const char *needle,
			  const char *field1_name, const char *field1_val,
			  const char *field2_name, const char *field2_val,
			  const char *field3_name, const char *field3_val,
			  const char *fmt,
			  char **out, size_t *out_len)
{
	char *buf = NULL;
	int n;

	if (!record_type || !needle || !field1_name || !field1_val ||
	    !fmt || !out || !out_len)
		return -1;

	if (!strcmp(fmt, "json")) {
		json_object *obj = json_object_new_object();
		const char *js;
		size_t js_len;

		if (!obj)
			return -1;
		json_object_object_add(obj, "record",
				       json_object_new_string(record_type));
		json_object_object_add(obj, "needle",
				       json_object_new_string(needle));
		json_object_object_add(obj, field1_name,
				       json_object_new_string(field1_val));
		if (field2_name && field2_val)
			json_object_object_add(obj, field2_name,
					       json_object_new_string(field2_val));
		if (field3_name && field3_val)
			json_object_object_add(obj, field3_name,
					       json_object_new_string(field3_val));
		js = json_object_to_json_string_ext(
			obj, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
		js_len = strlen(js);
		buf = malloc(js_len + 2U);
		if (buf) {
			memcpy(buf, js, js_len);
			buf[js_len]     = '\n';
			buf[js_len + 1] = '\0';
			*out_len = js_len + 1U;
		}
		json_object_put(obj);

	} else if (!strcmp(fmt, "csv")) {
		size_t needle_sz = strlen(needle) * 2U + 3U;
		char *fn = malloc(needle_sz);
		size_t wn;

		if (!fn)
			return -1;
		wn = csv_write(fn, needle_sz, needle, strlen(needle));

		if (field2_name && field2_val && field3_name && field3_val) {
			/* record_type,needle,field1_val,field2_val,field3_val\n */
			size_t total = strlen(record_type) + 1U + wn + 1U +
				       strlen(field1_val) + 1U +
				       strlen(field2_val) + 1U +
				       strlen(field3_val) + 2U;
			buf = malloc(total);
			if (buf) {
				n = snprintf(buf, total, "%s,%s,%s,%s,%s\n",
					     record_type, fn,
					     field1_val, field2_val, field3_val);
				*out_len = (n > 0) ? (size_t)n : 0;
			}
		} else if (field2_name && field2_val) {
			/* record_type,needle,field1_val,field2_val\n */
			size_t total = strlen(record_type) + 1U + wn + 1U +
				       strlen(field1_val) + 1U +
				       strlen(field2_val) + 2U;
			buf = malloc(total);
			if (buf) {
				n = snprintf(buf, total, "%s,%s,%s,%s\n",
					     record_type, fn,
					     field1_val, field2_val);
				*out_len = (n > 0) ? (size_t)n : 0;
			}
		} else {
			/* record_type,needle,field1_val\n */
			size_t total = strlen(record_type) + 1U + wn + 1U +
				       strlen(field1_val) + 2U;
			buf = malloc(total);
			if (buf) {
				n = snprintf(buf, total, "%s,%s,%s\n",
					     record_type, fn, field1_val);
				*out_len = (n > 0) ? (size_t)n : 0;
			}
		}
		free(fn);

	} else {
		/* txt */
		size_t needed = strlen(record_type) + strlen(needle) +
				strlen(field1_name) + strlen(field1_val) + 64U;
		if (field2_name && field2_val)
			needed += strlen(field2_name) + strlen(field2_val) + 8U;
		if (field3_name && field3_val)
			needed += strlen(field3_name) + strlen(field3_val) + 8U;
		buf = malloc(needed);
		if (buf) {
			if (field2_name && field2_val && field3_name && field3_val) {
				n = snprintf(buf, needed,
					     "%s: needle=%s %s=%s %s=%s %s=%s\n",
					     record_type, needle,
					     field1_name, field1_val,
					     field2_name, field2_val,
					     field3_name, field3_val);
			} else if (field2_name && field2_val) {
				n = snprintf(buf, needed,
					     "%s: needle=%s %s=%s %s=%s\n",
					     record_type, needle,
					     field1_name, field1_val,
					     field2_name, field2_val);
			} else {
				n = snprintf(buf, needed,
					     "%s: needle=%s %s=%s\n",
					     record_type, needle,
					     field1_name, field1_val);
			}
			*out_len = (n > 0) ? (size_t)n : 0;
		}
	}

	if (!buf)
		return -1;
	*out = buf;
	return 0;
}

int ela_process_watch_format_event(const char *needle,
				    const char *old_pid,
				    const char *new_pid,
				    const char *exe,
				    const char *fmt,
				    char **out, size_t *out_len)
{
	if (!needle || !old_pid || !new_pid || !exe || !fmt || !out || !out_len)
		return -1;
	return format_record("process_watch", needle,
			     "old_pid", old_pid,
			     "new_pid", new_pid,
			     "exe", exe,
			     fmt, out, out_len);
}

int ela_process_watch_format_list_entry(const char *needle,
					 const char *pids,
					 const char *fmt,
					 char **out, size_t *out_len)
{
	if (!needle || !pids || !fmt || !out || !out_len)
		return -1;
	return format_record("process_watch_list", needle,
			     "pids", pids,
			     NULL, NULL,
			     NULL, NULL,
			     fmt, out, out_len);
}

const char *ela_process_watch_content_type(const char *fmt)
{
	if (fmt && !strcmp(fmt, "json"))
		return "application/json; charset=utf-8";
	if (fmt && !strcmp(fmt, "csv"))
		return "text/csv; charset=utf-8";
	return "text/plain; charset=utf-8";
}
