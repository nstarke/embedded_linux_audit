// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "uboot_env_record_util.h"

#include "uboot_env_format_util.h"

#include "../../util/str_util.h"

#include <csv.h>
#include <json.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *ela_uboot_env_candidate_mode(bool bruteforce,
					 bool crc_ok_std,
					 bool crc_ok_redund)
{
	if (bruteforce)
		return "hint-only";
	if (crc_ok_redund && !crc_ok_std)
		return "redundant";
	return "standard";
}

size_t ela_uboot_env_data_offset(bool crc_ok_std, bool crc_ok_redund)
{
	(void)crc_ok_std;
	if (crc_ok_redund)
		return 5U;
	return 4U;
}

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

static int append_env_csv_header_if_needed(bool *csv_header_emitted,
					   char **out,
					   size_t *len,
					   size_t *cap)
{
	if (!csv_header_emitted || *csv_header_emitted)
		return 0;
	if (append_text(out, len, cap,
			"record,device,offset,crc_endian,mode,has_known_vars,cfg_offset,env_size,erase_size,sector_count\n") != 0)
		return -1;
	*csv_header_emitted = true;
	return 0;
}

int ela_uboot_env_format_candidate_record(int fmt,
					  bool *csv_header_emitted,
					  const char *dev,
					  uint64_t off,
					  const char *crc_endian,
					  const char *mode,
					  bool has_known_vars,
					  uint64_t cfg_off,
					  uint64_t env_size,
					  uint64_t erase_size,
					  uint64_t sector_count,
					  char **out)
{
	char off_s[32], cfg_s[32], env_s[32], erase_s[32], sec_s[32];
	char *buf = NULL;
	size_t len = 0, cap = 0;

	if (!out)
		return -1;
	*out = NULL;

	if (fmt == ELA_UBOOT_ENV_OUTPUT_CSV) {
		snprintf(off_s, sizeof(off_s), "0x%jx", (uintmax_t)off);
		snprintf(cfg_s, sizeof(cfg_s), "0x%jx", (uintmax_t)cfg_off);
		snprintf(env_s, sizeof(env_s), "0x%jx", (uintmax_t)env_size);
		snprintf(erase_s, sizeof(erase_s), "0x%jx", (uintmax_t)erase_size);
		snprintf(sec_s, sizeof(sec_s), "0x%jx", (uintmax_t)sector_count);

		if (append_env_csv_header_if_needed(csv_header_emitted, &buf, &len, &cap) != 0 ||
		    append_csv_field(&buf, &len, &cap, "env_candidate") != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, dev) != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, off_s) != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, crc_endian ? crc_endian : "") != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, mode ? mode : "") != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, has_known_vars ? "true" : "false") != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, cfg_s) != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, env_s) != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, erase_s) != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, sec_s) != 0 ||
		    append_text(&buf, &len, &cap, "\n") != 0) {
			free(buf);
			return -1;
		}
		*out = buf;
		return 0;
	}

	if (fmt == ELA_UBOOT_ENV_OUTPUT_JSON) {
		json_object *obj = json_object_new_object();
		const char *json_s;

		if (!obj)
			return -1;
		json_object_object_add(obj, "record", json_object_new_string("env_candidate"));
		json_object_object_add(obj, "device", json_object_new_string(dev ? dev : ""));
		json_object_object_add(obj, "offset", json_object_new_uint64(off));
		json_object_object_add(obj, "crc_endian", json_object_new_string(crc_endian ? crc_endian : ""));
		json_object_object_add(obj, "mode", json_object_new_string(mode ? mode : ""));
		json_object_object_add(obj, "has_known_vars", json_object_new_boolean(has_known_vars));
		json_object_object_add(obj, "cfg_offset", json_object_new_uint64(cfg_off));
		json_object_object_add(obj, "env_size", json_object_new_uint64(env_size));
		json_object_object_add(obj, "erase_size", json_object_new_uint64(erase_size));
		json_object_object_add(obj, "sector_count", json_object_new_uint64(sector_count));
		json_s = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
		append_text(&buf, &len, &cap, json_s);
		append_text(&buf, &len, &cap, "\n");
		json_object_put(obj);
		*out = buf;
		return 0;
	}

	if (!mode)
		mode = "";
	if (!strcmp(mode, "hint-only")) {
		append_text(&buf, &len, &cap, "  candidate offset=");
		snprintf(off_s, sizeof(off_s), "0x%jx", (uintmax_t)off);
		append_text(&buf, &len, &cap, off_s);
		append_text(&buf, &len, &cap, "  mode=hint-only  (has known vars)\n");
	} else if (!strcmp(mode, "redundant")) {
		snprintf(off_s, sizeof(off_s), "0x%jx", (uintmax_t)off);
		append_text(&buf, &len, &cap, "  candidate offset=");
		append_text(&buf, &len, &cap, off_s);
		append_text(&buf, &len, &cap, "  crc=");
		append_text(&buf, &len, &cap, crc_endian ? crc_endian : "");
		append_text(&buf, &len, &cap, "-endian  ");
		append_text(&buf, &len, &cap, has_known_vars ? "(has known vars)" : "(crc ok)");
		append_text(&buf, &len, &cap, " (redundant-env layout)\n");
	} else {
		snprintf(off_s, sizeof(off_s), "0x%jx", (uintmax_t)off);
		append_text(&buf, &len, &cap, "  candidate offset=");
		append_text(&buf, &len, &cap, off_s);
		append_text(&buf, &len, &cap, "  crc=");
		append_text(&buf, &len, &cap, crc_endian ? crc_endian : "");
		append_text(&buf, &len, &cap, "-endian  ");
		append_text(&buf, &len, &cap, has_known_vars ? "(has known vars)" : "(crc ok)");
		append_text(&buf, &len, &cap, "\n");
	}
	snprintf(cfg_s, sizeof(cfg_s), "0x%jx", (uintmax_t)cfg_off);
	snprintf(env_s, sizeof(env_s), "0x%jx", (uintmax_t)env_size);
	snprintf(erase_s, sizeof(erase_s), "0x%jx", (uintmax_t)erase_size);
	snprintf(sec_s, sizeof(sec_s), "0x%jx", (uintmax_t)sector_count);
	append_text(&buf, &len, &cap, "    uboot_env.config line: ");
	append_text(&buf, &len, &cap, dev ? dev : "");
	append_text(&buf, &len, &cap, " ");
	append_text(&buf, &len, &cap, cfg_s);
	append_text(&buf, &len, &cap, " ");
	append_text(&buf, &len, &cap, env_s);
	append_text(&buf, &len, &cap, " ");
	append_text(&buf, &len, &cap, erase_s);
	append_text(&buf, &len, &cap, " ");
	append_text(&buf, &len, &cap, sec_s);
	append_text(&buf, &len, &cap, "\n");
	*out = buf;
	return 0;
}

int ela_uboot_env_format_redundant_pair_record(int fmt,
					       bool *csv_header_emitted,
					       const char *dev,
					       uint64_t a,
					       uint64_t b,
					       char **out)
{
	char a_s[32], b_s[32];
	char *buf = NULL;
	size_t len = 0, cap = 0;

	if (!out)
		return -1;
	*out = NULL;

	snprintf(a_s, sizeof(a_s), "0x%jx", (uintmax_t)a);
	snprintf(b_s, sizeof(b_s), "0x%jx", (uintmax_t)b);

	if (fmt == ELA_UBOOT_ENV_OUTPUT_CSV) {
		if (append_env_csv_header_if_needed(csv_header_emitted, &buf, &len, &cap) != 0 ||
		    append_csv_field(&buf, &len, &cap, "redundant_pair") != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, dev ? dev : "") != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, a_s) != 0 ||
		    append_text(&buf, &len, &cap, ",,,,") != 0 ||
		    append_csv_field(&buf, &len, &cap, "false") != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, b_s) != 0 ||
		    append_text(&buf, &len, &cap, ",,,\n") != 0) {
			free(buf);
			return -1;
		}
		*out = buf;
		return 0;
	}

	if (fmt == ELA_UBOOT_ENV_OUTPUT_JSON) {
		json_object *obj = json_object_new_object();
		const char *json_s;

		if (!obj)
			return -1;
		json_object_object_add(obj, "record", json_object_new_string("redundant_pair"));
		json_object_object_add(obj, "device", json_object_new_string(dev ? dev : ""));
		json_object_object_add(obj, "offset_a", json_object_new_uint64(a));
		json_object_object_add(obj, "offset_b", json_object_new_uint64(b));
		json_s = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
		append_text(&buf, &len, &cap, json_s);
		append_text(&buf, &len, &cap, "\n");
		json_object_put(obj);
		*out = buf;
		return 0;
	}

	append_text(&buf, &len, &cap, "    redundant env candidate pair: ");
	append_text(&buf, &len, &cap, dev ? dev : "");
	append_text(&buf, &len, &cap, " ");
	append_text(&buf, &len, &cap, a_s);
	append_text(&buf, &len, &cap, " <-> ");
	append_text(&buf, &len, &cap, b_s);
	append_text(&buf, &len, &cap, "\n");
	*out = buf;
	return 0;
}

int ela_uboot_env_format_verbose_record(int fmt,
					bool verbose,
					bool *csv_header_emitted,
					const char *dev,
					uint64_t off,
					const char *msg,
					char **out)
{
	char off_s[32];
	char *buf = NULL;
	size_t len = 0, cap = 0;

	if (!out)
		return -1;
	*out = NULL;

	if (!verbose || !msg)
		return 0;

	if (fmt == ELA_UBOOT_ENV_OUTPUT_TXT) {
		append_text(&buf, &len, &cap, msg);
		append_text(&buf, &len, &cap, "\n");
		*out = buf;
		return 0;
	}

	if (fmt == ELA_UBOOT_ENV_OUTPUT_CSV) {
		snprintf(off_s, sizeof(off_s), "0x%jx", (uintmax_t)off);
		if (append_env_csv_header_if_needed(csv_header_emitted, &buf, &len, &cap) != 0 ||
		    append_csv_field(&buf, &len, &cap, "verbose") != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, dev ? dev : "") != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, off_s) != 0 ||
		    append_text(&buf, &len, &cap, ",,") != 0 ||
		    append_csv_field(&buf, &len, &cap, msg) != 0 ||
		    append_text(&buf, &len, &cap, ",") != 0 ||
		    append_csv_field(&buf, &len, &cap, "false") != 0 ||
		    append_text(&buf, &len, &cap, ",,,,\n") != 0) {
			free(buf);
			return -1;
		}
		*out = buf;
		return 0;
	}

	if (fmt == ELA_UBOOT_ENV_OUTPUT_JSON) {
		json_object *obj = json_object_new_object();
		const char *json_s;

		if (!obj)
			return -1;
		json_object_object_add(obj, "record", json_object_new_string("verbose"));
		if (dev)
			json_object_object_add(obj, "device", json_object_new_string(dev));
		json_object_object_add(obj, "offset", json_object_new_uint64(off));
		json_object_object_add(obj, "message", json_object_new_string(msg));
		json_s = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
		append_text(&buf, &len, &cap, json_s);
		append_text(&buf, &len, &cap, "\n");
		json_object_put(obj);
		*out = buf;
		return 0;
	}

	return -1;
}

int ela_uboot_env_format_scan_start_record(int fmt,
					   bool verbose,
					   bool *csv_header_emitted,
					   const char *dev,
					   uint64_t step,
					   uint64_t env_size,
					   uint64_t device_size,
					   char **out)
{
	char msg[256];
	int n;

	if (!out)
		return -1;
	*out = NULL;

	if (!verbose)
		return 0;

	n = snprintf(msg, sizeof(msg),
		     "Scanning %s (step=0x%jx, env_size=0x%jx, device_size=0x%jx)",
		     dev ? dev : "",
		     (uintmax_t)step,
		     (uintmax_t)env_size,
		     (uintmax_t)device_size);
	if (n < 0)
		return -1;

	if (fmt == ELA_UBOOT_ENV_OUTPUT_JSON) {
		json_object *obj = json_object_new_object();
		char *buf = NULL;
		size_t len = 0, cap = 0;
		const char *json_s;

		if (!obj)
			return -1;
		json_object_object_add(obj, "record", json_object_new_string("verbose"));
		if (dev)
			json_object_object_add(obj, "device", json_object_new_string(dev));
		json_object_object_add(obj, "offset", json_object_new_uint64(0));
		json_object_object_add(obj, "message", json_object_new_string(msg));
		json_object_object_add(obj, "step", json_object_new_uint64(step));
		json_object_object_add(obj, "env_size", json_object_new_uint64(env_size));
		json_object_object_add(obj, "device_size", json_object_new_uint64(device_size));
		json_s = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
		append_text(&buf, &len, &cap, json_s);
		append_text(&buf, &len, &cap, "\n");
		json_object_put(obj);
		*out = buf;
		return 0;
	}

	return ela_uboot_env_format_verbose_record(fmt, verbose, csv_header_emitted, dev, 0, msg, out);
}

int ela_uboot_env_format_vars_dump(int fmt,
				   const char *dev,
				   uint64_t env_off,
				   const uint8_t *data,
				   size_t len,
				   char **out)
{
	size_t cursor = 0;
	size_t count = 0;
	char *buf = NULL;
	size_t out_len = 0, out_cap = 0;
	json_object *vars_arr = NULL;

	if (!out)
		return -1;
	*out = NULL;

	if (fmt == ELA_UBOOT_ENV_OUTPUT_JSON) {
		vars_arr = json_object_new_array();
		if (!vars_arr)
			return -1;
	} else {
		append_text(&buf, &out_len, &out_cap, "    parsed env vars:\n");
	}

	while (data && cursor < len) {
		const char *s;
		size_t slen;
		const char *eq;
		bool printable = true;

		if (data[cursor] == '\0') {
			if ((cursor + 1 < len && data[cursor + 1] == '\0') || cursor + 1 >= len)
				break;
			cursor++;
			continue;
		}

		s = (const char *)(data + cursor);
		slen = strnlen(s, len - cursor);
		if (slen == len - cursor)
			break;

		eq = memchr(s, '=', slen);
		if (eq) {
			size_t key_len = (size_t)(eq - s);
			size_t val_len = slen - key_len - 1;
			for (size_t i = 0; i < slen; i++) {
				if ((unsigned char)s[i] < 32 && s[i] != '\t') {
					printable = false;
					break;
				}
			}

			if (printable) {
				if (fmt == ELA_UBOOT_ENV_OUTPUT_JSON) {
					json_object *kv = json_object_new_object();
					char *key = strndup(s, key_len);
					char *value = strndup(eq + 1, val_len);
					if (kv && key && value) {
						json_object_object_add(kv, "key", json_object_new_string(key));
						json_object_object_add(kv, "value", json_object_new_string(value));
						json_object_array_add(vars_arr, kv);
						count++;
					} else if (kv) {
						json_object_put(kv);
					}
					free(key);
					free(value);
				} else {
					append_text(&buf, &out_len, &out_cap, "      ");
					append_bytes(&buf, &out_len, &out_cap, s, slen);
					append_text(&buf, &out_len, &out_cap, "\n");
					count++;
				}
			}
		}

		cursor += slen + 1;
		if (count >= 256) {
			if (fmt != ELA_UBOOT_ENV_OUTPUT_JSON)
				append_text(&buf, &out_len, &out_cap, "      ... truncated after 256 vars ...\n");
			break;
		}
	}

	if (fmt == ELA_UBOOT_ENV_OUTPUT_JSON) {
		json_object *obj = json_object_new_object();
		const char *json_s;

		if (!obj) {
			json_object_put(vars_arr);
			return -1;
		}
		json_object_object_add(obj, "record", json_object_new_string("env_vars"));
		if (dev)
			json_object_object_add(obj, "device", json_object_new_string(dev));
		json_object_object_add(obj, "offset", json_object_new_uint64(env_off));
		json_object_object_add(obj, "vars", vars_arr);
		json_s = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
		append_text(&buf, &out_len, &out_cap, json_s);
		append_text(&buf, &out_len, &out_cap, "\n");
		json_object_put(obj);
		*out = buf;
		return 0;
	}

	if (!count)
		append_text(&buf, &out_len, &out_cap, "      (no parseable variables found)\n");

	*out = buf;
	return 0;
}
