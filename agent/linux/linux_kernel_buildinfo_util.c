// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "linux_kernel_buildinfo_util.h"

#include <stdio.h>
#include <string.h>

int ela_kernel_buildinfo_config_candidate(const char *root, const char *release,
					  unsigned int index,
					  char *out, size_t out_len)
{
	int n;

	if (!out || !out_len)
		return -1;
	if (!root)
		root = "";

	switch (index) {
	case 0:
		n = snprintf(out, out_len, "%s/proc/config.gz", root);
		break;
	case 1:
		if (!release || !*release)
			return -1;
		n = snprintf(out, out_len, "%s/boot/config-%s", root, release);
		break;
	case 2:
		n = snprintf(out, out_len, "%s/proc/config", root);
		break;
	default:
		return -1;
	}

	return (n >= 0 && (size_t)n < out_len) ? 0 : -1;
}

bool ela_kernel_buildinfo_config_is_gz(const char *path)
{
	size_t len;

	if (!path)
		return false;
	len = strlen(path);
	return len > 3 && !strcmp(path + len - 3, ".gz");
}

char *ela_kernel_buildinfo_trim_line(char *s)
{
	size_t len;

	if (!s)
		return NULL;
	len = strlen(s);
	if (len && s[len - 1] == '\n') {
		s[len - 1] = '\0';
		len--;
	}
	if (len && s[len - 1] == '\r')
		s[len - 1] = '\0';
	return s;
}

int ela_kernel_buildinfo_tool_candidate(const char *path_env, const char *name,
					unsigned int index,
					char *out, size_t out_len)
{
	/* Where module tools conventionally live; PATH on embedded inits
	 * frequently omits the sbin dirs even when the tools exist. */
	static const char *const fallback_dirs[] = {
		"/sbin", "/usr/sbin", "/bin", "/usr/bin",
	};
	unsigned int seen = 0;
	const char *p = path_env;
	int n;

	if (!name || !*name || !out || !out_len)
		return -1;

	while (p && *p) {
		const char *sep = strchr(p, ':');
		size_t seg_len = sep ? (size_t)(sep - p) : strlen(p);

		if (seg_len) {
			if (seen == index) {
				n = snprintf(out, out_len, "%.*s/%s",
					     (int)seg_len, p, name);
				return (n >= 0 && (size_t)n < out_len) ? 0 : -1;
			}
			seen++;
		}
		if (!sep)
			break;
		p = sep + 1;
	}

	if (index - seen >= sizeof(fallback_dirs) / sizeof(fallback_dirs[0]))
		return -1;
	n = snprintf(out, out_len, "%s/%s",
		     fallback_dirs[index - seen], name);
	return (n >= 0 && (size_t)n < out_len) ? 0 : -1;
}

static int append_json_escaped(char *out, size_t out_len, size_t *pos, const char *value)
{
	size_t i;

	if (!out || !out_len || !pos || !value)
		return -1;

	for (i = 0; value[i]; i++) {
		unsigned char c = (unsigned char)value[i];
		const char *esc = NULL;
		char hex[7];
		size_t need;

		if (c == '"')
			esc = "\\\"";
		else if (c == '\\')
			esc = "\\\\";
		else if (c == '\n')
			esc = "\\n";
		else if (c == '\r')
			esc = "\\r";
		else if (c == '\t')
			esc = "\\t";

		if (esc) {
			need = strlen(esc);
			if (*pos + need >= out_len)
				return -1;
			memcpy(out + *pos, esc, need);
			*pos += need;
			continue;
		}

		if (c < 0x20) {
			snprintf(hex, sizeof(hex), "\\u%04x", c);
			need = strlen(hex);
			if (*pos + need >= out_len)
				return -1;
			memcpy(out + *pos, hex, need);
			*pos += need;
			continue;
		}

		if (*pos + 1U >= out_len)
			return -1;
		out[*pos] = (char)c;
		(*pos)++;
	}
	out[*pos] = '\0';
	return 0;
}

/* Append `"key":"value"` (or `"key":null` for an empty value) plus a leading
 * comma when `pos` is past the opening brace. */
static int append_json_field(char *out, size_t out_len, size_t *pos,
			     const char *key, const char *value)
{
	int n;

	n = snprintf(out + *pos, out_len - *pos, "%s\"%s\":",
		     out[*pos - 1] == '{' ? "" : ",", key);
	if (n < 0 || (size_t)n >= out_len - *pos)
		return -1;
	*pos += (size_t)n;

	if (!value || !*value) {
		n = snprintf(out + *pos, out_len - *pos, "null");
		if (n < 0 || (size_t)n >= out_len - *pos)
			return -1;
		*pos += (size_t)n;
		return 0;
	}

	if (*pos + 1U >= out_len)
		return -1;
	out[(*pos)++] = '"';
	if (append_json_escaped(out, out_len, pos, value) != 0)
		return -1;
	if (*pos + 1U >= out_len)
		return -1;
	out[(*pos)++] = '"';
	out[*pos] = '\0';
	return 0;
}

int ela_kernel_buildinfo_format_payload(const char *format,
					const struct ela_kernel_buildinfo *info,
					char *out, size_t out_len)
{
	const char *isa;
	const char *bits;
	const char *endianness;
	size_t pos;
	int n;

	if (!info || !out || !out_len)
		return -1;

	isa = info->isa ? info->isa : "";
	bits = info->bits ? info->bits : "";
	endianness = info->endianness ? info->endianness : "";

	if (format && !strcmp(format, "json")) {
		n = snprintf(out, out_len, "{");
		if (n < 0 || (size_t)n >= out_len)
			return -1;
		pos = (size_t)n;
		if (append_json_field(out, out_len, &pos, "record", "module_buildinfo") != 0 ||
		    append_json_field(out, out_len, &pos, "kernel_release", info->kernel_release) != 0 ||
		    append_json_field(out, out_len, &pos, "proc_version", info->proc_version) != 0 ||
		    append_json_field(out, out_len, &pos, "vermagic", info->vermagic) != 0 ||
		    append_json_field(out, out_len, &pos, "module_path", info->module_path) != 0 ||
		    append_json_field(out, out_len, &pos, "isa", isa) != 0 ||
		    append_json_field(out, out_len, &pos, "bits", bits) != 0 ||
		    append_json_field(out, out_len, &pos, "endianness", endianness) != 0 ||
		    append_json_field(out, out_len, &pos, "config_source", info->config_source) != 0)
			return -1;
		n = snprintf(out + pos, out_len - pos,
			     ",\"config_available\":%s,\"config_compressed\":%s}\n",
			     info->config_available ? "true" : "false",
			     info->config_compressed ? "true" : "false");
		return (n >= 0 && (size_t)n < out_len - pos) ? 0 : -1;
	}

	if (format && !strcmp(format, "csv"))
		n = snprintf(out, out_len, "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",%s,%s\n",
			     info->kernel_release, info->proc_version,
			     info->vermagic, info->module_path, isa,
			     bits, endianness,
			     info->config_source,
			     info->config_available ? "true" : "false",
			     info->config_compressed ? "true" : "false");
	else
		n = snprintf(out, out_len,
			     "kernel_release=%s vermagic=%s module_path=%s isa=%s "
			     "bits=%s endianness=%s "
			     "config_source=%s config_available=%s config_compressed=%s\n",
			     info->kernel_release, info->vermagic,
			     info->module_path, isa, bits, endianness,
			     info->config_source[0] ? info->config_source : "-",
			     info->config_available ? "true" : "false",
			     info->config_compressed ? "true" : "false");

	return (n >= 0 && (size_t)n < out_len) ? 0 : -1;
}
