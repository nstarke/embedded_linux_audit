// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "linux_kernel_module_util.h"

#include <stdio.h>
#include <string.h>

static void set_err(char *errbuf, size_t errbuf_len, const char *msg)
{
	if (errbuf && errbuf_len)
		snprintf(errbuf, errbuf_len, "%s", msg ? msg : "");
}

bool ela_kernel_module_has_ko_suffix(const char *name)
{
	size_t len;

	if (!name)
		return false;
	len = strlen(name);
	return len > 3 && !strcmp(name + len - 3, ".ko");
}

static int append_param(char *buf, size_t buf_len, const char *param)
{
	size_t cur;
	size_t add;

	if (!buf || !buf_len || !param)
		return -1;

	cur = strlen(buf);
	add = strlen(param);
	if (cur + (cur ? 1U : 0U) + add + 1U > buf_len)
		return -1;
	if (cur) {
		buf[cur] = ' ';
		cur++;
	}
	memcpy(buf + cur, param, add + 1U);
	return 0;
}

int ela_kernel_module_parse_proc_line(const char *line,
				      struct ela_kernel_module_record *record)
{
	char extra[16];
	int matched;

	if (!line || !record)
		return -1;

	memset(record, 0, sizeof(*record));
	extra[0] = '\0';

	matched = sscanf(line, "%127s %lu %d %511s %63s %63s %15s",
			 record->name,
			 &record->size,
			 &record->refcount,
			 record->dependencies,
			 record->state,
			 record->address,
			 extra);
	if (matched != 6 || extra[0])
		return -1;

	if (!strcmp(record->dependencies, "-"))
		record->dependencies[0] = '\0';

	return 0;
}

int ela_kernel_module_prepare_request(int argc, char **argv,
				      struct ela_kernel_module_request *request,
				      char *errbuf, size_t errbuf_len)
{
	int i;

	if (!request) {
		set_err(errbuf, errbuf_len, "internal error: null module request");
		return 2;
	}

	memset(request, 0, sizeof(*request));

	if (argc < 1 || !argv || !argv[0]) {
		set_err(errbuf, errbuf_len, "missing modules command");
		return 2;
	}

	if (argc == 1 || !strcmp(argv[1], "-h") ||
	    !strcmp(argv[1], "--help") || !strcmp(argv[1], "help")) {
		request->show_help = true;
		return 0;
	}

	if (!strcmp(argv[1], "list")) {
		request->action = ELA_KERNEL_MODULE_ACTION_LIST;
		if (argc == 2)
			return 0;
		if (argc == 3 && (!strcmp(argv[2], "-h") || !strcmp(argv[2], "--help"))) {
			request->show_help = true;
			return 0;
		}
		set_err(errbuf, errbuf_len, "Unexpected argument for modules list");
		return 2;
	}

	if (!strcmp(argv[1], "load")) {
		request->action = ELA_KERNEL_MODULE_ACTION_LOAD;
		for (i = 2; i < argc; i++) {
			if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
				request->show_help = true;
				return 0;
			}
			if (!strcmp(argv[i], "--force")) {
				request->force_vermagic = true;
				continue;
			}
			if (!request->module_path) {
				request->module_path = argv[i];
				continue;
			}
			if (append_param(request->params, sizeof(request->params), argv[i]) != 0) {
				set_err(errbuf, errbuf_len, "Module parameters are too long");
				return 2;
			}
		}
		if (!request->module_path) {
			set_err(errbuf, errbuf_len, "modules load requires a module path");
			return 2;
		}
		return 0;
	}

	if (!strcmp(argv[1], "unload")) {
		request->action = ELA_KERNEL_MODULE_ACTION_UNLOAD;
		if (argc == 3 && (!strcmp(argv[2], "-h") || !strcmp(argv[2], "--help"))) {
			request->show_help = true;
			return 0;
		}
		if (argc != 3) {
			set_err(errbuf, errbuf_len, "modules unload requires exactly one module name");
			return 2;
		}
		request->module_name = argv[2];
		return 0;
	}

	if (!strcmp(argv[1], "vermagic")) {
		request->action = ELA_KERNEL_MODULE_ACTION_VERMAGIC;
		if (argc == 3 && (!strcmp(argv[2], "-h") || !strcmp(argv[2], "--help"))) {
			request->show_help = true;
			return 0;
		}
		if (argc == 2) {
			/* No path given: leave module_path NULL so the caller
			 * discovers the first .ko under the module tree. */
			return 0;
		}
		if (argc != 3) {
			set_err(errbuf, errbuf_len, "modules vermagic accepts at most one module path");
			return 2;
		}
		request->module_path = argv[2];
		return 0;
	}

	set_err(errbuf, errbuf_len, "Unknown modules action");
	return 2;
}

unsigned int ela_kernel_module_load_flags(const struct ela_kernel_module_request *request)
{
	if (!request || !request->force_vermagic)
		return 0;
	return ELA_MODULE_INIT_IGNORE_VERMAGIC;
}

int ela_kernel_module_extract_vermagic(const unsigned char *data, size_t data_len,
				       char *out, size_t out_len)
{
	static const char prefix[] = "vermagic=";
	size_t prefix_len = sizeof(prefix) - 1U;
	size_t i;
	size_t j;

	if (!data || !out || out_len == 0)
		return -1;

	out[0] = '\0';
	if (data_len < prefix_len)
		return -1;

	for (i = 0; i <= data_len - prefix_len; i++) {
		if (memcmp(data + i, prefix, prefix_len) != 0)
			continue;

		i += prefix_len;
		for (j = 0; i + j < data_len && data[i + j] != '\0'; j++) {
			if (j + 1U >= out_len)
				return -1;
			out[j] = (char)data[i + j];
		}
		if (i + j >= data_len)
			return -1;
		out[j] = '\0';
		return j > 0 ? 0 : -1;
	}

	return -1;
}
