// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_LINUX_KERNEL_MODULE_UTIL_H
#define ELA_LINUX_KERNEL_MODULE_UTIL_H

#include <stdbool.h>
#include <stddef.h>

#define ELA_MODULE_INIT_IGNORE_MODVERSIONS 1U
#define ELA_MODULE_INIT_IGNORE_VERMAGIC    2U

enum ela_kernel_module_action {
	ELA_KERNEL_MODULE_ACTION_NONE = 0,
	ELA_KERNEL_MODULE_ACTION_LIST,
	ELA_KERNEL_MODULE_ACTION_LOAD,
	ELA_KERNEL_MODULE_ACTION_UNLOAD,
	ELA_KERNEL_MODULE_ACTION_VERMAGIC,
};

struct ela_kernel_module_record {
	char name[128];
	unsigned long size;
	int refcount;
	char dependencies[512];
	char state[64];
	char address[64];
};

struct ela_kernel_module_request {
	enum ela_kernel_module_action action;
	const char *module_path;
	const char *module_name;
	char params[1024];
	bool force_vermagic;
	bool show_help;
};

int ela_kernel_module_parse_proc_line(const char *line,
				      struct ela_kernel_module_record *record);
int ela_kernel_module_prepare_request(int argc, char **argv,
				      struct ela_kernel_module_request *request,
				      char *errbuf, size_t errbuf_len);
unsigned int ela_kernel_module_load_flags(const struct ela_kernel_module_request *request);
int ela_kernel_module_extract_vermagic(const unsigned char *data, size_t data_len,
				       char *out, size_t out_len);

#endif
