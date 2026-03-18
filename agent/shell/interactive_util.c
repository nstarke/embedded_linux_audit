// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "interactive_util.h"

#include <stdio.h>
#include <string.h>

static const char *const interactive_top_level_commands[] = {
	"help", "quit", "exit", "set", "arch", "uboot", "linux", "efi", "bios", "tpm2", "transfer", NULL,
};
static const char *const interactive_group_arch[] = { "bit", "isa", "endianness", NULL };
static const char *const interactive_group_uboot[] = { "env", "image", "audit", NULL };
static const char *const interactive_group_linux[] = {
	"dmesg", "download-file", "execute-command", "grep", "list-files", "list-symlinks", "remote-copy", "ssh", NULL,
};
static const char *const interactive_group_efi[] = { "orom", "dump-vars", NULL };
static const char *const interactive_group_bios[] = { "orom", NULL };
static const char *const interactive_set_variables[] = {
	"ELA_API_URL", "ELA_API_INSECURE", "ELA_QUIET", "ELA_OUTPUT_FORMAT", "ELA_OUTPUT_TCP", "ELA_SCRIPT",
	"ELA_OUTPUT_HTTP", "ELA_OUTPUT_INSECURE", "ELA_API_KEY", "ELA_VERBOSE", "ELA_DEBUG", "ELA_WS_RETRY_ATTEMPTS", NULL,
};

static const char *ela_interactive_current(const char *value)
{
	return (value && *value) ? value : "<unset>";
}

const char *const *ela_interactive_candidates_for_position(int argc, char **argv)
{
	if (argc <= 1)
		return interactive_top_level_commands;
	if (!strcmp(argv[0], "arch"))
		return interactive_group_arch;
	if (!strcmp(argv[0], "uboot"))
		return interactive_group_uboot;
	if (!strcmp(argv[0], "linux"))
		return interactive_group_linux;
	if (!strcmp(argv[0], "efi"))
		return interactive_group_efi;
	if (!strcmp(argv[0], "bios"))
		return interactive_group_bios;
	if (!strcmp(argv[0], "set") && argc == 2)
		return interactive_set_variables;
	return NULL;
}

int ela_interactive_format_supported_variables(char *buf,
					       size_t buf_sz,
					       const char *ela_api_url,
					       const char *ela_api_insecure,
					       const char *ela_quiet,
					       const char *ela_output_format,
					       const char *ela_output_tcp,
					       const char *ela_script,
					       const char *ela_output_http,
					       const char *ela_output_insecure,
					       const char *ela_api_key,
					       const char *ela_verbose,
					       const char *ela_debug,
					       const char *ela_ws_retry)
{
	if (!buf || buf_sz == 0)
		return -1;

	return snprintf(buf, buf_sz,
			"Supported variables:\n"
			"  ELA_API_URL              current=%s\n"
			"  ELA_API_INSECURE         current=%s\n"
			"  ELA_QUIET                current=%s\n"
			"  ELA_OUTPUT_FORMAT        current=%s\n"
			"  ELA_OUTPUT_TCP           current=%s\n"
			"  ELA_SCRIPT               current=%s\n"
			"  ELA_OUTPUT_HTTP          current=%s\n"
			"  ELA_OUTPUT_INSECURE      current=%s\n"
			"  ELA_API_KEY              current=%s\n"
			"  ELA_VERBOSE              current=%s\n"
			"  ELA_DEBUG                current=%s\n"
			"  ELA_WS_RETRY_ATTEMPTS    current=%s\n",
			ela_interactive_current(ela_api_url),
			ela_interactive_current(ela_api_insecure),
			ela_interactive_current(ela_quiet),
			ela_interactive_current(ela_output_format),
			ela_interactive_current(ela_output_tcp),
			ela_interactive_current(ela_script),
			ela_interactive_current(ela_output_http),
			ela_interactive_current(ela_output_insecure),
			(ela_api_key && *ela_api_key) ? "<set>" : "<unset>",
			ela_interactive_current(ela_verbose),
			ela_interactive_current(ela_debug),
			ela_interactive_current(ela_ws_retry)) >= (int)buf_sz ? -1 : 0;
}
