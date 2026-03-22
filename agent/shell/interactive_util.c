// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "interactive_util.h"

#include "../net/tcp_parse_util.h"
#include "../util/command_parse_util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *const interactive_top_level_commands[] = {
	"help", "quit", "exit", "set", "arch", "uboot", "linux", "efi", "bios", "tpm2", "transfer", NULL,
};
static const char *const interactive_group_arch[] = { "bit", "isa", "endianness", NULL };
static const char *const interactive_group_uboot[] = { "env", "image", "audit", NULL };
static const char *const interactive_group_linux[] = {
	"dmesg", "download-file", "execute-command", "grep", "list-files", "list-symlinks", "remote-copy", "ssh", "process", "gdbserver", NULL,
};
static const char *const interactive_group_linux_gdbserver[] = { "tunnel", NULL };
static const char *const interactive_group_linux_process[] = { "watch", NULL };
static const char *const interactive_group_linux_process_watch[] = { "on", "off", "list", NULL };
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
	if (!strcmp(argv[0], "linux")) {
		if (argc >= 3) {
			if (!strcmp(argv[1], "process")) {
				if (argc == 3)
					return interactive_group_linux_process;
				if (argc == 4 && !strcmp(argv[2], "watch"))
					return interactive_group_linux_process_watch;
			}
			if (!strcmp(argv[1], "gdbserver") && argc == 3)
				return interactive_group_linux_gdbserver;
			return NULL;
		}
		return interactive_group_linux;
	}
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

static int interactive_plan_bool(const char *name,
				 const char *value,
				 enum ela_interactive_set_kind kind,
				 struct ela_interactive_set_plan *plan,
				 char *errbuf,
				 size_t errbuf_len)
{
	const char *normalized = NULL;

	if (!ela_parse_bool_string(value, &normalized)) {
		if (errbuf && errbuf_len) {
			snprintf(errbuf, errbuf_len,
				 "Invalid %s value: %s (expected true/false, 1/0, yes/no, on/off)",
				 name, value ? value : "");
		}
		return -1;
	}

	plan->kind = kind;
	plan->display_name = name;
	plan->primary_env_name = name;
	plan->primary_env_value = normalized;
	return 0;
}

int ela_interactive_plan_set_command(const char *name,
				     const char *value,
				     struct ela_interactive_set_plan *plan,
				     char *errbuf,
				     size_t errbuf_len)
{
	char *end = NULL;
	long retry_value;

	if (!plan || !name || !value) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "invalid set command");
		return -1;
	}

	memset(plan, 0, sizeof(*plan));

	if (!strcmp(name, "ELA_API_URL")) {
		if (strncmp(value, "http://", 7) && strncmp(value, "https://", 8)) {
			if (errbuf && errbuf_len) {
				snprintf(errbuf, errbuf_len,
					 "Invalid ELA_API_URL (expected http://host:port/... or https://host:port/...): %s",
					 value);
			}
			return -1;
		}
		plan->kind = ELA_INTERACTIVE_SET_API_URL;
		plan->display_name = "ELA_API_URL";
		plan->primary_env_name = "ELA_API_URL";
		plan->primary_env_value = value;
		plan->clear_output_overrides = true;
		plan->update_conf = true;
		return 0;
	}

	if (!strcmp(name, "ELA_API_INSECURE")) {
		if (interactive_plan_bool(name, value, ELA_INTERACTIVE_SET_API_INSECURE, plan, errbuf, errbuf_len) != 0)
			return -1;
		plan->update_conf = true;
		return 0;
	}

	if (!strcmp(name, "ELA_QUIET"))
		return interactive_plan_bool(name, value, ELA_INTERACTIVE_SET_QUIET, plan, errbuf, errbuf_len);

	if (!strcmp(name, "ELA_OUTPUT_FORMAT")) {
		if (strcmp(value, "txt") && strcmp(value, "csv") && strcmp(value, "json")) {
			if (errbuf && errbuf_len) {
				snprintf(errbuf, errbuf_len,
					 "Invalid ELA_OUTPUT_FORMAT: %s (expected: csv, json, txt)",
					 value);
			}
			return -1;
		}
		plan->kind = ELA_INTERACTIVE_SET_OUTPUT_FORMAT;
		plan->display_name = "ELA_OUTPUT_FORMAT";
		plan->primary_env_name = "ELA_OUTPUT_FORMAT";
		plan->primary_env_value = value;
		plan->update_conf = true;
		return 0;
	}

	if (!strcmp(name, "ELA_OUTPUT_TCP")) {
		if (!ela_is_valid_ipv4_tcp_target(value)) {
			if (errbuf && errbuf_len) {
				snprintf(errbuf, errbuf_len,
					 "Invalid ELA_OUTPUT_TCP target (expected IPv4:port): %s",
					 value);
			}
			return -1;
		}
		plan->kind = ELA_INTERACTIVE_SET_OUTPUT_TCP;
		plan->display_name = "ELA_OUTPUT_TCP";
		plan->primary_env_name = "ELA_OUTPUT_TCP";
		plan->primary_env_value = value;
		return 0;
	}

	if (!strcmp(name, "ELA_SCRIPT")) {
		plan->kind = ELA_INTERACTIVE_SET_SCRIPT;
		plan->display_name = "ELA_SCRIPT";
		plan->primary_env_name = "ELA_SCRIPT";
		plan->primary_env_value = value;
		return 0;
	}

	if (!strcmp(name, "ELA_OUTPUT_HTTP")) {
		if (strncmp(value, "http://", 7) && strncmp(value, "https://", 8)) {
			if (errbuf && errbuf_len) {
				snprintf(errbuf, errbuf_len,
					 "Invalid ELA_OUTPUT_HTTP (expected http://host:port/... or https://host:port/...): %s",
					 value);
			}
			return -1;
		}
		plan->kind = ELA_INTERACTIVE_SET_OUTPUT_HTTP;
		plan->display_name = "ELA_OUTPUT_HTTP";
		plan->primary_env_name = !strncmp(value, "https://", 8) ? "ELA_OUTPUT_HTTPS" : "ELA_OUTPUT_HTTP";
		plan->unset_env_name = !strncmp(value, "https://", 8) ? "ELA_OUTPUT_HTTP" : "ELA_OUTPUT_HTTPS";
		plan->primary_env_value = value;
		plan->update_conf = true;
		return 0;
	}

	if (!strcmp(name, "ELA_OUTPUT_INSECURE")) {
		if (interactive_plan_bool(name, value, ELA_INTERACTIVE_SET_OUTPUT_INSECURE, plan, errbuf, errbuf_len) != 0)
			return -1;
		plan->update_conf = true;
		return 0;
	}

	if (!strcmp(name, "ELA_API_KEY")) {
		if (strlen(value) > 1024) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "ELA_API_KEY value too long (max 1024 characters)");
			return -1;
		}
		plan->kind = ELA_INTERACTIVE_SET_API_KEY;
		plan->display_name = "ELA_API_KEY";
		plan->primary_env_name = "ELA_API_KEY";
		plan->primary_env_value = value;
		plan->redact_value = true;
		return 0;
	}

	if (!strcmp(name, "ELA_VERBOSE"))
		return interactive_plan_bool(name, value, ELA_INTERACTIVE_SET_VERBOSE, plan, errbuf, errbuf_len);

	if (!strcmp(name, "ELA_DEBUG"))
		return interactive_plan_bool(name, value, ELA_INTERACTIVE_SET_DEBUG, plan, errbuf, errbuf_len);

	if (!strcmp(name, "ELA_WS_RETRY_ATTEMPTS")) {
		errno = 0;
		retry_value = strtol(value, &end, 10);
		if (errno != 0 || !end || *end || retry_value < 0 || retry_value > 1000) {
			if (errbuf && errbuf_len) {
				snprintf(errbuf, errbuf_len,
					 "Invalid ELA_WS_RETRY_ATTEMPTS value: %s (expected integer 0-1000)",
					 value);
			}
			return -1;
		}
		plan->kind = ELA_INTERACTIVE_SET_WS_RETRY_ATTEMPTS;
		plan->display_name = "ELA_WS_RETRY_ATTEMPTS";
		plan->primary_env_name = "ELA_WS_RETRY_ATTEMPTS";
		plan->primary_env_value = value;
		return 0;
	}

	if (errbuf && errbuf_len)
		snprintf(errbuf, errbuf_len, "Unsupported variable for set: %s", name);
	return -1;
}

bool ela_interactive_is_exit_command(const char *cmd)
{
	return cmd && (!strcmp(cmd, "quit") || !strcmp(cmd, "exit"));
}

bool ela_interactive_is_help_command(const char *cmd)
{
	return cmd && !strcmp(cmd, "help");
}

bool ela_interactive_should_show_prompt(int tty_fd, const char *session_mac)
{
	return tty_fd >= 0 || (session_mac && *session_mac);
}

int ela_interactive_build_prompt(char *buf,
				 size_t buf_sz,
				 const char *prog,
				 const char *session_mac,
				 bool show_prompt)
{
	const char *bn;

	if (!buf || buf_sz == 0)
		return -1;
	if (!show_prompt) {
		buf[0] = '\0';
		return 0;
	}
	if (session_mac && *session_mac)
		return snprintf(buf, buf_sz, "(%s)> ", session_mac) >= (int)buf_sz ? -1 : 0;
	bn = prog ? strrchr(prog, '/') : NULL;
	return snprintf(buf, buf_sz, "%s> ", bn ? bn + 1 : (prog ? prog : "")) >= (int)buf_sz ? -1 : 0;
}

int ela_interactive_history_add(struct ela_interactive_history *history, const char *line)
{
	char **tmp_entries;
	char *copy;

	if (!history || !line || !*line)
		return 0;

	copy = strdup(line);
	if (!copy)
		return -1;

	if (history->count == history->cap) {
		size_t new_cap = history->cap ? history->cap * 2 : 16;
		tmp_entries = realloc(history->entries, new_cap * sizeof(*tmp_entries));
		if (!tmp_entries) {
			free(copy);
			return -1;
		}
		history->entries = tmp_entries;
		history->cap = new_cap;
	}

	history->entries[history->count++] = copy;
	return 0;
}

void ela_interactive_history_free(struct ela_interactive_history *history)
{
	size_t i;

	if (!history)
		return;
	for (i = 0; i < history->count; i++)
		free(history->entries[i]);
	free(history->entries);
	history->entries = NULL;
	history->count = 0;
	history->cap = 0;
}

size_t ela_interactive_collect_matches(const char *const *candidates,
				       const char *prefix,
				       const char **matches,
				       size_t max_matches)
{
	size_t count = 0;
	size_t prefix_len = prefix ? strlen(prefix) : 0;

	if (!candidates || !matches || max_matches == 0)
		return 0;

	for (; *candidates && count < max_matches; candidates++) {
		if (!prefix || strncmp(*candidates, prefix, prefix_len) == 0)
			matches[count++] = *candidates;
	}

	return count;
}
