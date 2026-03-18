// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_INTERACTIVE_UTIL_H
#define ELA_INTERACTIVE_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

enum ela_interactive_set_kind {
	ELA_INTERACTIVE_SET_UNSUPPORTED = 0,
	ELA_INTERACTIVE_SET_API_URL,
	ELA_INTERACTIVE_SET_API_INSECURE,
	ELA_INTERACTIVE_SET_QUIET,
	ELA_INTERACTIVE_SET_OUTPUT_FORMAT,
	ELA_INTERACTIVE_SET_OUTPUT_TCP,
	ELA_INTERACTIVE_SET_SCRIPT,
	ELA_INTERACTIVE_SET_OUTPUT_HTTP,
	ELA_INTERACTIVE_SET_OUTPUT_INSECURE,
	ELA_INTERACTIVE_SET_API_KEY,
	ELA_INTERACTIVE_SET_VERBOSE,
	ELA_INTERACTIVE_SET_DEBUG,
	ELA_INTERACTIVE_SET_WS_RETRY_ATTEMPTS,
};

struct ela_interactive_set_plan {
	enum ela_interactive_set_kind kind;
	const char *display_name;
	const char *primary_env_name;
	const char *primary_env_value;
	const char *unset_env_name;
	bool clear_output_overrides;
	bool update_conf;
	bool redact_value;
};

struct ela_interactive_history {
	char **entries;
	size_t count;
	size_t cap;
};

const char *const *ela_interactive_candidates_for_position(int argc, char **argv);
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
					       const char *ela_ws_retry);
int ela_interactive_plan_set_command(const char *name,
				     const char *value,
				     struct ela_interactive_set_plan *plan,
				     char *errbuf,
				     size_t errbuf_len);
bool ela_interactive_is_exit_command(const char *cmd);
bool ela_interactive_is_help_command(const char *cmd);
bool ela_interactive_should_show_prompt(int tty_fd, const char *session_mac);
int ela_interactive_build_prompt(char *buf,
				 size_t buf_sz,
				 const char *prog,
				 const char *session_mac,
				 bool show_prompt);
int ela_interactive_history_add(struct ela_interactive_history *history, const char *line);
void ela_interactive_history_free(struct ela_interactive_history *history);
size_t ela_interactive_collect_matches(const char *const *candidates,
				       const char *prefix,
				       const char **matches,
				       size_t max_matches);

#endif
