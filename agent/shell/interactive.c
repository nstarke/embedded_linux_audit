// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "interactive.h"
#include "interactive_util.h"
#include "../embedded_linux_audit_cmd.h"
#include "../net/ela_conf.h"
#include "../util/command_parse_util.h"
#include "../util/interactive_parse_util.h"

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#if defined(ELA_HAS_READLINE)
#include <readline/history.h>
#include <readline/readline.h>
#endif

/* Forward declaration: defined in embedded_linux_audit.c (non-static) */
int embedded_linux_audit_dispatch(int argc, char **argv);

static const char *const *interactive_candidates_for_position(int argc, char **argv)
{
	return ela_interactive_candidates_for_position(argc, argv);
}

#if defined(ELA_HAS_READLINE)
static const char *const *interactive_completion_candidates;
#endif

static void interactive_usage(const char *prog)
{
	printf("Interactive mode commands:\n"
	       "  help                          Show this interactive help\n"
	       "  quit | exit                   Leave interactive mode\n"

#if defined(ELA_HAS_READLINE)
	       "  <Tab>                         Complete commands/groups/subcommands\n"
#else
	       "  <Up>/<Down>                   Recall previous commands from history\n"
#endif
	       "  set                           Show supported interactive environment variables\n"
	       "  set ELA_API_URL <url>         Set default HTTP/HTTPS API endpoint\n"
	       "  set ELA_API_INSECURE <bool>   Set TLS verification policy (true/false)\n"
	       "  set ELA_QUIET <bool>          Set default top-level quiet mode (true/false)\n"
	       "  set ELA_OUTPUT_FORMAT <fmt>   Set default top-level output format (txt/csv/json)\n"
	       "  set ELA_OUTPUT_TCP <target>   Set default top-level TCP output (IPv4:port)\n"
	       "  set ELA_SCRIPT <path|url>     Set default top-level script source\n"
	       "  set ELA_OUTPUT_HTTP <url>     Set default HTTP/HTTPS data upload endpoint\n"
	       "  set ELA_OUTPUT_INSECURE <b>   Set upload TLS verification policy (true/false)\n"
	       "  set ELA_API_KEY <key>         Set bearer token for API authentication\n"
	       "  set ELA_VERBOSE <bool>        Set verbose output mode (true/false)\n"
	       "  set ELA_DEBUG <bool>          Set debug output mode (true/false)\n"
	       "  set ELA_WS_RETRY_ATTEMPTS <n> Set WebSocket reconnect attempts (0-1000, default 5)\n"
	       "\n"
	       "Available command groups:\n"
	       "  uboot env\n"
	       "  uboot image\n"
	       "  uboot audit\n"
	       "  linux dmesg\n"
	       "  linux download-file\n"
	       "  linux execute-command\n"
	       "  linux grep\n"
	       "  linux list-files\n"
	       "  linux list-symlinks\n"
	       "  linux remote-copy\n"
	       "  linux ssh\n"
	       "  tpm2\n"
	       "  efi orom\n"
	       "  efi dump-vars\n"
	       "  bios orom\n"
	       "\n"
	       "Examples:\n"
	       "  %s> set ELA_API_URL http://127.0.0.1:5000/upload\n"
	       "  %s> set ELA_OUTPUT_HTTP http://127.0.0.1:5000/data\n"
	       "  %s> set ELA_API_INSECURE true\n"
	       "  %s> set ELA_QUIET true\n"
	       "  %s> set ELA_OUTPUT_FORMAT json\n"
	       "  %s> set ELA_OUTPUT_TCP 127.0.0.1:5000\n"
	       "  %s> set ELA_SCRIPT ./commands.txt\n"
	       "  %s> set ELA_API_KEY mytoken\n"
	       "  %s> linux dmesg\n"
	       "  %s> linux execute-command \"uname -a\"\n"
	       "  %s> uboot env --size 0x10000\n",
	       prog, prog, prog, prog,
	       prog, prog, prog, prog,
	       prog, prog, prog);
}

static void print_set_values(void)
{
	const char *ela_api_url        = getenv("ELA_API_URL");
	const char *ela_api_insecure   = getenv("ELA_API_INSECURE");
	const char *ela_quiet          = getenv("ELA_QUIET");
	const char *ela_output_format  = getenv("ELA_OUTPUT_FORMAT");
	const char *ela_output_tcp     = getenv("ELA_OUTPUT_TCP");
	const char *ela_script         = getenv("ELA_SCRIPT");
	const char *ela_output_http    = getenv("ELA_OUTPUT_HTTP");
	const char *ela_output_insecure = getenv("ELA_OUTPUT_INSECURE");
	const char *ela_api_key        = getenv("ELA_API_KEY");
	const char *ela_verbose        = getenv("ELA_VERBOSE");
	const char *ela_debug          = getenv("ELA_DEBUG");

	printf("Supported variables:\n"
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
	       (ela_api_url && *ela_api_url) ? ela_api_url : "<unset>",
	       (ela_api_insecure && *ela_api_insecure) ? ela_api_insecure : "<unset>",
	       (ela_quiet && *ela_quiet) ? ela_quiet : "<unset>",
	       (ela_output_format && *ela_output_format) ? ela_output_format : "<unset>",
	       (ela_output_tcp && *ela_output_tcp) ? ela_output_tcp : "<unset>",
	       (ela_script && *ela_script) ? ela_script : "<unset>",
	       (ela_output_http && *ela_output_http) ? ela_output_http : "<unset>",
	       (ela_output_insecure && *ela_output_insecure) ? ela_output_insecure : "<unset>",
	       (ela_api_key && *ela_api_key) ? "<set>" : "<unset>",
	       (ela_verbose && *ela_verbose) ? ela_verbose : "<unset>",
	       (ela_debug && *ela_debug) ? ela_debug : "<unset>",
	       (getenv("ELA_WS_RETRY_ATTEMPTS") && *getenv("ELA_WS_RETRY_ATTEMPTS"))
	           ? getenv("ELA_WS_RETRY_ATTEMPTS") : "<unset>");
}

static int interactive_list_supported_variables(FILE *stream)
{
	char buf[2048];
	const char *ela_api_url        = getenv("ELA_API_URL");
	const char *ela_api_insecure   = getenv("ELA_API_INSECURE");
	const char *ela_quiet          = getenv("ELA_QUIET");
	const char *ela_output_format  = getenv("ELA_OUTPUT_FORMAT");
	const char *ela_output_tcp     = getenv("ELA_OUTPUT_TCP");
	const char *ela_script         = getenv("ELA_SCRIPT");
	const char *ela_output_http    = getenv("ELA_OUTPUT_HTTP");
	const char *ela_output_insecure = getenv("ELA_OUTPUT_INSECURE");
	const char *ela_api_key        = getenv("ELA_API_KEY");
	const char *ela_verbose        = getenv("ELA_VERBOSE");
	const char *ela_debug          = getenv("ELA_DEBUG");
	const char *ela_ws_retry       = getenv("ELA_WS_RETRY_ATTEMPTS");

	if (ela_interactive_format_supported_variables(buf, sizeof(buf),
						       ela_api_url, ela_api_insecure, ela_quiet,
						       ela_output_format, ela_output_tcp, ela_script,
						       ela_output_http, ela_output_insecure, ela_api_key,
						       ela_verbose, ela_debug, ela_ws_retry) != 0)
		return -1;
	return fputs(buf, stream);
}

int interactive_set_command(int argc, char **argv)
{
	const char *normalized_bool;

	if (argc == 1) {
		print_set_values();
		return 0;
	}

	if (argc != 3) {
		fprintf(stderr,
			"Usage: set <variable> <value>\n"
			"  set ELA_API_URL http://127.0.0.1:5000/upload\n"
			"  set ELA_API_INSECURE true\n"
			"  set ELA_QUIET true\n"
			"  set ELA_OUTPUT_FORMAT json\n"
			"  set ELA_OUTPUT_TCP 127.0.0.1:5000\n"
			"  set ELA_SCRIPT ./commands.txt\n"
			"  set ELA_OUTPUT_HTTP http://127.0.0.1:5000/data\n"
			"  set ELA_OUTPUT_INSECURE true\n"
			"  set ELA_API_KEY <token>\n"
			"  set ELA_VERBOSE true\n"
			"  set ELA_DEBUG true\n");
		return 2;
	}

	if (!strcmp(argv[1], "ELA_API_URL")) {
		if (strncmp(argv[2], "http://", 7) && strncmp(argv[2], "https://", 8)) {
			fprintf(stderr,
				"Invalid ELA_API_URL (expected http://host:port/... or https://host:port/...): %s\n",
				argv[2]);
			return 2;
		}

		if (setenv("ELA_API_URL", argv[2], 1) != 0) {
			fprintf(stderr, "Failed to set ELA_API_URL\n");
			return 2;
		}

		/* ELA_API_URL is only consulted when explicit transport overrides are unset. */
		unsetenv("ELA_OUTPUT_HTTP");
		unsetenv("ELA_OUTPUT_HTTPS");
		ela_conf_update_from_env();
		printf("ELA_API_URL=%s\n", argv[2]);
		return 0;
	}

	if (!strcmp(argv[1], "ELA_API_INSECURE")) {
		if (!ela_parse_bool_string(argv[2], &normalized_bool)) {
			fprintf(stderr,
				"Invalid ELA_API_INSECURE value: %s (expected true/false, 1/0, yes/no, on/off)\n",
				argv[2]);
			return 2;
		}

		if (setenv("ELA_API_INSECURE", normalized_bool, 1) != 0) {
			fprintf(stderr, "Failed to set ELA_API_INSECURE\n");
			return 2;
		}

		ela_conf_update_from_env();
		printf("ELA_API_INSECURE=%s\n", normalized_bool);
		return 0;
	}

	if (!strcmp(argv[1], "ELA_QUIET")) {
		if (!ela_parse_bool_string(argv[2], &normalized_bool)) {
			fprintf(stderr,
				"Invalid ELA_QUIET value: %s (expected true/false, 1/0, yes/no, on/off)\n",
				argv[2]);
			return 2;
		}

		if (setenv("ELA_QUIET", normalized_bool, 1) != 0) {
			fprintf(stderr, "Failed to set ELA_QUIET\n");
			return 2;
		}

		printf("ELA_QUIET=%s\n", normalized_bool);
		return 0;
	}

	if (!strcmp(argv[1], "ELA_OUTPUT_FORMAT")) {
		if (strcmp(argv[2], "txt") && strcmp(argv[2], "csv") && strcmp(argv[2], "json")) {
			fprintf(stderr,
				"Invalid ELA_OUTPUT_FORMAT: %s (expected: csv, json, txt)\n",
				argv[2]);
			return 2;
		}

		if (setenv("ELA_OUTPUT_FORMAT", argv[2], 1) != 0) {
			fprintf(stderr, "Failed to set ELA_OUTPUT_FORMAT\n");
			return 2;
		}

		ela_conf_update_from_env();
		printf("ELA_OUTPUT_FORMAT=%s\n", argv[2]);
		return 0;
	}

	if (!strcmp(argv[1], "ELA_OUTPUT_TCP")) {
		if (!ela_is_valid_tcp_output_target(argv[2])) {
			fprintf(stderr,
				"Invalid ELA_OUTPUT_TCP target (expected IPv4:port): %s\n",
				argv[2]);
			return 2;
		}

		if (setenv("ELA_OUTPUT_TCP", argv[2], 1) != 0) {
			fprintf(stderr, "Failed to set ELA_OUTPUT_TCP\n");
			return 2;
		}

		printf("ELA_OUTPUT_TCP=%s\n", argv[2]);
		return 0;
	}

	if (!strcmp(argv[1], "ELA_SCRIPT")) {
		if (setenv("ELA_SCRIPT", argv[2], 1) != 0) {
			fprintf(stderr, "Failed to set ELA_SCRIPT\n");
			return 2;
		}

		printf("ELA_SCRIPT=%s\n", argv[2]);
		return 0;
	}

	if (!strcmp(argv[1], "ELA_OUTPUT_HTTP")) {
		if (strncmp(argv[2], "http://", 7) && strncmp(argv[2], "https://", 8)) {
			fprintf(stderr,
				"Invalid ELA_OUTPUT_HTTP (expected http://host:port/... or https://host:port/...): %s\n",
				argv[2]);
			return 2;
		}

		if (!strncmp(argv[2], "https://", 8)) {
			if (setenv("ELA_OUTPUT_HTTPS", argv[2], 1) != 0) {
				fprintf(stderr, "Failed to set ELA_OUTPUT_HTTPS\n");
				return 2;
			}
			unsetenv("ELA_OUTPUT_HTTP");
		} else {
			if (setenv("ELA_OUTPUT_HTTP", argv[2], 1) != 0) {
				fprintf(stderr, "Failed to set ELA_OUTPUT_HTTP\n");
				return 2;
			}
			unsetenv("ELA_OUTPUT_HTTPS");
		}

		ela_conf_update_from_env();
		printf("ELA_OUTPUT_HTTP=%s\n", argv[2]);
		return 0;
	}

	if (!strcmp(argv[1], "ELA_OUTPUT_INSECURE")) {
		if (!ela_parse_bool_string(argv[2], &normalized_bool)) {
			fprintf(stderr,
				"Invalid ELA_OUTPUT_INSECURE value: %s (expected true/false, 1/0, yes/no, on/off)\n",
				argv[2]);
			return 2;
		}

		if (setenv("ELA_OUTPUT_INSECURE", normalized_bool, 1) != 0) {
			fprintf(stderr, "Failed to set ELA_OUTPUT_INSECURE\n");
			return 2;
		}

		ela_conf_update_from_env();
		printf("ELA_OUTPUT_INSECURE=%s\n", normalized_bool);
		return 0;
	}

	if (!strcmp(argv[1], "ELA_API_KEY")) {
		if (strlen(argv[2]) > 1024) {
			fprintf(stderr,
				"ELA_API_KEY value too long (max 1024 characters)\n");
			return 2;
		}

		if (setenv("ELA_API_KEY", argv[2], 1) != 0) {
			fprintf(stderr, "Failed to set ELA_API_KEY\n");
			return 2;
		}

		printf("ELA_API_KEY=<set>\n");
		return 0;
	}

	if (!strcmp(argv[1], "ELA_VERBOSE")) {
		if (!ela_parse_bool_string(argv[2], &normalized_bool)) {
			fprintf(stderr,
				"Invalid ELA_VERBOSE value: %s (expected true/false, 1/0, yes/no, on/off)\n",
				argv[2]);
			return 2;
		}

		if (setenv("ELA_VERBOSE", normalized_bool, 1) != 0) {
			fprintf(stderr, "Failed to set ELA_VERBOSE\n");
			return 2;
		}

		printf("ELA_VERBOSE=%s\n", normalized_bool);
		return 0;
	}

	if (!strcmp(argv[1], "ELA_DEBUG")) {
		if (!ela_parse_bool_string(argv[2], &normalized_bool)) {
			fprintf(stderr,
				"Invalid ELA_DEBUG value: %s (expected true/false, 1/0, yes/no, on/off)\n",
				argv[2]);
			return 2;
		}

		if (setenv("ELA_DEBUG", normalized_bool, 1) != 0) {
			fprintf(stderr, "Failed to set ELA_DEBUG\n");
			return 2;
		}

		printf("ELA_DEBUG=%s\n", normalized_bool);
		return 0;
	}

	if (!strcmp(argv[1], "ELA_WS_RETRY_ATTEMPTS")) {
		char *end;
		long v = strtol(argv[2], &end, 10);

		if (*end || v < 0 || v > 1000) {
			fprintf(stderr,
				"Invalid ELA_WS_RETRY_ATTEMPTS value: %s (expected integer 0-1000)\n",
				argv[2]);
			return 2;
		}

		if (setenv("ELA_WS_RETRY_ATTEMPTS", argv[2], 1) != 0) {
			fprintf(stderr, "Failed to set ELA_WS_RETRY_ATTEMPTS\n");
			return 2;
		}

		printf("ELA_WS_RETRY_ATTEMPTS=%s\n", argv[2]);
		return 0;
	}

	fprintf(stderr, "Unsupported variable for set: %s\n", argv[1]);
	interactive_list_supported_variables(stderr);
	return 2;
}

#if defined(ELA_HAS_READLINE)
static char *interactive_completion_generator(const char *text, int state)
{
	static int index;
	const char *name;
	size_t text_len;

	if (state == 0)
		index = 0;

	if (!interactive_completion_candidates)
		return NULL;

	text_len = strlen(text);
	while ((name = interactive_completion_candidates[index++]) != NULL) {
		if (!strncmp(name, text, text_len))
			return strdup(name);
	}

	return NULL;
}

static char **interactive_completion(const char *text, int start, int end)
{
	char *prefix;
	char **argv = NULL;
	int argc = 0;
	int rc;
	bool new_token;
	int completion_argc;

	(void)end;

	if (start < 0)
		return NULL;

	interactive_completion_candidates = NULL;
	prefix = malloc((size_t)start + 1);
	if (!prefix)
		return NULL;
	memcpy(prefix, rl_line_buffer, (size_t)start);
	prefix[start] = '\0';

	rc = interactive_parse_line(prefix, &argv, &argc);
	new_token = (start > 0) && isspace((unsigned char)rl_line_buffer[start - 1]);
	free(prefix);
	if (rc != 0) {
		interactive_free_argv(argv, argc);
		return NULL;
	}

	completion_argc = argc + (new_token ? 1 : 0);
	interactive_completion_candidates = interactive_candidates_for_position(completion_argc, argv);
	interactive_free_argv(argv, argc);
	if (!interactive_completion_candidates)
		return NULL;

	rl_attempted_completion_over = 1;
	return rl_completion_matches(text, interactive_completion_generator);
}
#endif

static void interactive_restore_terminal(int tty_fd,
					 const struct termios *saved_termios,
					 bool have_saved_termios)
{
	if (tty_fd < 0 || !saved_termios || !have_saved_termios)
		return;

	(void)tcsetattr(tty_fd, TCSANOW, saved_termios);
}

#if !defined(ELA_HAS_READLINE)
struct interactive_history {
	char **entries;
	size_t count;
	size_t cap;
};

static void interactive_history_free(struct interactive_history *history)
{
	if (!history)
		return;

	for (size_t i = 0; i < history->count; i++)
		free(history->entries[i]);
	free(history->entries);
	history->entries = NULL;
	history->count = 0;
	history->cap = 0;
}

static int interactive_history_add(struct interactive_history *history, const char *line)
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

static int interactive_set_raw_mode(int tty_fd,
				    const struct termios *saved_termios,
				    bool have_saved_termios)
{
	struct termios raw;

	if (tty_fd < 0 || !saved_termios || !have_saved_termios)
		return 0;

	raw = *saved_termios;
	raw.c_iflag &= (tcflag_t)~(IXON | ICRNL);
	raw.c_lflag &= (tcflag_t)~(ICANON | ECHO);
	raw.c_cc[VMIN] = 1;
	raw.c_cc[VTIME] = 0;

	return tcsetattr(tty_fd, TCSANOW, &raw);
}

static void interactive_redraw_prompt_line(const char *prompt, const char *line)
{
	printf("\r\033[2K%s%s", prompt ? prompt : "", line ? line : "");
	fflush(stdout);
}

/*
 * Perform tab completion on the current line buffer.  Works in both TTY and
 * pipe (WebSocket) modes by writing completions/matches to stdout.
 */
static void interactive_tab_complete_fallback(char **line_ptr, size_t *len_ptr,
					      size_t *cap_ptr, const char *prompt)
{
	char *line = *line_ptr;
	size_t len = *len_ptr;
	const char *const *candidates;
	char **argv = NULL;
	int argc = 0;
	size_t word_start;
	const char *cur_word;
	size_t cur_len;
	const char *matches[64];
	int nmatch = 0;
	int i;

	/* Find start of current (incomplete) word */
	word_start = len;
	if (word_start > 0 && !isspace((unsigned char)line[word_start - 1])) {
		while (word_start > 0 &&
		       !isspace((unsigned char)line[word_start - 1]))
			word_start--;
	}

	cur_word = (line && len > word_start) ? line + word_start : "";
	cur_len  = len - word_start;

	/*
	 * Parse the tokens that precede the current word to determine context.
	 * completion_argc counts the position we are completing (1-based token
	 * index), matching the logic in the readline completion handler.
	 */
	if (line && word_start > 0) {
		char *prefix = malloc(word_start + 1);

		if (!prefix)
			return;
		memcpy(prefix, line, word_start);
		prefix[word_start] = '\0';
		interactive_parse_line(prefix, &argv, &argc);
		free(prefix);
	}

	candidates = interactive_candidates_for_position(argc + 1, argv);
	interactive_free_argv(argv, argc);

	if (!candidates)
		return;

	for (i = 0; candidates[i] && nmatch < 64; i++) {
		if (strncmp(candidates[i], cur_word, cur_len) == 0)
			matches[nmatch++] = candidates[i];
	}

	if (nmatch == 0)
		return;

	if (nmatch == 1) {
		/* Single match: replace the current word with the full name + space */
		const char *full     = matches[0];
		size_t       full_len = strlen(full);
		size_t       new_len  = word_start + full_len + 1; /* trailing space */

		if (new_len + 1 > *cap_ptr) {
			size_t  new_cap = new_len + 32;
			char   *tmp     = realloc(*line_ptr, new_cap);

			if (!tmp)
				return;
			*line_ptr = tmp;
			*cap_ptr  = new_cap;
			line      = *line_ptr;
		}

		memcpy(line + word_start, full, full_len);
		line[word_start + full_len]     = ' ';
		line[word_start + full_len + 1] = '\0';
		*len_ptr = new_len;
		interactive_redraw_prompt_line(prompt, line);
		return;
	}

	/* Multiple matches: list them, then redraw the prompt */
	putchar('\n');
	for (i = 0; i < nmatch; i++)
		printf("%s  ", matches[i]);
	putchar('\n');
	fflush(stdout);
	interactive_redraw_prompt_line(prompt, line ? line : "");
}

static char *interactive_read_line_fallback(const char *prompt,
					    int tty_fd,
					    const struct termios *saved_termios,
					    bool have_saved_termios,
					    struct interactive_history *history)
{
	char *line = NULL;
	char *draft = NULL;
	size_t len = 0;
	size_t cap = 0;
	ssize_t history_index;
	bool tty_input;
	int read_fd;

	tty_input = tty_fd >= 0 && have_saved_termios && isatty(tty_fd);
	/*
	 * read_fd: use the real TTY when available, otherwise read from stdin
	 * directly (pipe from ws_client.c in WebSocket mode).  In both cases
	 * the loop below handles input character-by-character so that escape
	 * sequences for history and Tab for completion work over WebSocket too.
	 */
	read_fd = tty_input ? tty_fd : STDIN_FILENO;

	if (interactive_set_raw_mode(tty_fd, saved_termios, have_saved_termios) != 0)
		return NULL;

	history_index = (ssize_t)(history ? history->count : 0);
	if (tty_input) {
		interactive_redraw_prompt_line(prompt, "");
	} else if (prompt && *prompt) {
		printf("%s", prompt);
		fflush(stdout);
	}

	for (;;) {
		unsigned char ch;
		ssize_t nread = read(read_fd, &ch, 1);

		if (nread <= 0) {
			if (nread < 0 && errno == EINTR)
				continue;
			free(line);
			free(draft);
			interactive_restore_terminal(tty_fd, saved_termios, have_saved_termios);
			return NULL;
		}

		if (ch == '\r' || ch == '\n') {
			putchar('\n');
			fflush(stdout);
			break;
		}

		if (ch == 0x04) {
			if (len == 0) {
				putchar('\n');
				free(line);
				free(draft);
				interactive_restore_terminal(tty_fd, saved_termios, have_saved_termios);
				return NULL;
			}
			continue;
		}

		if (ch == 0x7f || ch == 0x08) {
			if (len > 0) {
				line[--len] = '\0';
				interactive_redraw_prompt_line(prompt, line);
			}
			continue;
		}

		if (ch == 0x15) { /* Ctrl+U: kill from beginning of line */
			len = 0;
			if (line)
				line[0] = '\0';
			interactive_redraw_prompt_line(prompt, "");
			continue;
		}

		if (ch == '\t') {
			interactive_tab_complete_fallback(&line, &len, &cap, prompt);
			continue;
		}

		if (ch == '\033') {
			unsigned char seq[2];

			if (read(read_fd, &seq[0], 1) != 1 || read(read_fd, &seq[1], 1) != 1)
				continue;

			if (seq[0] == '[' && history) {
				const char *replacement = NULL;
				size_t replacement_len;

				if (seq[1] == 'A') {
					if (history->count == 0 || history_index <= 0)
						continue;
					if (history_index == (ssize_t)history->count) {
						free(draft);
						draft = strdup(line ? line : "");
						if (!draft)
							goto oom;
					}
					history_index--;
					replacement = history->entries[history_index];
				} else if (seq[1] == 'B') {
					if (history->count == 0 || history_index >= (ssize_t)history->count)
						continue;
					history_index++;
					if (history_index == (ssize_t)history->count)
						replacement = draft ? draft : "";
					else
						replacement = history->entries[history_index];
				} else {
					continue;
				}

				replacement_len = strlen(replacement);
				if (replacement_len + 1 > cap) {
					size_t new_cap = replacement_len + 32;
					char *tmp = realloc(line, new_cap);

					if (!tmp)
						goto oom;
					line = tmp;
					cap = new_cap;
				}

				memcpy(line, replacement, replacement_len + 1);
				len = replacement_len;
				interactive_redraw_prompt_line(prompt, line);
			}
			continue;
		}

		if (isprint(ch)) {
			if (len + 2 > cap) {
				size_t new_cap = cap ? cap * 2 : 64;
				char *tmp;

				while (new_cap < len + 2)
					new_cap *= 2;

				tmp = realloc(line, new_cap);
				if (!tmp)
					goto oom;
				line = tmp;
				cap = new_cap;
			}

			line[len++] = (char)ch;
			line[len] = '\0';
			interactive_redraw_prompt_line(prompt, line);
		}
	}

	interactive_restore_terminal(tty_fd, saved_termios, have_saved_termios);
	free(draft);

	if (!line) {
		line = strdup("");
		if (!line)
			return NULL;
	}

	if (interactive_history_add(history, line) != 0) {
		free(line);
		return NULL;
	}

	return line;

oom:
	interactive_restore_terminal(tty_fd, saved_termios, have_saved_termios);
	free(line);
	free(draft);
	return NULL;
}
#endif

int interactive_loop(const char *prog)
{
	char *line;
	int last_rc = 0;
	int tty_fd = -1;
	struct termios saved_termios;
	bool have_saved_termios = false;

#if !defined(ELA_HAS_READLINE)
	struct interactive_history history = {0};
#endif

	if (isatty(STDIN_FILENO)) {
		tty_fd = STDIN_FILENO;
		if (tcgetattr(tty_fd, &saved_termios) == 0)
			have_saved_termios = true;
	}

	/* Show prompt on a real TTY, or when running over a WebSocket session
	 * (ELA_SESSION_MAC is set by ela_ws_run_interactive before forking). */
	const char *session_mac = getenv("ELA_SESSION_MAC");
	const bool show_prompt = tty_fd >= 0 || (session_mac && *session_mac);

	if (show_prompt) {
		printf("Entering interactive mode for %s. Type 'help' for commands or 'quit' to exit.\n\n", prog);
		interactive_usage(prog);
	}

#if defined(ELA_HAS_READLINE)
	rl_attempted_completion_function = interactive_completion;
#endif

	for (;;) {
		char **dispatch_argv = NULL;
		char **argv = NULL;
		int argc = 0;
		int rc;

#if defined(ELA_HAS_READLINE)
		char prompt[128];
		{
			if (!show_prompt) {
				prompt[0] = '\0';
			} else if (session_mac && *session_mac) {
				snprintf(prompt, sizeof(prompt), "(%s)> ", session_mac);
			} else {
				const char *bn = strrchr(prog, '/');
				snprintf(prompt, sizeof(prompt), "%s> ", bn ? bn + 1 : prog);
			}
		}
		interactive_restore_terminal(tty_fd, &saved_termios, have_saved_termios);
		line = readline(show_prompt ? prompt : NULL);
		if (!line) {
			if (show_prompt) putchar('\n');
			break;
		}

		if (*line)
			add_history(line);
#else
		char prompt[128];
		{
			if (!show_prompt) {
				prompt[0] = '\0';
			} else if (session_mac && *session_mac) {
				snprintf(prompt, sizeof(prompt), "(%s)> ", session_mac);
			} else {
				const char *bn = strrchr(prog, '/');
				snprintf(prompt, sizeof(prompt), "%s> ", bn ? bn + 1 : prog);
			}
		}
		line = interactive_read_line_fallback(prompt,
						 tty_fd,
						 &saved_termios,
						 have_saved_termios,
						 &history);
		if (!line) {
			if (show_prompt) putchar('\n');
			break;
		}
#endif

		rc = interactive_parse_line(line, &argv, &argc);
		if (rc == -1) {
			fprintf(stderr, "Out of memory while parsing interactive command\n");
			free(line);
			return 2;
		}
		if (rc != 0) {
			last_rc = rc;
			free(line);
			continue;
		}
		if (argc == 0) {
			interactive_free_argv(argv, argc);
			free(line);
			continue;
		}

		if (!strcmp(argv[0], "quit") || !strcmp(argv[0], "exit")) {
			interactive_free_argv(argv, argc);
			free(line);
			break;
		}

		if (!strcmp(argv[0], "help")) {
			interactive_usage(prog);
			interactive_free_argv(argv, argc);
			free(line);
			last_rc = 0;
			continue;
		}

		if (!strcmp(argv[0], "set")) {
			last_rc = interactive_set_command(argc, argv);
			interactive_free_argv(argv, argc);
			free(line);
			continue;
		}

		dispatch_argv = calloc((size_t)argc + 2, sizeof(*dispatch_argv));
		if (!dispatch_argv) {
			fprintf(stderr, "Out of memory while preparing interactive command\n");
			interactive_free_argv(argv, argc);
			free(line);
			return 2;
		}

		dispatch_argv[0] = (char *)prog;
		for (int i = 0; i < argc; i++)
			dispatch_argv[i + 1] = argv[i];

		last_rc = embedded_linux_audit_dispatch(argc + 1, dispatch_argv);
		free(dispatch_argv);
		interactive_free_argv(argv, argc);
		free(line);
	}

	interactive_restore_terminal(tty_fd, &saved_termios, have_saved_termios);

#if !defined(ELA_HAS_READLINE)
	interactive_history_free(&history);
#endif

	return last_rc;
}
