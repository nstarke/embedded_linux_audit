// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "interactive_parse_util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int interactive_append_arg(char ***argvp, int *argcp, const char *start, size_t len)
{
	char *copy;
	char **tmp;

	copy = malloc(len + 1);
	if (!copy)
		return -1;
	memcpy(copy, start, len);
	copy[len] = '\0';

	tmp = realloc(*argvp, (size_t)(*argcp + 2) * sizeof(**argvp));
	if (!tmp) {
		free(copy);
		return -1;
	}

	*argvp = tmp;
	(*argvp)[*argcp] = copy;
	(*argcp)++;
	(*argvp)[*argcp] = NULL;
	return 0;
}

void interactive_free_argv(char **argv, int argc)
{
	int i;

	if (!argv)
		return;

	for (i = 0; i < argc; i++)
		free(argv[i]);
	free(argv);
}

int interactive_parse_line(const char *line, char ***argv_out, int *argc_out)
{
	const char *p = line;
	char **argv = NULL;
	int argc = 0;

	if (!argv_out || !argc_out)
		return -1;

	while (*p) {
		const char *start;
		char quote = '\0';
		char *arg = NULL;
		size_t arg_len = 0;
		size_t arg_cap = 0;

		while (*p && isspace((unsigned char)*p))
			p++;
		if (*p == '#')
			break;
		if (!*p || *p == '\n')
			break;

		start = p;
		while (*p && (!isspace((unsigned char)*p) || quote)) {
			char ch = *p++;
			if (!quote && ch == '#') {
				p--;
				break;
			}
			if (!quote && (ch == '\'' || ch == '"')) {
				quote = ch;
				continue;
			}
			if (quote && ch == quote) {
				quote = '\0';
				continue;
			}
			if (ch == '\\' && *p)
				ch = *p++;
			if (arg_len + 2 > arg_cap) {
				size_t new_cap = arg_cap ? arg_cap * 2 : 32;
				char *tmp = realloc(arg, new_cap);
				if (!tmp) {
					free(arg);
					interactive_free_argv(argv, argc);
					return -1;
				}
				arg = tmp;
				arg_cap = new_cap;
			}
			arg[arg_len++] = ch;
		}

		if (quote) {
			fprintf(stderr, "Unterminated quote in interactive command: %s\n", start);
			free(arg);
			interactive_free_argv(argv, argc);
			return 2;
		}

		if (!arg) {
			if (interactive_append_arg(&argv, &argc, start, (size_t)(p - start)) != 0) {
				interactive_free_argv(argv, argc);
				return -1;
			}
		} else {
			char **tmp_argv;
			arg[arg_len] = '\0';
			tmp_argv = realloc(argv, (size_t)(argc + 2) * sizeof(*tmp_argv));
			if (!tmp_argv) {
				free(arg);
				interactive_free_argv(argv, argc);
				return -1;
			}
			argv = tmp_argv;
			argv[argc++] = arg;
			argv[argc] = NULL;
		}

		if (*p == '#')
			break;
	}

	*argv_out = argv;
	*argc_out = argc;
	return 0;
}
