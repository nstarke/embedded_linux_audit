// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "dispatch_util.h"

#include <stdlib.h>
#include <string.h>

static int dispatch_summary_append(char **buf, size_t *len, size_t *cap, const char *text)
{
	char *tmp;
	size_t text_len;
	size_t need;
	size_t new_cap;

	if (!buf || !len || !cap || !text)
		return -1;

	text_len = strlen(text);
	need = *len + text_len + 1;
	if (need > *cap) {
		new_cap = *cap ? *cap : 128;
		while (new_cap < need)
			new_cap *= 2;
		tmp = realloc(*buf, new_cap);
		if (!tmp)
			return -1;
		*buf = tmp;
		*cap = new_cap;
	}

	memcpy(*buf + *len, text, text_len);
	*len += text_len;
	(*buf)[*len] = '\0';
	return 0;
}

bool ela_command_should_emit_lifecycle_events(int argc, char **argv,
					      int cmd_idx,
					      const char *script_path)
{
	const char *group;
	const char *subcommand;

	if (script_path && *script_path)
		return true;

	if (!argv || cmd_idx < 0 || cmd_idx >= argc)
		return true;

	group = argv[cmd_idx];
	subcommand = (cmd_idx + 1 < argc) ? argv[cmd_idx + 1] : NULL;

	if (group && subcommand && !strcmp(group, "linux") &&
	    (!strcmp(subcommand, "download-file") ||
	     !strcmp(subcommand, "list-files") ||
	     !strcmp(subcommand, "list-symlinks") ||
	     !strcmp(subcommand, "remote-copy")))
		return false;

	return true;
}

char *ela_build_command_summary(int argc, char **argv, int start_idx)
{
	char *summary = NULL;
	size_t len = 0;
	size_t cap = 0;
	int i;

	if (!argv || start_idx < 0 || start_idx >= argc)
		return strdup("interactive");

	for (i = start_idx; i < argc; i++) {
		if (dispatch_summary_append(&summary, &len, &cap, argv[i]) != 0)
			goto fail;
		if (i + 1 < argc &&
		    dispatch_summary_append(&summary, &len, &cap, " ") != 0)
			goto fail;
	}

	return summary;

fail:
	free(summary);
	return NULL;
}
