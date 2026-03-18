// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef UTIL_INTERACTIVE_PARSE_UTIL_H
#define UTIL_INTERACTIVE_PARSE_UTIL_H

int interactive_parse_line(const char *line, char ***argv_out, int *argc_out);
void interactive_free_argv(char **argv, int argc);

#endif
