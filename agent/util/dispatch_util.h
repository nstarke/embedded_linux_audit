// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef UTIL_DISPATCH_UTIL_H
#define UTIL_DISPATCH_UTIL_H

#include <stdbool.h>

/*
 * Returns true if the command identified by cmd_idx should have lifecycle
 * events emitted around it.  Some linux subcommands suppress lifecycle events
 * because they own their own lifecycle reporting.
 */
bool ela_command_should_emit_lifecycle_events(int argc, char **argv,
					      int cmd_idx,
					      const char *script_path);

/*
 * Returns a heap-allocated space-joined string of argv[start_idx..argc-1],
 * or "interactive" when start_idx is out of range.  Returns NULL on OOM.
 * Caller must free.
 */
char *ela_build_command_summary(int argc, char **argv, int start_idx);

#endif /* UTIL_DISPATCH_UTIL_H */
