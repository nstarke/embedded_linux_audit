// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_TEST_SHELL_STUBS_H
#define ELA_TEST_SHELL_STUBS_H

/*
 * Controllable test doubles for the I/O boundaries that agent/shell/
 * interactive.c and script_exec.c depend on but that are defined elsewhere
 * (the top-level dispatcher, usage banner, conf reload, and HTTP fetch).
 * Linking the real implementations would drag the whole command/network
 * stack into the lightweight unit-test binary.
 */

/* embedded_linux_audit_dispatch() */
extern int         g_dispatch_calls;
extern int         g_dispatch_rc;       /* value the dispatch stub returns */

/* ela_usage() */
extern int         g_usage_calls;

/* ela_conf_update_from_env() */
extern int         g_conf_update_calls;

/* ela_http_get_to_file() */
extern int         g_http_get_calls;
extern int         g_http_get_rc;       /* value the fetch stub returns */
extern const char *g_http_get_payload;  /* if non-NULL and rc >= 0, written to the destination */

void ela_test_shell_stubs_reset(void);

#endif /* ELA_TEST_SHELL_STUBS_H */
