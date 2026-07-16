// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * `config.get` request/reply helpers for the WebSocket session.
 *
 * The terminal API needs to read a device's effective settings (chiefly
 * ELA_API_URL, for the module-download origin and the self-update flow) without
 * running a command on the device. Running `set` as an exec goes through the
 * REPL, which serializes behind whatever long command is already running — a
 * whole-rootfs `remote-copy` can hold it for an hour, and the read times out.
 *
 * `config.get` is answered by the WebSocket parent process straight from
 * /tmp/.ela.conf plus its own environment. It never touches the REPL, so it is
 * unaffected by a busy session.
 *
 * These helpers are pure (no I/O, injectable env lookup) so the parse, the
 * key policy and the value-precedence rules are unit-testable; the actual
 * conf load and frame send live in ws_client.c.
 */
#ifndef ELA_WS_CONFIG_UTIL_H
#define ELA_WS_CONFIG_UTIL_H

#include "ela_conf.h"

#include <stdbool.h>
#include <stddef.h>

#define ELA_WS_CONFIG_KEY_MAX    32
#define ELA_WS_CONFIG_VALUE_MAX  512
#define ELA_WS_CONFIG_ID_MAX     64
#define ELA_WS_CONFIG_MAX_KEYS   8

/*
 * Whether `config.get` may serve this variable.
 *
 * Only the variables ela_conf actually tracks are served, because only those
 * are guaranteed to survive a runtime `set` in the REPL child (which writes
 * through to /tmp/.ela.conf; see interactive_set_command). Anything else is
 * setenv-only in a process this one cannot see, so answering for it would mean
 * confidently returning a stale value.
 *
 * ELA_API_KEY is deliberately NOT readable, and must never become readable:
 * it is a bearer token, it is excluded from ela_conf on purpose (it is the one
 * `set` variable that redacts its value and skips update_conf), and
 * /tmp/.ela.conf is inside the tree `remote-copy` uploads (only /dev, /sys and
 * /proc are refused), so persisting or echoing it would leak the credential
 * into the artifact store.
 */
bool ela_ws_config_key_is_readable(const char *name);

/*
 * Parse a `{"_type":"config.get","id":"...","keys":["ELA_API_URL",...]}` frame.
 *
 * Unreadable or unknown key names are dropped rather than failing the request,
 * so a caller asking for a mix gets what it is allowed to have. Returns 0 on
 * success (n_keys_out may be 0), -1 when the payload is not a well-formed
 * config.get frame or carries no usable id.
 */
int ela_ws_config_parse_get(const char *payload,
			    size_t payload_len,
			    char *id_out,
			    size_t id_sz,
			    char keys_out[][ELA_WS_CONFIG_KEY_MAX],
			    size_t max_keys,
			    size_t *n_keys_out);

/*
 * Resolve one variable's effective value as the REPL child would report it.
 *
 * Precedence is not simply "conf wins". At startup ela_conf_export_to_env()
 * uses overwrite=0, so a value inherited from the launch environment beats a
 * value persisted by an earlier run — and that launch value is never written
 * back to conf. But a runtime `set` in the REPL child DOES write through to
 * conf. So:
 *
 *   - conf differs from the startup snapshot  -> a runtime `set` happened;
 *                                                conf is newest, conf wins.
 *   - conf unchanged since startup            -> the parent's own environment
 *                                                is the effective value.
 *
 * `env_lookup` is injected for testability (pass getenv in production).
 * Returns 0 with `out` set (possibly "" for unset), -1 if the key is not
 * readable.
 */
int ela_ws_config_resolve(const char *name,
			  const struct ela_conf *startup_conf,
			  const struct ela_conf *now_conf,
			  const char *(*env_lookup)(const char *name),
			  char *out,
			  size_t out_sz);

/*
 * Build `{"_type":"config.value","id":"...","values":{...}}`. Returns 0 on
 * success, -1 on bad arguments or if the reply does not fit in `out`.
 */
int ela_ws_config_build_value_reply(const char *id,
				    const char keys[][ELA_WS_CONFIG_KEY_MAX],
				    const char values[][ELA_WS_CONFIG_VALUE_MAX],
				    size_t n,
				    char *out,
				    size_t out_sz);

#endif /* ELA_WS_CONFIG_UTIL_H */
