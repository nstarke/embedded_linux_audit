// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke
//
// Persistent per-agent configuration stored in /tmp/.ela.conf.
// Settings are loaded at startup and override built-in defaults; they can
// be further overridden by environment variables or command-line flags.

#ifndef ELA_CONF_H
#define ELA_CONF_H

#define ELA_CONF_PATH "/tmp/.ela.conf"

/*
 * Mutable settings persisted across invocations.
 * All string fields are NUL-terminated; empty string means "not set".
 */
struct ela_conf {
	char remote[512];       /* --remote  [ws[s]://]host[:port]          */
	char output_http[512];  /* --output-http  http[s]://host[:port]/... */
	char output_format[16]; /* --output-format  txt | csv | json        */
	int  insecure;          /* --insecure  0 or 1                       */
};

/* Load /tmp/.ela.conf into *conf.  Missing or unreadable file → zeroed struct. */
void ela_conf_load(struct ela_conf *conf);

/* Atomically write *conf to /tmp/.ela.conf, mode 0600. */
void ela_conf_save(const struct ela_conf *conf);

/*
 * Re-read conf-tracked env vars (ELA_OUTPUT_HTTP / ELA_API_URL,
 * ELA_OUTPUT_FORMAT, ELA_API_INSECURE, ELA_OUTPUT_INSECURE) and persist
 * them to /tmp/.ela.conf.  Call this after any runtime `set` that changes
 * one of these variables.
 */
void ela_conf_update_from_env(void);

#endif /* ELA_CONF_H */
