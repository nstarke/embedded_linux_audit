// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "api_key.h"
#include "api_key_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_KEYS  64
#define KEY_FILE  "/tmp/ela.key"

/*
 * All functions in this file require real hardware, network I/O, or OS-level
 * services (ptrace, SSH, sockets, TPM2, EFI) and cannot be exercised in the
 * unit-test environment.
 */
/* LCOV_EXCL_START */

static char keys[MAX_KEYS][ELA_API_KEY_MAX_LEN + 1];
static int  key_count     = 0;
static int  key_current   = 0;
static int  key_confirmed = 0;

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

static void add_key(const char *k)
{
	if (ela_api_key_add_unique(keys, &key_count, MAX_KEYS, k) != 0)
		return;
}

static void load_key_file(const char *path)
{
	FILE *f = fopen(path, "r");
	char line[ELA_API_KEY_MAX_LEN + 2];
	size_t len;

	if (!f)
		return;
	while (fgets(line, (int)sizeof(line), f)) {
		len = strlen(line);
		(void)len;
		if (ela_api_key_line_normalize(line) == 0)
			add_key(line);
	}
	fclose(f);
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

void ela_api_key_init(const char *cli_key)
{
	key_count     = 0;
	key_current   = 0;
	key_confirmed = 0;

	add_key(cli_key);
	add_key(getenv("ELA_API_KEY"));
	load_key_file(KEY_FILE);
}

const char *ela_api_key_get(void)
{
	if (key_count == 0 || key_current >= key_count)
		return NULL;
	return keys[key_current];
}

const char *ela_api_key_next(void)
{
	if (key_confirmed)
		return NULL;
	key_current++;
	return ela_api_key_get();
}

void ela_api_key_confirm(void)
{
	key_confirmed = 1;
}

/* LCOV_EXCL_STOP */
