// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "ssh_parse_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *ela_ssh_effective_user(const char *env_user, const char *passwd_user)
{
	if (env_user && *env_user)
		return env_user;
	if (passwd_user && *passwd_user)
		return passwd_user;
	return "root";
}

int ela_ssh_parent_dir(const char *path, char *out, size_t out_sz)
{
	const char *slash;
	size_t len;

	if (!path || !*path || !out || out_sz < 2)
		return -1;

	slash = strrchr(path, '/');
	if (!slash) {
		snprintf(out, out_sz, ".");
		return 0;
	}

	len = (size_t)(slash - path);
	if (len == 0) {
		snprintf(out, out_sz, "/");
		return 0;
	}
	if (len + 1 > out_sz)
		return -1;

	memcpy(out, path, len);
	out[len] = '\0';
	return 0;
}

int ela_ssh_parse_port(const char *value, uint16_t *port_out)
{
	char *end = NULL;
	unsigned long parsed;

	if (!value || !*value || !port_out)
		return -1;

	parsed = strtoul(value, &end, 10);
	if (*end || parsed == 0 || parsed > 65535UL)
		return -1;

	*port_out = (uint16_t)parsed;
	return 0;
}
