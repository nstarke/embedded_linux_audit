// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef UTIL_SSH_PARSE_UTIL_H
#define UTIL_SSH_PARSE_UTIL_H

#include <stddef.h>
#include <stdint.h>

const char *ela_ssh_effective_user(const char *env_user, const char *passwd_user);
int ela_ssh_parent_dir(const char *path, char *out, size_t out_sz);
int ela_ssh_parse_port(const char *value, uint16_t *port_out);

#endif
