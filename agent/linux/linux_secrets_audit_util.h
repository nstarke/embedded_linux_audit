// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_LINUX_SECRETS_AUDIT_UTIL_H
#define ELA_LINUX_SECRETS_AUDIT_UTIL_H

#include <stdbool.h>
#include <stddef.h>

bool ela_secrets_compressed_name(const char *name);
bool ela_secrets_compressed_magic(const unsigned char *b, size_t n);
bool ela_secrets_candidate(const char *name);
bool ela_secrets_classify_line(const char *s, const char **rule, const char **title);

#endif
