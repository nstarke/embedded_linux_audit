// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef UTIL_TPM2_COMMAND_UTIL_H
#define UTIL_TPM2_COMMAND_UTIL_H

#include <stddef.h>

struct ela_tpm2_command_desc {
	const char *name;
	const char *summary;
};

const struct ela_tpm2_command_desc *ela_tpm2_supported_commands(size_t *count_out);
int ela_tpm2_is_help_token(const char *token);
int ela_tpm2_find_command_index(const char *name);

#endif
