// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef UTIL_TPM2_COMMAND_UTIL_H
#define UTIL_TPM2_COMMAND_UTIL_H

#include <stddef.h>
#include <stdint.h>

/* TPM2 hierarchy handle constants (matching TPM2-TSS values) */
#define ELA_TPM2_RH_OWNER       0x40000001u
#define ELA_TPM2_RH_PLATFORM    0x4000000Cu
#define ELA_TPM2_RH_ENDORSEMENT 0x4000000Bu
#define ELA_TPM2_RH_NULL        0x40000007u

struct ela_tpm2_command_desc {
	const char *name;
	const char *summary;
};

const struct ela_tpm2_command_desc *ela_tpm2_supported_commands(size_t *count_out);
int ela_tpm2_is_help_token(const char *token);
int ela_tpm2_find_command_index(const char *name);

/*
 * Parse a hierarchy name ("o"/"owner", "p"/"platform", "e"/"endorsement",
 * "n"/"null", or NULL) into its uint32_t handle constant (ELA_TPM2_RH_*).
 * Returns 0 on success, -1 if out is NULL or name is unrecognised.
 * A NULL name is treated as "null" (ELA_TPM2_RH_NULL).
 */
int ela_tpm2_parse_hierarchy(const char *name, uint32_t *out);

#endif
