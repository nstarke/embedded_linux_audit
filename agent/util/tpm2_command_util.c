// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "tpm2_command_util.h"

#include <stdint.h>
#include <string.h>

static const struct ela_tpm2_command_desc g_tpm2_supported_commands[] = {
	{ "createprimary", "Create a primary object and optionally serialize the ESYS context" },
	{ "getcap", "Query a small built-in set of TPM2 capabilities" },
	{ "nvreadpublic", "Read the public metadata for an NV index" },
	{ "pcrread", "Read PCR values for one or more PCR banks" },
};

const struct ela_tpm2_command_desc *ela_tpm2_supported_commands(size_t *count_out)
{
	if (count_out)
		*count_out = sizeof(g_tpm2_supported_commands) / sizeof(g_tpm2_supported_commands[0]);
	return g_tpm2_supported_commands;
}

int ela_tpm2_is_help_token(const char *token)
{
	return token &&
	       (!strcmp(token, "help") ||
		!strcmp(token, "--help") ||
		!strcmp(token, "-h"));
}

int ela_tpm2_find_command_index(const char *name)
{
	size_t i;
	size_t count;
	const struct ela_tpm2_command_desc *commands = ela_tpm2_supported_commands(&count);

	if (!name || !*name)
		return -1;

	for (i = 0; i < count; i++) {
		if (!strcmp(name, commands[i].name))
			return (int)i;
	}

	return -1;
}

int ela_tpm2_parse_hierarchy(const char *name, uint32_t *out)
{
	if (!out)
		return -1;

	if (!name) {
		*out = ELA_TPM2_RH_NULL;
		return 0;
	}

	if (!strcmp(name, "o") || !strcmp(name, "owner")) {
		*out = ELA_TPM2_RH_OWNER;
		return 0;
	}
	if (!strcmp(name, "p") || !strcmp(name, "platform")) {
		*out = ELA_TPM2_RH_PLATFORM;
		return 0;
	}
	if (!strcmp(name, "e") || !strcmp(name, "endorsement")) {
		*out = ELA_TPM2_RH_ENDORSEMENT;
		return 0;
	}
	if (!strcmp(name, "n") || !strcmp(name, "null")) {
		*out = ELA_TPM2_RH_NULL;
		return 0;
	}

	return -1;
}
