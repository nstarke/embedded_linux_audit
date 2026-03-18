// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "tpm2_pcr_parse_util.h"

#include "command_parse_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int ela_tpm2_parse_pcr_bank(const char *name, uint16_t *alg)
{
	if (!name || !alg)
		return -1;
	if (!strcmp(name, "sha1")) {
		*alg = ELA_TPM2_ALG_SHA1;
		return 0;
	}
	if (!strcmp(name, "sha256")) {
		*alg = ELA_TPM2_ALG_SHA256;
		return 0;
	}
	if (!strcmp(name, "sha384")) {
		*alg = ELA_TPM2_ALG_SHA384;
		return 0;
	}
	if (!strcmp(name, "sha512")) {
		*alg = ELA_TPM2_ALG_SHA512;
		return 0;
	}
	return -1;
}

int ela_tpm2_add_pcr_selection(struct ela_tpm2_pcr_selection *selection,
			       const char *spec,
			       char *errbuf,
			       size_t errbuf_len)
{
	char *copy = NULL;
	char *colon;
	char *bank_name;
	char *list;
	char *token;
	char *saveptr = NULL;
	uint16_t hash_alg;
	uint32_t pcr_index;
	size_t i;

	if (!selection || !spec || !*spec)
		return -1;

	if (selection->count >= ELA_TPM2_MAX_PCR_BANKS) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "tpm2: too many PCR banks requested");
		return -1;
	}

	copy = strdup(spec);
	if (!copy)
		return -1;

	colon = strchr(copy, ':');
	if (!colon) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "tpm2: PCR selector must be in alg:pcr[,pcr...] form: %s", spec);
		free(copy);
		return -1;
	}

	*colon = '\0';
	bank_name = copy;
	list = colon + 1;

	if (ela_tpm2_parse_pcr_bank(bank_name, &hash_alg) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "tpm2: unsupported PCR bank: %s", bank_name);
		free(copy);
		return -1;
	}

	for (i = 0; i < selection->count; i++) {
		if (selection->banks[i].hash_alg == hash_alg) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "tpm2: duplicate PCR bank requested: %s", bank_name);
			free(copy);
			return -1;
		}
	}

	memset(&selection->banks[selection->count], 0, sizeof(selection->banks[selection->count]));
	selection->banks[selection->count].hash_alg = hash_alg;

	for (token = strtok_r(list, ",", &saveptr); token; token = strtok_r(NULL, ",", &saveptr)) {
		if (ela_parse_u32(token, &pcr_index) != 0 || pcr_index > 23) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "tpm2: invalid PCR index: %s", token);
			free(copy);
			return -1;
		}
		selection->banks[selection->count].pcr_select[pcr_index / 8] |= (uint8_t)(1U << (pcr_index % 8));
	}

	selection->count++;
	free(copy);
	return 0;
}
