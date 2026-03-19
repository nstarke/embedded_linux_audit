// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef UTIL_TPM2_PCR_PARSE_UTIL_H
#define UTIL_TPM2_PCR_PARSE_UTIL_H

#include <stddef.h>
#include <stdint.h>

#define ELA_TPM2_ALG_ERROR 0x0000
#define ELA_TPM2_ALG_SHA1 0x0004
#define ELA_TPM2_ALG_SHA256 0x000b
#define ELA_TPM2_ALG_SHA384 0x000c
#define ELA_TPM2_ALG_SHA512 0x000d
#define ELA_TPM2_MAX_PCR_BANKS 16

struct ela_tpm2_pcr_bank_selection {
	uint16_t hash_alg;
	uint8_t pcr_select[3];
};

struct ela_tpm2_pcr_selection {
	size_t count;
	struct ela_tpm2_pcr_bank_selection banks[ELA_TPM2_MAX_PCR_BANKS];
};

int ela_tpm2_parse_pcr_bank(const char *name, uint16_t *alg);
int ela_tpm2_add_pcr_selection(struct ela_tpm2_pcr_selection *selection,
			       const char *spec,
			       char *errbuf,
			       size_t errbuf_len);

#endif
