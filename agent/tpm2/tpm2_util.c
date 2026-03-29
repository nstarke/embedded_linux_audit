// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "tpm2_internal.h"

#include "../util/command_parse_util.h"
#include "../util/tpm2_pcr_parse_util.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(ELA_HAS_TPM2)

int tpm2_rc_to_exit_code(TSS2_RC rc)
{
	if (rc == TPM2_RC_SUCCESS)
		return 0;
	return 1;
}

int parse_u32(const char *text, uint32_t *value)
{
	return ela_parse_u32(text, value);
}

TPM2_ALG_ID parse_hash_alg(const char *name)
{
	uint16_t alg;

	if (ela_tpm2_parse_pcr_bank(name, &alg) != 0)
		return TPM2_ALG_ERROR;
	return (TPM2_ALG_ID)alg;
}

/* LCOV_EXCL_START - tpm2_open/tpm2_close require a real /dev/tpm0 device */
int tpm2_open(ESYS_CONTEXT **esys, TSS2_TCTI_CONTEXT **tcti)
{
	TSS2_ABI_VERSION abi = TSS2_ABI_VERSION_CURRENT;
	TSS2_RC rc;
	size_t tcti_size = 0;

	if (!esys || !tcti)
		return 1;

	*esys = NULL;
	*tcti = NULL;

	rc = Tss2_Tcti_Device_Init(NULL, &tcti_size, NULL);
	if (rc != TPM2_RC_SUCCESS) {
		fprintf(stderr, "tpm2: failed to size device TCTI context: 0x%08" PRIx32 "\n", rc);
		return tpm2_rc_to_exit_code(rc);
	}

	*tcti = calloc(1, tcti_size);
	if (!*tcti)
		return 1;

	rc = Tss2_Tcti_Device_Init(*tcti, &tcti_size, NULL);
	if (rc != TPM2_RC_SUCCESS) {
		fprintf(stderr, "tpm2: failed to initialize device TCTI: 0x%08" PRIx32 "\n", rc);
		free(*tcti);
		*tcti = NULL;
		return tpm2_rc_to_exit_code(rc);
	}

	rc = Esys_Initialize(esys, *tcti, &abi);
	if (rc != TPM2_RC_SUCCESS) {
		fprintf(stderr, "tpm2: failed to initialize ESYS context: 0x%08" PRIx32 "\n", rc);
		TSS2_TCTI_FINALIZE(*tcti)(*tcti);
		// cppcheck-suppress legacyUninitvar
		free(*tcti);
		*tcti = NULL;
		return tpm2_rc_to_exit_code(rc);
	}

	return 0;
}

void tpm2_close(ESYS_CONTEXT **esys, TSS2_TCTI_CONTEXT **tcti)
{
	if (esys && *esys)
		Esys_Finalize(esys);
	if (tcti && *tcti) {
		TSS2_TCTI_FINALIZE(*tcti)(*tcti);
		// cppcheck-suppress legacyUninitvar
		free(*tcti);
		*tcti = NULL;
	}
}
/* LCOV_EXCL_STOP */

#endif /* ELA_HAS_TPM2 */
