// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "tpm2_internal.h"

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
	char *end = NULL;
	unsigned long parsed;

	if (!text || !*text || !value)
		return -1;

	errno = 0;
	parsed = strtoul(text, &end, 0);
	if (errno != 0 || !end || *end != '\0' || parsed > UINT32_MAX)
		return -1;

	*value = (uint32_t)parsed;
	return 0;
}

TPM2_ALG_ID parse_hash_alg(const char *name)
{
	if (!name)
		return TPM2_ALG_ERROR;
	if (!strcmp(name, "sha1"))
		return TPM2_ALG_SHA1;
	if (!strcmp(name, "sha256"))
		return TPM2_ALG_SHA256;
	if (!strcmp(name, "sha384"))
		return TPM2_ALG_SHA384;
	if (!strcmp(name, "sha512"))
		return TPM2_ALG_SHA512;
	return TPM2_ALG_ERROR;
}

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
		free(*tcti);
		*tcti = NULL;
	}
}

#endif /* ELA_HAS_TPM2 */
