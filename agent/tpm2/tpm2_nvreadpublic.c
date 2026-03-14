// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "tpm2_internal.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(ELA_HAS_TPM2)

static void usage_nvreadpublic(const char *prog)
{
	fprintf(stderr,
		"Usage: %s nvreadpublic <nv-index>\n"
		"  Example: %s nvreadpublic 0x1500016\n",
		prog, prog);
}

int cmd_nvreadpublic(int argc, char **argv)
{
	ESYS_CONTEXT *esys = NULL;
	TSS2_TCTI_CONTEXT *tcti = NULL;
	TPM2_HANDLE nv_index;
	TPM2B_NV_PUBLIC *public_info = NULL;
	TPM2B_NAME *name = NULL;
	TSS2_RC rc;
	int ret;

	if (argc >= 3 && (!strcmp(argv[2], "--help") || !strcmp(argv[2], "-h"))) {
		usage_nvreadpublic(argv[0]);
		return 0;
	}

	if (argc != 3 || parse_u32(argv[2], &nv_index) != 0) {
		usage_nvreadpublic(argv[0]);
		return 2;
	}

	ret = tpm2_open(&esys, &tcti);
	if (ret != 0)
		return ret;

	rc = Esys_NV_ReadPublic(esys,
				ESYS_TR_NONE,
				ESYS_TR_NONE,
				ESYS_TR_NONE,
				nv_index,
				&public_info,
				&name);
	if (rc != TPM2_RC_SUCCESS) {
		fprintf(stderr, "tpm2: Esys_NV_ReadPublic failed: 0x%08" PRIx32 "\n", rc);
		ret = tpm2_rc_to_exit_code(rc);
		goto done;
	}

	printf("nv-index: 0x%08" PRIx32 "\n", public_info->nvPublic.nvIndex);
	printf("name-alg: 0x%04x\n", public_info->nvPublic.nameAlg);
	printf("attributes: 0x%08" PRIx32 "\n", public_info->nvPublic.attributes);
	printf("data-size: %u\n", public_info->nvPublic.dataSize);
	printf("name: ");
	for (uint16_t i = 0; i < name->size; i++)
		printf("%02x", name->name[i]);
	printf("\n");

	ret = 0;

done:
	if (public_info)
		Esys_Free(public_info);
	if (name)
		Esys_Free(name);
	tpm2_close(&esys, &tcti);
	return ret;
}

#endif /* ELA_HAS_TPM2 */
