// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "tpm2_internal.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(ELA_HAS_TPM2)

/*
 * All functions in this file require real hardware, network I/O, or OS-level
 * services (ptrace, SSH, sockets, TPM2, EFI) and cannot be exercised in the
 * unit-test environment.
 */
/* LCOV_EXCL_START */

static void usage_nvreadpublic(const char *prog)
{
	fprintf(stderr,
		"Usage: %s nvreadpublic <nv-index>\n"
		"  Example: %s nvreadpublic 0x1500016\n"
		"  Output honors --output-format (txt, csv, json)\n"
		"  When --output-http is configured, POST to /:mac/upload/tpm2-nvreadpublic\n",
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
	struct tpm2_output_ctx out;
	int ret;

	if (argc >= 3 && (!strcmp(argv[2], "--help") || !strcmp(argv[2], "-h"))) {
		usage_nvreadpublic(argv[0]);
		return 0;
	}

	if (argc != 3 || parse_u32(argv[2], &nv_index) != 0) {
		usage_nvreadpublic(argv[0]);
		return 2;
	}

	ret = tpm2_output_init(&out);
	if (ret != 0)
		return ret;

	ret = tpm2_open(&esys, &tcti);
	if (ret != 0)
		goto done;

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

	{
		char val[32];
		char *name_hex;
		uint16_t i;
		size_t vlen;

		snprintf(val, sizeof(val), "0x%08" PRIx32, public_info->nvPublic.nvIndex);
		if (tpm2_output_kv(&out, "nv-index", val) != 0) { ret = 1; goto done; }

		snprintf(val, sizeof(val), "0x%04x", public_info->nvPublic.nameAlg);
		if (tpm2_output_kv(&out, "name-alg", val) != 0) { ret = 1; goto done; }

		snprintf(val, sizeof(val), "0x%08" PRIx32, public_info->nvPublic.attributes);
		if (tpm2_output_kv(&out, "attributes", val) != 0) { ret = 1; goto done; }

		snprintf(val, sizeof(val), "%u", public_info->nvPublic.dataSize);
		if (tpm2_output_kv(&out, "data-size", val) != 0) { ret = 1; goto done; }

		name_hex = malloc(name->size * 2u + 1u);
		if (!name_hex) { ret = 1; goto done; }
		vlen = 0;
		for (i = 0; i < name->size; i++) {
			snprintf(name_hex + vlen, 3, "%02x", name->name[i]);
			vlen += 2;
		}
		name_hex[vlen] = '\0';
		ret = tpm2_output_kv(&out, "name", name_hex);
		free(name_hex);
		if (ret != 0) { ret = 1; goto done; }
	}

	ret = tpm2_output_flush(&out, "tpm2-nvreadpublic");

done:
	if (public_info)
		Esys_Free(public_info);
	if (name)
		Esys_Free(name);
	tpm2_close(&esys, &tcti);
	tpm2_output_free(&out);
	return ret;
}

#endif /* ELA_HAS_TPM2 */

/* LCOV_EXCL_STOP */
