// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "tpm2_internal.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(ELA_HAS_TPM2)

static void usage_getcap(const char *prog)
{
	fprintf(stderr,
		"Usage: %s getcap <properties-fixed|properties-variable|algorithms|commands|pcrs>\n"
		"  Query a built-in TPM2 capability set using TPM2-TSS\n"
		"  Output honors --output-format (txt, csv, json)\n"
		"  When --output-http is configured, POST to /:mac/upload/tpm2-getcap\n",
		prog);
}

int cmd_getcap(int argc, char **argv)
{
	ESYS_CONTEXT *esys = NULL;
	TSS2_TCTI_CONTEXT *tcti = NULL;
	TPM2_CAP capability;
	uint32_t property = 0;
	uint32_t property_count = TPM2_MAX_TPM_PROPERTIES;
	TPMI_YES_NO more_data = TPM2_NO;
	TPMS_CAPABILITY_DATA *cap_data = NULL;
	TSS2_RC rc;
	struct tpm2_output_ctx out;
	int ret;
	UINT32 i;

	if (argc >= 3 && (!strcmp(argv[2], "--help") || !strcmp(argv[2], "-h"))) {
		usage_getcap(argv[0]);
		return 0;
	}

	if (argc != 3) {
		usage_getcap(argv[0]);
		return 2;
	}

	if (!strcmp(argv[2], "properties-fixed")) {
		capability = TPM2_CAP_TPM_PROPERTIES;
		property = TPM2_PT_FIXED;
		property_count = 16;
	} else if (!strcmp(argv[2], "properties-variable")) {
		capability = TPM2_CAP_TPM_PROPERTIES;
		property = TPM2_PT_VAR;
		property_count = 16;
	} else if (!strcmp(argv[2], "algorithms")) {
		capability = TPM2_CAP_ALGS;
		property = 0;
		property_count = 64;
	} else if (!strcmp(argv[2], "commands")) {
		capability = TPM2_CAP_COMMANDS;
		property = 0;
		property_count = 64;
	} else if (!strcmp(argv[2], "pcrs")) {
		capability = TPM2_CAP_PCRS;
		property = 0;
		property_count = 1;
	} else {
		fprintf(stderr, "tpm2: unsupported getcap selector: %s\n", argv[2]);
		usage_getcap(argv[0]);
		return 2;
	}

	ret = tpm2_output_init(&out);
	if (ret != 0)
		return ret;

	ret = tpm2_open(&esys, &tcti);
	if (ret != 0)
		goto done;

	rc = Esys_GetCapability(esys,
				ESYS_TR_NONE,
				ESYS_TR_NONE,
				ESYS_TR_NONE,
				capability,
				property,
				property_count,
				&more_data,
				&cap_data);
	if (rc != TPM2_RC_SUCCESS) {
		fprintf(stderr, "tpm2: Esys_GetCapability failed: 0x%08" PRIx32 "\n", rc);
		ret = tpm2_rc_to_exit_code(rc);
		goto done;
	}

	switch (capability) {
	case TPM2_CAP_TPM_PROPERTIES:
		for (i = 0; i < cap_data->data.tpmProperties.count; i++) {
			const TPMS_TAGGED_PROPERTY *prop = &cap_data->data.tpmProperties.tpmProperty[i];
			char key[32], val[32];
			snprintf(key, sizeof(key), "0x%08" PRIx32, prop->property);
			snprintf(val, sizeof(val), "0x%08" PRIx32, prop->value);
			if (tpm2_output_kv(&out, key, val) != 0) {
				ret = 1;
				goto done;
			}
		}
		break;
	case TPM2_CAP_ALGS:
		for (i = 0; i < cap_data->data.algorithms.count; i++) {
			const TPMS_ALG_PROPERTY *alg = &cap_data->data.algorithms.algProperties[i];
			char key[32], val[32];
			snprintf(key, sizeof(key), "0x%04x", alg->alg);
			snprintf(val, sizeof(val), "0x%08" PRIx32, alg->algProperties);
			if (tpm2_output_kv(&out, key, val) != 0) {
				ret = 1;
				goto done;
			}
		}
		break;
	case TPM2_CAP_COMMANDS:
		for (i = 0; i < cap_data->data.command.count; i++) {
			char key[32], val[32];
			snprintf(key, sizeof(key), "0x%04" PRIx32,
				cap_data->data.command.commandAttributes[i] & 0xFFFFu);
			snprintf(val, sizeof(val), "0x%08" PRIx32,
				cap_data->data.command.commandAttributes[i]);
			if (tpm2_output_kv(&out, key, val) != 0) {
				ret = 1;
				goto done;
			}
		}
		break;
	case TPM2_CAP_PCRS:
		for (i = 0; i < cap_data->data.assignedPCR.count; i++) {
			const TPMS_PCR_SELECTION *sel = &cap_data->data.assignedPCR.pcrSelections[i];
			char key[16];
			char val[32] = {0};
			uint32_t byte_idx;
			size_t vlen = 0;

			snprintf(key, sizeof(key), "0x%04x", sel->hash);
			for (byte_idx = 0; byte_idx < sel->sizeofSelect && vlen < sizeof(val) - 2; byte_idx++) {
				snprintf(val + vlen, sizeof(val) - vlen, "%02x", sel->pcrSelect[byte_idx]);
				vlen += 2;
			}
			if (tpm2_output_kv(&out, key, val) != 0) {
				ret = 1;
				goto done;
			}
		}
		break;
	default:
		fprintf(stderr, "tpm2: unhandled capability response\n");
		ret = 1;
		goto done;
	}

	if (more_data == TPM2_YES)
		fprintf(stderr, "tpm2: additional capability data is available but was not requested\n");

	ret = tpm2_output_flush(&out, "tpm2-getcap");

done:
	if (cap_data)
		Esys_Free(cap_data);
	tpm2_close(&esys, &tcti);
	tpm2_output_free(&out);
	return ret;
}

#endif /* ELA_HAS_TPM2 */
