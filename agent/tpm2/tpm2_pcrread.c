// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "tpm2_internal.h"

#include "../util/tpm2_pcr_parse_util.h"

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

static void usage_pcrread(const char *prog)
{
	fprintf(stderr,
		"Usage: %s pcrread <alg:pcr[,pcr...]> [alg:pcr[,pcr...]]...\n"
		"  Example: %s pcrread sha256:0,1,2 sha1:0,7\n"
		"  Output honors --output-format (txt, csv, json)\n"
		"  When --output-http is configured, POST to /:mac/upload/tpm2-pcrread\n",
		prog, prog);
}

static int add_pcr_selection(TPML_PCR_SELECTION *selection, const char *spec)
{
	struct ela_tpm2_pcr_selection parsed = {0};
	char errbuf[256];

	if (!selection || !spec || !*spec)
		return -1;

	if (selection->count >= TPM2_NUM_PCR_BANKS) {
		fprintf(stderr, "tpm2: too many PCR banks requested\n");
		return -1;
	}

	if (ela_tpm2_add_pcr_selection(&parsed, spec, errbuf, sizeof(errbuf)) != 0) {
		fprintf(stderr, "%s\n", errbuf);
		return -1;
	}

	selection->pcrSelections[selection->count].hash = (TPMI_ALG_HASH)parsed.banks[0].hash_alg;
	selection->pcrSelections[selection->count].sizeofSelect = 3;
	memcpy(selection->pcrSelections[selection->count].pcrSelect,
	       parsed.banks[0].pcr_select,
	       sizeof(selection->pcrSelections[selection->count].pcrSelect));

	selection->count++;
	return 0;
}

int cmd_pcrread(int argc, char **argv)
{
	ESYS_CONTEXT *esys = NULL;
	TSS2_TCTI_CONTEXT *tcti = NULL;
	TPML_PCR_SELECTION selection = { 0 };
	TPML_PCR_SELECTION *pcr_update = NULL;
	TPML_DIGEST *values = NULL;
	TSS2_RC rc;
	struct tpm2_output_ctx out;
	int ret;
	UINT32 bank_idx;
	UINT32 digest_idx = 0;

	if (argc >= 3 && (!strcmp(argv[2], "--help") || !strcmp(argv[2], "-h"))) {
		usage_pcrread(argv[0]);
		return 0;
	}

	if (argc < 3) {
		usage_pcrread(argv[0]);
		return 2;
	}

	for (int i = 2; i < argc; i++) {
		if (add_pcr_selection(&selection, argv[i]) != 0)
			return 2;
	}

	ret = tpm2_output_init(&out);
	if (ret != 0)
		return ret;

	ret = tpm2_open(&esys, &tcti);
	if (ret != 0)
		goto done;

	rc = Esys_PCR_Read(esys,
			   ESYS_TR_NONE,
			   ESYS_TR_NONE,
			   ESYS_TR_NONE,
			   &selection,
			   NULL,
			   &pcr_update,
			   &values);
	if (rc != TPM2_RC_SUCCESS) {
		fprintf(stderr, "tpm2: Esys_PCR_Read failed: 0x%08" PRIx32 "\n", rc);
		ret = tpm2_rc_to_exit_code(rc);
		goto done;
	}

	for (bank_idx = 0; bank_idx < pcr_update->count; bank_idx++) {
		const TPMS_PCR_SELECTION *bank = &pcr_update->pcrSelections[bank_idx];

		for (uint32_t pcr = 0; pcr < (uint32_t)(bank->sizeofSelect * 8); pcr++) {
			char key[32];
			char *val;
			uint16_t byte_idx;
			size_t vlen;

			if ((bank->pcrSelect[pcr / 8] & (1U << (pcr % 8))) == 0)
				continue;
			if (digest_idx >= values->count) {
				fprintf(stderr, "tpm2: PCR digest count mismatch\n");
				ret = 1;
				goto done;
			}

			snprintf(key, sizeof(key), "0x%04x:%u", bank->hash, pcr);

			/* hex-encode the digest into a heap buffer */
			val = malloc(values->digests[digest_idx].size * 2u + 1u);
			if (!val) {
				ret = 1;
				goto done;
			}
			vlen = 0;
			for (byte_idx = 0; byte_idx < values->digests[digest_idx].size; byte_idx++) {
				snprintf(val + vlen, 3, "%02x",
					values->digests[digest_idx].buffer[byte_idx]);
				vlen += 2;
			}
			val[vlen] = '\0';

			ret = tpm2_output_kv(&out, key, val);
			free(val);
			if (ret != 0) {
				ret = 1;
				goto done;
			}
			digest_idx++;
		}
	}

	ret = tpm2_output_flush(&out, "tpm2-pcrread");

done:
	if (pcr_update)
		Esys_Free(pcr_update);
	if (values)
		Esys_Free(values);
	tpm2_close(&esys, &tcti);
	tpm2_output_free(&out);
	return ret;
}

#endif /* ELA_HAS_TPM2 */

/* LCOV_EXCL_STOP */
