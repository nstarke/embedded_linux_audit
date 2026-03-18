// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "tpm2_internal.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(ELA_HAS_TPM2)

static void usage_pcrread(const char *prog)
{
	fprintf(stderr,
		"Usage: %s pcrread <alg:pcr[,pcr...]> [alg:pcr[,pcr...]]...\n"
		"  Example: %s pcrread sha256:0,1,2 sha1:0,7\n"
		"  Output honors --output-format (txt, csv, json)\n"
		"  When --output-http is configured, POST to /:mac/upload/tpm2-pcrread\n",
		prog, prog);
}

static int parse_pcr_bank(const char *name, TPMI_ALG_HASH *alg)
{
	TPM2_ALG_ID parsed = parse_hash_alg(name);

	if (parsed == TPM2_ALG_ERROR)
		return -1;

	*alg = parsed;
	return 0;
}

static int add_pcr_selection(TPML_PCR_SELECTION *selection, const char *spec)
{
	char *copy = NULL;
	char *colon;
	char *bank_name;
	char *list;
	char *token;
	char *saveptr = NULL;
	TPMI_ALG_HASH hash_alg;
	uint32_t pcr_index;
	size_t i;

	if (!selection || !spec || !*spec)
		return -1;

	if (selection->count >= TPM2_NUM_PCR_BANKS) {
		fprintf(stderr, "tpm2: too many PCR banks requested\n");
		return -1;
	}

	copy = strdup(spec);
	if (!copy)
		return -1;

	colon = strchr(copy, ':');
	if (!colon) {
		fprintf(stderr, "tpm2: PCR selector must be in alg:pcr[,pcr...] form: %s\n", spec);
		free(copy);
		return -1;
	}

	*colon = '\0';
	bank_name = copy;
	list = colon + 1;

	if (parse_pcr_bank(bank_name, &hash_alg) != 0) {
		fprintf(stderr, "tpm2: unsupported PCR bank: %s\n", bank_name);
		free(copy);
		return -1;
	}

	selection->pcrSelections[selection->count].hash = hash_alg;
	selection->pcrSelections[selection->count].sizeofSelect = 3;
	memset(selection->pcrSelections[selection->count].pcrSelect, 0, sizeof(selection->pcrSelections[selection->count].pcrSelect));

	for (token = strtok_r(list, ",", &saveptr); token; token = strtok_r(NULL, ",", &saveptr)) {
		if (parse_u32(token, &pcr_index) != 0 || pcr_index > 23) {
			fprintf(stderr, "tpm2: invalid PCR index: %s\n", token);
			free(copy);
			return -1;
		}
		selection->pcrSelections[selection->count].pcrSelect[pcr_index / 8] |= (uint8_t)(1U << (pcr_index % 8));
	}

	for (i = 0; i < selection->count; i++) {
		if (selection->pcrSelections[i].hash == hash_alg) {
			fprintf(stderr, "tpm2: duplicate PCR bank requested: %s\n", bank_name);
			free(copy);
			return -1;
		}
	}

	selection->count++;
	free(copy);
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
