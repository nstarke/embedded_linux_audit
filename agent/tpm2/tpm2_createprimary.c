// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "tpm2_internal.h"

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(ELA_HAS_TPM2)

static void usage_createprimary(const char *prog)
{
	fprintf(stderr,
		"Usage: %s createprimary [-C <o|p|e|n>] [-g <sha1|sha256|sha384|sha512>] [-G <rsa|ecc>] [-c <context-file>]\n"
		"  Create a primary object with a minimal built-in template.\n"
		"  When -c is provided, the ESYS serialized handle is written to that file.\n"
		"  Output honors --output-format (txt, csv, json)\n"
		"  When --output-http is configured, POST to /:mac/upload/tpm2-createprimary\n",
		prog);
}

static TPMI_RH_HIERARCHY parse_hierarchy(const char *name)
{
	if (!name)
		return TPM2_RH_NULL;
	if (!strcmp(name, "o") || !strcmp(name, "owner"))
		return TPM2_RH_OWNER;
	if (!strcmp(name, "p") || !strcmp(name, "platform"))
		return TPM2_RH_PLATFORM;
	if (!strcmp(name, "e") || !strcmp(name, "endorsement"))
		return TPM2_RH_ENDORSEMENT;
	if (!strcmp(name, "n") || !strcmp(name, "null"))
		return TPM2_RH_NULL;
	return 0;
}

static int write_serialized_handle(const char *path, const uint8_t *buf, size_t len)
{
	FILE *fp;

	if (!path || !buf || len == 0)
		return -1;

	fp = fopen(path, "wb");
	if (!fp) {
		fprintf(stderr, "tpm2: failed to open %s for writing: %s\n", path, strerror(errno));
		return -1;
	}

	if (fwrite(buf, 1, len, fp) != len) {
		fprintf(stderr, "tpm2: failed to write %s: %s\n", path, strerror(errno));
		fclose(fp);
		return -1;
	}

	if (fclose(fp) != 0) {
		fprintf(stderr, "tpm2: failed to close %s: %s\n", path, strerror(errno));
		return -1;
	}

	return 0;
}

static int build_public_template(const char *key_alg_name,
				 TPM2_ALG_ID name_alg,
				 TPM2B_PUBLIC *public)
{
	if (!key_alg_name || !public)
		return -1;

	memset(public, 0, sizeof(*public));
	public->size = 0;
	public->publicArea.nameAlg = name_alg;
	public->publicArea.objectAttributes =
		TPMA_OBJECT_RESTRICTED |
		TPMA_OBJECT_DECRYPT |
		TPMA_OBJECT_FIXEDTPM |
		TPMA_OBJECT_FIXEDPARENT |
		TPMA_OBJECT_SENSITIVEDATAORIGIN |
		TPMA_OBJECT_USERWITHAUTH;

	if (!strcmp(key_alg_name, "rsa")) {
		public->publicArea.type = TPM2_ALG_RSA;
		public->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
		public->publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
		public->publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
		public->publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
		public->publicArea.parameters.rsaDetail.keyBits = 2048;
		public->publicArea.parameters.rsaDetail.exponent = 0;
		public->publicArea.unique.rsa.size = 0;
		return 0;
	}

	if (!strcmp(key_alg_name, "ecc")) {
		public->publicArea.type = TPM2_ALG_ECC;
		public->publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_AES;
		public->publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
		public->publicArea.parameters.eccDetail.symmetric.mode.sym = TPM2_ALG_CFB;
		public->publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
		public->publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
		public->publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
		public->publicArea.unique.ecc.x.size = 0;
		public->publicArea.unique.ecc.y.size = 0;
		return 0;
	}

	return -1;
}

int cmd_createprimary(int argc, char **argv)
{
	ESYS_CONTEXT *esys = NULL;
	TSS2_TCTI_CONTEXT *tcti = NULL;
	TPMI_RH_HIERARCHY hierarchy = TPM2_RH_OWNER;
	TPM2_ALG_ID name_alg = TPM2_ALG_SHA256;
	const char *key_alg_name = "rsa";
	const char *context_path = NULL;
	TPM2B_SENSITIVE_CREATE in_sensitive = { 0 };
	TPM2B_PUBLIC in_public;
	TPM2B_DATA outside_info = { 0 };
	TPML_PCR_SELECTION creation_pcr = { 0 };
	ESYS_TR object_handle = ESYS_TR_NONE;
	TPM2B_PUBLIC *out_public = NULL;
	TPM2B_CREATION_DATA *creation_data = NULL;
	TPM2B_DIGEST *creation_hash = NULL;
	TPMT_TK_CREATION *creation_ticket = NULL;
	uint8_t *serialized = NULL;
	size_t serialized_size = 0;
	TSS2_RC rc;
	struct tpm2_output_ctx out;
	int ret;
	int opt;

	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "hierarchy", required_argument, NULL, 'C' },
		{ "hash-alg", required_argument, NULL, 'g' },
		{ "key-alg", required_argument, NULL, 'G' },
		{ "context", required_argument, NULL, 'c' },
		{ 0, 0, 0, 0 }
	};

	if (argc >= 3 && (!strcmp(argv[2], "--help") || !strcmp(argv[2], "-h"))) {
		usage_createprimary(argv[0]);
		return 0;
	}

	optind = 2;
	while ((opt = getopt_long(argc, argv, "hC:g:G:c:", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage_createprimary(argv[0]);
			return 0;
		case 'C':
			hierarchy = parse_hierarchy(optarg);
			if (hierarchy == 0) {
				fprintf(stderr, "tpm2: unsupported hierarchy: %s\n", optarg);
				return 2;
			}
			break;
		case 'g':
			name_alg = parse_hash_alg(optarg);
			if (name_alg == TPM2_ALG_ERROR) {
				fprintf(stderr, "tpm2: unsupported hash algorithm: %s\n", optarg);
				return 2;
			}
			break;
		case 'G':
			if (strcmp(optarg, "rsa") && strcmp(optarg, "ecc")) {
				fprintf(stderr, "tpm2: unsupported key algorithm: %s\n", optarg);
				return 2;
			}
			key_alg_name = optarg;
			break;
		case 'c':
			context_path = optarg;
			break;
		default:
			usage_createprimary(argv[0]);
			return 2;
		}
	}

	if (optind != argc) {
		usage_createprimary(argv[0]);
		return 2;
	}

	if (build_public_template(key_alg_name, name_alg, &in_public) != 0) {
		fprintf(stderr, "tpm2: failed to build public template\n");
		return 1;
	}

	ret = tpm2_output_init(&out);
	if (ret != 0)
		return ret;

	ret = tpm2_open(&esys, &tcti);
	if (ret != 0)
		goto done;

	rc = Esys_CreatePrimary(esys,
				hierarchy,
				ESYS_TR_PASSWORD,
				ESYS_TR_NONE,
				ESYS_TR_NONE,
				&in_sensitive,
				&in_public,
				&outside_info,
				&creation_pcr,
				&object_handle,
				&out_public,
				&creation_data,
				&creation_hash,
				&creation_ticket);
	if (rc != TPM2_RC_SUCCESS) {
		fprintf(stderr, "tpm2: Esys_CreatePrimary failed: 0x%08" PRIx32 "\n", rc);
		ret = tpm2_rc_to_exit_code(rc);
		goto done;
	}

	if (context_path) {
		rc = Esys_TR_Serialize(esys, object_handle, &serialized, &serialized_size);
		if (rc != TPM2_RC_SUCCESS) {
			fprintf(stderr, "tpm2: failed to serialize primary object: 0x%08" PRIx32 "\n", rc);
			ret = tpm2_rc_to_exit_code(rc);
			goto done;
		}
		if (write_serialized_handle(context_path, serialized, serialized_size) != 0) {
			ret = 1;
			goto done;
		}
	}

	{
		char val[32];

		snprintf(val, sizeof(val), "0x%08x", hierarchy);
		if (tpm2_output_kv(&out, "hierarchy", val) != 0) { ret = 1; goto done; }

		snprintf(val, sizeof(val), "0x%04x", out_public->publicArea.type);
		if (tpm2_output_kv(&out, "type", val) != 0) { ret = 1; goto done; }

		snprintf(val, sizeof(val), "0x%04x", out_public->publicArea.nameAlg);
		if (tpm2_output_kv(&out, "name-alg", val) != 0) { ret = 1; goto done; }

		if (context_path) {
			if (tpm2_output_kv(&out, "context", context_path) != 0) { ret = 1; goto done; }
		}
	}

	ret = tpm2_output_flush(&out, "tpm2-createprimary");

done:
	if (serialized)
		Esys_Free(serialized);
	if (creation_ticket)
		Esys_Free(creation_ticket);
	if (creation_hash)
		Esys_Free(creation_hash);
	if (creation_data)
		Esys_Free(creation_data);
	if (out_public)
		Esys_Free(out_public);
	if (object_handle != ESYS_TR_NONE)
		Esys_TR_Close(esys, &object_handle);
	tpm2_close(&esys, &tcti);
	tpm2_output_free(&out);
	return ret;
}

#endif /* ELA_HAS_TPM2 */
