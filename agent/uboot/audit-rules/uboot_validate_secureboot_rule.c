// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "uboot/audit-rules/uboot_audit_util.h"
#include "uboot/audit-rules/uboot_validate_secureboot_util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

/*
 * All functions in this file require real hardware, network I/O, or OS-level
 * services (ptrace, SSH, sockets, TPM2, EFI) and cannot be exercised in the
 * unit-test environment.
 */
/* LCOV_EXCL_START */

static int read_file_all(const char *path, uint8_t **out, size_t *out_len)
{
	int fd = -1;
	struct stat st;
	uint8_t *buf = NULL;
	ssize_t got;

	if (!path || !*path || !out || !out_len)
		return -1;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	if (fstat(fd, &st) != 0 || st.st_size <= 0) {
		close(fd);
		return -1;
	}

	buf = malloc((size_t)st.st_size);
	if (!buf) {
		close(fd);
		return -1;
	}

	got = read(fd, buf, (size_t)st.st_size);
	close(fd);
	if (got < 0 || (size_t)got != (size_t)st.st_size) {
		free(buf);
		return -1;
	}

	*out = buf;
	*out_len = (size_t)st.st_size;
	return 0;
}

static int verify_signature(const char *sig_value,
			    const char *blob_path,
			    const char *pubkey_path,
			    const char *digest_name)
{
	uint8_t *blob = NULL;
	size_t blob_len = 0;
	uint8_t *sig = NULL;
	size_t sig_len = 0;
	BIO *bio = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_MD_CTX *mdctx = NULL;
	const EVP_MD *md;
	int rc = -1;

	if (!sig_value || !blob_path || !pubkey_path)
		return -1;

	if (ela_uboot_decode_signature_value(sig_value, &sig, &sig_len) != 0 || !sig_len)
		goto out;

	if (read_file_all(blob_path, &blob, &blob_len) != 0 || !blob_len)
		goto out;

	bio = BIO_new_file(pubkey_path, "r");
	if (!bio)
		goto out;

	pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	if (!pkey)
		goto out;

	md = EVP_get_digestbyname((digest_name && *digest_name) ? digest_name : "sha256");
	if (!md)
		goto out;

	mdctx = EVP_MD_CTX_new();
	if (!mdctx)
		goto out;

	if (EVP_DigestVerifyInit(mdctx, NULL, md, NULL, pkey) != 1)
		goto out;

	rc = EVP_DigestVerify(mdctx, sig, sig_len, blob, blob_len);

out:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	BIO_free(bio);
	free(sig);
	free(blob);
	if (rc == 1)
		return 0;
	if (rc == 0)
		return 1;
	return -1;
}

static int run_validate_secureboot(const struct embedded_linux_audit_input *input, char *message, size_t message_len)
{
	struct env_kv_view pairs[512];
	const char *secureboot;
	const char *verify;
	const char *bootm_verify_sig;
	const char *signature;
	const char *signature_name;
	const char *used_digest = NULL;
	int verify_rc;
	char detail[320] = "";
	int issues = 0;
	size_t data_off = 0;
	int count;

	if (!input || !input->data || !input->crc32_table || input->data_len < 8) {
		if (message && message_len)
			snprintf(message, message_len, "input too small (need at least 8 bytes)");
		return -1;
	}

	if (ela_uboot_choose_env_data_offset(input, &data_off) != 0) {
		if (message && message_len)
			snprintf(message, message_len, "unable to parse env vars: invalid CRC32 for standard/redundant layouts");
		return -1;
	}

	count = ela_uboot_parse_env_pairs(input->data, input->data_len, data_off, pairs, sizeof(pairs) / sizeof(pairs[0]));
	if (count < 0) {
		if (message && message_len)
			snprintf(message, message_len, "failed to parse environment key/value pairs");
		return -1;
	}

	secureboot = ela_uboot_find_env_value(pairs, (size_t)count, "secureboot");
	verify = ela_uboot_find_env_value(pairs, (size_t)count, "verify");
	bootm_verify_sig = ela_uboot_find_env_value(pairs, (size_t)count, "bootm_verify_sig");
	signature = ela_uboot_find_env_value(pairs, (size_t)count, "signature");
	signature_name = "signature";
	if (!ela_uboot_value_is_nonempty(signature)) {
		signature = ela_uboot_find_env_value(pairs, (size_t)count, "boot_signature");
		signature_name = "boot_signature";
	}
	if (!ela_uboot_value_is_nonempty(signature)) {
		signature = ela_uboot_find_env_value(pairs, (size_t)count, "fit_signature");
		signature_name = "fit_signature";
	}

	issues = ela_uboot_secureboot_check_env_policy(secureboot, verify, bootm_verify_sig, signature,
						       detail, sizeof(detail));

	if (ela_uboot_value_is_nonempty(signature)) {
		if (!input->signature_blob_path || !*input->signature_blob_path ||
		    !input->signature_pubkey_path || !*input->signature_pubkey_path) {
			issues++;
			snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail),
				 "%s--signature-blob/--signature-pubkey required for cryptographic verification",
				 detail[0] ? "; " : "");
		} else {
			if (input->signature_algorithm && *input->signature_algorithm) {
				used_digest = input->signature_algorithm;
				verify_rc = verify_signature(signature,
							     input->signature_blob_path,
							     input->signature_pubkey_path,
							     used_digest);
				if (verify_rc < 0) {
					if (message && message_len) {
						snprintf(message, message_len,
							 "signature verification error (%s): blob=%s pubkey=%s digest=%s",
							 signature_name,
							 input->signature_blob_path,
							 input->signature_pubkey_path,
							 used_digest);
					}
					return -1;
				}
			} else {
				static const char *fallback_digests[] = {
					"sha256", "sha384", "sha512", "sha1", "sha224"
				};
				verify_rc = 1;
				for (size_t i = 0; i < sizeof(fallback_digests) / sizeof(fallback_digests[0]); i++) {
					int try_rc = verify_signature(signature,
								 input->signature_blob_path,
								 input->signature_pubkey_path,
								 fallback_digests[i]);
					if (try_rc == 0) {
						verify_rc = 0;
						used_digest = fallback_digests[i];
						break;
					}
					if (try_rc < 0) {
						if (message && message_len) {
							snprintf(message, message_len,
								 "signature verification error (%s): blob=%s pubkey=%s digest=%s",
								 signature_name,
								 input->signature_blob_path,
								 input->signature_pubkey_path,
								 fallback_digests[i]);
						}
						return -1;
					}
				}
			}

			if (verify_rc > 0) {
				issues++;
				snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail),
					 "%ssignature verification failed (%s)",
					 detail[0] ? "; " : "", signature_name);
			}
		}
	}

	if (!issues) {
		if (message && message_len) {
			snprintf(message, message_len,
				 "secure boot vars validated: secureboot=%s verify=%s bootm_verify_sig=%s %s=<verified> digest=%s",
				 secureboot, verify, bootm_verify_sig, signature_name,
				 used_digest ? used_digest : (input->signature_algorithm ? input->signature_algorithm : "n/a"));
		}
		return 0;
	}

	if (message && message_len) {
		snprintf(message, message_len,
			 "secure boot variable misconfiguration: %s", detail[0] ? detail : "unknown");
	}

	return 1;
}

static const struct embedded_linux_audit_rule uboot_validate_secureboot_rule = {
	.name = "uboot_validate_secureboot",
	.description = "Validate secure boot env vars and cryptographically verify signature field",
	.run = run_validate_secureboot,
};

ELA_REGISTER_RULE(uboot_validate_secureboot_rule);

/* LCOV_EXCL_STOP */
