// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_TPM2_OUTPUT_H
#define ELA_TPM2_OUTPUT_H

#if defined(ELA_HAS_TPM2)

#include <stdbool.h>
#include <stddef.h>
#include "../util/output_buffer.h"

/*
 * Output context shared by all tpm2 subcommands.
 * Populated by tpm2_output_init(); caller must call tpm2_output_free()
 * when done regardless of whether init succeeded.
 */
struct tpm2_output_ctx {
	const char         *format;      /* "txt", "csv", or "json" */
	const char         *output_uri;  /* resolved http/https base URI or NULL */
	int                 output_sock; /* connected TCP socket or -1 */
	bool                insecure;
	struct output_buffer buf;
};

/*
 * Read ELA_OUTPUT_FORMAT / ELA_OUTPUT_HTTP / ELA_OUTPUT_HTTPS /
 * ELA_OUTPUT_TCP / ELA_OUTPUT_INSECURE from the environment.
 * Validates the format, resolves the HTTP URI, and opens the TCP socket.
 * Returns 0 on success, non-zero on error (message already printed to stderr).
 */
int  tpm2_output_init(struct tpm2_output_ctx *ctx);

/*
 * Append one key/value pair to the internal buffer in the configured format.
 * txt:  "key: value\n"
 * csv:  CSV-quoted "key","value"\n
 * json: {"key":"...","value":"..."}\n
 * Returns 0 on success, -1 on allocation failure.
 */
int  tpm2_output_kv(struct tpm2_output_ctx *ctx, const char *key, const char *value);

/*
 * Write the accumulated buffer to stdout, and if configured, to the TCP
 * socket and/or HTTP endpoint.  upload_type is the suffix passed to
 * ela_http_build_upload_uri() (e.g. "tpm2-getcap").
 * Returns 0 on success, non-zero if any sink failed.
 */
int  tpm2_output_flush(struct tpm2_output_ctx *ctx, const char *upload_type);

/*
 * Release the output buffer and close the TCP socket (if open).
 * Safe to call even when tpm2_output_init() failed partway through.
 */
void tpm2_output_free(struct tpm2_output_ctx *ctx);

#endif /* ELA_HAS_TPM2 */
#endif /* ELA_TPM2_OUTPUT_H */
