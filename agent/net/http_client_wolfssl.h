// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_HTTP_CLIENT_WOLFSSL_H
#define ELA_HTTP_CLIENT_WOLFSSL_H

/*
 * wolfSSL HTTPS backend, used on PowerPC targets (see ELA_ENABLE_WOLFSSL in the
 * Makefile).  The implementation lives in its own translation unit because
 * wolfSSL is built with --enable-opensslextra, so <wolfssl/ssl.h> pulls in the
 * wolfssl/openssl compatibility headers and aliases the OpenSSL type and
 * function names onto the WOLFSSL_* ones (ASN1_INTEGER, OPENSSL_STACK,
 * OPENSSL_sk_free, and a few hundred more).  Those aliases collide
 * irreconcilably with the real OpenSSL headers, which the agent still needs for
 * libssh and the embedded CA store, so the two header trees must never meet in
 * one translation unit.  Keep this header free of both: it deliberately exposes
 * only plain C types.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../util/http_uri_util.h"

#ifdef ELA_HAS_WOLFSSL

/* POST `data` to an https:// URI. Returns 0 on a 2xx response, -1 otherwise. */
int ela_http_wolfssl_post(const struct parsed_http_uri *parsed,
			  const char *uri,
			  const uint8_t *data,
			  size_t len,
			  const char *content_type,
			  const char *auth_key,
			  bool insecure,
			  bool verbose,
			  char *errbuf,
			  size_t errbuf_len,
			  int *status_out);

/* GET an https:// URI into `output_path`. Returns 0 on success, -1 otherwise. */
int ela_http_wolfssl_get_to_file(const struct parsed_http_uri *parsed,
				 const char *uri,
				 const char *output_path,
				 bool insecure,
				 bool verbose,
				 char *errbuf,
				 size_t errbuf_len);

#endif /* ELA_HAS_WOLFSSL */

#endif
