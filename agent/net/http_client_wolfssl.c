// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "http_client_wolfssl.h"

#ifdef ELA_HAS_WOLFSSL

#include "http_client_body_util.h"
#include "http_client_protocol_util.h"
#include "http_client_runtime_util.h"
#include "tcp_util.h"
#include "../util/http_protocol_util.h"
#include "../util/isa_util.h"
#include "../util/str_util.h"
#include "../embedded_linux_audit_cmd.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * This translation unit must not pull in a real OpenSSL header, directly or
 * transitively -- see http_client_wolfssl.h for why. Everything included above
 * is plain C or agent headers that are free of both TLS stacks.
 */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

/*
 * All functions in this file require real network I/O and cannot be exercised
 * in the unit-test environment.
 */
/* LCOV_EXCL_START */

static int wolfssl_read_headers(WOLFSSL *ssl, char **headers_out)
{
	char *headers = NULL;
	size_t len = 0, cap = 0;
	char ch;

	while (1) {
		int n = wolfSSL_read(ssl, &ch, 1);
		if (n <= 0)
			goto fail;
		if (append_bytes(&headers, &len, &cap, &ch, 1) != 0)
			goto fail;
		if (len >= 4 && !memcmp(headers + len - 4, "\r\n\r\n", 4))
			break;
	}
	*headers_out = headers;
	return 0;
fail:
	free(headers);
	return -1;
}

static int wolfssl_copy_response_body_to_file(WOLFSSL *ssl, FILE *fp)
{
	char buf[4096];
	for (;;) {
		int n = wolfSSL_read(ssl, buf, sizeof(buf));
		if (n == 0)
			break;
		if (n < 0)
			return -1;
		if (fwrite(buf, 1, (size_t)n, fp) != (size_t)n)
			return -1;
	}
	return 0;
}

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
			  int *status_out)
{
	WOLFSSL_CTX *ctx = NULL;
	WOLFSSL *ssl = NULL;
	int sock = -1;
	char *headers = NULL;
	char *request = NULL;
	size_t request_len = 0;
	int status;
	int rc;

	if (status_out)
		*status_out = 0;

	ela_set_sigill_stage("https:wolfssl_post_init");
	if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "wolfSSL_Init failed");
		goto cleanup;
	}

	ela_set_sigill_stage("https:wolfssl_post_ctx_new");
	ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
	if (!ctx) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "wolfSSL_CTX_new failed");
		goto cleanup;
	}
	wolfSSL_CTX_set_verify(ctx, insecure ? WOLFSSL_VERIFY_NONE : WOLFSSL_VERIFY_PEER, NULL);
	if (!insecure) {
		ela_set_sigill_stage("https:wolfssl_post_load_ca");
		if (wolfSSL_CTX_load_verify_buffer(ctx,
				(const unsigned char *)ela_default_ca_bundle_pem,
				(long)ela_default_ca_bundle_pem_len,
				WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "wolfSSL_CTX_load_verify_buffer failed");
			goto cleanup;
		}
	}

	ela_set_sigill_stage("https:wolfssl_post_tcp_connect");
	sock = connect_tcp_host_port_any(parsed->host, parsed->port);
	if (sock < 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to connect to %s:%u", parsed->host, (unsigned int)parsed->port);
		goto cleanup;
	}

	ela_set_sigill_stage("https:wolfssl_post_new");
	ssl = wolfSSL_new(ctx);
	if (!ssl) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "wolfSSL_new failed");
		goto cleanup;
	}
	if (wolfSSL_set_fd(ssl, sock) != WOLFSSL_SUCCESS) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "wolfSSL_set_fd failed");
		goto cleanup;
	}
	if (!insecure)
		wolfSSL_check_domain_name(ssl, parsed->host);

	ela_set_sigill_stage("https:wolfssl_post_connect");
	while ((rc = wolfSSL_connect(ssl)) != WOLFSSL_SUCCESS) {
		int err = wolfSSL_get_error(ssl, rc);
		if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE &&
		    err != WANT_READ && err != WANT_WRITE) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "wolfSSL_connect failed: %d", err);
			goto cleanup;
		}
	}

	if (ela_http_build_post_request(&request,
					&request_len,
					parsed->path,
					parsed->host,
					content_type,
					len,
					auth_key,
					data,
					len) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to build HTTPS request");
		goto cleanup;
	}

	if (verbose) {
		fprintf(stderr, "HTTPS POST request uri=%s bytes=%zu content-type=%s insecure=%s (wolfssl)\n",
			uri, len, content_type, insecure ? "true" : "false");
	}

	ela_set_sigill_stage("https:wolfssl_post_write_request");
	if ((rc = wolfSSL_write(ssl, request, (int)request_len)) <= 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "wolfSSL_write failed: %d", wolfSSL_get_error(ssl, rc));
		goto cleanup;
	}

	ela_set_sigill_stage("https:wolfssl_post_read_headers");
	if (wolfssl_read_headers(ssl, &headers) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to read HTTPS response headers");
		goto cleanup;
	}

	status = ela_http_parse_status_code_from_headers(headers);
	if (status_out)
		*status_out = status;
	if (status < 200 || status >= 300) {
		if (errbuf && errbuf_len)
			ela_http_format_status_error(status, errbuf, errbuf_len);
		goto cleanup;
	}

	if (verbose)
		fprintf(stderr, "HTTPS POST success uri=%s status=%d\n", uri, status);

	free(headers);
	free(request);
	wolfSSL_shutdown(ssl);
	wolfSSL_free(ssl);
	wolfSSL_CTX_free(ctx);
	if (sock >= 0)
		close(sock);
	return 0;

cleanup:
	free(headers);
	free(request);
	if (ssl) {
		wolfSSL_shutdown(ssl);
		wolfSSL_free(ssl);
	}
	if (ctx)
		wolfSSL_CTX_free(ctx);
	if (sock >= 0)
		close(sock);
	return -1;
}

int ela_http_wolfssl_get_to_file(const struct parsed_http_uri *parsed,
				 const char *uri,
				 const char *output_path,
				 bool insecure,
				 bool verbose,
				 char *errbuf,
				 size_t errbuf_len)
{
	WOLFSSL_CTX *ctx = NULL;
	WOLFSSL *ssl = NULL;
	int sock = -1;
	FILE *fp = NULL;
	char *headers = NULL, *request = NULL;
	size_t request_len = 0;
	int status;
	int rc;

	ela_set_sigill_stage("https:wolfssl_init");
	if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "wolfSSL_Init failed");
		goto cleanup;
	}

	ela_set_sigill_stage("https:wolfssl_ctx_new");
	ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
	if (!ctx) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "wolfSSL_CTX_new failed");
		goto cleanup;
	}
	wolfSSL_CTX_set_verify(ctx, insecure ? WOLFSSL_VERIFY_NONE : WOLFSSL_VERIFY_PEER, NULL);
	if (!insecure) {
		ela_set_sigill_stage("https:wolfssl_load_ca");
		if (wolfSSL_CTX_load_verify_buffer(ctx,
				(const unsigned char *)ela_default_ca_bundle_pem,
				(long)ela_default_ca_bundle_pem_len,
				WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "wolfSSL_CTX_load_verify_buffer failed");
			goto cleanup;
		}
	}

	ela_set_sigill_stage("https:wolfssl_tcp_connect");
	sock = connect_tcp_host_port_any(parsed->host, parsed->port);
	if (sock < 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to connect to %s:%u", parsed->host, (unsigned int)parsed->port);
		goto cleanup;
	}

	ela_set_sigill_stage("https:wolfssl_new");
	ssl = wolfSSL_new(ctx);
	if (!ssl) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "wolfSSL_new failed");
		goto cleanup;
	}
	if (wolfSSL_set_fd(ssl, sock) != WOLFSSL_SUCCESS) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "wolfSSL_set_fd failed");
		goto cleanup;
	}
	if (!insecure)
		wolfSSL_check_domain_name(ssl, parsed->host);

	ela_set_sigill_stage("https:wolfssl_connect");
	while ((rc = wolfSSL_connect(ssl)) != WOLFSSL_SUCCESS) {
		int err = wolfSSL_get_error(ssl, rc);
		if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE &&
		    err != WANT_READ && err != WANT_WRITE) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "wolfSSL_connect failed: %d", err);
			goto cleanup;
		}
	}

	fp = fopen(output_path, "wb");
	if (!fp) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "cannot open output file %s: %s", output_path, strerror(errno));
		goto cleanup;
	}

	if (ela_http_build_identity_get_request(&request, &request_len, parsed->path, parsed->host) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to build HTTPS request");
		goto cleanup;
	}

	if (verbose)
		fprintf(stderr, "HTTPS GET request uri=%s -> file=%s insecure=%s (wolfssl)\n",
			uri, output_path, insecure ? "true" : "false");

	ela_set_sigill_stage("https:wolfssl_write_request");
	if ((rc = wolfSSL_write(ssl, request, (int)request_len)) <= 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "wolfSSL_write failed: %d", wolfSSL_get_error(ssl, rc));
		goto cleanup;
	}

	ela_set_sigill_stage("https:wolfssl_read_headers");
	if (wolfssl_read_headers(ssl, &headers) != 0)
		goto cleanup;
	status = ela_http_parse_status_code_from_headers(headers);
	if (status < 200 || status >= 300) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "HTTP status %d", status);
		goto cleanup;
	}

	ela_set_sigill_stage("https:wolfssl_read_body");
	if (wolfssl_copy_response_body_to_file(ssl, fp) != 0)
		goto cleanup;

	free(headers);
	free(request);
	wolfSSL_shutdown(ssl);
	wolfSSL_free(ssl);
	wolfSSL_CTX_free(ctx);
	if (sock >= 0)
		close(sock);
	if (fclose(fp) != 0) {
		unlink(output_path);
		return -1;
	}
	return 0;

cleanup:
	free(headers);
	free(request);
	if (fp)
		fclose(fp);
	unlink(output_path);
	if (ssl) {
		wolfSSL_shutdown(ssl);
		wolfSSL_free(ssl);
	}
	if (ctx)
		wolfSSL_CTX_free(ctx);
	if (sock >= 0)
		close(sock);
	return -1;
}

/* LCOV_EXCL_STOP */

#endif /* ELA_HAS_WOLFSSL */
