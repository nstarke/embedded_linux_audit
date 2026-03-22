// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "http_client.h"
#include "api_key.h"
#include "http_client_body_util.h"
#include "http_client_parse_util.h"
#include "http_client_protocol_util.h"
#include "http_client_runtime_util.h"
#include "http_client_transfer_util.h"
#include "http_ws_policy_util.h"
#include "tcp_util.h"
#include "../util/http_uri_util.h"
#include "../util/http_protocol_util.h"
#include "../util/str_util.h"
#include "../util/isa_util.h"
#include "../embedded_linux_audit_cmd.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <sys/time.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <curl/curl.h>

#ifdef ELA_HAS_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#endif
#ifdef SHA256
#undef SHA256
#endif
#ifdef SHA224
#undef SHA224
#endif
#ifdef SHA384
#undef SHA384
#endif
#ifdef SHA512
#undef SHA512
#endif
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#ifdef __linux__
#include <linux/if_arp.h>
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/*
 * All functions in this file require real hardware, network I/O, or OS-level
 * services (ptrace, SSH, sockets, TPM2, EFI) and cannot be exercised in the
 * unit-test environment.
 */
/* LCOV_EXCL_START */

static int ssl_ctx_add_embedded_ca_store(X509_STORE *store, char *errbuf, size_t errbuf_len)
{
	BIO *bio;
	bool loaded_any = false;

	if (!store) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to access OpenSSL certificate store");
		return -1;
	}

	if (ela_default_ca_bundle_pem_len == 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "embedded CA bundle is empty");
		return -1;
	}

	bio = BIO_new_mem_buf((const void *)ela_default_ca_bundle_pem,
			     (int)ela_default_ca_bundle_pem_len);
	if (!bio) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to create OpenSSL BIO for embedded CA bundle");
		return -1;
	}

	for (;;) {
		X509 *cert = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
		if (!cert)
			break;
		loaded_any = true;
		if (X509_STORE_add_cert(store, cert) != 1) {
			unsigned long ssl_err = ERR_peek_last_error();
			if (ERR_GET_REASON(ssl_err) != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
				if (errbuf && errbuf_len)
					snprintf(errbuf, errbuf_len, "failed to add embedded CA certificate to OpenSSL store");
				X509_free(cert);
				BIO_free(bio);
				return -1;
			}
			ERR_clear_error();
		}
		X509_free(cert);
	}

	BIO_free(bio);
	if (!loaded_any) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "embedded CA bundle did not contain any readable certificates");
		ERR_clear_error();
		return -1;
	}

	ERR_clear_error();
	return 0;
}

static int read_http_status_and_headers(int sock, int *status_out)
{
	char headers[8192];
	size_t used = 0;
	size_t header_len = 0;

	if (!status_out)
		return -1;

	for (;;) {
		ssize_t n;

		if (used >= sizeof(headers) - 1)
			return -1;
		n = recv(sock, headers + used, sizeof(headers) - 1 - used, MSG_PEEK);
		if (n <= 0)
			return -1;
		used += (size_t)n;
		headers[used] = '\0';
		if (ela_http_parse_response_headers(headers, used, status_out, &header_len) == 0)
			break;
		if (used == sizeof(headers) - 1)
			return -1;
		if (recv(sock, headers, (size_t)n, 0) != n)
			return -1;
		used = 0;
	}

	while (header_len) {
		ssize_t n = recv(sock, headers, header_len, 0);
		if (n <= 0)
			return -1;
		header_len -= (size_t)n;
	}

	return 0;
}

static int simple_http_post(const char *uri,
			    const uint8_t *data,
			    size_t len,
			    const char *content_type,
			    const char *auth_key,
			    bool verbose,
			    char *errbuf,
			    size_t errbuf_len,
			    int *status_out)
{
	struct parsed_http_uri parsed;
	char *request = NULL;
	size_t request_len = 0;
	int sock;
	int status_code;

	if (status_out)
		*status_out = 0;

	if (parse_http_uri(uri, &parsed) != 0 || parsed.https) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "unsupported or invalid HTTP URI");
		return -1;
	}

	sock = connect_tcp_host_port(parsed.host, parsed.port);
	if (sock < 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to connect to %s:%u", parsed.host, (unsigned int)parsed.port);
		return -1;
	}

	if (ela_http_build_post_request(&request,
					&request_len,
					parsed.path,
					parsed.host,
					content_type,
					len,
					auth_key,
					data,
					len) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to build HTTP request");
		free(request);
		close(sock);
		return -1;
	}

	if (verbose) {
		fprintf(stderr, "HTTP POST request uri=%s bytes=%zu content-type=%s insecure=false (socket)\n",
			uri, len, content_type);
	}

	if (ela_send_all(sock, (const uint8_t *)request, request_len) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to send HTTP request");
		free(request);
		close(sock);
		return -1;
	}
	free(request);

	if (read_http_status_and_headers(sock, &status_code) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to read HTTP response");
		close(sock);
		return -1;
	}
	close(sock);

	if (status_out)
		*status_out = status_code;

	if (!ela_http_status_is_success(status_code)) {
		if (errbuf && errbuf_len)
			ela_http_format_status_error(status_code, errbuf, errbuf_len);
		if (verbose)
			fprintf(stderr, "HTTP POST response failure uri=%s status=%d\n", uri, status_code);
		return -1;
	}

	if (verbose)
		fprintf(stderr, "HTTP POST success uri=%s status=%d\n", uri, status_code);

	return 0;
}

#ifdef ELA_HAS_WOLFSSL
static int wolfssl_read_headers(WOLFSSL *ssl, char **headers_out);
#endif

#ifdef ELA_HAS_WOLFSSL
static int simple_wolfssl_https_post(const struct parsed_http_uri *parsed,
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
#endif

static int simple_http_get_to_file(const char *uri,
				   const char *output_path,
				   bool verbose,
				   char *errbuf,
				   size_t errbuf_len)
{
	struct parsed_http_uri parsed;
	char *request = NULL;
	size_t request_len = 0;
	FILE *fp = NULL;
	int sock = -1;
	int status_code;
	char buf[4096];

	if (parse_http_uri(uri, &parsed) != 0 || parsed.https) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "unsupported or invalid HTTP URI");
		return -1;
	}

	sock = connect_tcp_host_port(parsed.host, parsed.port);
	if (sock < 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to connect to %s:%u", parsed.host, (unsigned int)parsed.port);
		return -1;
	}

	fp = fopen(output_path, "wb");
	if (!fp) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "cannot open output file %s: %s", output_path, strerror(errno));
		close(sock);
		return -1;
	}

	if (ela_http_build_get_request(&request, &request_len, parsed.path, parsed.host) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to build HTTP request");
		goto fail;
	}

	if (verbose)
		fprintf(stderr, "HTTP GET request uri=%s -> file=%s insecure=false (socket)\n", uri, output_path);

	if (ela_send_all(sock, (const uint8_t *)request, request_len) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to send HTTP request");
		goto fail;
	}
	free(request);
	request = NULL;

	if (read_http_status_and_headers(sock, &status_code) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to read HTTP response");
		goto fail;
	}

	if (status_code < 200 || status_code >= 300) {
		if (errbuf && errbuf_len)
			ela_http_format_status_error(status_code, errbuf, errbuf_len);
		if (verbose)
			fprintf(stderr, "HTTP GET response failure uri=%s status=%d\n", uri, status_code);
		goto fail;
	}

	for (;;) {
		ssize_t n = recv(sock, buf, sizeof(buf), 0);
		if (n < 0) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "failed while reading HTTP response body");
			goto fail;
		}
		if (n == 0)
			break;
		if (fwrite(buf, 1, (size_t)n, fp) != (size_t)n) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "failed writing to output file %s", output_path);
			goto fail;
		}
	}

	if (fclose(fp) != 0) {
		fp = NULL;
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to finalize output file %s", output_path);
		goto fail;
	}
	fp = NULL;
	close(sock);

	if (verbose)
		fprintf(stderr, "HTTP GET success uri=%s status=%d\n", uri, status_code);

	return 0;

fail:
	if (request)
		free(request);
	if (fp)
		fclose(fp);
	if (sock >= 0)
		close(sock);
	unlink(output_path);
	return -1;
}

#ifdef ELA_HAS_WOLFSSL
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

static int simple_wolfssl_https_get_to_file(const struct parsed_http_uri *parsed,
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
	size_t request_len = 0, request_cap = 0;
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
#endif

static int ssl_readline(SSL *ssl, char *buf, size_t buf_sz)
{
	size_t len = 0;
	char ch;
	if (!buf || buf_sz < 2)
		return -1;
	while (len + 1 < buf_sz) {
		int n = SSL_read(ssl, &ch, 1);
		if (n <= 0)
			return -1;
		buf[len++] = ch;
		if (ch == '\n')
			break;
	}
	buf[len] = '\0';
	return (int)len;
}

static int ssl_copy_response_body_to_file(SSL *ssl, const char *headers, FILE *fp)
{
	char buf[4096];
	if (ela_http_body_is_chunked(headers)) {
		for (;;) {
			char line[128];
			unsigned long chunk_len;
			if (ssl_readline(ssl, line, sizeof(line)) < 0)
				return -1;
			if (ela_http_parse_chunk_size_line(line, &chunk_len) != 0)
				return -1;
			if (chunk_len == 0) {
				if (ssl_readline(ssl, line, sizeof(line)) < 0)
					return -1;
				break;
			}
			while (chunk_len) {
				int want = (int)ela_http_chunk_read_size(chunk_len, sizeof(buf));
				int n = SSL_read(ssl, buf, want);
				if (n <= 0)
					return -1;
				if (fwrite(buf, 1, (size_t)n, fp) != (size_t)n)
					return -1;
				chunk_len -= (unsigned long)n;
			}
			if (SSL_read(ssl, buf, 2) != 2)
				return -1;
		}
		return 0;
	}

	for (;;) {
		int n = SSL_read(ssl, buf, sizeof(buf));
		if (n < 0)
			return -1;
		if (n == 0)
			break;
		if (fwrite(buf, 1, (size_t)n, fp) != (size_t)n)
			return -1;
	}
	return 0;
}

static int ssl_read_headers(SSL *ssl, char **headers_out)
{
	char *headers = NULL;
	size_t len = 0;
	size_t cap = 0;
	char ch;

	while (1) {
		int n = SSL_read(ssl, &ch, 1);
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

static int ssl_write_all(SSL *ssl, const uint8_t *buf, size_t len)
{
	while (len) {
		int n = SSL_write(ssl, buf, (int)len);
		if (n <= 0)
			return -1;
		buf += (size_t)n;
		len -= (size_t)n;
	}
	return 0;
}

static int ssl_connect_with_embedded_ca(const struct parsed_http_uri *parsed,
					 bool insecure,
					 SSL_CTX **ctx_out,
					 SSL **ssl_out,
					 int *sock_out,
					 char *errbuf,
					 size_t errbuf_len)
{
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	X509_VERIFY_PARAM *vpm;
	int sock = -1;

	if (!parsed || !ctx_out || !ssl_out || !sock_out)
		return -1;

	ela_install_sigill_debug_handler();
	ela_set_sigill_stage("https:openssl_init");
	ela_force_conservative_crypto_caps();

	if (OPENSSL_init_ssl(0, NULL) != 1) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to initialize OpenSSL");
		return -1;
	}

	ela_set_sigill_stage("https:ssl_ctx_new");
	ctx = SSL_CTX_new(TLS_client_method());
	if (!ctx) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to create OpenSSL TLS context");
		goto fail;
	}

	SSL_CTX_set_verify(ctx, insecure ? SSL_VERIFY_NONE : SSL_VERIFY_PEER, NULL);
	ela_set_sigill_stage("https:set_tls12_only");
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
	/*
	 * Further narrow the handshake for PowerPC troubleshooting: avoid TLS 1.3
	 * key share and signature negotiation, and prefer older broadly-supported
	 * TLS 1.2 ciphers/curves so we can determine whether the SIGILL is in a
	 * newer handshake primitive such as X25519/ChaCha20 or related code.
	 */
	SSL_CTX_set_cipher_list(ctx,
		"ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:AES128-SHA");
	SSL_CTX_set1_groups_list(ctx, "P-256");
	if (!insecure) {
		ela_set_sigill_stage("https:load_ca_store");
		if (ssl_ctx_add_embedded_ca_store(SSL_CTX_get_cert_store(ctx), errbuf, errbuf_len) < 0)
			goto fail;
	}

	ela_set_sigill_stage("https:tcp_connect");
	sock = connect_tcp_host_port_any(parsed->host, parsed->port);
	if (sock < 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to connect to %s:%u", parsed->host, (unsigned int)parsed->port);
		goto fail;
	}

	ela_set_sigill_stage("https:ssl_new");
	ssl = SSL_new(ctx);
	if (!ssl) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to create OpenSSL SSL session");
		goto fail;
	}

	ela_set_sigill_stage("https:set_sni");
	if (SSL_set_tlsext_host_name(ssl, parsed->host) != 1) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to set TLS SNI hostname");
		goto fail;
	}

	vpm = SSL_get0_param(ssl);
	if (!insecure) {
		ela_set_sigill_stage("https:set_verify_host");
		X509_VERIFY_PARAM_set_hostflags(vpm, 0);
		if (X509_VERIFY_PARAM_set1_host(vpm, parsed->host, 0) != 1) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "failed to set TLS certificate hostname verification");
			goto fail;
		}
	}

	SSL_set_fd(ssl, sock);
	ela_set_sigill_stage("https:ssl_connect");
	if (SSL_connect(ssl) != 1) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "TLS handshake failed");
		goto fail;
	}

	if (!insecure) {
		ela_set_sigill_stage("https:verify_peer");
		if (SSL_get_verify_result(ssl) != X509_V_OK) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "TLS peer certificate verification failed");
			goto fail;
		}
	}

	*ctx_out = ctx;
	*ssl_out = ssl;
	*sock_out = sock;
	ela_set_sigill_stage("https:connected");
	return 0;

fail:
	if (ssl)
		SSL_free(ssl);
	if (sock >= 0)
		close(sock);
	if (ctx)
		SSL_CTX_free(ctx);
	return -1;
}

static int simple_https_post(const char *uri,
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
	struct parsed_http_uri parsed;
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	int sock = -1;
	char *headers = NULL;
	char *request = NULL;
	size_t request_len = 0;
	int status;

	if (status_out)
		*status_out = 0;

	if (parse_http_uri(uri, &parsed) != 0 || !parsed.https) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "unsupported or invalid HTTPS URI");
		return -1;
	}

#ifdef ELA_HAS_WOLFSSL
	if (ela_http_choose_https_backend(isa_is_powerpc_family(ela_detect_isa())) ==
	    ELA_HTTP_HTTPS_BACKEND_WOLFSSL) {
		ela_set_sigill_stage("https:wolfssl_post_fallback");
		return simple_wolfssl_https_post(&parsed, uri, data, len, content_type,
						 auth_key, insecure, verbose,
						 errbuf, errbuf_len, status_out);
	}
#endif

	ela_install_sigill_debug_handler();
	ela_set_sigill_stage("https:post:start");
	if (ssl_connect_with_embedded_ca(&parsed, insecure, &ctx, &ssl, &sock, errbuf, errbuf_len) < 0)
		return -1;

	if (ela_http_build_post_request(&request,
					&request_len,
					parsed.path,
					parsed.host,
					content_type,
					len,
					auth_key,
					data,
					len) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to build HTTPS request");
		goto fail;
	}

	if (verbose) {
		fprintf(stderr, "HTTPS POST request uri=%s bytes=%zu content-type=%s insecure=%s (openssl)\n",
			uri, len, content_type, insecure ? "true" : "false");
	}

	ela_set_sigill_stage("https:post:write_request");
	if (ssl_write_all(ssl, (const uint8_t *)request, request_len) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to send HTTPS request");
		goto fail;
	}

	ela_set_sigill_stage("https:post:read_headers");
	if (ssl_read_headers(ssl, &headers) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to read HTTPS response headers");
		goto fail;
	}

	status = ela_http_parse_status_code_from_headers(headers);
	if (status_out)
		*status_out = status;
	if (!ela_http_status_is_success(status)) {
		if (errbuf && errbuf_len)
			ela_http_format_status_error(status, errbuf, errbuf_len);
		goto fail;
	}

	if (verbose)
		fprintf(stderr, "HTTPS POST success uri=%s status=%d\n", uri, status);

	free(headers);
	free(request);
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(sock);
	SSL_CTX_free(ctx);
	return 0;

fail:
	free(headers);
	free(request);
	if (ssl) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
	}
	if (sock >= 0)
		close(sock);
	if (ctx)
		SSL_CTX_free(ctx);
	return -1;
}

static int simple_https_get_to_file(const char *uri,
				    const char *output_path,
				    bool insecure,
				    bool verbose,
				    char *errbuf,
				    size_t errbuf_len)
{
	struct parsed_http_uri parsed;
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	int sock = -1;
	FILE *fp = NULL;
	char *headers = NULL;
	char *request = NULL;
	size_t request_len = 0;
	int status;

	if (parse_http_uri(uri, &parsed) != 0 || !parsed.https) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "unsupported or invalid HTTPS URI");
		return -1;
	}

	#ifdef ELA_HAS_WOLFSSL
	if (ela_http_choose_https_backend(isa_is_powerpc_family(ela_detect_isa())) ==
	    ELA_HTTP_HTTPS_BACKEND_WOLFSSL) {
		ela_set_sigill_stage("https:wolfssl_fallback");
		return simple_wolfssl_https_get_to_file(&parsed, uri, output_path, insecure,
			verbose, errbuf, errbuf_len);
	}
	#endif

	ela_install_sigill_debug_handler();
	ela_set_sigill_stage("https:get:start");
	if (ssl_connect_with_embedded_ca(&parsed, insecure, &ctx, &ssl, &sock, errbuf, errbuf_len) < 0)
		return -1;

	ela_set_sigill_stage("https:get:fopen");
	fp = fopen(output_path, "wb");
	if (!fp) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "cannot open output file %s: %s", output_path, strerror(errno));
		goto fail;
	}

	ela_set_sigill_stage("https:get:build_request");
	if (ela_http_build_identity_get_request(&request, &request_len, parsed.path, parsed.host) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to build HTTPS request");
		goto fail;
	}

	if (verbose)
		fprintf(stderr, "HTTPS GET request uri=%s -> file=%s insecure=%s (openssl)\n",
			uri, output_path, insecure ? "true" : "false");

	ela_set_sigill_stage("https:get:write_request");
	if (ssl_write_all(ssl, (const uint8_t *)request, request_len) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to send HTTPS request");
		goto fail;
	}

	ela_set_sigill_stage("https:get:read_headers");
	if (ssl_read_headers(ssl, &headers) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to read HTTPS response headers");
		goto fail;
	}

	status = ela_http_parse_status_code_from_headers(headers);
	ela_set_sigill_stage("https:get:read_body");
	if (!ela_http_status_is_success(status)) {
		if (errbuf && errbuf_len)
			ela_http_format_status_error(status, errbuf, errbuf_len);
		goto fail;
	}

	if (ssl_copy_response_body_to_file(ssl, headers, fp) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed while reading HTTPS response body");
		goto fail;
	}

	ela_set_sigill_stage("https:get:done");
	free(headers);
	free(request);
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(sock);
	SSL_CTX_free(ctx);
	if (fclose(fp) != 0) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to finalize output file %s", output_path);
		unlink(output_path);
		return -1;
	}
	return 0;

fail:
	free(headers);
	free(request);
	if (fp)
		fclose(fp);
	if (ssl) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
	}
	if (sock >= 0)
		close(sock);
	if (ctx)
		SSL_CTX_free(ctx);
	unlink(output_path);
	return -1;
}

static size_t __attribute__((unused)) curl_write_to_fp(void *ptr, size_t size, size_t nmemb, void *userdata)
{
	FILE *fp = (FILE *)userdata;
	if (!fp)
		return 0;
	return fwrite(ptr, size, nmemb, fp);
}

struct curl_ssl_ctx_error_data {
	char *errbuf;
	size_t errbuf_len;
};

static CURLcode curl_ssl_ctx_load_embedded_ca(CURL *curl, void *sslctx, void *parm)
{
	struct curl_ssl_ctx_error_data *err = (struct curl_ssl_ctx_error_data *)parm;
	SSL_CTX *ctx = (SSL_CTX *)sslctx;
	X509_STORE *store;

	(void)curl;

	if (!ctx) {
		if (err && err->errbuf && err->errbuf_len)
			snprintf(err->errbuf, err->errbuf_len, "libcurl did not provide an SSL_CTX");
		return CURLE_SSL_CERTPROBLEM;
	}

	store = SSL_CTX_get_cert_store(ctx);
	if (ssl_ctx_add_embedded_ca_store(store,
				      err ? err->errbuf : NULL,
				      err ? err->errbuf_len : 0) < 0)
		return CURLE_SSL_CERTPROBLEM;

	return CURLE_OK;
}

static int __attribute__((unused)) resolve_uri_ipv4(const char *base_uri, struct in_addr *addr_out)
{
	char host[256];
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	int rc;

	if (!addr_out)
		return -1;
	if (ela_parse_http_uri_host(base_uri, host, sizeof(host)) < 0)
		return -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	rc = getaddrinfo(host, NULL, &hints, &res);
	if (rc != 0 || !res)
		return -1;

	*addr_out = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
	freeaddrinfo(res);
	return 0;
}

static int __attribute__((unused)) route_iface_for_ipv4(struct in_addr dest_addr, char *ifname_buf, size_t ifname_buf_len)
{
	FILE *fp;
	int rc;

	if (!ifname_buf || ifname_buf_len < IF_NAMESIZE)
		return -1;

	fp = fopen("/proc/net/route", "r");
	if (!fp)
		return -1;

	rc = ela_http_parse_route_table(fp, dest_addr.s_addr, ifname_buf, ifname_buf_len);
	fclose(fp);
	return rc;
}

static int __attribute__((unused)) mac_for_interface(const char *ifname, char *mac_buf, size_t mac_buf_len)
{
	int fd;
	struct ifreq ifr;
	unsigned char *hwaddr;

	if (!ifname || !*ifname || !mac_buf || mac_buf_len < 18)
		return -1;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		close(fd);
		return -1;
	}
	close(fd);

#ifdef __linux__
	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
		return -1;
#endif

	hwaddr = (unsigned char *)ifr.ifr_hwaddr.sa_data;
	snprintf(mac_buf, mac_buf_len,
		 "%02x:%02x:%02x:%02x:%02x:%02x",
		 hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
	return 0;
}

static int first_non_loopback_mac(char *mac_buf, size_t mac_buf_len)
{
	DIR *dir;
	struct dirent *de;
	char path[PATH_MAX];
	char addr[32];
	FILE *fp;

	if (!mac_buf || mac_buf_len < 18)
		return -1;

	dir = opendir("/sys/class/net");
	if (!dir)
		return -1;

	while ((de = readdir(dir)) != NULL) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..") || !strcmp(de->d_name, "lo"))
			continue;

		snprintf(path, sizeof(path), "/sys/class/net/%s/address", de->d_name);
		fp = fopen(path, "r");
		if (!fp)
			continue;

		if (!fgets(addr, sizeof(addr), fp)) {
			fclose(fp);
			continue;
		}
		fclose(fp);

		addr[strcspn(addr, "\r\n")] = '\0';
		if (ela_http_is_zero_mac_address_string(addr))
			continue;
		if (!ela_http_is_valid_mac_address_string(addr))
			continue;

		snprintf(mac_buf, mac_buf_len, "%s", addr);
		closedir(dir);
		return 0;
	}

	closedir(dir);
	return -1;
}

int ela_http_get_upload_mac(const char *base_uri, char *mac_buf, size_t mac_buf_len)
{
	struct in_addr dest_addr;
	char ifname[IF_NAMESIZE];
	char routed_mac[18];

	if (!mac_buf || mac_buf_len < 18)
		return -1;
	mac_buf[0] = '\0';

	/*
	 * Prefer the MAC address from the routed egress interface for the upload
	 * destination when we can resolve it. This handles systems with multiple
	 * interfaces, including VLAN subinterfaces such as eth1.70, more reliably
	 * than a simple first-entry scan of /sys/class/net.
	 */
	if (base_uri && *base_uri &&
	    resolve_uri_ipv4(base_uri, &dest_addr) == 0 &&
	    route_iface_for_ipv4(dest_addr, ifname, sizeof(ifname)) == 0 &&
	    mac_for_interface(ifname, routed_mac, sizeof(routed_mac)) == 0 &&
	    ela_http_is_valid_mac_address_string(routed_mac) &&
	    !ela_http_is_zero_mac_address_string(routed_mac)) {
		snprintf(mac_buf, mac_buf_len, "%s", routed_mac);
		return 0;
	}

	/*
	 * Prefer a simple sysfs lookup over route/interface resolution. This keeps
	 * the upload path away from heavier libc/network helper code on older
	 * compatibility targets where we've seen runtime CPU faults.
	 */
	if (first_non_loopback_mac(routed_mac, sizeof(routed_mac)) == 0)
		return ela_http_choose_upload_mac_address(NULL, routed_mac, mac_buf, mac_buf_len);

	return ela_http_choose_upload_mac_address(NULL, NULL, mac_buf, mac_buf_len);
}


char *ela_http_build_upload_uri(const char *base_uri, const char *upload_type, const char *file_path)
{
	const char *scheme_end;
	const char *authority;
	const char *authority_end;
	const char *query = "";
	char mac_addr[18];
	char *out;
	char *escaped_file = NULL;
	size_t prefix_len;
	size_t query_len;
	size_t mac_len;
	size_t type_len;

	if (!base_uri || !*base_uri || !upload_type || !*upload_type)
		return NULL;

	scheme_end = strstr(base_uri, "://");
	if (!scheme_end)
		return strdup(base_uri);

	authority = scheme_end + 3;
	authority_end = authority;
	while (*authority_end && *authority_end != '/' && *authority_end != '?' && *authority_end != '#')
		authority_end++;

	if (ela_http_get_upload_mac(base_uri, mac_addr, sizeof(mac_addr)) < 0)
		return NULL;

	if (file_path && *file_path) {
		escaped_file = url_percent_encode(file_path);
		if (!escaped_file)
			return NULL;
		query = "?filePath=";
	}

	prefix_len = (size_t)(authority_end - base_uri);
	mac_len = strlen(mac_addr);
	type_len = strlen(upload_type);
	query_len = strlen(query) + (escaped_file ? strlen(escaped_file) : 0);
	out = malloc(prefix_len + 1 + mac_len + strlen("/upload/") + type_len + query_len + 1);
	if (!out) {
		if (escaped_file)
			free(escaped_file);
		return NULL;
	}

	memcpy(out, base_uri, prefix_len);
	out[prefix_len] = '/';
	memcpy(out + prefix_len + 1, mac_addr, mac_len);
	memcpy(out + prefix_len + 1 + mac_len, "/upload/", strlen("/upload/"));
	memcpy(out + prefix_len + 1 + mac_len + strlen("/upload/"), upload_type, type_len);
	memcpy(out + prefix_len + 1 + mac_len + strlen("/upload/") + type_len, query, strlen(query));
	if (escaped_file)
		memcpy(out + prefix_len + 1 + mac_len + strlen("/upload/") + type_len + strlen(query), escaped_file, strlen(escaped_file));
	out[prefix_len + 1 + mac_len + strlen("/upload/") + type_len + query_len] = '\0';

	if (escaped_file)
		free(escaped_file);
	return out;
}

int ela_http_post_log_message(const char *base_uri, const char *message,
				bool insecure, bool verbose,
				char *errbuf, size_t errbuf_len)
{
	char *upload_uri;
	int rc;

	if (errbuf && errbuf_len)
		errbuf[0] = '\0';

	if (!base_uri || !*base_uri || !message || !*message) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "log upload requires base URI and message");
		return -1;
	}

	upload_uri = ela_http_build_upload_uri(base_uri, "log", NULL);
	if (!upload_uri) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to build log upload URI");
		return -1;
	}

	rc = ela_http_post(upload_uri,
		(const uint8_t *)message,
		strlen(message),
		"text/plain; charset=utf-8",
		insecure,
		verbose,
		errbuf,
		errbuf_len);
	free(upload_uri);
	return rc;
}

/* -------------------------------------------------------------------------
 * Minimal UDP DNS resolver — used as a fallback for statically linked
 * glibc builds where getaddrinfo() does not consult /etc/resolv.conf.
 * ---------------------------------------------------------------------- */

/* Read up to max_ns IPv4 nameserver strings from /etc/resolv.conf. */
static int ela_read_nameservers(char ns[][16], int max_ns)
{
	FILE *f;
	int count;

	f = fopen("/etc/resolv.conf", "r");
	if (!f)
		return 0;
	count = ela_http_parse_resolv_conf(f, ns, max_ns);
	fclose(f);
	return count;
}

/* Build a DNS A-record query packet.  Returns packet length or -1. */
static int ela_dns_build_query(const char *hostname, uint8_t *buf, int buf_len)
{
	return ela_http_build_dns_query_packet(hostname, buf, buf_len);
}

/*
 * Send a DNS A-record query to ns_ip:53 and return the first IPv4 result.
 * Returns 0 on success (ip_buf filled), -1 on failure.
 */
static int ela_dns_query_a(const char *ns_ip, const char *hostname,
			   char *ip_buf, size_t ip_buf_len)
{
	uint8_t pkt[512];
	uint8_t resp[512];
	struct sockaddr_in ns_addr;
	struct timeval tv;
	int sock;
	int pkt_len;
	ssize_t n;

	pkt_len = ela_dns_build_query(hostname, pkt, (int)sizeof(pkt));
	if (pkt_len < 0)
		return -1;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return -1;

	tv.tv_sec  = 2;
	tv.tv_usec = 0;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
		close(sock);
		return -1;
	}

	memset(&ns_addr, 0, sizeof(ns_addr));
	ns_addr.sin_family = AF_INET;
	ns_addr.sin_port   = htons(53);
	if (inet_pton(AF_INET, ns_ip, &ns_addr.sin_addr) != 1) {
		close(sock);
		return -1;
	}

	if (sendto(sock, pkt, (size_t)pkt_len, 0,
		   (struct sockaddr *)&ns_addr, sizeof(ns_addr)) != pkt_len) {
		close(sock);
		return -1;
	}

	n = recv(sock, resp, sizeof(resp), 0);
	close(sock);
	if (n < 12)
		return -1;
	if (n > (ssize_t)sizeof(resp))
		n = (ssize_t)sizeof(resp); /* cap tainted recv length */
	return ela_http_parse_dns_a_response(resp, (int)n, ip_buf, ip_buf_len);
}

/*
 * Try to resolve hostname → dotted-decimal IPv4 by querying nameservers
 * from /etc/resolv.conf directly over UDP.  Works in statically linked
 * glibc builds where getaddrinfo() does not consult DNS.
 */
static int ela_udp_resolve(const char *hostname, char *ip_buf, size_t ip_buf_len)
{
	char ns[3][16];
	int ns_count;
	int i;

	ela_ensure_dns_configured();
	ns_count = ela_read_nameservers(ns, 3);

	for (i = 0; i < ns_count; i++) {
		if (ela_dns_query_a(ns[i], hostname, ip_buf, ip_buf_len) == 0)
			return 0;
	}
	return -1;
}

/*
 * Parse hostname and port from a normalised URL and return a curl_slist
 * entry "host:port:ip" for CURLOPT_RESOLVE so curl uses the pre-resolved
 * IP (bypassing glibc NSS) while keeping the original hostname for TLS SNI
 * and the Host header.  Returns NULL when resolution is unnecessary (numeric
 * host) or fails.  Caller must free with curl_slist_free_all().
 */
static struct curl_slist *ela_curl_resolve_list(const char *url)
{
	char host[256], port_str[8], ip[16], entry[288];

	if (!url)
		return NULL;
	if (ela_http_parse_url_authority(url, host, sizeof(host), port_str, sizeof(port_str)) != 0)
		return NULL;

	if (!ela_http_should_try_udp_resolve_host(host))
		return NULL;

	if (ela_udp_resolve(host, ip, sizeof(ip)) != 0)
		return NULL;

	if (ela_http_build_resolve_entry(url, ip, entry, sizeof(entry)) != 0)
		return NULL;
	return curl_slist_append(NULL, entry);
}

/*
 * Single HTTPS POST attempt via curl.  Returns 0 on success, -1 on failure.
 * *status_out is set to the HTTP response code when a response is received.
 */
static int __attribute__((unused)) ela_http_post_https_once(const char *effective_uri,
							    const uint8_t *data, size_t len,
							    const char *content_type,
							    const char *auth_key,
							    bool insecure, bool verbose,
							    char *errbuf, size_t errbuf_len,
							    int *status_out)
{
	CURL *curl;
	CURLcode rc;
	long http_code = 0;
	struct curl_slist *headers = NULL;
	struct curl_slist *resolve_list = NULL;
	char header_line[256 + ELA_API_KEY_MAX_LEN];
	static bool curl_global_ready;
	struct curl_ssl_ctx_error_data ssl_ctx_err = { errbuf, errbuf_len };

	if (status_out)
		*status_out = 0;

	ela_ensure_dns_configured();
	ela_force_conservative_crypto_caps();

	if (!curl_global_ready) {
		if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "curl_global_init failed");
			return -1;
		}
		curl_global_ready = true;
	}

	curl = curl_easy_init();
	if (!curl) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "curl_easy_init failed");
		return -1;
	}

	if (verbose) {
		fprintf(stderr,
			"HTTP POST request uri=%s bytes=%zu content-type=%s insecure=%s\n",
			effective_uri, len, content_type, insecure ? "true" : "false");
	}

	snprintf(header_line, sizeof(header_line), "Content-Type: %s", content_type);
	headers = curl_slist_append(headers, header_line);
	if (!headers) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "failed to prepare HTTP headers");
		curl_easy_cleanup(curl);
		return -1;
	}

	if (auth_key && *auth_key) {
		snprintf(header_line, sizeof(header_line), "Authorization: Bearer %s", auth_key);
		headers = curl_slist_append(headers, header_line);
		if (!headers) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "failed to prepare auth header");
			curl_easy_cleanup(curl);
			return -1;
		}
	}

	curl_easy_setopt(curl, CURLOPT_URL, effective_uri);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (const char *)data);
	/* False-positive suppression: CURLOPT_POSTFIELDSIZE_LARGE only returns
	 * CURLE_BAD_FUNCTION_ARGUMENT when the value is negative; (curl_off_t)len
	 * is always >= 0 because len is size_t. */
	/* coverity[check_return] */
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)len);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

	if (insecure) {
		rc = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		if (rc == CURLE_OK)
			rc = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		if (rc != CURLE_OK) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len,
					 "failed to disable TLS verification: %s",
					 curl_easy_strerror(rc));
			curl_slist_free_all(headers);
			curl_easy_cleanup(curl);
			return -1;
		}
	} else {
		rc = curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, curl_ssl_ctx_load_embedded_ca);
		if (rc == CURLE_OK)
			/* coverity[bad_sizeof] */
			rc = curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, &ssl_ctx_err);
		if (rc != CURLE_OK) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "failed to configure HTTPS CA bundle: %s",
					 curl_easy_strerror(rc));
			curl_slist_free_all(headers);
			curl_easy_cleanup(curl);
			return -1;
		}
	}

	resolve_list = ela_curl_resolve_list(effective_uri);
	if (resolve_list) {
		rc = curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve_list);
		if (rc != CURLE_OK) {
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "failed to set resolve list: %s",
					 curl_easy_strerror(rc));
			curl_slist_free_all(resolve_list);
			curl_slist_free_all(headers);
			curl_easy_cleanup(curl);
			return -1;
		}
	}

	rc = curl_easy_perform(curl);
	if (rc != CURLE_OK) {
		if (verbose) {
			fprintf(stderr, "HTTP POST transport failure uri=%s error=%s\n",
				effective_uri, curl_easy_strerror(rc));
			if (rc == CURLE_COULDNT_RESOLVE_HOST)
				fprintf(stderr,
					"  hint: DNS resolution failed — check /etc/resolv.conf"
					" or use an IP address in ELA_API_URL\n");
		}
		if (errbuf && errbuf_len)
			ela_http_format_curl_transport_error(curl_easy_strerror(rc), errbuf, errbuf_len);
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);
		curl_slist_free_all(resolve_list);
		return -1;
	}

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	curl_slist_free_all(resolve_list);

	if (status_out)
		*status_out = (int)http_code;

	if (http_code < 200 || http_code >= 300) {
		if (verbose)
			fprintf(stderr, "HTTP POST response failure uri=%s status=%ld\n",
				effective_uri, http_code);
		if (errbuf && errbuf_len)
			ela_http_format_status_error(http_code, errbuf, errbuf_len);
		return -1;
	}

	if (verbose)
		fprintf(stderr, "HTTP POST success uri=%s status=%ld\n", effective_uri, http_code);

	return 0;
}

int ela_http_post(const char *uri, const uint8_t *data, size_t len,
		 const char *content_type, bool insecure, bool verbose,
		 char *errbuf, size_t errbuf_len)
{
	struct ela_http_transfer_plan plan;
	const char *key;
	int status = 0;
	int ret;

	if (errbuf && errbuf_len)
		errbuf[0] = '\0';

	if (ela_http_prepare_post_plan(uri, content_type, &plan, errbuf, errbuf_len) != 0)
		return -1;

	key = ela_api_key_get();
	do {
		if (plan.transport == ELA_HTTP_TRANSPORT_HTTPS) {
			ret = simple_https_post(plan.effective_uri, data, len,
						plan.content_type, key, insecure, verbose,
						errbuf, errbuf_len, &status);
		} else {
			/*
			 * For plain http://, use the lightweight socket-based POST
			 * to avoid curl / OpenSSL initialisation on architectures
			 * where curl_global_init is unreliable under QEMU.
			 */
			ret = simple_http_post(plan.effective_uri, data, len, plan.content_type,
					       key, verbose, errbuf, errbuf_len,
					       &status);
		}
		if (ret == 0) {
			ela_api_key_confirm();
			ela_http_transfer_plan_cleanup(&plan);
			return 0;
		}
		/* Retry with the next candidate key only on 401 */
		if (ela_http_should_retry_with_next_api_key(status))
			key = ela_api_key_next();
		else
			break;
	} while (key);

	if (ela_http_should_warn_unauthorized_status(status))
		fprintf(stderr,
			"warning: server returned 401 Unauthorized\n"
			"  Set a bearer token via --api-key, ELA_API_KEY, or /tmp/ela.key\n");

	ela_http_transfer_plan_cleanup(&plan);
	return -1;
}

int ela_http_get_to_file(const char *uri, const char *output_path,
			   bool insecure, bool verbose,
			   char *errbuf, size_t errbuf_len)
{
	struct ela_http_transfer_plan plan;

	if (errbuf && errbuf_len)
		errbuf[0] = '\0';

	if (ela_http_prepare_get_plan(uri, output_path, &plan, errbuf, errbuf_len) != 0)
		return -1;

	ela_install_sigill_debug_handler();
	ela_set_sigill_stage("download-file:entry");

	if (plan.transport == ELA_HTTP_TRANSPORT_HTTP) {
		int rc = simple_http_get_to_file(plan.effective_uri, output_path, verbose,
						 errbuf, errbuf_len);
		ela_http_transfer_plan_cleanup(&plan);
		return rc;
	}

	{
		int rc = simple_https_get_to_file(plan.effective_uri, output_path, insecure,
						  verbose, errbuf, errbuf_len);
		ela_http_transfer_plan_cleanup(&plan);
		return rc;
	}
}

/* LCOV_EXCL_STOP */
