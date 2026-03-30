// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke
//
// Native WebSocket client — uses raw POSIX sockets for ws:// and
// wolfSSL (or OpenSSL) for wss://.  Does not use curl's WebSocket API,
// which generates instructions that cause SIGILL on some embedded PowerPC
// cores even after -mcpu=ppc.

#include "ws_client.h"
#include "api_key.h"
#include "http_ws_policy_util.h"
#include "ws_connect_util.h"
#include "ws_client_runtime_util.h"
#include "ws_interactive_util.h"
#include "ws_recv_util.h"
#include "ws_frame_util.h"
#include "ws_session_util.h"
#include "ws_url_util.h"
#include "tcp_util.h"
#include "../embedded_linux_audit_cmd.h"
#include "../shell/interactive.h"

#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifdef __linux__
#include <ifaddrs.h>
#include <net/if.h>
#include <netpacket/packet.h>
#endif

/* -------------------------------------------------------------------------
 * TLS abstraction: wolfSSL (PowerPC) or OpenSSL (everything else)
 * ---------------------------------------------------------------------- */

#ifdef ELA_HAS_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

/*
 * All functions in this file require real hardware, network I/O, or OS-level
 * services (ptrace, SSH, sockets, TPM2, EFI) and cannot be exercised in the
 * unit-test environment.
 */
/* LCOV_EXCL_START */
typedef WOLFSSL      ws_ssl_t;
typedef WOLFSSL_CTX  ws_ssl_ctx_t;
#define ws_tls_init()           wolfSSL_Init()
#define ws_tls_cleanup()        wolfSSL_Cleanup()
#define ws_ctx_new()            wolfSSL_CTX_new(wolfTLSv1_2_client_method())
#define ws_ctx_free(c)          wolfSSL_CTX_free(c)
#define ws_ctx_set_verify_none(c) \
	wolfSSL_CTX_set_verify((c), WOLFSSL_VERIFY_NONE, NULL)
#define ws_ctx_load_ca(c, d, l) \
	wolfSSL_CTX_load_verify_buffer((c), (const unsigned char *)(d), \
				       (long)(l), WOLFSSL_FILETYPE_PEM)
#define ws_ssl_new(c)           wolfSSL_new(c)
#define ws_ssl_free(s)          wolfSSL_free(s)
#define ws_ssl_set_fd(s, fd)    wolfSSL_set_fd((s), (fd))
#ifdef HAVE_SNI
#define ws_ssl_set_sni(s, h) \
	(wolfSSL_UseSNI((s), WOLFSSL_SNI_HOST_NAME, (h), (word16)strlen(h)), \
	 wolfSSL_check_domain_name((s), (h)))
#else
#define ws_ssl_set_sni(s, h)    wolfSSL_check_domain_name((s), (h))
#endif
#define ws_ssl_connect(s)       wolfSSL_connect(s)
#define ws_ssl_read(s, b, n)    wolfSSL_read((s), (b), (int)(n))
#define ws_ssl_write(s, b, n)   wolfSSL_write((s), (b), (int)(n))
#define WS_TLS_SUCCESS          WOLFSSL_SUCCESS
#define WS_TLS_WANT_READ        WOLFSSL_ERROR_WANT_READ
#define WS_TLS_WANT_WRITE       WOLFSSL_ERROR_WANT_WRITE
#define ws_ssl_get_error(s, r)  wolfSSL_get_error((s), (r))
#else
/* Suppress SHA macro conflicts before including OpenSSL */
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
#include <openssl/ssl.h>
#include <openssl/err.h>
typedef SSL     ws_ssl_t;
typedef SSL_CTX ws_ssl_ctx_t;
#define ws_tls_init()           SSL_library_init()
#define ws_tls_cleanup()        ((void)0)
#define ws_ctx_new()            SSL_CTX_new(TLS_client_method())
#define ws_ctx_free(c)          SSL_CTX_free(c)
#define ws_ctx_set_verify_none(c) \
	SSL_CTX_set_verify((c), SSL_VERIFY_NONE, NULL)
#define ws_ctx_load_ca(c, d, l) ela_ws_openssl_load_ca((c), (d), (l))

/* Load PEM CA bundle into an OpenSSL SSL_CTX via X509_STORE */
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
static int ela_ws_openssl_load_ca(SSL_CTX *ctx,
				   const void *pem_data, size_t pem_len)
{
	BIO   *bio;
	X509  *cert;
	X509_STORE *store = SSL_CTX_get_cert_store(ctx);
	int    loaded = 0;

	bio = BIO_new_mem_buf(pem_data, (int)pem_len);
	if (!bio)
		return 0;
	for (;;) {
		cert = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
		if (!cert)
			break;
		X509_STORE_add_cert(store, cert);
		X509_free(cert);
		loaded++;
	}
	BIO_free(bio);
	ERR_clear_error();
	return loaded > 0 ? 1 : 0; /* 1 == WS_TLS_SUCCESS for OpenSSL */
}
#define ws_ssl_new(c)           SSL_new(c)
#define ws_ssl_free(s)          SSL_free(s)
#define ws_ssl_set_fd(s, fd)    SSL_set_fd((s), (fd))
#define ws_ssl_set_sni(s, h)    SSL_set_tlsext_host_name((s), (h))
#define ws_ssl_connect(s)       SSL_connect(s)
#define ws_ssl_read(s, b, n)    SSL_read((s), (b), (int)(n))
#define ws_ssl_write(s, b, n)   SSL_write((s), (b), (int)(n))
#define WS_TLS_SUCCESS          1
#define WS_TLS_WANT_READ        SSL_ERROR_WANT_READ
#define WS_TLS_WANT_WRITE       SSL_ERROR_WANT_WRITE
#define ws_ssl_get_error(s, r)  SSL_get_error((s), (r))
#endif /* ELA_HAS_WOLFSSL */

/* -------------------------------------------------------------------------
 * TLS I/O helpers
 * ---------------------------------------------------------------------- */

static ssize_t ws_tls_read_exact(ws_ssl_t *ssl, void *buf, size_t len)
{
	uint8_t *p = (uint8_t *)buf;
	size_t done = 0;

	while (done < len) {
		int n = ws_ssl_read(ssl, p + done, len - done);
		if (n <= 0)
			return -1;
		done += (size_t)n;
	}
	return (ssize_t)done;
}

static ssize_t ws_tls_write_all(ws_ssl_t *ssl, const void *buf, size_t len)
{
	const uint8_t *p = (const uint8_t *)buf;
	size_t done = 0;

	while (done < len) {
		int n = ws_ssl_write(ssl, p + done, len - done);
		if (n <= 0)
			return -1;
		done += (size_t)n;
	}
	return (ssize_t)done;
}

/* -------------------------------------------------------------------------
 * Plain-socket I/O helpers
 * ---------------------------------------------------------------------- */

static ssize_t ws_fd_read_exact(int fd, void *buf, size_t len)
{
	uint8_t *p = (uint8_t *)buf;
	size_t done = 0;

	while (done < len) {
		ssize_t n = read(fd, p + done, len - done);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1; /* EOF */
		done += (size_t)n;
	}
	return (ssize_t)done;
}

static ssize_t ws_fd_write_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = (const uint8_t *)buf;
	size_t done = 0;

	while (done < len) {
		ssize_t n = write(fd, p + done, len - done);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		done += (size_t)n;
	}
	return (ssize_t)done;
}

/* Dispatch to TLS or plain socket */
static ssize_t ws_conn_read(const struct ela_ws_conn *ws, void *buf, size_t len)
{
	if (ws->is_tls && ws->ssl)
		return ws_tls_read_exact((ws_ssl_t *)ws->ssl, buf, len);
	return ws_fd_read_exact(ws->sock, buf, len);
}

static ssize_t ws_conn_write(const struct ela_ws_conn *ws,
			     const void *buf, size_t len)
{
	if (ws->is_tls && ws->ssl)
		return ws_tls_write_all((ws_ssl_t *)ws->ssl, buf, len);
	return ws_fd_write_all(ws->sock, buf, len);
}

/* -------------------------------------------------------------------------
 * Base64 encoding (for Sec-WebSocket-Key)
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * Primary MAC address discovery (same as original ws_client.c)
 * ---------------------------------------------------------------------- */

static void get_primary_mac(char *buf, size_t buf_sz)
{
#ifdef __linux__
	struct ifaddrs *ifap, *ifa;
	unsigned char *m;

	if (getifaddrs(&ifap) == 0) {
		for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
			struct sockaddr_ll *sll;

			if (!ifa->ifa_addr ||
			    ifa->ifa_addr->sa_family != AF_PACKET)
				continue;
			if (ifa->ifa_flags & IFF_LOOPBACK)
				continue;

			sll = (struct sockaddr_ll *)ifa->ifa_addr;
			if (sll->sll_halen != 6)
				continue;

			m = sll->sll_addr;
			if (ela_ws_mac_is_zero(m))
				continue;

			ela_ws_format_mac_bytes(m, buf, buf_sz);
			freeifaddrs(ifap);
			return;
		}
		freeifaddrs(ifap);
	}
#endif
	snprintf(buf, buf_sz, "unknown");
}

/*
 * Parse ws[s]://host[:port][/path] → host, port, path.
 * Returns 0 on success, -1 if the URL is malformed.
 */
/* -------------------------------------------------------------------------
 * WebSocket handshake
 * ---------------------------------------------------------------------- */

/*
 * Generate a random 16-byte nonce, base64-encode it → the Sec-WebSocket-Key
 * value.  Uses /dev/urandom; falls back to time-seeded rand().
 */
static void ws_make_key(char *out, size_t out_sz)
{
	uint8_t nonce[16];
	int fd = open("/dev/urandom", O_RDONLY);

	if (fd >= 0) {
		ssize_t n = read(fd, nonce, sizeof(nonce));
		close(fd);
		if (n == (ssize_t)sizeof(nonce)) {
				ela_ws_base64_encode(nonce, sizeof(nonce), out, out_sz);
				return;
		}
	}
	/* fallback */
	{
		uint64_t seed = (uint64_t)time(NULL);
		ela_ws_fill_nonce_from_seed(seed, nonce);
		ela_ws_base64_encode(nonce, sizeof(nonce), out, out_sz);
	}
}

/*
 * Send the HTTP/1.1 WebSocket upgrade request and verify the server responds
 * with 101 Switching Protocols.  Returns 0 on success, -1 on failure.
 */
static int ws_do_handshake(struct ela_ws_conn *ws,
			   const char *host, uint16_t port,
			   const char *path, int is_tls)
{
	char key[32];
	char req[1024];
	int req_len;
	char resp[2048];
	char errbuf[256];
	size_t resp_len = 0;

	ws_make_key(key, sizeof(key));

	req_len = ela_ws_build_handshake_request(req, sizeof(req), host, port, path, is_tls,
						 ws->auth_token[0] ? ws->auth_token : NULL, key);

	if (req_len <= 0 || req_len >= (int)sizeof(req)) {
		fprintf(stderr, "ws: request URL too long\n");
		return -1;
	}

	if (ws_conn_write(ws, req, (size_t)req_len) < 0) {
		fprintf(stderr, "ws: failed to send upgrade request\n");
		return -1;
	}

	/*
	 * Read the response headers (\r\n\r\n terminator).
	 * Read one byte at a time to avoid consuming WebSocket frame data.
	 */
	while (resp_len < sizeof(resp) - 1) {
		if (ws_conn_read(ws, resp + resp_len, 1) < 0) {
			fprintf(stderr, "ws: failed to read server response\n");
			return -1;
		}
		resp_len++;
		if (ela_ws_response_headers_complete(resp, resp_len))
			break;
	}
	resp[resp_len] = '\0';

	if (ela_ws_format_handshake_error(resp, errbuf, sizeof(errbuf)) != 0) {
		fprintf(stderr, "%s\n", errbuf);
		return -1;
	}

	return 0;
}

/* -------------------------------------------------------------------------
 * Connection
 * ---------------------------------------------------------------------- */

int ela_ws_connect(const char *base_url, int insecure,
		   struct ela_ws_conn *ws_out)
{
	char mac[32];
	char full_url[512];
	char host[256];
	char path[512];
	uint16_t port;
	int is_tls;
	int sock = -1;
	const char *api_key;

	if (!base_url || !ws_out)
		return -1;

	memset(ws_out, 0, sizeof(*ws_out));
	ws_out->sock = -1;

	get_primary_mac(mac, sizeof(mac));

	if (ela_ws_build_terminal_url(base_url, mac, full_url, sizeof(full_url)) != 0) {
		fprintf(stderr, "ws: URL too long: %s\n", base_url);
		return -1;
	}

	if (ela_ws_parse_url(full_url, host, sizeof(host), &port, path, sizeof(path),
			     &is_tls) != 0) {
		fprintf(stderr, "ws: malformed URL: %s\n", full_url);
		return -1;
	}

	/* Store auth token */
	api_key = ela_api_key_get();
	if (api_key && *api_key)
		snprintf(ws_out->auth_token, sizeof(ws_out->auth_token),
			 "%s", api_key);

	/* TCP connect */
	sock = connect_tcp_host_port_any(host, port);
	if (sock < 0) {
		fprintf(stderr, "ws: connect to %s:%u failed\n",
			host, (unsigned int)port);
		return -1;
	}
	ws_out->sock   = sock;
	ws_out->is_tls = is_tls;

	/* TLS handshake for wss:// */
	if (is_tls) {
		ws_ssl_ctx_t *ctx = NULL;
		ws_ssl_t     *ssl = NULL;
		int           rc;

		ws_tls_init();
		ctx = ws_ctx_new();
		if (!ctx) {
			fprintf(stderr, "ws: TLS context creation failed\n");
			goto fail;
		}

		if (insecure) {
			ws_ctx_set_verify_none(ctx);
		} else if (ela_default_ca_bundle_pem_len > 0) {
			if (ws_ctx_load_ca(ctx, ela_default_ca_bundle_pem,
					   ela_default_ca_bundle_pem_len) !=
			    WS_TLS_SUCCESS) {
				fprintf(stderr, "ws: failed to load CA bundle\n");
				ws_ctx_free(ctx);
				goto fail;
			}
		}

		ssl = ws_ssl_new(ctx);
		if (!ssl) {
			fprintf(stderr, "ws: TLS session creation failed\n");
			ws_ctx_free(ctx);
			goto fail;
		}

		ws_ssl_set_fd(ssl, sock);
		if (!insecure)
			ws_ssl_set_sni(ssl, host);

		do {
			rc = ws_ssl_connect(ssl);
		} while (rc != WS_TLS_SUCCESS &&
			 (ws_ssl_get_error(ssl, rc) == WS_TLS_WANT_READ ||
			  ws_ssl_get_error(ssl, rc) == WS_TLS_WANT_WRITE));

		if (rc != WS_TLS_SUCCESS) {
			fprintf(stderr, "ws: TLS handshake failed\n");
			ws_ssl_free(ssl);
			ws_ctx_free(ctx);
			goto fail;
		}

		ws_out->ssl     = ssl;
		ws_out->ssl_ctx = ctx;
	}

	/* HTTP WebSocket upgrade */
	if (ws_do_handshake(ws_out, host, port, path, is_tls) != 0)
		goto fail_tls;

	return 0;

fail_tls:
	if (ws_out->ssl) {
		ws_ssl_free((ws_ssl_t *)ws_out->ssl);
		ws_out->ssl = NULL;
	}
	if (ws_out->ssl_ctx) {
		ws_ctx_free((ws_ssl_ctx_t *)ws_out->ssl_ctx);
		ws_out->ssl_ctx = NULL;
	}
fail:
	close(sock);
	ws_out->sock = -1;
	return -1;
}

int ela_ws_connect_url(const char *url, int insecure,
		       struct ela_ws_conn *ws_out)
{
	char     host[256];
	char     path[512];
	uint16_t port;
	int      is_tls;
	int      sock = -1;
	const char *api_key;

	if (!url || !ws_out)
		return -1;

	memset(ws_out, 0, sizeof(*ws_out));
	ws_out->sock = -1;

	if (ela_ws_parse_url(url, host, sizeof(host), &port, path,
			     sizeof(path), &is_tls) != 0) {
		fprintf(stderr, "ws: malformed URL: %s\n", url);
		return -1;
	}

	api_key = ela_api_key_get();
	if (api_key && *api_key)
		snprintf(ws_out->auth_token, sizeof(ws_out->auth_token),
			 "%s", api_key);

	sock = connect_tcp_host_port_any(host, port);
	if (sock < 0) {
		fprintf(stderr, "ws: connect to %s:%u failed\n",
			host, (unsigned int)port);
		return -1;
	}
	ws_out->sock   = sock;
	ws_out->is_tls = is_tls;

	if (is_tls) {
		ws_ssl_ctx_t *ctx = NULL;
		ws_ssl_t     *ssl = NULL;
		int           rc;

		ws_tls_init();
		ctx = ws_ctx_new();
		if (!ctx) {
			fprintf(stderr, "ws: TLS context creation failed\n");
			goto fail;
		}

		if (insecure) {
			ws_ctx_set_verify_none(ctx);
		} else if (ela_default_ca_bundle_pem_len > 0) {
			if (ws_ctx_load_ca(ctx, ela_default_ca_bundle_pem,
					   ela_default_ca_bundle_pem_len) !=
			    WS_TLS_SUCCESS) {
				fprintf(stderr, "ws: failed to load CA bundle\n");
				ws_ctx_free(ctx);
				goto fail;
			}
		}

		ssl = ws_ssl_new(ctx);
		if (!ssl) {
			fprintf(stderr, "ws: TLS session creation failed\n");
			ws_ctx_free(ctx);
			goto fail;
		}

		ws_ssl_set_fd(ssl, sock);
		if (!insecure)
			ws_ssl_set_sni(ssl, host);

		do {
			rc = ws_ssl_connect(ssl);
		} while (rc != WS_TLS_SUCCESS &&
			 (ws_ssl_get_error(ssl, rc) == WS_TLS_WANT_READ ||
			  ws_ssl_get_error(ssl, rc) == WS_TLS_WANT_WRITE));

		if (rc != WS_TLS_SUCCESS) {
			fprintf(stderr, "ws: TLS handshake failed\n");
			ws_ssl_free(ssl);
			ws_ctx_free(ctx);
			goto fail;
		}

		ws_out->ssl     = ssl;
		ws_out->ssl_ctx = ctx;
	}

	if (ws_do_handshake(ws_out, host, port, path, is_tls) != 0)
		goto fail_tls;

	return 0;

fail_tls:
	if (ws_out->ssl) {
		ws_ssl_free((ws_ssl_t *)ws_out->ssl);
		ws_out->ssl = NULL;
	}
	if (ws_out->ssl_ctx) {
		ws_ctx_free((ws_ssl_ctx_t *)ws_out->ssl_ctx);
		ws_out->ssl_ctx = NULL;
	}
fail:
	close(sock);
	ws_out->sock = -1;
	return -1;
}

void ela_ws_close_parent_fd(const struct ela_ws_conn *ws)
{
	if (!ws)
		return;
	/* Close only the socket fd — do not send a CLOSE frame so the child's
	 * session (which shares the fd via fork) is not disrupted. */
	if (ws->sock >= 0)
		close(ws->sock);
	/* TLS structures are heap-allocated; the child gets its own copies via
	 * the fork COW mapping.  We intentionally do not free them here. */
}

void ela_ws_close(struct ela_ws_conn *ws)
{
	if (!ws)
		return;
	if (ws->ssl) {
		ws_ssl_free((ws_ssl_t *)ws->ssl);
		ws->ssl = NULL;
	}
	if (ws->ssl_ctx) {
		ws_ctx_free((ws_ssl_ctx_t *)ws->ssl_ctx);
		ws->ssl_ctx = NULL;
	}
	if (ws->sock >= 0) {
		close(ws->sock);
		ws->sock = -1;
	}
}

/* -------------------------------------------------------------------------
 * WebSocket frame format
 *
 *  Byte 0: FIN(1) RSV(3) OPCODE(4)
 *  Byte 1: MASK(1) PAYLOAD_LEN(7)  [+ 2 or 8 extended length bytes]
 *  [4-byte masking key if MASK=1]
 *  [payload]
 * ---------------------------------------------------------------------- */

/* Send a single text frame (FIN=1, MASK=1 as required for client frames) */
static int ws_send_text(const struct ela_ws_conn *ws,
			const char *payload, size_t payload_len)
{
	uint8_t  mask[4];
	uint8_t *frame = NULL;
	size_t   frame_len = 0;
	int      fd;

	/* Build masking key from /dev/urandom or fallback */
	fd = open("/dev/urandom", O_RDONLY);
	if (fd >= 0) {
		ssize_t n = read(fd, mask, 4);
		close(fd);
		if (n != 4) {
			ela_ws_default_mask_key(mask);
		}
	} else {
		ela_ws_default_mask_key(mask);
	}

	if (ela_ws_build_masked_frame(ELA_WS_OPCODE_TEXT, mask, payload, payload_len, &frame, &frame_len) != 0)
		return -1;
	if (ws_conn_write(ws, frame, frame_len) < 0) {
		free(frame);
		return -1;
	}
	free(frame);
	return 0;
}

/* Receive one complete WebSocket frame.  Sets *opcode, fills buf up to
 * buf_sz-1 bytes, NUL-terminates.  Returns payload length or -1 on error. */
static ssize_t ws_recv_frame(const struct ela_ws_conn *ws,
			     uint8_t *opcode_out,
			     char *buf, size_t buf_sz)
{
	uint8_t  hdr[2];
	uint64_t payload_len;
	uint8_t  mask[4];
	int      masked;
	uint8_t  ext[8];
	size_t   i;
	uint8_t  opcode;

	if (ws_conn_read(ws, hdr, 2) < 0)
		return -1;

	opcode      = hdr[0] & 0x0F;
	masked      = (hdr[1] & 0x80) != 0;
	payload_len = (uint64_t)(hdr[1] & 0x7F);

	if (payload_len == 126) {
		if (ws_conn_read(ws, ext, 2) < 0)
			return -1;
		payload_len = ((uint64_t)ext[0] << 8) | ext[1];
	} else if (payload_len == 127) {
		if (ws_conn_read(ws, ext, 8) < 0)
			return -1;
		payload_len = 0;
		for (i = 0; i < 8; i++)
			payload_len = (payload_len << 8) | ext[i];
	}

	if (masked) {
		if (ws_conn_read(ws, mask, 4) < 0)
			return -1;
	}

	/* Read payload, truncating if larger than buffer */
	if (payload_len >= buf_sz) {
		/* Read what fits, discard the rest */
		size_t to_read = ela_ws_payload_copy_len(payload_len, buf_sz);
		size_t to_skip = ela_ws_payload_skip_len(payload_len, buf_sz);
		char   discard[64];

		/* Reject absurdly large frames to bound the drain loop */
		if (to_skip > 1024 * 1024)
			return -1;

		if (ws_conn_read(ws, buf, to_read) < 0)
			return -1;
		while (to_skip > 0) {
			size_t chunk = to_skip < sizeof(discard)
				       ? to_skip : sizeof(discard);
			if (ws_conn_read(ws, discard, chunk) < 0)
				return -1;
			to_skip -= chunk;
		}
		buf[to_read] = '\0';
		if (opcode_out)
			*opcode_out = opcode;
		return (ssize_t)to_read;
	}

	if (payload_len > 0 && ws_conn_read(ws, buf, (size_t)payload_len) < 0)
		return -1;

	buf[payload_len] = '\0';

	if (masked) {
		for (i = 0; i < payload_len; i++)
			buf[i] ^= mask[i & 3];
	}

	if (opcode_out)
		*opcode_out = opcode;
	return (ssize_t)payload_len;
}

/* -------------------------------------------------------------------------
 * Heartbeat response
 * ---------------------------------------------------------------------- */

static int send_heartbeat_ack(const struct ela_ws_conn *ws)
{
	char date_str[64];
	char ack[160];
	time_t t = time(NULL);
	struct tm *tm_info;

	tm_info = localtime(&t);
	if (tm_info)
		strftime(date_str, sizeof(date_str),
			 "%a %b %d %H:%M:%S %Z %Y", tm_info);
	else
		strncpy(date_str, "unknown", sizeof(date_str) - 1);

	date_str[sizeof(date_str) - 1] = '\0';
	if (ela_ws_build_heartbeat_ack(date_str, ack, sizeof(ack)) == 0)
		return ws_send_text(ws, ack, strlen(ack));
	return -1;
}

struct ws_loop_dispatch_ctx {
	const struct ela_ws_conn *ws;
	int repl_fd;
};

static int ws_dispatch_write_repl(void *ctx, const char *payload, size_t payload_len)
{
	struct ws_loop_dispatch_ctx *dispatch = (struct ws_loop_dispatch_ctx *)ctx;

	if (!dispatch || dispatch->repl_fd < 0 || !payload)
		return -1;
	return write(dispatch->repl_fd, payload, payload_len) < 0 ? -1 : 0;
}

static int ws_dispatch_send_pong(void *ctx)
{
	struct ws_loop_dispatch_ctx *dispatch = (struct ws_loop_dispatch_ctx *)ctx;
	uint8_t pong[6];
	size_t pong_len = 0;

	if (!dispatch || !dispatch->ws)
		return -1;
	if (ela_ws_build_zero_mask_control_frame(ELA_WS_OPCODE_PONG, pong, &pong_len) != 0)
		return -1;
	return ws_conn_write(dispatch->ws, pong, pong_len) < 0 ? -1 : 0;
}

static int ws_dispatch_send_heartbeat_ack(void *ctx)
{
	struct ws_loop_dispatch_ctx *dispatch = (struct ws_loop_dispatch_ctx *)ctx;

	if (!dispatch || !dispatch->ws)
		return -1;
	return send_heartbeat_ack(dispatch->ws);
}

/* -------------------------------------------------------------------------
 * Interactive session bridge
 * ---------------------------------------------------------------------- */

/* Send a masked WebSocket PING (zero-length payload) */
static void ws_send_ping(const struct ela_ws_conn *ws)
{
	uint8_t frame[6];
	size_t frame_len = 0;

	if (ela_ws_build_ping_frame(frame, &frame_len) == 0)
		(void)ws_conn_write(ws, frame, frame_len); /* best-effort; drop detected on next recv */
}

int ela_ws_run_interactive(struct ela_ws_conn *ws, const char *prog)
{
	int    pipe_to_loop[2];
	int    pipe_from_loop[2];
	pid_t  child;
	char   frame_buf[65536];
	char   read_buf[65536];
	time_t last_ping_t;
	char   mac[32];
	int    child_exited = 0;

	if (pipe(pipe_to_loop) != 0 || pipe(pipe_from_loop) != 0) {
		fprintf(stderr, "ws: pipe: %s\n", strerror(errno));
		return 1;
	}

	/* Let the child know its session MAC so it can show the prompt. */
	get_primary_mac(mac, sizeof(mac));
	setenv("ELA_SESSION_MAC", mac, 1);

	child = fork();
	if (child < 0) {
		fprintf(stderr, "ws: fork: %s\n", strerror(errno));
		return 1;
	}

	if (child == 0) {
		dup2(pipe_to_loop[0],   STDIN_FILENO);
		dup2(pipe_from_loop[1], STDOUT_FILENO);
		dup2(pipe_from_loop[1], STDERR_FILENO);
		close(pipe_to_loop[0]);
		close(pipe_to_loop[1]);
		close(pipe_from_loop[0]);
		close(pipe_from_loop[1]);
		setvbuf(stdout, NULL, _IONBF, 0);
		setvbuf(stderr, NULL, _IONBF, 0);
		exit(interactive_loop(prog));
	}

	close(pipe_to_loop[0]);
	close(pipe_from_loop[1]);

	last_ping_t = time(NULL);

	for (;;) {
		fd_set         rfds;
		struct timeval tv;
		int            maxfd;
		int            sel;
		int            child_status;
		uint8_t        opcode;
		ssize_t        frame_len;

		if (ela_ws_child_wait_exited(waitpid(child, &child_status, WNOHANG))) {
			child_exited = 1;
			break;
		}

		/* Send a WebSocket PING every 25 s to keep NAT sessions alive.
		 * The server's ws library automatically replies with a PONG. */
		{
			time_t now = time(NULL);
			if (ela_ws_should_send_keepalive(now, last_ping_t, 25)) {
				ws_send_ping(ws);
				last_ping_t = now;
			}
		}

		/* We use a plain fd for select; for TLS we still select on the
		 * underlying socket fd and then let wolfSSL/OpenSSL drain it. */
		FD_ZERO(&rfds);
		FD_SET(ws->sock, &rfds);
		FD_SET(pipe_from_loop[0], &rfds);
		maxfd = ws->sock > pipe_from_loop[0]
			? ws->sock : pipe_from_loop[0];

		tv.tv_sec  = 1;
		tv.tv_usec = 0;
		sel = select(maxfd + 1, &rfds, NULL, NULL, &tv);
		if (sel < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		/* WebSocket frame → interactive_loop.
		 * For TLS the library may have already buffered a complete record
		 * whose bytes select() won't see on the raw socket; check
		 * pending bytes too. */
		{
			int ws_readable = FD_ISSET(ws->sock, &rfds);
			int pending_bytes = 0;
			struct ws_loop_dispatch_ctx dispatch_ctx = {
				.ws = ws,
				.repl_fd = pipe_to_loop[1],
			};
			struct ela_ws_runtime_dispatch_ops dispatch_ops = {
				.write_repl_fn = ws_dispatch_write_repl,
				.send_pong_fn = ws_dispatch_send_pong,
				.send_heartbeat_ack_fn = ws_dispatch_send_heartbeat_ack,
			};
			if (!ws_readable && ws->is_tls && ws->ssl) {
#ifdef ELA_HAS_WOLFSSL
				pending_bytes = wolfSSL_pending((ws_ssl_t *)ws->ssl);
#else
				pending_bytes = SSL_pending((ws_ssl_t *)ws->ssl);
#endif
			}
		if (ela_ws_socket_readable(ws_readable, ws->is_tls != 0, pending_bytes)) {
			frame_len = ws_recv_frame(ws, &opcode,
						  frame_buf, sizeof(frame_buf));
			if (frame_len < 0)
				break;

			{
				int dispatch_rc = ela_ws_dispatch_incoming_frame(
					opcode,
					frame_buf,
					frame_len > 0 ? (size_t)frame_len : 0U,
					&dispatch_ops,
					&dispatch_ctx);
				if (dispatch_rc != 0)
					break;
			}
		}
		} /* end ws_readable compound block */

		/* interactive_loop output → WebSocket */
		if (FD_ISSET(pipe_from_loop[0], &rfds)) {
			ssize_t n = read(pipe_from_loop[0],
					 read_buf, sizeof(read_buf));
			if (ela_ws_child_output_should_break(n))
				break;
			ws_send_text(ws, read_buf, (size_t)n);
		}
	}

	close(pipe_to_loop[1]);
	close(pipe_from_loop[0]);
	waitpid(child, NULL, 0);

	if (ws->ssl) {
		ws_ssl_free((ws_ssl_t *)ws->ssl);
		ws->ssl = NULL;
	}
	if (ws->ssl_ctx) {
		ws_ctx_free((ws_ssl_ctx_t *)ws->ssl_ctx);
		ws->ssl_ctx = NULL;
	}
	if (ws->sock >= 0) {
		close(ws->sock);
		ws->sock = -1;
	}
	return ela_ws_interactive_exit_code(child_exited);
}

/* -------------------------------------------------------------------------
 * GDB RSP tunnel bridge
 * ---------------------------------------------------------------------- */

/* Send a single binary frame (FIN=1, MASK=1, opcode=0x02) */
static int ws_send_binary(const struct ela_ws_conn *ws,
			  const void *payload, size_t payload_len)
{
	uint8_t  mask[4];
	uint8_t *frame = NULL;
	size_t   frame_len = 0;
	int      fd;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd >= 0) {
		ssize_t n = read(fd, mask, 4);
		close(fd);
		if (n != 4)
			ela_ws_default_mask_key(mask);
	} else {
		ela_ws_default_mask_key(mask);
	}

	if (ela_ws_build_masked_frame(ELA_WS_OPCODE_BINARY, mask,
				      payload, payload_len,
				      &frame, &frame_len) != 0)
		return -1;
	if (ws_conn_write(ws, frame, frame_len) < 0) {
		free(frame);
		return -1;
	}
	free(frame);
	return 0;
}

/* Write a single log line to debug_fd with a [relay PID] prefix. */
static void gdb_relay_log(int debug_fd, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

static void gdb_relay_log(int debug_fd, const char *fmt, ...)
{
	char    buf[256];
	int     n, total;
	va_list ap;

	if (debug_fd < 0)
		return;

	n = snprintf(buf, sizeof(buf), "[ela-relay %d] ", (int)getpid());
	if (n < 0 || n >= (int)sizeof(buf))
		return;

	va_start(ap, fmt);
	total = n + vsnprintf(buf + n, sizeof(buf) - (size_t)n, fmt, ap);
	va_end(ap);

	if (total >= (int)sizeof(buf))
		total = (int)sizeof(buf) - 1;
	buf[total++] = '\n';
	(void)write(debug_fd, buf, (size_t)total);
}

int ela_ws_run_gdb_bridge(struct ela_ws_conn *ws, int rsp_fd, int debug_fd)
{
	char    ws_buf[16384];
	char    rsp_buf[16384];
	long    ws_frames = 0;
	long    rsp_reads = 0;

	if (!ws || rsp_fd < 0)
		return -1;

	gdb_relay_log(debug_fd, "relay loop started ws.sock=%d rsp_fd=%d",
		      ws->sock, rsp_fd);

	for (;;) {
		fd_set         rfds;
		struct timeval tv;
		int            maxfd, sel;
		int            ws_readable, pending_bytes = 0;
		uint8_t        opcode;
		ssize_t        frame_len;
		ssize_t        n;

		FD_ZERO(&rfds);
		FD_SET(ws->sock, &rfds);
		FD_SET(rsp_fd, &rfds);
		maxfd = ws->sock > rsp_fd ? ws->sock : rsp_fd;

		tv.tv_sec  = 5;
		tv.tv_usec = 0;
		sel = select(maxfd + 1, &rfds, NULL, NULL, &tv);
		if (sel < 0) {
			if (errno == EINTR)
				continue;
			gdb_relay_log(debug_fd,
				      "select error: %s — exiting relay",
				      strerror(errno));
			break;
		}

		ws_readable = FD_ISSET(ws->sock, &rfds);
		if (!ws_readable && ws->is_tls && ws->ssl) {
#ifdef ELA_HAS_WOLFSSL
			pending_bytes = wolfSSL_pending((ws_ssl_t *)ws->ssl);
#else
			pending_bytes = SSL_pending((ws_ssl_t *)ws->ssl);
#endif
		}

		if (ela_ws_socket_readable(ws_readable,
					   ws->is_tls != 0, pending_bytes)) {
			frame_len = ws_recv_frame(ws, &opcode,
						  ws_buf, sizeof(ws_buf) - 1);
			if (frame_len < 0) {
				gdb_relay_log(debug_fd,
					      "ws_recv_frame error after %ld frames"
					      " — exiting relay", ws_frames);
				break;
			}
			if (opcode == ELA_WS_OPCODE_CLOSE) {
				gdb_relay_log(debug_fd,
					      "received WS CLOSE frame after"
					      " %ld frames — exiting relay",
					      ws_frames);
				break;
			}
			if (opcode == ELA_WS_OPCODE_BINARY && frame_len > 0) {
				ws_frames++;
				gdb_relay_log(debug_fd,
					      "WS→rsp frame #%ld opcode=0x%02x"
					      " len=%zd",
					      ws_frames, opcode, frame_len);
				if (ws_fd_write_all(rsp_fd, ws_buf,
						    (size_t)frame_len) < 0) {
					gdb_relay_log(debug_fd,
						      "ws_fd_write_all error: %s"
						      " — exiting relay",
						      strerror(errno));
					break;
				}
			} else if (opcode == ELA_WS_OPCODE_PING) {
				uint8_t pong[6];
				size_t  pong_len = 0;
				gdb_relay_log(debug_fd,
					      "WS PING received — sending PONG");
				if (ela_ws_build_zero_mask_control_frame(
					    ELA_WS_OPCODE_PONG, pong, &pong_len) == 0)
					(void)ws_conn_write(ws, pong, pong_len);
			} else {
				gdb_relay_log(debug_fd,
					      "WS frame ignored: opcode=0x%02x"
					      " len=%zd", opcode, frame_len);
			}
		}

		if (FD_ISSET(rsp_fd, &rfds)) {
			n = read(rsp_fd, rsp_buf, sizeof(rsp_buf));
			if (n <= 0) {
				gdb_relay_log(debug_fd,
					      "rsp_fd read returned %zd"
					      " (EOF/error %s) after %ld reads"
					      " — exiting relay",
					      n, n < 0 ? strerror(errno) : "EOF",
					      rsp_reads);
				break;
			}
			rsp_reads++;
			gdb_relay_log(debug_fd,
				      "rsp→WS read #%ld len=%zd",
				      rsp_reads, n);
			if (ws_send_binary(ws, rsp_buf, (size_t)n) < 0) {
				gdb_relay_log(debug_fd,
					      "ws_send_binary error: %s"
					      " — exiting relay",
					      strerror(errno));
				break;
			}
		}
	}

	gdb_relay_log(debug_fd,
		      "relay loop exited: ws_frames=%ld rsp_reads=%ld",
		      ws_frames, rsp_reads);
	return 0;
}

/* LCOV_EXCL_STOP */
