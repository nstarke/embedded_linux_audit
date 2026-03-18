// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke
//
// Native WebSocket client — uses raw POSIX sockets for ws:// and
// wolfSSL (or OpenSSL) for wss://.  Does not use curl's WebSocket API,
// which generates instructions that cause SIGILL on some embedded PowerPC
// cores even after -mcpu=ppc.

#include "ws_client.h"
#include "api_key.h"
#include "ws_url_util.h"
#include "tcp_util.h"
#include "../embedded_linux_audit_cmd.h"
#include "../shell/interactive.h"

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
#define ws_ssl_set_sni(s, h)    wolfSSL_check_domain_name((s), (h))
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
			if (!m[0] && !m[1] && !m[2] && !m[3] && !m[4] && !m[5])
				continue;

			snprintf(buf, buf_sz,
				 "%02x-%02x-%02x-%02x-%02x-%02x",
				 m[0], m[1], m[2], m[3], m[4], m[5]);
			freeifaddrs(ifap);
			return;
		}
		freeifaddrs(ifap);
	}
#endif
	snprintf(buf, buf_sz, "unknown");
}

/* -------------------------------------------------------------------------
 * URL helpers
 * ---------------------------------------------------------------------- */

int ela_is_ws_url(const char *url)
{
	if (!url)
		return 0;
	return strncmp(url, "ws://", 5) == 0 ||
	       strncmp(url, "wss://", 6) == 0;
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
		unsigned int seed = (unsigned int)time(NULL);
		size_t i;
		for (i = 0; i < sizeof(nonce); i++) {
			seed = seed * 1664525u + 1013904223u;
			nonce[i] = (uint8_t)(seed >> 16);
		}
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
		if (resp_len >= 4 &&
		    resp[resp_len-4] == '\r' && resp[resp_len-3] == '\n' &&
		    resp[resp_len-2] == '\r' && resp[resp_len-1] == '\n')
			break;
	}
	resp[resp_len] = '\0';

	/* Verify 101 status */
	if (strncmp(resp, "HTTP/1.1 101", 12) != 0) {
		long code = 0;
		const char *sp = strchr(resp, ' ');
		if (sp)
			code = strtol(sp + 1, NULL, 10);
		if (code == 401)
			fprintf(stderr,
				"ws: server returned 401 Unauthorized\n"
				"  Set a bearer token via --api-key, ELA_API_KEY, or /tmp/ela.key\n");
		else
			fprintf(stderr, "ws: server returned unexpected response: %.40s\n", resp);
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

#define WS_OPCODE_TEXT   0x01
#define WS_OPCODE_CLOSE  0x08
#define WS_OPCODE_PING   0x09
#define WS_OPCODE_PONG   0x0A

/* Send a single text frame (FIN=1, MASK=1 as required for client frames) */
static int ws_send_text(const struct ela_ws_conn *ws,
			const char *payload, size_t payload_len)
{
	uint8_t  header[10];
	uint8_t  mask[4];
	uint8_t *masked;
	size_t   hdr_len = 2;
	size_t   i;
	int      fd;

	/* Build masking key from /dev/urandom or fallback */
	fd = open("/dev/urandom", O_RDONLY);
	if (fd >= 0) {
		ssize_t n = read(fd, mask, 4);
		close(fd);
		if (n != 4) {
			mask[0] = 0xDE; mask[1] = 0xAD;
			mask[2] = 0xBE; mask[3] = 0xEF;
		}
	} else {
		mask[0] = 0xDE; mask[1] = 0xAD;
		mask[2] = 0xBE; mask[3] = 0xEF;
	}

	header[0] = 0x80 | WS_OPCODE_TEXT; /* FIN=1, opcode=text */

	if (payload_len < 126) {
		header[1] = 0x80 | (uint8_t)payload_len;
	} else if (payload_len < 65536) {
		header[1] = 0x80 | 126;
		header[2] = (uint8_t)(payload_len >> 8);
		header[3] = (uint8_t)(payload_len);
		hdr_len   = 4;
	} else {
		header[1] = 0x80 | 127;
		header[2] = 0; header[3] = 0; header[4] = 0; header[5] = 0;
		header[6] = (uint8_t)(payload_len >> 24);
		header[7] = (uint8_t)(payload_len >> 16);
		header[8] = (uint8_t)(payload_len >> 8);
		header[9] = (uint8_t)(payload_len);
		hdr_len   = 10;
	}

	if (ws_conn_write(ws, header, hdr_len) < 0)
		return -1;
	if (ws_conn_write(ws, mask, 4) < 0)
		return -1;

	masked = malloc(payload_len);
	if (!masked)
		return -1;
	for (i = 0; i < payload_len; i++)
		masked[i] = (uint8_t)payload[i] ^ mask[i & 3];

	if (ws_conn_write(ws, masked, payload_len) < 0) {
		free(masked);
		return -1;
	}
	free(masked);
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
		size_t to_read = buf_sz - 1;
		size_t to_skip = (size_t)(payload_len - to_read);
		char   discard[64];

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

static void send_heartbeat_ack(const struct ela_ws_conn *ws)
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

	snprintf(ack, sizeof(ack),
		 "{\"_type\":\"heartbeat_ack\",\"date\":\"%s\"}", date_str);
	ws_send_text(ws, ack, strlen(ack));
}

/* -------------------------------------------------------------------------
 * Interactive session bridge
 * ---------------------------------------------------------------------- */

/* Send a masked WebSocket PING (zero-length payload) */
static void ws_send_ping(const struct ela_ws_conn *ws)
{
	uint8_t frame[6];

	frame[0] = 0x80 | WS_OPCODE_PING; /* FIN=1, opcode=PING */
	frame[1] = 0x80;                   /* MASK=1, payload_len=0 */
	frame[2] = 0; frame[3] = 0;       /* masking key (zeros) */
	frame[4] = 0; frame[5] = 0;
	ws_conn_write(ws, frame, 6);
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

		if (waitpid(child, &child_status, WNOHANG) > 0) {
			child_exited = 1;
			break;
		}

		/* Send a WebSocket PING every 25 s to keep NAT sessions alive.
		 * The server's ws library automatically replies with a PONG. */
		{
			time_t now = time(NULL);
			if (now - last_ping_t >= 25) {
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
			if (!ws_readable && ws->is_tls && ws->ssl) {
#ifdef ELA_HAS_WOLFSSL
				ws_readable = wolfSSL_pending(
						(ws_ssl_t *)ws->ssl) > 0;
#else
				ws_readable = SSL_pending(
						(ws_ssl_t *)ws->ssl) > 0;
#endif
			}
		if (ws_readable) {
			frame_len = ws_recv_frame(ws, &opcode,
						  frame_buf, sizeof(frame_buf));
			if (frame_len < 0)
				break;

			if (opcode == WS_OPCODE_CLOSE)
				break;

			if (opcode == WS_OPCODE_PING) {
				/* RFC 6455: client frames MUST be masked */
				uint8_t pong[6];
				pong[0] = 0x80 | WS_OPCODE_PONG;
				pong[1] = 0x80; /* MASK=1, payload_len=0 */
				pong[2] = 0; pong[3] = 0;
				pong[4] = 0; pong[5] = 0; /* zero mask */
				ws_conn_write(ws, pong, 6);
				continue;
			}

			if (opcode == WS_OPCODE_TEXT && frame_len > 0) {
				if (strstr(frame_buf, "\"_type\":\"heartbeat\"")) {
					send_heartbeat_ack(ws);
				} else {
					if (write(pipe_to_loop[1],
						  frame_buf,
						  (size_t)frame_len) < 0)
						break;
				}
			}
		}
		} /* end ws_readable compound block */

		/* interactive_loop output → WebSocket */
		if (FD_ISSET(pipe_from_loop[0], &rfds)) {
			ssize_t n = read(pipe_from_loop[0],
					 read_buf, sizeof(read_buf));
			if (n <= 0)
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
	return child_exited ? ELA_WS_EXIT_CLEAN : 0;
}
