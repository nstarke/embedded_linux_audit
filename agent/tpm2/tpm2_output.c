// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "tpm2_output.h"

#if defined(ELA_HAS_TPM2)

#include "../embedded_linux_audit_cmd.h"

#include <json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int tpm2_output_init(struct tpm2_output_ctx *ctx)
{
	const char *output_format = getenv("ELA_OUTPUT_FORMAT");
	const char *output_tcp    = getenv("ELA_OUTPUT_TCP");
	const char *output_http   = getenv("ELA_OUTPUT_HTTP");
	const char *output_https  = getenv("ELA_OUTPUT_HTTPS");
	const char *parsed_output_http  = NULL;
	const char *parsed_output_https = NULL;
	char errbuf[256];

	memset(ctx, 0, sizeof(*ctx));
	ctx->output_sock = -1;

	ctx->format = (output_format && *output_format) ? output_format : "txt";

	if (strcmp(ctx->format, "txt") &&
	    strcmp(ctx->format, "csv") &&
	    strcmp(ctx->format, "json")) {
		fprintf(stderr, "tpm2: invalid output format: %s\n", ctx->format);
		return 2;
	}

	ctx->insecure = getenv("ELA_OUTPUT_INSECURE") &&
	                !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");

	if (output_http && *output_http &&
	    ela_parse_http_output_uri(output_http,
	                              &parsed_output_http,
	                              &parsed_output_https,
	                              errbuf, sizeof(errbuf)) < 0) {
		fprintf(stderr, "%s\n", errbuf);
		return 2;
	}

	if (output_http && output_https) {
		fprintf(stderr, "tpm2: use only one of --output-http or --output-https\n");
		return 2;
	}

	if (parsed_output_http)
		ctx->output_uri = parsed_output_http;
	if (parsed_output_https)
		ctx->output_uri = parsed_output_https;
	if (output_https)
		ctx->output_uri = output_https;

	if (output_tcp && *output_tcp) {
		ctx->output_sock = ela_connect_tcp_ipv4(output_tcp);
		if (ctx->output_sock < 0) {
			fprintf(stderr,
				"tpm2: invalid/failed output target"
				" (expected IPv4:port): %s\n", output_tcp);
			return 2;
		}
	}

	return 0;
}

int tpm2_output_kv(struct tpm2_output_ctx *ctx, const char *key, const char *value)
{
	if (!ctx || !key || !value)
		return -1;

	if (!strcmp(ctx->format, "txt")) {
		if (output_buffer_append(&ctx->buf, key)   != 0 ||
		    output_buffer_append(&ctx->buf, ": ")  != 0 ||
		    output_buffer_append(&ctx->buf, value) != 0 ||
		    output_buffer_append(&ctx->buf, "\n")  != 0)
			return -1;
		return 0;
	}

	if (!strcmp(ctx->format, "csv")) {
		if (csv_write_to_buf(&ctx->buf, key)      != 0 ||
		    output_buffer_append(&ctx->buf, ",")   != 0 ||
		    csv_write_to_buf(&ctx->buf, value)     != 0 ||
		    output_buffer_append(&ctx->buf, "\n")  != 0)
			return -1;
		return 0;
	}

	if (!strcmp(ctx->format, "json")) {
		json_object *obj = json_object_new_object();
		const char  *js;
		int          err;

		if (!obj)
			return -1;
		json_object_object_add(obj, "key",   json_object_new_string(key));
		json_object_object_add(obj, "value", json_object_new_string(value));
		js  = json_object_to_json_string_ext(obj,
		          JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
		err = output_buffer_append(&ctx->buf, js);
		if (err == 0)
			err = output_buffer_append(&ctx->buf, "\n");
		json_object_put(obj);
		return err;
	}

	return -1;
}

int tpm2_output_flush(struct tpm2_output_ctx *ctx, const char *upload_type)
{
	const char  *data = ctx->buf.data ? ctx->buf.data : "";
	size_t       len  = ctx->buf.len;
	char         errbuf[256];
	int          ret = 0;

	if (len && fwrite(data, 1, len, stdout) != len) {
		fprintf(stderr, "tpm2: failed to write output\n");
		ret = 1;
	}

	if (ctx->output_sock >= 0 && len &&
	    ela_send_all(ctx->output_sock, (const uint8_t *)data, len) < 0) {
		fprintf(stderr, "tpm2: failed sending output to TCP target\n");
		ret = 1;
	}

	if (ctx->output_uri && upload_type) {
		char       *upload_uri = ela_http_build_upload_uri(ctx->output_uri, upload_type, NULL);
		const char *content_type;

		if (!upload_uri) {
			fprintf(stderr, "tpm2: unable to build upload URI\n");
			return 1;
		}

		content_type = !strcmp(ctx->format, "csv")  ? "text/csv; charset=utf-8" :
		               !strcmp(ctx->format, "json") ? "application/json; charset=utf-8" :
		                                              "text/plain; charset=utf-8";

		if (ela_http_post(upload_uri,
		                  (const uint8_t *)data, len,
		                  content_type,
		                  ctx->insecure,
		                  false,
		                  errbuf, sizeof(errbuf)) < 0) {
			fprintf(stderr, "tpm2: failed HTTP(S) POST to %s: %s\n",
				upload_uri, errbuf[0] ? errbuf : "unknown error");
			ret = 1;
		} else {
			fprintf(stderr, "tpm2: HTTP POST completed successfully: %s\n",
				upload_uri);
		}

		free(upload_uri);
	}

	return ret;
}

void tpm2_output_free(struct tpm2_output_ctx *ctx)
{
	if (!ctx)
		return;
	free(ctx->buf.data);
	ctx->buf.data = NULL;
	ctx->buf.len  = 0;
	ctx->buf.cap  = 0;
	if (ctx->output_sock >= 0) {
		close(ctx->output_sock);
		ctx->output_sock = -1;
	}
}

#endif /* ELA_HAS_TPM2 */
