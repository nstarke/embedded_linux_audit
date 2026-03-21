// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "orom_pull_cmd_common.h"
#include "orom_pull_cmd_util.h"
#include "../util/orom_util.h"

#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

/*
 * All functions in this file require real hardware, network I/O, or OS-level
 * services (ptrace, SSH, sockets, TPM2, EFI) and cannot be exercised in the
 * unit-test environment.
 */
/* LCOV_EXCL_START */

static void usage(const char *prog, const char *fw_mode)
{
	fprintf(stderr,
		"Usage: %s <pull|list>\n"
		"  pull: read %s PCI option ROM payloads from sysfs and stream bytes to remote output\n"
		"  list: enumerate %s PCI option ROM candidates and emit formatted records\n",
		prog, fw_mode, fw_mode);
}

struct orom_ctx {
	const char *fw_mode;
	bool verbose;
	bool insecure;
	const char *output_tcp;
	const char *output_uri;
	enum orom_output_format fmt;
	bool csv_header_emitted;
};

static void mirror_log_to_remote(struct orom_ctx *ctx, const char *line)
{
	char errbuf[256];
	char *upload_uri = NULL;

	if (!ctx || !line || !*line)
		return;

	if (ctx->output_uri) {
		upload_uri = ela_http_build_upload_uri(ctx->output_uri, "log", NULL);
		if (upload_uri) {
			(void)ela_http_post(upload_uri,
			(const uint8_t *)line,
			strlen(line),
			"text/plain; charset=utf-8",
			ctx->insecure,
			ctx->verbose,
			errbuf,
			sizeof(errbuf));
			free(upload_uri);
		}
	}

	if (ctx->output_tcp) {
		int sock = ela_connect_tcp_ipv4(ctx->output_tcp);
		if (sock >= 0) {
			(void)ela_send_all(sock, (const uint8_t *)line, strlen(line));
			close(sock);
		}
	}
}

static void log_line(struct orom_ctx *ctx, bool verbose_only, const char *fmt, ...)
{
	char line[1024];
	va_list ap;

	if (verbose_only && (!ctx || !ctx->verbose))
		return;

	va_start(ap, fmt);
	vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);

	fputs(line, stderr);
	mirror_log_to_remote(ctx, line);
}

static int read_rom_bytes(const char *rom_path, uint8_t **out, size_t *out_len)
{
	uint8_t *buf = NULL;
	size_t cap = 0;
	size_t len = 0;
	int fd;

	*out = NULL;
	*out_len = 0;

	fd = open(rom_path, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return -1;

	if (write(fd, "1", 1) < 0) {
		close(fd);
		return -1;
	}
	(void)lseek(fd, 0, SEEK_SET);

	for (;;) {
		uint8_t tmp[4096];
		ssize_t n = read(fd, tmp, sizeof(tmp));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			free(buf);
			(void)lseek(fd, 0, SEEK_SET);
			if (write(fd, "0", 1) < 0) {
				/* best effort disable */
			}
			close(fd);
			return -1;
		}
		if (n == 0)
			break;
		if (len + (size_t)n > cap) {
			size_t next = cap ? cap * 2U : 8192U;
			uint8_t *grown;
			while (next < len + (size_t)n)
				next *= 2U;
			grown = realloc(buf, next);
			if (!grown) {
				free(buf);
				(void)lseek(fd, 0, SEEK_SET);
				if (write(fd, "0", 1) < 0) {
					/* best effort disable */
				}
				close(fd);
				return -1;
			}
			buf = grown;
			cap = next;
		}
		memcpy(buf + len, tmp, (size_t)n);
		len += (size_t)n;
	}

	(void)lseek(fd, 0, SEEK_SET);
	if (write(fd, "0", 1) < 0) {
		/* best effort disable */
	}
	close(fd);

	*out = buf;
	*out_len = len;
	return 0;
}

static int send_rom_tcp(const char *output_tcp, const char *name, const uint8_t *data, size_t len)
{
	int sock;
	char hdr[512];
	int hlen;

	sock = ela_connect_tcp_ipv4(output_tcp);
	if (sock < 0)
		return -1;

	hlen = ela_orom_build_tcp_header(hdr, sizeof(hdr), name, len);
	if (hlen < 0) {
		close(sock);
		return -1;
	}

	if (ela_send_all(sock, (const uint8_t *)hdr, (size_t)hlen) < 0 ||
	    ela_send_all(sock, data, len) < 0) {
		close(sock);
		return -1;
	}

	close(sock);
	return 0;
}

static int send_rom_http(const char *output_uri,
			 bool insecure,
			 bool verbose,
			 const char *name,
			 const uint8_t *data,
			 size_t len)
{
	char errbuf[256];
	char *upload_uri;
	uint8_t *payload = NULL;
	size_t payload_len = 0;
	int rc;

	if (ela_orom_build_http_payload(name, data, len, &payload, &payload_len) < 0)
		return -1;

	upload_uri = ela_http_build_upload_uri(output_uri, "orom", name);
	if (!upload_uri) {
		free(payload);
		return -1;
	}

	rc = ela_http_post(upload_uri,
		payload,
		payload_len,
		"application/octet-stream",
		insecure,
		verbose,
		errbuf,
		sizeof(errbuf));
	free(upload_uri);
	free(payload);
	return rc;
}

static void emit_record(struct orom_ctx *ctx,
			const char *record,
			const char *rom_path,
			size_t size,
			const char *type,
			const char *value)
{
	struct output_buffer line = {0};

	if (!ctx)
		return;

	if (ctx->fmt == OROM_FMT_CSV && !ctx->csv_header_emitted) {
		fputs("record,mode,rom_path,size,type,value\n", stdout);
		fflush(stdout);
		ctx->csv_header_emitted = true;
	}

	if (ela_orom_format_record(&line, ctx->fmt, ctx->fw_mode ? ctx->fw_mode : "",
				   record, rom_path, size, type, value) != 0)
		goto out;
	fwrite(line.data, 1, line.len, stdout);
	fflush(stdout);
	mirror_log_to_remote(ctx, line.data);
out:
	free(line.data);
}

static int orom_execute_pull(struct orom_ctx *ctx)
{
	glob_t g;
	int pulled = 0;

	if ((!ctx->output_tcp || !*ctx->output_tcp) && (!ctx->output_uri || !*ctx->output_uri)) {
		log_line(ctx, false,
			"pull requires one of --output-tcp or --output-http\n");
		return 2;
	}

	if (glob("/sys/bus/pci/devices/*/rom", 0, NULL, &g) != 0) {
		log_line(ctx, false, "No PCI ROM sysfs nodes found\n");
		return 1;
	}

	for (size_t i = 0; i < g.gl_pathc; i++) {
		const char *rom_path = g.gl_pathv[i];
		uint8_t *rom = NULL;
		size_t rom_len = 0;

		log_line(ctx, true, "[orom %s pull] inspect %s\n", ctx->fw_mode, rom_path);

		if (read_rom_bytes(rom_path, &rom, &rom_len) < 0 || !rom || rom_len == 0) {
			free(rom);
			continue;
		}

		if (!ela_orom_rom_matches_mode(rom, rom_len, ctx->fw_mode)) {
			free(rom);
			continue;
		}

		log_line(ctx, true, "[orom %s pull] send %s bytes=%zu\n", ctx->fw_mode, rom_path, rom_len);

		if (ctx->output_tcp) {
			if (send_rom_tcp(ctx->output_tcp, rom_path, rom, rom_len) < 0) {
				free(rom);
				globfree(&g);
				log_line(ctx, false, "Failed to send ROM over TCP\n");
				return 1;
			}
		} else {
			if (send_rom_http(ctx->output_uri, ctx->insecure, ctx->verbose, rom_path, rom, rom_len) < 0) {
				free(rom);
				globfree(&g);
				log_line(ctx, false, "Failed to send ROM over HTTP(S)\n");
				return 1;
			}
		}

		emit_record(ctx, "orom_pull", rom_path, rom_len, "status", "sent");
		pulled++;
		free(rom);
	}

	globfree(&g);

	if (pulled == 0) {
		log_line(ctx, false, "No matching %s option ROM payloads found\n", ctx->fw_mode);
		return 1;
	}

	log_line(ctx, true, "[orom %s pull] sent %d ROM payload(s)\n", ctx->fw_mode, pulled);
	return 0;
}

static int orom_execute_list(struct orom_ctx *ctx)
{
	glob_t g;
	int listed = 0;

	if (glob("/sys/bus/pci/devices/*/rom", 0, NULL, &g) != 0) {
		log_line(ctx, false, "No PCI ROM sysfs nodes found\n");
		return 1;
	}

	for (size_t i = 0; i < g.gl_pathc; i++) {
		const char *rom_path = g.gl_pathv[i];
		uint8_t *rom = NULL;
		size_t rom_len = 0;

		log_line(ctx, true, "[orom %s list] inspect %s\n", ctx->fw_mode, rom_path);

		if (read_rom_bytes(rom_path, &rom, &rom_len) < 0 || !rom || rom_len == 0) {
			free(rom);
			continue;
		}

		if (!ela_orom_rom_matches_mode(rom, rom_len, ctx->fw_mode)) {
			free(rom);
			continue;
		}

		emit_record(ctx, "orom_list", rom_path, rom_len, "match", "true");
		listed++;
		free(rom);
	}

	globfree(&g);

	if (listed == 0) {
		log_line(ctx, false, "No matching %s option ROM payloads found\n", ctx->fw_mode);
		emit_record(ctx, "orom_list", "", 0, "match", "none");
		return 1;
	}

	return 0;
}

int orom_group_main(const char *fw_mode, int argc, char **argv)
{
	struct ela_orom_env env;
	struct ela_orom_parsed_args args;
	struct orom_ctx ctx;
	char errbuf[256];
	int rc;

	env.verbose      = getenv("ELA_VERBOSE");
	env.insecure     = getenv("ELA_OUTPUT_INSECURE");
	env.output_tcp   = getenv("ELA_OUTPUT_TCP");
	env.output_http  = getenv("ELA_OUTPUT_HTTP");
	env.output_https = getenv("ELA_OUTPUT_HTTPS");
	env.output_fmt   = getenv("ELA_OUTPUT_FORMAT");

	errbuf[0] = '\0';
	rc = ela_orom_parse_args(argc, argv, fw_mode, &env, &args, errbuf, sizeof(errbuf));
	if (rc == 1) {
		usage(argv[0], fw_mode);
		return 0;
	}
	if (rc == 2) {
		if (errbuf[0])
			fprintf(stderr, "%s\n", errbuf);
		usage(argv[0], fw_mode);
		return 2;
	}

	{
		const char *isa = ela_detect_isa();

		if (!ela_isa_supported_for_efi_bios(isa)) {
			fprintf(stderr,
				"Unsupported ISA for %s group: %s (supported: x86, x86_64, aarch64-be, aarch64-le)\n",
				fw_mode, isa ? isa : "unknown");
			return 1;
		}
	}

	memset(&ctx, 0, sizeof(ctx));
	ctx.fw_mode    = fw_mode;
	ctx.verbose    = args.verbose;
	ctx.insecure   = args.insecure;
	ctx.output_tcp = args.output_tcp;
	ctx.output_uri = args.output_uri;
	ctx.fmt        = args.fmt;

	if (!strcmp(args.action, "pull"))
		return orom_execute_pull(&ctx);

	return orom_execute_list(&ctx);
}

/* LCOV_EXCL_STOP */
