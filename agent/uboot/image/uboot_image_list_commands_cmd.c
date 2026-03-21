// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "uboot/image/uboot_command_extract_util.h"
#include "uboot/image/uboot_image_cmd.h"
#include "uboot/image/uboot_image_internal.h"
#include "uboot/image/uboot_image_list_commands_util.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s --dev <device> --offset <bytes> [--send-logs --output-tcp <IPv4:port>]\n",
		prog);
}

int uboot_image_list_commands_main(int argc, char **argv)
{
	const char *dev = NULL;
	const char *output_tcp = getenv("ELA_OUTPUT_TCP");
	const char *output_http = getenv("ELA_OUTPUT_HTTP");
	const char *output_https = getenv("ELA_OUTPUT_HTTPS");
	const char *parsed_output_http = NULL;
	const char *parsed_output_https = NULL;
	uint64_t offset = 0;
	bool have_offset = false;
	bool verbose = getenv("ELA_VERBOSE") && !strcmp(getenv("ELA_VERBOSE"), "1");
	bool insecure = getenv("ELA_OUTPUT_INSECURE") && !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");
	bool send_logs = false;
	int opt;
	int rc;

	optind = 1;

	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "dev", required_argument, NULL, 'd' },
		{ "offset", required_argument, NULL, 'o' },
		{ "output-tcp", required_argument, NULL, 't' },
		{ "output-http", required_argument, NULL, 'O' },
		{ "send-logs", no_argument, NULL, 'L' },
		{ 0, 0, 0, 0 }
	};

	while ((opt = getopt_long(argc, argv, "hd:o:t:O:L", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'd':
			dev = optarg;
			break;
		case 'o':
			offset = uboot_image_parse_u64(optarg);
			have_offset = true;
			break;
		case 't':
			output_tcp = optarg;
			break;
		case 'O':
			if (ela_parse_http_output_uri(optarg,
						  &parsed_output_http,
						  &parsed_output_https,
						  NULL,
						  0) < 0) {
				fprintf(stderr, "Invalid --output-http URI (expected http://host:port/... or https://host:port/...): %s\n", optarg);
				return 2;
			}
			output_http = parsed_output_http;
			output_https = parsed_output_https;
			break;
		case 'L':
			send_logs = true;
			break;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	if (!dev || !have_offset) {
		usage(argv[0]);
		return 2;
	}

	if (optind < argc) {
		usage(argv[0]);
		return 2;
	}

	if (!send_logs && output_tcp) {
		fprintf(stderr, "--output-tcp requires --send-logs for list-commands\n");
		return 2;
	}

	rc = uboot_image_prepare(verbose, insecure, send_logs, output_tcp, output_http, output_https);
	if (rc)
		return rc;

	rc = uboot_image_list_commands_execute(dev, offset);
	return uboot_image_finish(rc);
}

int list_image_commands(const char *dev, uint64_t offset)
{
	uint8_t hdr[UIMAGE_HDR_SIZE];
	uint64_t dev_size = uboot_guess_size_any(dev);
	uint8_t *image_blob = NULL;
	size_t image_len = 0;
	const uint8_t *payload = NULL;
	size_t payload_len = 0;
	struct extracted_command *cmds = NULL;
	size_t cmd_count = 0;
	int fd;
	int rc = 1;

	fd = open(dev, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		uboot_img_err_printf("Cannot open %s: %s\n", dev, strerror(errno));
		return 1;
	}

	if (pread(fd, hdr, sizeof(hdr), (off_t)offset) != (ssize_t)sizeof(hdr)) {
		uboot_img_err_printf("Unable to read image header from %s @ 0x%jx\n", dev, (uintmax_t)offset);
		goto out;
	}

	if (!memcmp(hdr, "\x27\x05\x19\x56", 4)) {
		uint32_t total_size;
		uint32_t data_size;

		if (!validate_uimage_header(hdr, offset, dev_size ? dev_size : UINT64_MAX)) {
			uboot_img_err_printf("uImage header validation failed at offset 0x%jx\n", (uintmax_t)offset);
			goto out;
		}

		data_size = ela_read_be32(hdr + 12);
		if (data_size == 0 || data_size > 64 * 1024 * 1024) {
			uboot_img_err_printf("uImage data_size out of range: %u\n", data_size);
			goto out;
		}
		total_size = UIMAGE_HDR_SIZE + data_size;
		image_len = (size_t)total_size;
		image_blob = malloc(image_len);
		if (!image_blob) {
			uboot_img_err_printf("Unable to allocate memory to inspect uImage\n");
			goto out;
		}

		if (pread(fd, image_blob, image_len, (off_t)offset) != (ssize_t)image_len) {
			uboot_img_err_printf("Unable to read full uImage for command extraction\n");
			goto out;
		}

		payload = image_blob + UIMAGE_HDR_SIZE;
		payload_len = data_size;
	} else if (!memcmp(hdr, "\xD0\x0D\xFE\xED", 4)) {
		uint32_t total_size;
		uint64_t uboot_off = 0;
		bool uboot_off_found = false;
		uint32_t unused_addr = 0;

		if (!validate_fit_header(hdr, offset, dev_size ? dev_size : UINT64_MAX)) {
			uboot_img_err_printf("FIT header validation failed at offset 0x%jx\n", (uintmax_t)offset);
			goto out;
		}

		total_size = ela_read_be32(hdr + 4);
		if (total_size == 0 || total_size > 64 * 1024 * 1024) {
			uboot_img_err_printf("FIT image total_size out of range: %u\n", total_size);
			goto out;
		}
		image_len = (size_t)total_size;
		image_blob = malloc(image_len + 1);
		if (!image_blob) {
			uboot_img_err_printf("Unable to allocate memory to inspect FIT image\n");
			goto out;
		}

		if (pread(fd, image_blob, image_len, (off_t)offset) != (ssize_t)image_len) {
			uboot_img_err_printf("Unable to read full FIT image for command extraction\n");
			goto out;
		}
		image_blob[image_len] = '\0';

		(void)fit_find_load_address(image_blob,
					    image_len,
					    &unused_addr,
					    &uboot_off,
					    &uboot_off_found);

		ela_uboot_image_list_select_payload(image_blob, image_len,
						    uboot_off_found, uboot_off,
						    &payload, &payload_len);
	} else {
		uboot_img_err_printf("Unknown image format at offset 0x%jx\n", (uintmax_t)offset);
		goto out;
	}

	if (ela_uboot_extract_commands_from_blob(payload, payload_len, &cmds, &cmd_count) < 0) {
		uboot_img_err_printf("Failed command extraction from image payload\n");
		goto out;
	}

	if (!cmd_count) {
		if (g_output_format == FW_OUTPUT_TXT)
			uboot_img_out_printf("No likely U-Boot commands extracted from image bytes.\n");
		else
			emit_image_record("image_command", dev, offset, "low", "none");
		rc = 0;
		goto out;
	}

	bool emitted_any = false;
	for (size_t i = 0; i < cmd_count; i++) {
		int score = ela_uboot_extracted_command_final_score(&cmds[i]);
		const char *confidence = ela_uboot_confidence_from_score(score);

		if (score < 5)
			continue;
		emitted_any = true;

		if (g_output_format == FW_OUTPUT_TXT) {
			uboot_img_out_printf("image command: %s offset=0x%jx command=%s confidence=%s score=%d hits=%u\n",
				dev, (uintmax_t)offset, cmds[i].name, confidence, score, cmds[i].hits);
		} else {
			emit_image_record("image_command", dev, offset, confidence, cmds[i].name);
		}
	}

	if (!emitted_any) {
		if (g_output_format == FW_OUTPUT_TXT)
			uboot_img_out_printf("No likely U-Boot commands extracted from image bytes.\n");
		else
			emit_image_record("image_command", dev, offset, "low", "none");
	}

	rc = 0;

out:
	ela_uboot_free_extracted_commands(cmds, cmd_count);
	free(image_blob);
	close(fd);
	return rc;
}

int uboot_image_list_commands_execute(const char *dev, uint64_t offset)
{
	return list_image_commands(dev, offset);
}
