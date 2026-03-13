// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef UBOOT_IMAGE_CMD_H
#define UBOOT_IMAGE_CMD_H

#include <stdbool.h>
#include <stdint.h>

uint64_t uboot_image_parse_u64(const char *s);
int uboot_image_prepare(bool verbose,
			bool insecure,
			bool send_logs,
			const char *output_tcp_target,
			const char *output_http_target,
			const char *output_https_target);
int uboot_image_finish(int rc);

int uboot_image_pull_execute(const char *dev,
			     uint64_t offset,
			     const char *output_tcp_target,
			     const char *output_http_uri);
int uboot_image_find_address_execute(const char *dev, uint64_t offset);
int uboot_image_list_commands_execute(const char *dev, uint64_t offset);

int uboot_image_pull_main(int argc, char **argv);
int uboot_image_find_address_main(int argc, char **argv);
int uboot_image_list_commands_main(int argc, char **argv);

#endif