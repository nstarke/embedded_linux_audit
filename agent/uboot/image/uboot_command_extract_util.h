// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_UBOOT_COMMAND_EXTRACT_UTIL_H
#define ELA_UBOOT_COMMAND_EXTRACT_UTIL_H

#include "uboot_image_internal.h"

bool ela_uboot_is_printable_ascii(uint8_t c);
bool ela_uboot_token_looks_like_command_name(const char *s);
int ela_uboot_extracted_command_final_score(const struct extracted_command *cmd);
const char *ela_uboot_confidence_from_score(int score);
int ela_uboot_extract_commands_from_blob(const uint8_t *blob,
					 size_t blob_len,
					 struct extracted_command **out_cmds,
					 size_t *out_count);
void ela_uboot_free_extracted_commands(struct extracted_command *cmds,
				       size_t count);

#endif
