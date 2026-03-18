// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_UBOOT_IMAGE_FORMAT_UTIL_H
#define ELA_UBOOT_IMAGE_FORMAT_UTIL_H

#include "uboot/image/uboot_image_internal.h"

#include <stdbool.h>
#include <stddef.h>

enum uboot_output_format ela_uboot_image_detect_output_format(const char *fmt);
const char *ela_uboot_image_http_content_type(enum uboot_output_format fmt);
size_t ela_uboot_image_align_up_4(size_t v);
bool ela_uboot_image_str_contains_token_ci(const char *haystack, const char *needle);

#endif
