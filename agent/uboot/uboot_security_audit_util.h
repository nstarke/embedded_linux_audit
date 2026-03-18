// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_UBOOT_SECURITY_AUDIT_UTIL_H
#define ELA_UBOOT_SECURITY_AUDIT_UTIL_H

#include "uboot/audit/uboot_audit_internal.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool ela_uboot_buffer_has_newline(const char *buf, size_t len);
bool ela_uboot_audit_rule_may_need_signature_artifacts(const char *rule_filter);
enum uboot_output_format ela_uboot_audit_detect_output_format(const char *fmt);
bool ela_uboot_fit_header_looks_valid(const uint8_t *p, uint64_t abs_off, uint64_t dev_size);

#endif
