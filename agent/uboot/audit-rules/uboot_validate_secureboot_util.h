// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_UBOOT_VALIDATE_SECUREBOOT_UTIL_H
#define ELA_UBOOT_VALIDATE_SECUREBOOT_UTIL_H

#include <stddef.h>

int ela_uboot_secureboot_check_env_policy(const char *secureboot,
					  const char *verify,
					  const char *bootm_verify_sig,
					  const char *signature,
					  char *detail,
					  size_t detail_len);

#endif
