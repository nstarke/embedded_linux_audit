// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_UBOOT_VALIDATE_ENV_SECURITY_UTIL_H
#define ELA_UBOOT_VALIDATE_ENV_SECURITY_UTIL_H

#include <stddef.h>

int ela_uboot_validate_env_security_check_vars(const char *bootdelay,
					       const char *preboot,
					       const char *boot_targets,
					       const char *bootcmd,
					       const char *altbootcmd,
					       const char *bootfile,
					       const char *serverip,
					       const char *ipaddr,
					       const char *factory_reset,
					       const char *reset_to_defaults,
					       const char *resetenv,
					       const char *eraseenv,
					       int *bootdelay_i_out,
					       char *detail,
					       size_t detail_len);

#endif
