// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "uboot_validate_env_writeability_util.h"

#include <errno.h>

int ela_uboot_validate_env_errno_classify(int saved_errno)
{
	if (saved_errno == EACCES || saved_errno == EPERM || saved_errno == EROFS)
		return 0;
	return -1;
}
