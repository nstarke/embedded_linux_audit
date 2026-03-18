// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "uboot_env_record_util.h"

const char *ela_uboot_env_candidate_mode(bool bruteforce,
					 bool crc_ok_std,
					 bool crc_ok_redund)
{
	if (bruteforce)
		return "hint-only";
	if (crc_ok_redund && !crc_ok_std)
		return "redundant";
	return "standard";
}

size_t ela_uboot_env_data_offset(bool crc_ok_std, bool crc_ok_redund)
{
	(void)crc_ok_std;
	if (crc_ok_redund)
		return 5U;
	return 4U;
}
