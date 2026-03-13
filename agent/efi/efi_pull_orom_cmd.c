// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "orom/orom_pull_cmd_common.h"

int efi_orom_main(int argc, char **argv)
{
	return orom_group_main("efi", argc, argv);
}
