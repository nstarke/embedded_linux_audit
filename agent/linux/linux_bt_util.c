// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "linux/linux_bt_util.h"

#include <string.h>

int bt_parse_hci_dev(const char *name, int *index)
{
	long v = 0;
	int digits = 0;
	const char *p;

	if (!name || !index)
		return -1;
	if (strncmp(name, "hci", 3) != 0)
		return -1;
	p = name + 3;
	if (*p == '\0')
		return -1;		/* "hci" with no number */
	for (; *p; p++) {
		if (*p < '0' || *p > '9')
			return -1;
		v = v * 10 + (*p - '0');
		if (++digits > 5 || v > 65535)
			return -1;	/* hci_dev is a u16 */
	}
	*index = (int)v;
	return 0;
}
