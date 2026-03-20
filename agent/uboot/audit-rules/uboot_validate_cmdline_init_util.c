// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "uboot_validate_cmdline_init_util.h"

#include <stdio.h>

int ela_uboot_cmdline_init_writeability_result(bool has_init,
					       bool init_valid,
					       bool writeable,
					       const char *init_value,
					       const char *device,
					       char *message,
					       size_t message_len)
{
	if (!has_init) {
		if (message && message_len)
			snprintf(message, message_len,
				 "kernel cmdline parsed; init= not present");
		return 0;
	}

	if (!init_valid) {
		if (message && message_len)
			snprintf(message, message_len,
				 "kernel cmdline parsed; init= present but invalid (%s)",
				 init_value ? init_value : "");
		return 0;
	}

	if (writeable) {
		if (message && message_len)
			snprintf(message, message_len,
				 "WARNING: valid init=%s and environment block appears writeable (%s)",
				 init_value ? init_value : "",
				 device ? device : "(unknown)");
		return 1;
	}

	if (message && message_len)
		snprintf(message, message_len,
			 "kernel cmdline parsed; valid init=%s and environment block not writeable",
			 init_value ? init_value : "");

	return 0;
}
