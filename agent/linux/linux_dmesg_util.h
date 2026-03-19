// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_LINUX_DMESG_UTIL_H
#define ELA_LINUX_DMESG_UTIL_H

#include <stddef.h>

enum ela_dmesg_mode {
	ELA_DMESG_MODE_ALL = 0,
	ELA_DMESG_MODE_HEAD,
	ELA_DMESG_MODE_TAIL,
};

int ela_dmesg_determine_mode(size_t head_count,
			     size_t tail_count,
			     enum ela_dmesg_mode *mode_out,
			     char *errbuf,
			     size_t errbuf_len);
void ela_dmesg_tail_window(size_t tail_seen,
			   size_t tail_count,
			   size_t *start_out,
			   size_t *emit_count_out);

#endif
