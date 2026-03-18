// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "linux_dmesg_util.h"

#include <stdio.h>

int ela_dmesg_determine_mode(size_t head_count,
			     size_t tail_count,
			     enum ela_dmesg_mode *mode_out,
			     char *errbuf,
			     size_t errbuf_len)
{
	if (!mode_out)
		return -1;
	if (head_count && tail_count) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "Use only one of --head or --tail");
		return -1;
	}
	if (head_count) {
		*mode_out = ELA_DMESG_MODE_HEAD;
		return 0;
	}
	if (tail_count) {
		*mode_out = ELA_DMESG_MODE_TAIL;
		return 0;
	}
	*mode_out = ELA_DMESG_MODE_ALL;
	return 0;
}

void ela_dmesg_tail_window(size_t tail_seen,
			   size_t tail_count,
			   size_t *start_out,
			   size_t *emit_count_out)
{
	size_t emit_count = tail_seen < tail_count ? tail_seen : tail_count;
	size_t start = tail_seen < tail_count ? 0 : (tail_seen % tail_count);

	if (start_out)
		*start_out = start;
	if (emit_count_out)
		*emit_count_out = emit_count;
}
