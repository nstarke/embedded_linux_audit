// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Shared ela_kmod-shim transport for the ethernet firmware-command targets
 * (bnxt/i40e/ice/cxgb4/mlx5). They differ only in grammar, driver id, and
 * endianness; the attach/inject/liveness/recover/close plumbing is identical
 * to the WLAN shim targets (kprobe the driver send, capture context, inject a
 * fuzzed command, watch the firmware-restart counter as the crash oracle).
 */
#ifndef ETH_FUZZ_SHIM_H
#define ETH_FUZZ_SHIM_H

#include <stdint.h>

#include "eth_fuzz.h"

struct eth_shim_priv {
	int         fd;
	uint32_t    driver_id;	/* ELA_ETH_DRV_* */
	const char *name;
	uint64_t    restart_base;
};

int  eth_shim_attach(struct target *t);
int  eth_shim_send(struct target *t, const struct msg *m,
		   const uint8_t *payload, int len);
int  eth_shim_probe(struct target *t);
int  eth_shim_recover(struct target *t);
void eth_shim_close(struct target *t);

/* Define a shim-backed target constructor: name, driver id, endianness, grammar.
 * `grammar` must not be named `msgs` -- that would collide with the struct field
 * during macro substitution (the preprocessor would rewrite `.msgs`). */
#define ETH_SHIM_TARGET(ctor, tname, drv, be, grammar)			\
	struct target *ctor(void)					\
	{								\
		static struct eth_shim_priv priv = {			\
			.fd = -1, .driver_id = (drv), .name = tname,	\
		};							\
		static struct target t = {				\
			.name = tname, .big_endian = (be),		\
			.msgs = (grammar),				\
			.nmsgs = (int)(sizeof(grammar) / sizeof((grammar)[0])), \
			.attach = eth_shim_attach, .send = eth_shim_send, \
			.probe_alive = eth_shim_probe,			\
			.recover = eth_shim_recover,			\
			.close = eth_shim_close, .priv = &priv,		\
		};							\
		return &t;						\
	}

#endif
