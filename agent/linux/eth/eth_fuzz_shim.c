// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "eth_fuzz_shim.h"
#include "linux/wlan/wlan_fuzz_kmod.h"
#include "../../../kmod/ela_ioctl.h"

#include <stdio.h>

/* Live injection needs the module loaded and the driver bound, so these paths
 * run only in the field, not under the offline self-test. */
/* LCOV_EXCL_START */

int eth_shim_attach(struct target *t)
{
	struct eth_shim_priv *p = t->priv;
	uint64_t restarts = 0;

	p->fd = wlan_kmod_open();
	if (p->fd < 0) {
		fprintf(stderr, "[!] cannot open %s (load ela_kmod, run as root)\n",
			ELA_KMOD_DEVICE_PATH);
		return -1;
	}
	if (wlan_kmod_attach(p->fd, p->driver_id) < 0) {
		fprintf(stderr,
			"[!] %s shim attach failed: the driver's firmware-send symbol "
			"was not found (driver loaded? kernel with CONFIG_KPROBES? "
			"matching driver version?)\n", p->name);
		wlan_kmod_close(p->fd);
		p->fd = -1;
		return -1;
	}
	printf("[*] waiting for %s firmware traffic to capture driver context...\n",
	       p->name);
	printf("    (bring the interface up / trigger driver activity to generate it)\n");
	if (wlan_kmod_wait_capture(p->fd, 20000) < 0) {
		fprintf(stderr, "[!] no %s firmware traffic captured; is the interface up?\n",
			p->name);
		wlan_kmod_detach(p->fd, p->driver_id);
		wlan_kmod_close(p->fd);
		p->fd = -1;
		return -1;
	}
	wlan_kmod_status(p->fd, &restarts, NULL);
	p->restart_base = restarts;
	printf("[*] %s context captured; injecting firmware commands\n", p->name);
	return 0;
}

int eth_shim_send(struct target *t, const struct msg *m,
		  const uint8_t *payload, int len)
{
	struct eth_shim_priv *p = t->priv;
	int32_t send_ret = 0;
	int r;

	/* The command opcode lives in the payload for these drivers; cmd_id is
	 * carried through but ignored by the ethernet inject shims. */
	r = wlan_kmod_inject(p->fd, m->cmd_id, payload, len, &send_ret);
	return r < 0 ? -1 : 0;
}

int eth_shim_probe(struct target *t)
{
	struct eth_shim_priv *p = t->priv;
	uint64_t restarts = p->restart_base;

	if (wlan_kmod_status(p->fd, &restarts, NULL) < 0)
		return 0;
	return restarts == p->restart_base;	/* a restart => firmware crashed */
}

int eth_shim_recover(struct target *t)
{
	struct eth_shim_priv *p = t->priv;
	int i;

	for (i = 0; i < 30; i++) {
		uint32_t captured = 0;
		uint64_t restarts = 0;

		msleep_ms(1000);
		if (wlan_kmod_status(p->fd, &restarts, &captured) == 0 && captured) {
			p->restart_base = restarts;
			return 1;
		}
	}
	return 0;
}

void eth_shim_close(struct target *t)
{
	struct eth_shim_priv *p = t->priv;

	if (p->fd >= 0) {
		wlan_kmod_detach(p->fd, p->driver_id);
		wlan_kmod_close(p->fd);
		p->fd = -1;
	}
}

/* LCOV_EXCL_STOP */
