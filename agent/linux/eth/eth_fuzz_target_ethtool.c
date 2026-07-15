// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Target: generic/blind ethernet NIC via ethtool ioctls, addressed by
 * interface name. The broad fallback for any NIC -- like wext-generic is for
 * WLAN -- it fuzzes the driver's SIOCETHTOOL handlers over an AF_INET socket.
 *
 * It drives the read-path ops that take a device offset/length the driver must
 * bound-check (GEEPROM/GMODULEEEPROM/GREGS -- the classic "driver trusts len
 * against a fixed buffer" class) and the non-persistent SET ops whose counts
 * the driver validates (ring/channel/pause/msglvl/self-test/phys-id).
 *
 * >>> This exercises the HOST KERNEL driver, not device firmware; a bug can
 *     oops or PANIC the host (pair with --output-http for remote crash
 *     capture). SET ops need CAP_NET_ADMIN. Persistent writes (SEEPROM/SFLASH)
 *     are deliberately NOT fuzzed -- they could brick the NIC's EEPROM/flash.
 *     AUTHORIZED USE ONLY, on your own hardware. <<<
 *
 * Liveness is judged out-of-band by ETHTOOL_GLINK (unprivileged); expected
 * per-op errors (EPERM/EINVAL/EOPNOTSUPP/EFAULT) are NOT treated as death.
 */
#include <errno.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "eth_fuzz.h"
#include "eth_fuzz_ethtool.h"

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef SOCK_DGRAM
#define SOCK_DGRAM 2
#endif

#define ETHTOOL_BUFSZ 8192	/* kernel writes up to the op's len into ifr_data */

/*
 * Field order is the little-endian struct layout msg_build renders; the first
 * u32 is the ethtool command the kernel dispatches on. `offset` is OPAQUE
 * (drives device over-reads); `len` is FC_LENGTH (drives the copy-size
 * boundary); ring/channel counts are FC_COUNT (drive the driver's validation).
 */
static const struct field f_geeprom[] = {	/* also GMODULEEEPROM */
	{ "cmd",    FT_U32, FC_OPAQUE, ETHTOOL_GEEPROM, 0, 0 },
	{ "magic",  FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "offset", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "len",    FT_U32, FC_LENGTH, 128, 0, 0 },
};
static const struct field f_gregs[] = {
	{ "cmd",     FT_U32, FC_OPAQUE, ETHTOOL_GREGS, 0, 0 },
	{ "version", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "len",     FT_U32, FC_LENGTH, 256, 0, 0 },
};
static const struct field f_ringparam[] = {
	{ "cmd",           FT_U32, FC_OPAQUE, ETHTOOL_SRINGPARAM, 0, 0 },
	{ "rx_max",        FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "rx_mini_max",   FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "rx_jumbo_max",  FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "tx_max",        FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "rx_pending",    FT_U32, FC_COUNT, 0, 4096, 0 },
	{ "rx_mini",       FT_U32, FC_COUNT, 0, 4096, 0 },
	{ "rx_jumbo",      FT_U32, FC_COUNT, 0, 4096, 0 },
	{ "tx_pending",    FT_U32, FC_COUNT, 0, 4096, 0 },
};
static const struct field f_channels[] = {
	{ "cmd",           FT_U32, FC_OPAQUE, ETHTOOL_SCHANNELS, 0, 0 },
	{ "max_rx",        FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "max_tx",        FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "max_other",     FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "max_combined",  FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "rx_count",      FT_U32, FC_COUNT, 0, 64, 0 },
	{ "tx_count",      FT_U32, FC_COUNT, 0, 64, 0 },
	{ "other_count",   FT_U32, FC_COUNT, 0, 64, 0 },
	{ "combined_count", FT_U32, FC_COUNT, 0, 64, 0 },
};
static const struct field f_pause[] = {
	{ "cmd",     FT_U32, FC_OPAQUE, ETHTOOL_SPAUSEPARAM, 0, 0 },
	{ "autoneg", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "rx",      FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "tx",      FT_U32, FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_value[] = {	/* SMSGLVL / PHYS_ID (ethtool_value) */
	{ "cmd",  FT_U32, FC_OPAQUE, ETHTOOL_SMSGLVL, 0, 0 },
	{ "data", FT_U32, FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_test[] = {
	{ "cmd",   FT_U32, FC_OPAQUE, ETHTOOL_TEST, 0, 0 },
	{ "flags", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "rsvd",  FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "len",   FT_U32, FC_OPAQUE, 0, 0, 0 },	/* kernel overwrites */
};
static const struct field f_physid[] = {
	{ "cmd",  FT_U32, FC_OPAQUE, ETHTOOL_PHYS_ID, 0, 0 },
	{ "data", FT_U32, FC_OPAQUE, 0, 0, 0 },
};

#define M(nm, flds, cid, w) \
	{ nm, w, (int)(sizeof(flds) / sizeof(flds[0])), flds, cid }

static const struct msg ethtool_msgs[] = {
	M("GEEPROM",       f_geeprom,   ETHTOOL_GEEPROM,       3.0),
	M("GMODULEEEPROM", f_geeprom,   ETHTOOL_GMODULEEEPROM, 2.0),
	M("GREGS",         f_gregs,     ETHTOOL_GREGS,         2.0),
	M("SRINGPARAM",    f_ringparam, ETHTOOL_SRINGPARAM,    2.0),
	M("SCHANNELS",     f_channels,  ETHTOOL_SCHANNELS,     2.0),
	M("SPAUSEPARAM",   f_pause,     ETHTOOL_SPAUSEPARAM,   1.0),
	M("SMSGLVL",       f_value,     ETHTOOL_SMSGLVL,       1.0),
	M("TEST",          f_test,      ETHTOOL_TEST,          1.0),
	M("PHYS_ID",       f_physid,    ETHTOOL_PHYS_ID,       1.0),
};

/* ---- transport ------------------------------------------------------------- */
/* Live ioctl transport needs the physical NIC + root, so it is out of coverage. */
/* LCOV_EXCL_START */

struct ethtool_priv {
	int  fd;
	char iface[IFNAMSIZ];
	uint8_t buf[ETHTOOL_BUFSZ];
};

static uint32_t le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void put_le32(uint8_t *p, uint32_t v)
{
	p[0] = v & 0xFF;
	p[1] = (v >> 8) & 0xFF;
	p[2] = (v >> 16) & 0xFF;
	p[3] = (v >> 24) & 0xFF;
}

/* Cap the op's len word so the kernel's copy into our buffer can't overrun it. */
static void clamp_len(uint8_t *buf, int word_index)
{
	int off = word_index * 4;
	uint32_t len = le32(buf + off);
	uint32_t max = ETHTOOL_BUFSZ - (uint32_t)(off + 4);

	if (len > max)
		put_le32(buf + off, max);
}

static int ethtool_attach(struct target *t)
{
	struct ethtool_priv *p = t->priv;

	p->fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (p->fd < 0)
		return -1;
	if (geteuid() != 0)
		fprintf(stderr,
			"[!] ethtool-generic: not root -- SET/EEPROM ops will EPERM; "
			"run with CAP_NET_ADMIN to actually fuzz\n");
	return 0;
}

static int ethtool_ioctl_cmd(struct ethtool_priv *p, uint32_t cmd)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	memcpy(ifr.ifr_name, p->iface, sizeof(ifr.ifr_name));
	ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';
	ifr.ifr_data = (void *)p->buf;
	(void)cmd;
	return ioctl(p->fd, SIOCETHTOOL, &ifr);
}

static int ethtool_send(struct target *t, const struct msg *m,
			const uint8_t *payload, int len)
{
	struct ethtool_priv *p = t->priv;
	int r;

	if (len < 4)
		return 0;
	if (len > (int)sizeof(p->buf))
		len = sizeof(p->buf);
	memset(p->buf, 0, sizeof(p->buf));
	memcpy(p->buf, payload, (size_t)len);

	switch (m->cmd_id) {
	case ETHTOOL_GEEPROM:
	case ETHTOOL_GMODULEEEPROM:
		clamp_len(p->buf, 3);	/* len is the 4th word */
		break;
	case ETHTOOL_GREGS:
		clamp_len(p->buf, 2);	/* len is the 3rd word */
		break;
	default:
		break;
	}

	r = ethtool_ioctl_cmd(p, m->cmd_id);
	if (r < 0 && errno == ENODEV)
		return -1;	/* interface vanished: transport dead */
	return 0;		/* EPERM/EINVAL/EOPNOTSUPP/EFAULT are normal */
}

/* ETHTOOL_GLINK: unprivileged; a live NIC answers, a wedged driver does not. */
static int ethtool_probe(struct target *t)
{
	struct ethtool_priv *p = t->priv;
	int i;

	for (i = 0; i < 3; i++) {
		memset(p->buf, 0, 8);
		put_le32(p->buf, ETHTOOL_GLINK);
		if (ethtool_ioctl_cmd(p, ETHTOOL_GLINK) == 0)
			return 1;
		if (errno == ENODEV)
			return 0;
		msleep_ms(100);
	}
	return 0;
}

static int ethtool_recover(struct target *t)
{
	struct ethtool_priv *p = t->priv;

	if (p->fd >= 0)
		close(p->fd);
	p->fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (p->fd < 0)
		return 0;
	msleep_ms(500);
	return ethtool_probe(t);
}

static void ethtool_close(struct target *t)
{
	struct ethtool_priv *p = t->priv;

	if (p->fd >= 0) {
		close(p->fd);
		p->fd = -1;
	}
}

/* LCOV_EXCL_STOP */

struct target *target_ethtool_generic(const char *iface)
{
	static struct ethtool_priv priv = { .fd = -1 };
	static struct target t = {
		.name = "ethtool-generic",
		.big_endian = 0,
		.msgs = ethtool_msgs,
		.nmsgs = (int)(sizeof(ethtool_msgs) / sizeof(ethtool_msgs[0])),
		.attach = ethtool_attach,
		.send = ethtool_send,
		.probe_alive = ethtool_probe,
		.recover = ethtool_recover,
		.close = ethtool_close,
		.priv = &priv,
	};

	snprintf(priv.iface, sizeof(priv.iface), "%s", iface ? iface : "");
	return &t;
}
