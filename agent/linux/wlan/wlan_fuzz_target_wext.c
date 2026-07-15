// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Target: generic/blind Wireless Extensions (WEXT) NIC, addressed by interface
 * name. For interfaces `wlan list` marks with DETECT=wext -- older or
 * proprietary drivers that expose the legacy WEXT ioctl API but map to no
 * class-directed firmware target.
 *
 * Unlike the firmware targets, this fuzzes the *kernel driver's* SIOCSIWxxx
 * ioctl handlers from userspace over an AF_INET socket. Each handler parses a
 * union payload (essid/key/IE buffers with a length, channel/rate/power
 * params, a BSSID); the fuzzer drives the length and content boundaries those
 * handlers trust. There is no per-device grammar -- the WEXT ioctl ABI is the
 * grammar -- so this is semi-blind: it knows the ioctl shapes, not the
 * device's semantics.
 *
 * >>> This exercises the HOST KERNEL, not device firmware. A driver bug here
 *     can oops or PANIC the host, which no userspace recovery can undo. SET
 *     ioctls need CAP_NET_ADMIN (run as root). AUTHORIZED USE ONLY, on your
 *     own hardware. <<<
 *
 * Liveness is judged out-of-band by SIOCGIWNAME (a harmless GET); expected
 * per-ioctl errors (EPERM/EINVAL/E2BIG/EOPNOTSUPP) are NOT treated as death.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "wlan_fuzz.h"
#include "wlan_fuzz_wext.h"

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef SOCK_DGRAM
#define SOCK_DGRAM 2
#endif

/* wire header the param/freq grammars render before their payload */
#define PARAM_HDR 6	/* value(u32) + flags(u16) */
#define FREQ_HDR  8	/* m(u32) + e(u16) + i(u8) + flags(u8) */

/*
 * Field order defines the little-endian byte layout msg_build renders;
 * wext_send() reassembles the integers host-endian-correctly (buf[0]|buf[1]<<8
 * ...), so the target works on LE and BE hosts alike.
 *
 * POINT ioctls carry a single FT_BYTES/LENGTH payload -- the engine sweeps its
 * size across the short/long boundaries where the driver's fixed key/SSID/IE
 * buffers overflow. PARAM ioctls fuzz a 32-bit value (+ INDEX flags for AUTH).
 */
static const struct field f_point[] = {
	{ "buf", FT_BYTES, FC_LENGTH, 0, 0, 32 },
};
static const struct field f_param[] = {
	{ "value", FT_U32, FC_OPAQUE, 0, 0,    0 },
	{ "flags", FT_U16, FC_INDEX,  0, 0x0F, 0 },
};
static const struct field f_freq[] = {
	{ "m",     FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "e",     FT_U16, FC_INDEX,  0, 6, 0 },
	{ "i",     FT_U8,  FC_INDEX,  0, 0, 0 },
	{ "flags", FT_U8,  FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_mode[] = {
	{ "mode", FT_U32, FC_INDEX, 0, 7, 0 },
};
static const struct field f_addr[] = {
	{ "sa_data", FT_BYTES, FC_OPAQUE, 0, 0, 14 },	/* BSSID + pad */
};

#define M(nm, flds, req, w) \
	{ nm, w, (int)(sizeof(flds) / sizeof(flds[0])), flds, req }

static const struct msg wext_msgs[] = {
	M("SIWESSID",     f_point, SIOCSIWESSID,     3.0),
	M("SIWENCODE",    f_point, SIOCSIWENCODE,    3.0),
	M("SIWENCODEEXT", f_point, SIOCSIWENCODEEXT, 2.0),
	M("SIWGENIE",     f_point, SIOCSIWGENIE,     3.0),
	M("SIWMLME",      f_point, SIOCSIWMLME,      1.5),
	M("SIWNICKN",     f_point, SIOCSIWNICKN,     1.0),
	M("SIWSCAN",      f_point, SIOCSIWSCAN,      1.0),
	M("SIWFREQ",      f_freq,  SIOCSIWFREQ,      2.0),
	M("SIWMODE",      f_mode,  SIOCSIWMODE,      1.0),
	M("SIWAP",        f_addr,  SIOCSIWAP,        1.5),
	M("SIWRATE",      f_param, SIOCSIWRATE,      1.5),
	M("SIWTXPOW",     f_param, SIOCSIWTXPOW,     1.5),
	M("SIWRTS",       f_param, SIOCSIWRTS,       1.0),
	M("SIWFRAG",      f_param, SIOCSIWFRAG,      1.0),
	M("SIWPOWER",     f_param, SIOCSIWPOWER,     1.0),
	M("SIWRETRY",     f_param, SIOCSIWRETRY,     1.0),
	M("SIWSENS",      f_param, SIOCSIWSENS,      1.0),
	M("SIWAUTH",      f_param, SIOCSIWAUTH,      1.5),
};

/* Shape of the union member a SET ioctl expects. */
enum wext_shape { WS_POINT, WS_PARAM, WS_FREQ, WS_MODE, WS_ADDR };

static enum wext_shape wext_shape(uint32_t req)
{
	switch (req) {
	case SIOCSIWFREQ:  return WS_FREQ;
	case SIOCSIWMODE:  return WS_MODE;
	case SIOCSIWAP:    return WS_ADDR;
	case SIOCSIWSENS:
	case SIOCSIWRATE:
	case SIOCSIWRTS:
	case SIOCSIWFRAG:
	case SIOCSIWTXPOW:
	case SIOCSIWRETRY:
	case SIOCSIWPOWER:
	case SIOCSIWAUTH:  return WS_PARAM;
	default:           return WS_POINT;
	}
}

/* ---- transport ------------------------------------------------------------- */
/* Live ioctl transport needs the physical NIC + root, so it is out of coverage. */
/* LCOV_EXCL_START */

struct wext_priv {
	int  fd;
	char iface[WEXT_IFNAMSIZ];
};

static uint32_t le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int wext_attach(struct target *t)
{
	struct wext_priv *p = t->priv;

	p->fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (p->fd < 0)
		return -1;
	if (geteuid() != 0)
		fprintf(stderr,
			"[!] wext-generic: not root -- SET ioctls will EPERM; "
			"run with CAP_NET_ADMIN to actually fuzz\n");
	return 0;
}

static int wext_send(struct target *t, const struct msg *m,
		     const uint8_t *payload, int len)
{
	struct wext_priv *p = t->priv;
	uint8_t buf[FIELD_BYTES_MAX];
	struct iwreq iwr;
	int r;

	memset(&iwr, 0, sizeof(iwr));
	memcpy(iwr.ifr_name, p->iface, sizeof(iwr.ifr_name));
	iwr.ifr_name[sizeof(iwr.ifr_name) - 1] = '\0';

	switch (wext_shape(m->cmd_id)) {
	case WS_POINT: {
		int blen = len;

		if (blen > (int)sizeof(buf))
			blen = sizeof(buf);
		memcpy(buf, payload, (size_t)blen);	/* driver may read it */
		iwr.u.data.pointer = buf;
		iwr.u.data.length = (uint16_t)blen;
		iwr.u.data.flags = 0;
		break;
	}
	case WS_PARAM:
		if (len < PARAM_HDR)
			return 0;
		iwr.u.param.value = (int32_t)le32(payload);
		iwr.u.param.flags = (uint16_t)(payload[4] | (payload[5] << 8));
		break;
	case WS_FREQ:
		if (len < FREQ_HDR)
			return 0;
		iwr.u.freq.m = (int32_t)le32(payload);
		iwr.u.freq.e = (int16_t)(payload[4] | (payload[5] << 8));
		iwr.u.freq.i = payload[6];
		iwr.u.freq.flags = payload[7];
		break;
	case WS_MODE:
		if (len < 4)
			return 0;
		iwr.u.mode = le32(payload);
		break;
	case WS_ADDR:
		iwr.u.ap_addr.sa_family = WEXT_ARPHRD_ETHER;
		memcpy(iwr.u.ap_addr.sa_data, payload,
		       len > 14 ? 14 : (size_t)len);
		break;
	}

	r = ioctl(p->fd, m->cmd_id, &iwr);
	/* Expected per-ioctl rejections are not firmware/driver death; only a
	 * vanished interface is. Real crashes surface via the probe. */
	if (r < 0 && errno == ENODEV)
		return -1;
	return 0;
}

/* SIOCGIWNAME: any live WEXT interface answers it; a wedged driver does not. */
static int wext_probe(struct target *t)
{
	struct wext_priv *p = t->priv;
	struct iwreq iwr;
	int i;

	for (i = 0; i < 3; i++) {
		memset(&iwr, 0, sizeof(iwr));
		memcpy(iwr.ifr_name, p->iface, sizeof(iwr.ifr_name));
		iwr.ifr_name[sizeof(iwr.ifr_name) - 1] = '\0';
		if (ioctl(p->fd, SIOCGIWNAME, &iwr) == 0)
			return 1;
		if (errno == ENODEV)
			return 0;
		msleep_ms(100);
	}
	return 0;
}

/*
 * A WEXT/driver crash is a host-kernel event; userspace cannot restart it.
 * Best effort: reopen the socket and re-probe (recovers a transient hiccup or
 * a driver that reloaded; a real panic leaves nothing to recover).
 */
static int wext_recover(struct target *t)
{
	struct wext_priv *p = t->priv;

	if (p->fd >= 0)
		close(p->fd);
	p->fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (p->fd < 0)
		return 0;
	msleep_ms(500);
	return wext_probe(t);
}

static void wext_close(struct target *t)
{
	struct wext_priv *p = t->priv;

	if (p->fd >= 0) {
		close(p->fd);
		p->fd = -1;
	}
}

/* LCOV_EXCL_STOP */

struct target *target_wext_generic(const char *iface)
{
	static struct wext_priv priv = { .fd = -1 };
	static struct target t = {
		.name = "wext-generic",
		.big_endian = 0,
		.msgs = wext_msgs,
		.nmsgs = (int)(sizeof(wext_msgs) / sizeof(wext_msgs[0])),
		.attach = wext_attach,
		.send = wext_send,
		.probe_alive = wext_probe,
		.recover = wext_recover,
		.close = wext_close,
		.priv = &priv,
	};

	snprintf(priv.iface, sizeof(priv.iface), "%s", iface ? iface : "");
	return &t;
}
