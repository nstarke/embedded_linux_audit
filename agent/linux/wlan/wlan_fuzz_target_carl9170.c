// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Target: Atheros AR9170 USB (carl9170 firmware) -- AR9170/AR9130 USB dongles.
 * Grammar extracted from drivers/net/wireless/ath/carl9170/{fwcmd.h,hw.h}
 * (kernel master); struct sizes are asserted against the driver's own
 * CARL9170_*_SIZE defines by the offline self-test.
 *
 * Command = 4-byte head { u8 len, u8 cmd, u8 seq, u8 ext } + payload (<= 60).
 * `len` is the payload length the firmware trusts. Commands go OUT on the
 * interrupt CMD endpoint (EP4); responses/traps come IN on the interrupt
 * IRQ endpoint (EP3). Little-endian. Oracle: CARL9170_CMD_ECHO round-trip.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "wlan_fuzz.h"
#include "wlan_fuzz_usbfs.h"

#define ATHEROS_VID 0x0CF3
/* AR9170_USB_EP_* are a 1-based enum: TX=1, RX=2, IRQ=3, CMD=4 (hw.h). */
#define EP_CMD_OUT 0x04
#define EP_IRQ_IN  0x83
#define CARL_CMD_MAX 64		/* CARL9170_MAX_CMD_LEN */
#define CARL_PAYLOAD_MAX 60	/* CARL9170_MAX_CMD_PAYLOAD_LEN */

/* enum carl9170_cmd_oids (fwcmd.h) */
#define CARL_CMD_RREG      0x00
#define CARL_CMD_WREG      0x01
#define CARL_CMD_ECHO      0x02
#define CARL_CMD_BCN_CTRL  0x05
#define CARL_CMD_READ_TSF  0x06
#define CARL_CMD_RX_FILTER 0x07
#define CARL_CMD_WOL       0x08
#define CARL_CMD_WREGB     0x0A
#define CARL_CMD_EKEY      0x10
#define CARL_CMD_DKEY      0x11
#define CARL_CMD_RF_INIT   0x21
#define CARL_CMD_PSM       0x24
#define CARL_CMD_ASYNC_FLAG 0x40
#define CARL_RSP_FLAG      0xC0

#define CARL_RAW 0xFFFF		/* pseudo-cmd: raw head+body, fuzz len/cmd/ext */

/* firmware array bounds (hw.h) */
#define CAM_MAX_USER  64	/* AR9170_CAM_MAX_USER  */
#define MAX_VIF        7	/* AR9170_MAX_VIRTUAL_MAC */

/* ---- grammar (sizes verified vs CARL9170_*_SIZE in the self-test) -------- */

static const struct field f_echo[] = {	/* oracle payload; also fuzz length */
	{ "payload", FT_BYTES, FC_LENGTH, 0, 0, 4 },
};
static const struct field f_rreg[] = {	/* le32 reg addrs; resp sized by count */
	{ "regs", FT_BYTES, FC_LENGTH, 0, 0, 16 },
};
static const struct field f_wreg[] = {	/* {addr,val} le32 pairs: by-design write */
	{ "pairs", FT_BYTES, FC_OPAQUE, 0, 0, 16 },
};
static const struct field f_wregb[] = {	/* addr,count,val[]: count lies about val */
	{ "addr",  FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "count", FT_U32, FC_COUNT, 4, 52, 0 },
	{ "val",   FT_BYTES, FC_ARRAY, 0, 0, 8 },
};
static const struct field f_ekey[] = {	/* carl9170_set_key_cmd, 28B */
	{ "user",    FT_U16, FC_INDEX, 0, CAM_MAX_USER - 1, 0 },
	{ "keyId",   FT_U16, FC_INDEX, 0, 3, 0 },
	{ "type",    FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "macAddr", FT_BYTES, FC_OPAQUE, 0, 0, 6 },
	{ "key",     FT_BYTES, FC_OPAQUE, 0, 0, 16 },
};
static const struct field f_dkey[] = {	/* carl9170_disable_key_cmd, 4B */
	{ "user",    FT_U16, FC_INDEX, 0, CAM_MAX_USER - 1, 0 },
	{ "padding", FT_U16, FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_bcn[] = {	/* carl9170_bcn_ctrl_cmd, 16B */
	{ "vif_id",   FT_U32, FC_INDEX, 0, MAX_VIF - 1, 0 },
	{ "mode",     FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "bcn_addr", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "bcn_len",  FT_U32, FC_LENGTH, 0, 0, 0 },
};
static const struct field f_rxfilter[] = {	/* carl9170_rx_filter_cmd, 4B */
	{ "rx_filter", FT_U32, FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_rfinit[] = {	/* carl9170_rf_init, 28B */
	{ "freq",        FT_U32, FC_OPAQUE, 2412, 0, 0 },
	{ "ht_settings", FT_U8,  FC_OPAQUE, 0, 0, 0 },
	{ "padding2",    FT_BYTES, FC_OPAQUE, 0, 0, 3 },
	{ "dsc_exp",     FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "dsc_man",     FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "dsc_exp_shgi", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "dsc_man_shgi", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "finiteLoop",  FT_U32, FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_psm[] = {	/* carl9170_psm, 4B */
	{ "state", FT_U32, FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_wol[] = {	/* carl9170_wol_cmd, 60B */
	{ "flags",         FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "mac",           FT_BYTES, FC_OPAQUE, 0, 0, 6 },
	{ "bssid",         FT_BYTES, FC_OPAQUE, 0, 0, 6 },
	{ "null_interval", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "free_for_use2", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "mask",          FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "pattern",       FT_BYTES, FC_OPAQUE, 0, 0, 32 },
};
static const struct field f_raw[] = {	/* head + body: fuzz len/cmd/ext directly */
	{ "len",  FT_U8, FC_LENGTH, 8, 0, 0 },
	{ "cmd",  FT_U8, FC_INDEX, CARL_CMD_ECHO, CARL_CMD_ASYNC_FLAG, 0 },
	{ "seq",  FT_U8, FC_OPAQUE, 0, 0, 0 },	/* overwritten on send */
	{ "ext",  FT_U8, FC_OPAQUE, 0, 0, 0 },
	{ "body", FT_BYTES, FC_LENGTH, 0, 0, 8 },
};

#define M(nm, flds, w, id) \
	{ nm, w, (int)(sizeof(flds) / sizeof(flds[0])), flds, id }

static const struct msg carl9170_msgs[] = {
	M("ECHO",       f_echo,     2.0, CARL_CMD_ECHO),
	M("RREG",       f_rreg,     3.0, CARL_CMD_RREG),
	M("WREG",       f_wreg,     0.3, CARL_CMD_WREG),
	M("WREGB",      f_wregb,    2.0, CARL_CMD_WREGB),
	M("EKEY",       f_ekey,     3.0, CARL_CMD_EKEY),
	M("DKEY",       f_dkey,     2.0, CARL_CMD_DKEY),
	M("BCN_CTRL",   f_bcn,      2.5, CARL_CMD_BCN_CTRL),
	M("RX_FILTER",  f_rxfilter, 1.5, CARL_CMD_RX_FILTER),
	M("RF_INIT",    f_rfinit,   1.0, CARL_CMD_RF_INIT),
	M("PSM",        f_psm,      1.0, CARL_CMD_PSM),
	M("WOL",        f_wol,      1.0, CARL_CMD_WOL),
	M("RAW_CMD",    f_raw,      2.0, CARL_RAW),
};

/* ---- transport ------------------------------------------------------------- */
/* Live USB transport needs the physical NIC, so it is out of coverage. */
/* LCOV_EXCL_START */

struct carl_priv {
	int fd;
	uint8_t seq;
};

/* attach: firmware must already be resident (let carl9170 load it once). */
static int carl_attach(struct target *t)
{
	struct carl_priv *p = t->priv;
	/* Atheros reference plus a few common OEM vid/pid pairs (usb.c). */
	static const struct {
		uint16_t vid;
		uint16_t pids[6];
		int npids;
	} ids[] = {
		{ 0x0CF3, { 0x9170, 0x1001, 0x1002, 0x1010, 0x1011 }, 5 },
		{ 0x07D1, { 0x3C10, 0x3A09, 0x3A0F }, 3 },
		{ 0x0846, { 0x9040, 0x9010, 0x9001 }, 3 },
		{ 0x1435, { 0x0804, 0x0326 }, 2 },
		{ 0x1668, { 0x1200 }, 1 },
	};
	size_t i;

	for (i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
		p->fd = usbfs_open(ids[i].vid, ids[i].pids, ids[i].npids, NULL);
		if (p->fd >= 0)
			break;
	}
	if (p->fd < 0)
		return -1;
	usbfs_detach_kernel(p->fd, 0);
	if (usbfs_claim(p->fd, 0) < 0)
		return -1;
	return 0;
}

static int carl_send_frame(struct carl_priv *p, const uint8_t *frame, int n)
{
	uint8_t resp[CARL_CMD_MAX];

	if (usbfs_xfer(p->fd, EP_CMD_OUT, (void *)frame, n, 1000) < 0)
		return -1;
	usbfs_xfer(p->fd, EP_IRQ_IN, resp, sizeof(resp), 20);	/* drain */
	return 0;
}

static int carl_send(struct target *t, const struct msg *m,
		     const uint8_t *payload, int len)
{
	struct carl_priv *p = t->priv;
	uint8_t frame[CARL_CMD_MAX];
	int n;

	if (m->cmd_id == CARL_RAW) {
		/* payload already is { len, cmd, seq, ext, body... } */
		if (len < 4)
			return 0;
		n = len > CARL_CMD_MAX ? CARL_CMD_MAX : len;
		memcpy(frame, payload, (size_t)n);
		frame[2] = p->seq++;	/* live seq; len byte stays fuzzed */
	} else {
		int plen = len > CARL_PAYLOAD_MAX ? CARL_PAYLOAD_MAX : len;

		frame[0] = (uint8_t)plen;
		frame[1] = (uint8_t)m->cmd_id;
		frame[2] = p->seq++;
		frame[3] = 0;
		memcpy(frame + 4, payload, (size_t)plen);
		n = 4 + plen;
	}
	return carl_send_frame(p, frame, n);
}

static int carl_probe(struct target *t)
{
	struct carl_priv *p = t->priv;
	static const uint8_t cookie[4] = { 'P', 'I', 'N', 'G' };
	uint8_t frame[8], resp[CARL_CMD_MAX];
	int r, i;

	frame[0] = 4;			/* payload len */
	frame[1] = CARL_CMD_ECHO;
	frame[2] = p->seq++;
	frame[3] = 0;
	memcpy(frame + 4, cookie, 4);
	if (usbfs_xfer(p->fd, EP_CMD_OUT, frame, sizeof(frame), 1000) < 0)
		return 0;
	r = usbfs_xfer(p->fd, EP_IRQ_IN, resp, sizeof(resp), 1500);
	/* firmware echoes the 4-byte cookie back in the response payload */
	for (i = 0; i + 4 <= r; i++)
		if (!memcmp(resp + i, cookie, 4))
			return 1;
	return 0;
}

static int carl_recover(struct target *t)
{
	return usb_recover_generic(t, 10, 2000);
}

static void carl_close(struct target *t)
{
	struct carl_priv *p = t->priv;

	if (p->fd >= 0) {
		close(p->fd);
		p->fd = -1;
	}
}

/* LCOV_EXCL_STOP */

struct target *target_carl9170(void)
{
	static struct carl_priv priv = { .fd = -1 };
	static struct target t = {
		.name = "carl9170",
		.big_endian = 0,
		.msgs = carl9170_msgs,
		.nmsgs = (int)(sizeof(carl9170_msgs) / sizeof(carl9170_msgs[0])),
		.attach = carl_attach,
		.send = carl_send,
		.probe_alive = carl_probe,
		.recover = carl_recover,
		.close = carl_close,
		.priv = &priv,
	};

	return &t;
}
