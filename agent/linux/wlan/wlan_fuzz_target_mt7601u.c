// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Target: MediaTek MT7601U. Grammar from mt7601u/mcu.h + dma.h (kernel master).
 *
 * MCU command = 4-byte DMA header (LEN GENMASK(15,0) | SEQ GENMASK(19,16) |
 * CMD GENMASK(26,20) | D_PORT GENMASK(29,27)=CPU_TX_PORT(1) |
 * TYPE GENMASK(31,30)=DMA_COMMAND(2)) + le32 payload words.
 * Bulk EP 0x08 OUT / 0x85 IN. Little-endian.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "wlan_fuzz.h"
#include "wlan_fuzz_usbfs.h"

#define MEDIATEK_VID 0x148F
#define MT7601U_PID  0x7601
#define EP_MCU_OUT 0x08
#define EP_MCU_IN  0x85

#define VEND_SINGLE_READ 0x7
#define MT_MCU_COM_REG0  0x0730
#define INBAND_MAX 192

/* enum mcu_cmd (mcu.h) */
#define CMD_FUN_SET_OP     1
#define CMD_BURST_WRITE    8
#define CMD_RANDOM_READ   10
#define CMD_POWER_SAVING  20
#define CMD_SWITCH_CHAN   30
#define CMD_CALIBRATION   31
#define CMD_BEACON_OP     32

static const struct field f_funset[] = {
	{ "func",  FT_U32, FC_INDEX, 1, 5, 0 },
	{ "value", FT_U32, FC_OPAQUE, 1, 0, 0 },
};
static const struct field f_cal[] = {	/* dispatch-table INDEX 1..9 */
	{ "cal",   FT_U32, FC_INDEX, 1, 9, 0 },
	{ "value", FT_U32, FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_chan[] = {
	{ "chan",   FT_U8, FC_INDEX, 1, 14, 0 },
	{ "bw_idx", FT_U8, FC_INDEX, 0, 3, 0 },
	{ "body",   FT_BYTES, FC_OPAQUE, 0, 0, 6 },
};
static const struct field f_burst[] = {	/* by-design mem write: low weight */
	{ "addr",  FT_U32, FC_OPAQUE, 0x00410000, 0, 0 },
	{ "words", FT_BYTES, FC_LENGTH, 0, 0, 16 },
};
static const struct field f_rread[] = {	/* H1 pattern: response by count */
	{ "pairs", FT_BYTES, FC_LENGTH, 0, 0, 16 },
};
static const struct field f_psave[] = {
	{ "mode", FT_U32, FC_INDEX, 0x30, 0x34, 0 },
	{ "body", FT_BYTES, FC_OPAQUE, 0, 0, 4 },
};
static const struct field f_beacon[] = {
	{ "offset", FT_U32, FC_INDEX, 0, 7, 0 },
	{ "body",   FT_BYTES, FC_LENGTH, 0, 0, 32 },
};
static const struct field f_raw[] = {
	{ "body", FT_BYTES, FC_OPAQUE, 0, 0, 16 },
};

#define M(nm, flds, w, cmd) \
	{ nm, w, (int)(sizeof(flds) / sizeof(flds[0])), flds, cmd }

static const struct msg mt7601u_msgs[] = {
	M("FUN_SET",        f_funset, 2.0, CMD_FUN_SET_OP),
	M("CALIBRATE",      f_cal,    3.0, CMD_CALIBRATION),
	M("SWITCH_CHANNEL", f_chan,   2.0, CMD_SWITCH_CHAN),
	M("BURST_WRITE",    f_burst,  0.5, CMD_BURST_WRITE),
	M("RANDOM_READ",    f_rread,  2.0, CMD_RANDOM_READ),
	M("POWER_SAVING",   f_psave,  1.5, CMD_POWER_SAVING),
	M("BEACON_OP",      f_beacon, 2.0, CMD_BEACON_OP),
	M("RAW_CMD",        f_raw,    0.5, CMD_FUN_SET_OP),
};

/* ---- transport ------------------------------------------------------------- */
/* Live USB transport needs the physical NIC, so it is out of coverage. */
/* LCOV_EXCL_START */

struct mt_priv {
	int fd;
	unsigned int seq;
};

static void dma_cmd_hdr(uint8_t *out, int payload_len, unsigned int cmd,
			unsigned int seq)
{
	unsigned int rounded = ((unsigned int)payload_len + 3) & ~3u;
	uint32_t w = (rounded & 0xFFFF) | ((seq & 0xF) << 16) |
		     ((cmd & 0x7F) << 20) | (1u << 27) | (2u << 30);

	out[0] = w & 0xFF;
	out[1] = (w >> 8) & 0xFF;
	out[2] = (w >> 16) & 0xFF;
	out[3] = (w >> 24) & 0xFF;
}

static int mt_attach(struct target *t)
{
	struct mt_priv *p = t->priv;
	static const uint16_t pids[] = { MT7601U_PID };

	p->fd = usbfs_open(MEDIATEK_VID, pids, 1, NULL);
	if (p->fd < 0)
		return -1;
	usbfs_detach_kernel(p->fd, 0);
	if (usbfs_claim(p->fd, 0) < 0)
		return -1;
	return 0;
}

static int mt_send_cmd(struct mt_priv *p, unsigned int cmd,
		       const uint8_t *payload, int len)
{
	uint8_t frame[4 + INBAND_MAX + 4], resp[512];
	int pad;

	if (len > INBAND_MAX)
		len = INBAND_MAX;
	p->seq = (p->seq % 15) + 1;	/* seq 0 = no-response in fw */
	pad = (-len) & 3;
	dma_cmd_hdr(frame, len, cmd, p->seq);
	memcpy(frame + 4, payload, (size_t)len);
	memset(frame + 4 + len, 0, (size_t)pad);
	if (usbfs_xfer(p->fd, EP_MCU_OUT, frame, 4 + len + pad, 1000) < 0)
		return -1;
	usbfs_xfer(p->fd, EP_MCU_IN, resp, sizeof(resp), 50);	/* drain */
	return 0;
}

static int mt_send(struct target *t, const struct msg *m,
		   const uint8_t *payload, int len)
{
	return mt_send_cmd(t->priv, m->cmd_id, payload, len);
}

static int mt_probe(struct target *t)
{
	struct mt_priv *p = t->priv;
	uint8_t body[8] = { 1, 0, 0, 0, 1, 0, 0, 0 };	/* Q_SELECT, 1 */
	uint8_t frame[16], resp[512], reg[4];
	int r;

	p->seq = (p->seq % 15) + 1;
	dma_cmd_hdr(frame, 8, CMD_FUN_SET_OP, p->seq);
	memcpy(frame + 4, body, 8);
	if (usbfs_xfer(p->fd, EP_MCU_OUT, frame, 12, 1000) < 0)
		return 0;
	r = usbfs_xfer(p->fd, EP_MCU_IN, resp, sizeof(resp), 500);
	if (r > 0)
		return 1;
	/* tier 2: MCU semaphore register readable and not bus-dead */
	r = usbfs_ctrl(p->fd, 0xC0, VEND_SINGLE_READ, 0, MT_MCU_COM_REG0,
		       reg, 4, 1000);
	if (r < 0)
		return 0;
	return !(reg[0] == 0xFF && reg[1] == 0xFF &&
		 reg[2] == 0xFF && reg[3] == 0xFF);
}

static int mt_recover(struct target *t)
{
	return usb_recover_generic(t, 10, 2000);
}

static void mt_close(struct target *t)
{
	struct mt_priv *p = t->priv;

	if (p->fd >= 0) {
		close(p->fd);
		p->fd = -1;
	}
}

/* LCOV_EXCL_STOP */

struct target *target_mt7601u(void)
{
	static struct mt_priv priv = { .fd = -1 };
	static struct target t = {
		.name = "mt7601u",
		.big_endian = 0,
		.msgs = mt7601u_msgs,
		.nmsgs = (int)(sizeof(mt7601u_msgs) / sizeof(mt7601u_msgs[0])),
		.attach = mt_attach,
		.send = mt_send,
		.probe_alive = mt_probe,
		.recover = mt_recover,
		.close = mt_close,
		.priv = &priv,
	};

	return &t;
}
