// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Target: Marvell/NXP mwifiex USB (USB8766/8797/8801/8997).
 * Grammar from mwifiex/fw.h (kernel master).
 *
 * Command = le32 tag 0xF00DFACE + host_cmd_ds_gen{cmd,size,seq,result} +
 * body (often TLV chains). Bulk EP 0x01 OUT / 0x81 IN. Little-endian.
 * Oracle: GET_HW_SPEC (0x0003) round-trip; response sets bit 0x8000.
 */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "wlan_fuzz.h"
#include "wlan_fuzz_usbfs.h"

#define MARVELL_VID  0x1286
#define USB_TYPE_CMD 0xF00DFACEu
#define EP_CMD_OUT 0x01
#define EP_CMD_IN  0x81

#define CMD_GET_HW_SPEC   0x0003
#define CMD_SNMP_MIB      0x0016
#define CMD_MAC_REG       0x0019
#define CMD_MAC_CONTROL   0x0028
#define CMD_MAC_ADDRESS   0x004D
#define CMD_KEY_MATERIAL  0x005E
#define CMD_MEM_ACCESS    0x0086
#define CMD_ADDBA_REQ     0x00CE
#define CMD_DELBA         0x00D0
#define CMD_TXBUF_CFG     0x00D9
#define CMD_AMSDU_CTRL    0x00DF

#define TLV_KEY_PARAM_V2 0x019C

/* host_cmd_ds_gen header fields, shared prefix of every message.
 * "size" is FC_LENGTH: default = correct total, mutations lie. */
#define GEN_HDR(cmd, body_size) \
	{ "command", FT_U16, FC_OPAQUE, cmd, 0, 0 }, \
	{ "size",    FT_U16, FC_LENGTH, 8 + (body_size), 0, 0 }, \
	{ "seq_num", FT_U16, FC_OPAQUE, 0, 0, 0 }, \
	{ "result",  FT_U16, FC_OPAQUE, 0, 0, 0 }

static const struct field f_snmp[] = {
	GEN_HDR(CMD_SNMP_MIB, 8),
	{ "query_type", FT_U16, FC_OPAQUE, 1, 0, 0 },
	{ "oid",        FT_U16, FC_INDEX, 0, 32, 0 },
	{ "buf_size",   FT_U16, FC_LENGTH, 2, 0, 0 },
	{ "value",      FT_BYTES, FC_ARRAY, 0, 0, 2 },
};
static const struct field f_key[] = {	/* key_len vs key[50]: H3 pattern */
	GEN_HDR(CMD_KEY_MATERIAL, 62),
	{ "action",      FT_U16, FC_OPAQUE, 1, 0, 0 },
	{ "tlv_type",    FT_U16, FC_OPAQUE, TLV_KEY_PARAM_V2, 0, 0 },
	{ "tlv_len",     FT_U16, FC_LENGTH, 56, 0, 0 },
	{ "key_type_id", FT_U16, FC_OPAQUE, 2, 0, 0 },
	{ "key_info",    FT_U16, FC_OPAQUE, 3, 0, 0 },
	{ "key_len",     FT_U16, FC_COUNT, 16, 50, 0 },
	{ "key",         FT_BYTES, FC_ARRAY, 0, 0, 50 },
};
static const struct field f_addba[] = {	/* TID bits + SSN: BAW class */
	GEN_HDR(CMD_ADDBA_REQ, 14),
	{ "result",       FT_U8, FC_OPAQUE, 0, 0, 0 },
	{ "peer_mac",     FT_BYTES, FC_OPAQUE, 0, 0, 6 },
	{ "dialog_token", FT_U8, FC_OPAQUE, 1, 0, 0 },
	{ "ba_param_set", FT_U16, FC_INDEX, (64 << 6) | 2, 0xFFFF, 0 },
	{ "ba_tmo",       FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "ssn",          FT_U16, FC_INDEX, 0, 0xFFF, 0 },
};
static const struct field f_delba[] = {
	GEN_HDR(CMD_DELBA, 12),
	{ "result",   FT_U8, FC_OPAQUE, 0, 0, 0 },
	{ "peer_mac", FT_BYTES, FC_OPAQUE, 0, 0, 6 },
	{ "param",    FT_U16, FC_INDEX, 0, 0xFFFF, 0 },
	{ "reason",   FT_U16, FC_OPAQUE, 1, 0, 0 },
	{ "rsv",      FT_U8, FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_txbuf[] = {
	GEN_HDR(CMD_TXBUF_CFG, 8),
	{ "action",    FT_U16, FC_OPAQUE, 1, 0, 0 },
	{ "buff_size", FT_U16, FC_LENGTH, 2048, 0, 0 },
	{ "mp_end",    FT_U16, FC_OPAQUE, 16, 0, 0 },
	{ "rsv",       FT_U16, FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_amsdu[] = {
	GEN_HDR(CMD_AMSDU_CTRL, 6),
	{ "action",   FT_U16, FC_OPAQUE, 1, 0, 0 },
	{ "enable",   FT_U16, FC_OPAQUE, 1, 0, 0 },
	{ "buf_size", FT_U16, FC_LENGTH, 4096, 0, 0 },
};
static const struct field f_macaddr[] = {
	GEN_HDR(CMD_MAC_ADDRESS, 8),
	{ "action", FT_U16, FC_OPAQUE, 1, 0, 0 },
	{ "mac",    FT_BYTES, FC_OPAQUE, 0, 0, 6 },
};
static const struct field f_macreg[] = {	/* by-design reg r/w: low weight */
	GEN_HDR(CMD_MAC_REG, 8),
	{ "action", FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "offset", FT_U16, FC_INDEX, 0, 0xFFFF, 0 },
	{ "value",  FT_U32, FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_mem[] = {		/* action=0 GET by default */
	GEN_HDR(CMD_MEM_ACCESS, 12),
	{ "action", FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "rsv",    FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "addr",   FT_U32, FC_OPAQUE, 0x04000000, 0, 0 },
	{ "value",  FT_U32, FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_tlv[] = {		/* generic TLV-parser probe */
	GEN_HDR(CMD_MAC_CONTROL, 24),
	{ "mac_action", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "tlv_type",   FT_U16, FC_OPAQUE, 0x0100, 0, 0 },
	{ "tlv_len",    FT_U16, FC_LENGTH, 16, 0, 0 },
	{ "tlv_data",   FT_BYTES, FC_ARRAY, 0, 0, 16 },
};

#define M(nm, flds, w) \
	{ nm, w, (int)(sizeof(flds) / sizeof(flds[0])), flds, 0 }

static const struct msg mwifiex_msgs[] = {
	M("SNMP_MIB", f_snmp, 3.0),
	M("KEY_MATERIAL", f_key, 3.0),
	M("ADDBA_REQ", f_addba, 3.0),
	M("DELBA", f_delba, 2.0),
	M("TXBUF_CFG", f_txbuf, 2.0),
	M("AMSDU_AGGR_CTRL", f_amsdu, 1.5),
	M("MAC_ADDRESS", f_macaddr, 1.0),
	M("MAC_REG_ACCESS", f_macreg, 0.3),
	M("MEM_ACCESS", f_mem, 0.3),
	M("TLV_CHAIN", f_tlv, 2.0),
};

/* ---- transport ------------------------------------------------------------- */
/* Live USB transport needs the physical NIC, so it is out of coverage. */
/* LCOV_EXCL_START */

struct mwifiex_priv {
	int fd;
	uint16_t seq;
};

static int mw_attach(struct target *t)
{
	struct mwifiex_priv *p = t->priv;
	static const uint16_t pids[] = {
		0x2041, 0x2042, 0x2043, 0x2044, 0x2049, 0x204A, 0x2052, 0x204E,
	};

	p->fd = usbfs_open(MARVELL_VID, pids, 8, NULL);
	if (p->fd < 0)
		return -1;
	usbfs_detach_kernel(p->fd, 0);
	if (usbfs_claim(p->fd, 0) < 0)
		return -1;
	return 0;
}

static int mw_send(struct target *t, const struct msg *m,
		   const uint8_t *payload, int len)
{
	struct mwifiex_priv *p = t->priv;
	uint8_t frame[4 + CASE_MAX_BYTES], resp[2048];

	(void)m;
	p->seq++;
	frame[0] = USB_TYPE_CMD & 0xFF;
	frame[1] = (USB_TYPE_CMD >> 8) & 0xFF;
	frame[2] = (USB_TYPE_CMD >> 16) & 0xFF;
	frame[3] = (USB_TYPE_CMD >> 24) & 0xFF;
	memcpy(frame + 4, payload, (size_t)len);
	if (len >= 8) {	/* live seq into host_cmd_ds_gen.seq_num (off 4) */
		frame[4 + 4] = p->seq & 0xFF;
		frame[4 + 5] = p->seq >> 8;
	}
	if (usbfs_xfer(p->fd, EP_CMD_OUT, frame, 4 + len, 1000) < 0)
		return -1;
	usbfs_xfer(p->fd, EP_CMD_IN, resp, sizeof(resp), 50);	/* drain */
	return 0;
}

static int mw_probe(struct target *t)
{
	struct mwifiex_priv *p = t->priv;
	uint8_t frame[4 + 10] = {
		USB_TYPE_CMD & 0xFF, (USB_TYPE_CMD >> 8) & 0xFF,
		(USB_TYPE_CMD >> 16) & 0xFF, (USB_TYPE_CMD >> 24) & 0xFF,
		CMD_GET_HW_SPEC & 0xFF, CMD_GET_HW_SPEC >> 8,
		10, 0,	/* size */
		0, 0,	/* seq */
		0, 0,	/* result */
		0, 0,	/* 2-byte body */
	};
	uint8_t resp[2048];
	time_t deadline = time(NULL) + 2;
	int r;

	if (usbfs_xfer(p->fd, EP_CMD_OUT, frame, sizeof(frame), 1000) < 0)
		return 0;
	while (time(NULL) < deadline) {
		r = usbfs_xfer(p->fd, EP_CMD_IN, resp, sizeof(resp), 300);
		if (r >= 6) {
			uint32_t tag = resp[0] | (resp[1] << 8) |
				       (resp[2] << 16) | ((uint32_t)resp[3] << 24);
			uint16_t cmd = resp[4] | (resp[5] << 8);

			if (tag == USB_TYPE_CMD &&
			    cmd == (CMD_GET_HW_SPEC | 0x8000))
				return 1;
		}
	}
	return 0;
}

static int mw_recover(struct target *t)
{
	return usb_recover_generic(t, 10, 2000);
}

static void mw_close(struct target *t)
{
	struct mwifiex_priv *p = t->priv;

	if (p->fd >= 0) {
		close(p->fd);
		p->fd = -1;
	}
}

/* LCOV_EXCL_STOP */

struct target *target_mwifiex(void)
{
	static struct mwifiex_priv priv = { .fd = -1 };
	static struct target t = {
		.name = "mwifiex-usb",
		.big_endian = 0,
		.msgs = mwifiex_msgs,
		.nmsgs = (int)(sizeof(mwifiex_msgs) / sizeof(mwifiex_msgs[0])),
		.attach = mw_attach,
		.send = mw_send,
		.probe_alive = mw_probe,
		.recover = mw_recover,
		.close = mw_close,
		.priv = &priv,
	};

	return &t;
}
