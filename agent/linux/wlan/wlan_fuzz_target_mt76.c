// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Target: MediaTek mt76 connac-generation MCU (mt7615/mt7915/mt7921/mt7996)
 * over the ela_kmod kernel shim. Injects through the exported
 * mt76_mcu_send_and_get_msg(dev, cmd, data, len, ...) -- the shim's mt76
 * adapter (ELA_WLAN_DRV_MT76) hands it the raw command body; the driver
 * prepends the MCU TX descriptor. Oracle = the per-chip *_mac_reset_work
 * crash worker (the shim tries each until one resolves for the bound chip).
 *
 * Grammar from drivers/net/wireless/mediatek/mt76/mt76_connac_mcu.h (kernel
 * master). A connac command body is a station/wtbl request header followed by
 * a run of TLVs; this target fuzzes the header's fixed-array index fields
 * (bss/wlan/muar) and tlv_num count, plus one trailing TLV whose tag/len drive
 * the firmware's TLV parser. cmd_id/oracle caveats are as in wlan-fuzz.md.
 */
#include <stdio.h>
#include <string.h>

#include "wlan_fuzz.h"
#include "wlan_fuzz_kmod.h"
#include "../../../kmod/ela_ioctl.h"

/*
 * Full MCU command word (mt76_connac_mcu.h bitfields). EXT commands carry
 * EXT_CID(0xed) in bits[7:0] and the ext id in bits[15:8].
 */
#define MCU_EXT_STA_REC_UPDATE 0x0025ed	/* MCU_EXT_CMD(STA_REC_UPDATE) */
#define MCU_EXT_WTBL_UPDATE    0x0032ed	/* MCU_EXT_CMD(WTBL_UPDATE)    */

#define MT76_RAW 0xFFFFFFFFu		/* pseudo: le32 cmd_id prefixes body */

/* fixed-array bounds (per-chip; smallest tables chosen for off-by-one) */
#define MT76_MAX_VIF   16	/* MT7615_MAX_INTERFACES ... MT7996 */
#define MT76_WTBL_LO   32	/* MT7663_WTBL_SIZE (smallest); lo byte */
#define MT76_MUAR      16

/* ---- grammar (fixed header + one fuzzable TLV) --------------------------- */

/* struct sta_req_hdr (8B) + a generic TLV { __le16 tag; __le16 len; body } */
static const struct field f_sta_rec[] = {
	{ "bss_idx",       FT_U8,  FC_INDEX, 0, MT76_MAX_VIF - 1, 0 },
	{ "wlan_idx_lo",   FT_U8,  FC_INDEX, 0, MT76_WTBL_LO - 1, 0 },
	{ "tlv_num",       FT_U16, FC_COUNT, 1, 8, 0 },
	{ "is_tlv_append", FT_U8,  FC_OPAQUE, 1, 0, 0 },
	{ "muar_idx",      FT_U8,  FC_INDEX, 0, MT76_MUAR - 1, 0 },
	{ "wlan_idx_hi",   FT_U8,  FC_INDEX, 0, 4, 0 },
	{ "rsv",           FT_U8,  FC_OPAQUE, 0, 0, 0 },
	{ "tlv_tag",       FT_U16, FC_INDEX, 0, 30, 0 },
	{ "tlv_len",       FT_U16, FC_LENGTH, 20, 0, 0 },
	{ "tlv_body",      FT_BYTES, FC_ARRAY, 0, 0, 16 },
};

/* struct wtbl_req_hdr (8B) + a generic TLV */
static const struct field f_wtbl[] = {
	{ "wlan_idx_lo", FT_U8,  FC_INDEX, 0, MT76_WTBL_LO - 1, 0 },
	{ "operation",   FT_U8,  FC_OPAQUE, 1, 0, 0 },
	{ "tlv_num",     FT_U16, FC_COUNT, 1, 8, 0 },
	{ "wlan_idx_hi", FT_U8,  FC_INDEX, 0, 4, 0 },
	{ "rsv",         FT_BYTES, FC_OPAQUE, 0, 0, 3 },
	{ "tlv_tag",     FT_U16, FC_INDEX, 0, 30, 0 },
	{ "tlv_len",     FT_U16, FC_LENGTH, 20, 0, 0 },
	{ "tlv_body",    FT_BYTES, FC_ARRAY, 0, 0, 16 },
};

static const struct field f_raw[] = {	/* fuzz the full MCU cmd word + body */
	{ "cmd_id", FT_U32, FC_INDEX, 0x25ed, 0x50000, 0 },
	{ "body",   FT_BYTES, FC_LENGTH, 0, 0, 16 },
};

#define M(nm, flds, w, id) \
	{ nm, w, (int)(sizeof(flds) / sizeof(flds[0])), flds, id }

static const struct msg mt76_msgs[] = {
	M("STA_REC_UPDATE", f_sta_rec, 3.0, MCU_EXT_STA_REC_UPDATE),
	M("WTBL_UPDATE",    f_wtbl,    3.0, MCU_EXT_WTBL_UPDATE),
	M("RAW_MCU",        f_raw,     1.5, MT76_RAW),
};

/* ---- transport (ela_kmod shim) -------------------------------------------- */
/* LCOV_EXCL_START -- live injection needs the module + a bound driver */

struct mt76_priv {
	int fd;
	uint64_t restart_base;
};

static int mt76_attach(struct target *t)
{
	struct mt76_priv *p = t->priv;
	uint64_t restarts = 0;

	p->fd = wlan_kmod_open();
	if (p->fd < 0) {
		fprintf(stderr, "[!] cannot open %s (load ela_kmod, run as root)\n",
			ELA_KMOD_DEVICE_PATH);
		return -1;
	}
	if (wlan_kmod_attach(p->fd, ELA_WLAN_DRV_MT76) < 0) {
		fprintf(stderr, "[!] mt76 shim attach failed (driver loaded? CONFIG_KPROBES?)\n");
		wlan_kmod_close(p->fd);
		p->fd = -1;
		return -1;
	}
	printf("[*] waiting for mt76 MCU traffic to capture driver context...\n");
	printf("    (bring the interface up or trigger a scan to generate it)\n");
	if (wlan_kmod_wait_capture(p->fd, 20000) < 0) {
		fprintf(stderr, "[!] no MCU traffic captured; is the interface up?\n");
		wlan_kmod_detach(p->fd, ELA_WLAN_DRV_MT76);
		wlan_kmod_close(p->fd);
		p->fd = -1;
		return -1;
	}
	wlan_kmod_status(p->fd, &restarts, NULL);
	p->restart_base = restarts;
	printf("[*] mt76 context captured; injecting MCU commands\n");
	return 0;
}

static int mt76_send(struct target *t, const struct msg *m,
		     const uint8_t *payload, int len)
{
	struct mt76_priv *p = t->priv;
	int32_t send_ret = 0;
	int r;

	if (m->cmd_id == MT76_RAW) {
		uint32_t cid;

		if (len < 4)
			return 0;
		cid = payload[0] | (payload[1] << 8) | (payload[2] << 16) |
		      ((uint32_t)payload[3] << 24);
		r = wlan_kmod_inject(p->fd, cid, payload + 4, len - 4, &send_ret);
	} else {
		r = wlan_kmod_inject(p->fd, m->cmd_id, payload, len, &send_ret);
	}
	return r < 0 ? -1 : 0;
}

static int mt76_probe(struct target *t)
{
	struct mt76_priv *p = t->priv;
	uint64_t restarts = p->restart_base;

	if (wlan_kmod_status(p->fd, &restarts, NULL) < 0)
		return 0;
	return restarts == p->restart_base;
}

static int mt76_recover(struct target *t)
{
	struct mt76_priv *p = t->priv;
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

static void mt76_close(struct target *t)
{
	struct mt76_priv *p = t->priv;

	if (p->fd >= 0) {
		wlan_kmod_detach(p->fd, ELA_WLAN_DRV_MT76);
		wlan_kmod_close(p->fd);
		p->fd = -1;
	}
}

/* LCOV_EXCL_STOP */

struct target *target_mt76(void)
{
	static struct mt76_priv priv = { .fd = -1 };
	static struct target t = {
		.name = "mt76",
		.big_endian = 0,
		.msgs = mt76_msgs,
		.nmsgs = (int)(sizeof(mt76_msgs) / sizeof(mt76_msgs[0])),
		.attach = mt76_attach,
		.send = mt76_send,
		.probe_alive = mt76_probe,
		.recover = mt76_recover,
		.close = mt76_close,
		.priv = &priv,
	};

	return &t;
}
