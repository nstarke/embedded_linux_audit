// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Target: Realtek rtl8xxxu USB (RTL8723AU/BU, RTL8188EU/FU, RTL8192EU/FU,
 * RTL8710BU). Grammar + transport extracted from
 * drivers/net/wireless/realtek/rtl8xxxu/{rtl8xxxu.h,core.c,regs.h}
 * (kernel master).
 *
 * H2C = fixed <=8-byte mailbox "box", cmd id in byte 0 (struct h2c_cmd).
 * Delivered gen2-style: write HMBOX_EXT (bytes 4-7) then HMBOX (bytes 0-3)
 * via USB vendor control transfers (bRequest 0x05; rtl8xxxu_write32).
 * Little-endian. This is a distinct chip family and command set from the
 * newer rtw88 target, though the mailbox transport is the same shape.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "wlan_fuzz.h"
#include "wlan_fuzz_usbfs.h"

#define REALTEK_VID   0x0BDA
#define USB_VENDOR_REQ 0x05	/* REALTEK_USB_CMD_REQ */

/* registers (regs.h); gen2/8723B mailbox-ext layout */
#define REG_HMTFR         0x01CC
#define REG_HMBOX0        0x01D0
#define REG_HMBOX_EXT0    0x01F0	/* REG_HMBOX_EXT0_8723B */
#define REG_MCU_FW_DL     0x0080

/* enum h2c_cmd_8723b (rtl8xxxu.h) */
#define H2C_MEDIA_STATUS_RPT 0x01
#define H2C_SCAN_ENABLE      0x02
#define H2C_KEEP_ALIVE       0x03
#define H2C_AP_OFFLOAD       0x08
#define H2C_SET_PWR_MODE     0x20
#define H2C_MACID_CFG_RAID   0x40
#define H2C_RSSI_SETTING     0x42
#define H2C_BT_MP_OPER       0x67

/*
 * macid indexes the firmware station table. Its size is chip-dependent
 * (16 on 8188F/8710B, 32 on 8192C, 128 on 8723B/8192E/8192F), so the two
 * range endpoints of MEDIA_STATUS_RPT probe the small- and large-table
 * off-by-ones separately; the boundary set also always hits 0x7F/0x80/0xFF.
 */
#define MACID_SMALL 16
#define MACID_LARGE 128

static const struct field f_media[] = {	/* media_status_rpt: macid range */
	{ "cmd",       FT_U8, FC_OPAQUE, H2C_MEDIA_STATUS_RPT, 0, 0 },
	{ "parm",      FT_U8, FC_OPAQUE, 1, 0, 0 },
	{ "macid",     FT_U8, FC_INDEX, 0, MACID_SMALL - 1, 0 },
	{ "macid_end", FT_U8, FC_INDEX, 0, MACID_LARGE - 1, 0 },
};
static const struct field f_macid_cfg[] = {	/* b_macid_cfg: rate-mask array */
	{ "cmd",    FT_U8, FC_OPAQUE, H2C_MACID_CFG_RAID, 0, 0 },
	{ "macid",  FT_U8, FC_INDEX, 0, MACID_SMALL - 1, 0 },
	{ "data1",  FT_U8, FC_OPAQUE, 0, 0, 0 },	/* [0:4] RAID, [7] SGI */
	{ "data2",  FT_U8, FC_OPAQUE, 0, 0, 0 },
	{ "ramask", FT_BYTES, FC_ARRAY, 0, 0, 4 },
};
static const struct field f_rssi[] = {	/* rssi_report */
	{ "cmd",          FT_U8, FC_OPAQUE, H2C_RSSI_SETTING, 0, 0 },
	{ "macid",        FT_U8, FC_INDEX, 0, MACID_SMALL - 1, 0 },
	{ "unknown0",     FT_U8, FC_OPAQUE, 0, 0, 0 },
	{ "rssi",         FT_U8, FC_OPAQUE, 40, 0, 0 },
	{ "data",         FT_U8, FC_OPAQUE, 0, 0, 0 },
	{ "ra_th_offset", FT_U8, FC_OPAQUE, 0, 0, 0 },
	{ "pad",          FT_BYTES, FC_OPAQUE, 0, 0, 2 },
};
static const struct field f_pwr[] = {	/* set_pwr_mode box */
	{ "cmd",       FT_U8, FC_OPAQUE, H2C_SET_PWR_MODE, 0, 0 },
	{ "mode",      FT_U8, FC_OPAQUE, 0, 0, 0 },
	{ "rlbm",      FT_U8, FC_OPAQUE, 0, 0, 0 },
	{ "smart_ps",  FT_U8, FC_OPAQUE, 0, 0, 0 },
	{ "awake_int", FT_U8, FC_OPAQUE, 1, 0, 0 },
	{ "pad",       FT_BYTES, FC_OPAQUE, 0, 0, 3 },
};
static const struct field f_scan[] = {
	{ "cmd",    FT_U8, FC_OPAQUE, H2C_SCAN_ENABLE, 0, 0 },
	{ "enable", FT_U8, FC_OPAQUE, 1, 0, 0 },
	{ "pad",    FT_BYTES, FC_OPAQUE, 0, 0, 6 },
};
static const struct field f_keepalive[] = {
	{ "cmd",    FT_U8, FC_OPAQUE, H2C_KEEP_ALIVE, 0, 0 },
	{ "enable", FT_U8, FC_OPAQUE, 0, 0, 0 },
	{ "period", FT_U8, FC_OPAQUE, 5, 0, 0 },
	{ "pad",    FT_BYTES, FC_OPAQUE, 0, 0, 5 },
};
static const struct field f_btmp[] = {	/* bt_mp_oper: opcode indexes BT table */
	{ "cmd",     FT_U8, FC_OPAQUE, H2C_BT_MP_OPER, 0, 0 },
	{ "operreq", FT_U8, FC_OPAQUE, 0, 0, 0 },
	{ "opcode",  FT_U8, FC_INDEX, 0, 20, 0 },
	{ "data",    FT_U8, FC_OPAQUE, 0, 0, 0 },
	{ "addr",    FT_U8, FC_INDEX, 0, 0xFF, 0 },
};
static const struct field f_apoffload[] = {
	{ "cmd",   FT_U8, FC_OPAQUE, H2C_AP_OFFLOAD, 0, 0 },
	{ "data1", FT_U8, FC_OPAQUE, 0, 0, 0 },
	{ "data2", FT_U8, FC_OPAQUE, 0, 0, 0 },
	{ "data3", FT_U8, FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_raw[] = {	/* arbitrary cmd id + box body */
	{ "cmd",  FT_U8, FC_INDEX, 0, H2C_BT_MP_OPER, 0 },
	{ "body", FT_BYTES, FC_OPAQUE, 0, 0, 7 },
};

#define M(nm, flds, w) \
	{ nm, w, (int)(sizeof(flds) / sizeof(flds[0])), flds, 0 }

static const struct msg rtl8xxxu_msgs[] = {
	M("MEDIA_STATUS_RPT", f_media, 3.0),
	M("MACID_CFG_RAID", f_macid_cfg, 3.0),
	M("RSSI_SETTING", f_rssi, 2.0),
	M("SET_PWR_MODE", f_pwr, 2.0),
	M("SCAN_ENABLE", f_scan, 1.5),
	M("KEEP_ALIVE", f_keepalive, 1.0),
	M("BT_MP_OPER", f_btmp, 1.5),
	M("AP_OFFLOAD", f_apoffload, 1.0),
	M("RAW_BOX", f_raw, 1.0),
};

/* ---- transport ------------------------------------------------------------- */
/* Live USB transport needs the physical NIC, so it is out of coverage. */
/* LCOV_EXCL_START */

struct rtl_priv {
	int fd;
	uint32_t fw_ready_baseline;
};

static int reg_write(struct rtl_priv *p, uint16_t addr, uint32_t val, int w)
{
	uint8_t d[4] = { val & 0xFF, (val >> 8) & 0xFF,
			 (val >> 16) & 0xFF, (val >> 24) & 0xFF };

	return usbfs_ctrl(p->fd, 0x40, USB_VENDOR_REQ, addr, 0, d,
			  (uint16_t)w, 1000);
}

static int reg_read(struct rtl_priv *p, uint16_t addr, uint32_t *out, int w)
{
	uint8_t d[4] = { 0 };
	int r = usbfs_ctrl(p->fd, 0xC0, USB_VENDOR_REQ, addr, 0, d,
			   (uint16_t)w, 1000);

	*out = d[0] | (d[1] << 8) | (d[2] << 16) | ((uint32_t)d[3] << 24);
	return r;
}

static int rtl_attach(struct target *t)
{
	struct rtl_priv *p = t->priv;
	/* common gen2 rtl8xxxu USB PIDs (core.c id_table) */
	static const uint16_t pids[] = {
		0xB720, 0x818B, 0xF179, 0x8179, 0x8724, 0x0179,
	};

	p->fd = usbfs_open(REALTEK_VID, pids, 6, NULL);
	if (p->fd < 0)
		return -1;
	usbfs_detach_kernel(p->fd, 0);
	if (usbfs_claim(p->fd, 0) < 0)
		return -1;
	return reg_read(p, REG_MCU_FW_DL, &p->fw_ready_baseline, 4);
}

static int send_box(struct rtl_priv *p, const uint8_t box[8])
{
	uint32_t busy, main_w, ext_w;
	int i;

	for (i = 0; i < 100; i++) {	/* wait for mbox 0 ready (HMTFR bit0) */
		if (reg_read(p, REG_HMTFR, &busy, 1) < 0)
			return -1;
		if (!(busy & 1))
			break;
		msleep_ms(2);
	}
	if (i == 100)
		return -1;	/* mailbox stuck full: MCU not consuming */
	ext_w = box[4] | (box[5] << 8) | (box[6] << 16) | ((uint32_t)box[7] << 24);
	main_w = box[0] | (box[1] << 8) | (box[2] << 16) | ((uint32_t)box[3] << 24);
	if (reg_write(p, REG_HMBOX_EXT0, ext_w, 4) < 0)
		return -1;
	return reg_write(p, REG_HMBOX0, main_w, 4);	/* triggers fetch */
}

static int rtl_send(struct target *t, const struct msg *m,
		    const uint8_t *payload, int len)
{
	uint8_t box[8] = { 0 };

	(void)m;
	memcpy(box, payload, len > 8 ? 8 : (size_t)len);	/* clamp: fixed box */
	return send_box(t->priv, box);
}

static int rtl_probe(struct target *t)
{
	struct rtl_priv *p = t->priv;
	uint8_t box[8] = { H2C_KEEP_ALIVE, 0 };	/* benign: keep-alive disabled */
	uint32_t busy, ctrl;

	if (send_box(p, box) < 0)
		return 0;
	msleep_ms(20);
	if (reg_read(p, REG_HMTFR, &busy, 1) < 0 || (busy & 1))
		return 0;	/* MCU never drained the box */
	if (reg_read(p, REG_MCU_FW_DL, &ctrl, 4) < 0)
		return 0;
	return (ctrl & 0xFF) == (p->fw_ready_baseline & 0xFF);
}

static int rtl_recover(struct target *t)
{
	return usb_recover_generic(t, 10, 2000);
}

static void rtl_close(struct target *t)
{
	struct rtl_priv *p = t->priv;

	if (p->fd >= 0) {
		close(p->fd);
		p->fd = -1;
	}
}

/* LCOV_EXCL_STOP */

struct target *target_rtl8xxxu(void)
{
	static struct rtl_priv priv = { .fd = -1 };
	static struct target t = {
		.name = "rtl8xxxu",
		.big_endian = 0,
		.msgs = rtl8xxxu_msgs,
		.nmsgs = (int)(sizeof(rtl8xxxu_msgs) / sizeof(rtl8xxxu_msgs[0])),
		.attach = rtl_attach,
		.send = rtl_send,
		.probe_alive = rtl_probe,
		.recover = rtl_recover,
		.close = rtl_close,
		.priv = &priv,
	};

	return &t;
}
