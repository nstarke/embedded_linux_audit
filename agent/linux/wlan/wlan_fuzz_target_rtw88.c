// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Target: Realtek rtw88 USB (RTL8723DU/8821CU/8822BU/CU).
 * Grammar from rtw88/fw.h (kernel master).
 *
 * H2C = fixed 8-byte box, cmd id in byte 0. Delivered by writing
 * HMEBOX_EXT (bytes 4-7) then HMEBOX (bytes 0-3) via USB vendor ctrl
 * (bRequest 0x05, wValue = register address -- rtw_usb.c). Little-endian.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "wlan_fuzz.h"
#include "wlan_fuzz_usbfs.h"

#define REALTEK_VID   0x0BDA
#define USB_VENDOR_REQ 0x05

#define REG_HMETFR      0x01CC
#define REG_HMEBOX0     0x01D0
#define REG_HMEBOX_EXT0 0x0088
#define REG_MCUFW_CTRL  0x0080

#define H2C_MEDIA_STATUS 0x01
#define H2C_KEEP_ALIVE   0x03
#define H2C_PWR_MODE     0x20
#define H2C_DEFAULT_PORT 0x2C
#define H2C_RA_INFO      0x40
#define H2C_RSSI_MON     0x42
#define H2C_RA_INFO_HI   0x46
#define H2C_BCN_FILTER_P1 0x57
#define H2C_SCAN         0x59
#define H2C_QUERY_BT     0x61

#define MACID_MAX 32
#define PORT_MAX  5

static const struct field f_media[] = {
	{ "cmd",     FT_U8, FC_OPAQUE, H2C_MEDIA_STATUS, 0, 0 },
	{ "op_mode", FT_U8, FC_OPAQUE, 1, 0, 0 },
	{ "macid",   FT_U8, FC_INDEX, 0, MACID_MAX - 1, 0 },
	{ "pad",     FT_BYTES, FC_OPAQUE, 0, 0, 5 },
};
static const struct field f_defport[] = {
	{ "cmd",     FT_U8, FC_OPAQUE, H2C_DEFAULT_PORT, 0, 0 },
	{ "port_id", FT_U8, FC_INDEX, 0, PORT_MAX - 1, 0 },
	{ "macid",   FT_U8, FC_INDEX, 0, MACID_MAX - 1, 0 },
	{ "pad",     FT_BYTES, FC_OPAQUE, 0, 0, 5 },
};
static const struct field f_ra_info[] = {
	{ "cmd",     FT_U8, FC_OPAQUE, H2C_RA_INFO, 0, 0 },
	{ "macid",   FT_U8, FC_INDEX, 0, MACID_MAX - 1, 0 },
	{ "rateid",  FT_U8, FC_INDEX, 0, 9, 0 },
	{ "bw_sgi",  FT_U8, FC_OPAQUE, 0, 0, 0 },
	{ "ra_mask", FT_BYTES, FC_ARRAY, 0, 0, 4 },
};
static const struct field f_ra_hi[] = {
	{ "cmd",   FT_U8, FC_OPAQUE, H2C_RA_INFO_HI, 0, 0 },
	{ "macid", FT_U8, FC_INDEX, 0, MACID_MAX - 1, 0 },
	{ "body",  FT_BYTES, FC_ARRAY, 0, 0, 6 },
};
static const struct field f_rssi[] = {
	{ "cmd",    FT_U8, FC_OPAQUE, H2C_RSSI_MON, 0, 0 },
	{ "macid",  FT_U8, FC_INDEX, 0, MACID_MAX - 1, 0 },
	{ "unused", FT_U8, FC_OPAQUE, 0, 0, 0 },
	{ "rssi",   FT_U8, FC_OPAQUE, 40, 0, 0 },
	{ "pad",    FT_BYTES, FC_OPAQUE, 0, 0, 4 },
};
static const struct field f_bcnf[] = {
	{ "cmd",   FT_U8, FC_OPAQUE, H2C_BCN_FILTER_P1, 0, 0 },
	{ "macid", FT_U8, FC_INDEX, 0, MACID_MAX - 1, 0 },
	{ "cfg",   FT_BYTES, FC_OPAQUE, 0, 0, 6 },
};
static const struct field f_pwr[] = {
	{ "cmd",       FT_U8, FC_OPAQUE, H2C_PWR_MODE, 0, 0 },
	{ "mode",      FT_U8, FC_OPAQUE, 0, 0, 0 },
	{ "rlbm",      FT_U8, FC_OPAQUE, 0, 0, 0 },
	{ "awake_int", FT_U8, FC_OPAQUE, 1, 0, 0 },
	{ "port_byte", FT_U8, FC_INDEX, 0, PORT_MAX - 1, 0 },
	{ "pwr_state", FT_U8, FC_OPAQUE, 0, 0, 0 },
	{ "pad",       FT_BYTES, FC_OPAQUE, 0, 0, 2 },
};
static const struct field f_keepalive[] = {
	{ "cmd",    FT_U8, FC_OPAQUE, H2C_KEEP_ALIVE, 0, 0 },
	{ "enable", FT_U8, FC_OPAQUE, 1, 0, 0 },
	{ "period", FT_U8, FC_OPAQUE, 5, 0, 0 },
	{ "pad",    FT_BYTES, FC_OPAQUE, 0, 0, 5 },
};
static const struct field f_scan[] = {
	{ "cmd",   FT_U8, FC_OPAQUE, H2C_SCAN, 0, 0 },
	{ "start", FT_U8, FC_OPAQUE, 1, 0, 0 },
	{ "pad",   FT_BYTES, FC_OPAQUE, 0, 0, 6 },
};
static const struct field f_raw[] = {
	{ "cmd",  FT_U8, FC_OPAQUE, 0, 0, 0 },
	{ "body", FT_BYTES, FC_OPAQUE, 0, 0, 7 },
};

#define M(nm, flds, w) \
	{ nm, w, (int)(sizeof(flds) / sizeof(flds[0])), flds, 0 }

static const struct msg rtw88_msgs[] = {
	M("MEDIA_STATUS_RPT", f_media, 3.0),
	M("DEFAULT_PORT", f_defport, 3.0),
	M("RA_INFO", f_ra_info, 3.0),
	M("RA_INFO_HI", f_ra_hi, 2.0),
	M("RSSI_MONITOR", f_rssi, 2.0),
	M("BCN_FILTER_P1", f_bcnf, 2.0),
	M("SET_PWR_MODE", f_pwr, 2.0),
	M("KEEP_ALIVE", f_keepalive, 1.0),
	M("SCAN", f_scan, 1.0),
	M("RAW_BOX", f_raw, 0.5),
};

/* ---- transport ------------------------------------------------------------- */
/* Live USB transport needs the physical NIC, so it is out of coverage. */
/* LCOV_EXCL_START */

struct rtw_priv {
	int fd;
	uint32_t fw_ready_baseline;
};

static int reg_write(struct rtw_priv *p, uint16_t addr, uint32_t val, int w)
{
	uint8_t d[4] = { val & 0xFF, (val >> 8) & 0xFF,
			 (val >> 16) & 0xFF, (val >> 24) & 0xFF };

	return usbfs_ctrl(p->fd, 0x40, USB_VENDOR_REQ, addr, 0, d,
			  (uint16_t)w, 1000);
}

static int reg_read(struct rtw_priv *p, uint16_t addr, uint32_t *out, int w)
{
	uint8_t d[4] = { 0 };
	int r = usbfs_ctrl(p->fd, 0xC0, USB_VENDOR_REQ, addr, 0, d,
			   (uint16_t)w, 1000);

	*out = d[0] | (d[1] << 8) | (d[2] << 16) | ((uint32_t)d[3] << 24);
	return r;
}

static int rtw_attach(struct target *t)
{
	struct rtw_priv *p = t->priv;
	static const uint16_t pids[] = { 0xD723, 0xC820, 0xB82C, 0xC82C, 0x8822 };

	p->fd = usbfs_open(REALTEK_VID, pids, 5, NULL);
	if (p->fd < 0)
		return -1;
	usbfs_detach_kernel(p->fd, 0);
	if (usbfs_claim(p->fd, 0) < 0)
		return -1;
	return reg_read(p, REG_MCUFW_CTRL, &p->fw_ready_baseline, 4);
}

static int send_box(struct rtw_priv *p, const uint8_t box[8])
{
	uint32_t busy, main_w, ext_w;
	int i;

	for (i = 0; i < 50; i++) {
		if (reg_read(p, REG_HMETFR, &busy, 1) < 0)
			return -1;
		if (!(busy & 1))
			break;
		msleep_ms(2);
	}
	if (i == 50)
		return -1;	/* box stuck full: MCU not consuming */
	ext_w = box[4] | (box[5] << 8) | (box[6] << 16) | ((uint32_t)box[7] << 24);
	main_w = box[0] | (box[1] << 8) | (box[2] << 16) | ((uint32_t)box[3] << 24);
	if (reg_write(p, REG_HMEBOX_EXT0, ext_w, 4) < 0)
		return -1;
	return reg_write(p, REG_HMEBOX0, main_w, 4);	/* triggers fetch */
}

static int rtw_send(struct target *t, const struct msg *m,
		    const uint8_t *payload, int len)
{
	uint8_t box[8] = { 0 };

	(void)m;
	memcpy(box, payload, len > 8 ? 8 : (size_t)len);	/* clamp: fixed box */
	return send_box(t->priv, box);
}

static int rtw_probe(struct target *t)
{
	struct rtw_priv *p = t->priv;
	uint8_t box[8] = { H2C_QUERY_BT };
	uint32_t busy, ctrl;

	if (send_box(p, box) < 0)
		return 0;
	msleep_ms(20);
	if (reg_read(p, REG_HMETFR, &busy, 1) < 0 || (busy & 1))
		return 0;	/* MCU never drained the box */
	if (reg_read(p, REG_MCUFW_CTRL, &ctrl, 4) < 0)
		return 0;
	return (ctrl & 0xFF) == (p->fw_ready_baseline & 0xFF);
}

static int rtw_recover(struct target *t)
{
	return usb_recover_generic(t, 10, 2000);
}

static void rtw_close(struct target *t)
{
	struct rtw_priv *p = t->priv;

	if (p->fd >= 0) {
		close(p->fd);
		p->fd = -1;
	}
}

/* LCOV_EXCL_STOP */

struct target *target_rtw88(void)
{
	static struct rtw_priv priv = { .fd = -1 };
	static struct target t = {
		.name = "rtw88-usb",
		.big_endian = 0,
		.msgs = rtw88_msgs,
		.nmsgs = (int)(sizeof(rtw88_msgs) / sizeof(rtw88_msgs[0])),
		.attach = rtw_attach,
		.send = rtw_send,
		.probe_alive = rtw_probe,
		.recover = rtw_recover,
		.close = rtw_close,
		.priv = &priv,
	};

	return &t;
}
