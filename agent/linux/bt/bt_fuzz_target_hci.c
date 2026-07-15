// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Target: generic Bluetooth controller via HCI commands, addressed by
 * controller index (hci0, hci1, ...). Fuzzes the host->controller HCI command
 * interface over a raw HCI User Channel socket -- the direct analog of
 * wext-generic/ethtool-generic, but HCI is a genuine firmware command protocol
 * (opcode + parameter-length + params), so this is class-directed.
 *
 * The grammar drives the parameter-length byte the controller trusts against
 * the actual params, and the length bytes inside LE advertising/scan data
 * (LE_Set_Advertising_Data et al.) -- the classic "firmware trusts a length
 * against a fixed buffer" class -- plus opcode sweeps over the standard/LE and
 * vendor command space.
 *
 * >>> Fuzzed commands traverse the kernel HCI layer + driver on the way to the
 *     controller firmware. They can crash the controller firmware AND oops or
 *     PANIC the host kernel (pair with --output-http for remote crash capture).
 *     Needs CAP_NET_ADMIN and the controller DOWN (User Channel is exclusive:
 *     `sudo hciconfig hciN down`, or stop bluetoothd / rfkill block, first).
 *     AUTHORIZED USE ONLY, on your own hardware. <<<
 *
 * Liveness is judged out-of-band by Read_BD_ADDR (a harmless read); a wedged
 * controller stops answering.
 */
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "bt_fuzz.h"
#include "bt_fuzz_hci.h"

#ifndef SOCK_RAW
#define SOCK_RAW 3
#endif

/* Standard opcodes (OGF, OCF). */
#define OP_RESET             HCI_OPCODE(0x03, 0x0003)
#define OP_SET_EVENT_MASK    HCI_OPCODE(0x03, 0x0001)
#define OP_WRITE_LOCAL_NAME  HCI_OPCODE(0x03, 0x0013)
#define OP_INQUIRY           HCI_OPCODE(0x01, 0x0001)
#define OP_READ_LOCAL_VER    HCI_OPCODE(0x04, 0x0001)
#define OP_READ_BD_ADDR      HCI_OPCODE(0x04, 0x0009)
#define OP_LE_SET_ADV_PARAM  HCI_OPCODE(0x08, 0x0006)
#define OP_LE_SET_ADV_DATA   HCI_OPCODE(0x08, 0x0008)
#define OP_LE_SET_SCAN_PARAM HCI_OPCODE(0x08, 0x000B)
#define OP_LE_SET_SCAN_EN    HCI_OPCODE(0x08, 0x000C)
#define OP_LE_SET_EXT_ADV    HCI_OPCODE(0x08, 0x0037)

/* Field order = the little-endian on-wire layout after the packet-type byte:
 * opcode(2), param_total_len(1), params. `plen`/inner length bytes are the
 * trust boundaries, so they carry FC_LENGTH. */
static const struct field f_reset[] = {
	{ "opcode", FT_U16, FC_OPAQUE, OP_RESET, 0, 0 },
	{ "plen",   FT_U8,  FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_set_event_mask[] = {
	{ "opcode", FT_U16, FC_OPAQUE, OP_SET_EVENT_MASK, 0, 0 },
	{ "plen",   FT_U8,  FC_LENGTH, 8, 0, 0 },
	{ "mask",   FT_BYTES, FC_OPAQUE, 0, 0, 8 },
};
static const struct field f_write_local_name[] = {
	{ "opcode", FT_U16, FC_OPAQUE, OP_WRITE_LOCAL_NAME, 0, 0 },
	{ "plen",   FT_U8,  FC_LENGTH, 248, 0, 0 },	/* vs the 248-byte name buf */
	{ "name",   FT_BYTES, FC_LENGTH, 0, 0, 32 },
};
static const struct field f_inquiry[] = {
	{ "opcode",   FT_U16, FC_OPAQUE, OP_INQUIRY, 0, 0 },
	{ "plen",     FT_U8,  FC_LENGTH, 5, 0, 0 },
	{ "lap",      FT_BYTES, FC_OPAQUE, 0, 0, 3 },
	{ "length",   FT_U8,  FC_OPAQUE, 0, 0, 0 },
	{ "num_resp", FT_U8,  FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_read_local_ver[] = {
	{ "opcode", FT_U16, FC_OPAQUE, OP_READ_LOCAL_VER, 0, 0 },
	{ "plen",   FT_U8,  FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_read_bd_addr[] = {
	{ "opcode", FT_U16, FC_OPAQUE, OP_READ_BD_ADDR, 0, 0 },
	{ "plen",   FT_U8,  FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_le_adv_param[] = {
	{ "opcode",    FT_U16, FC_OPAQUE, OP_LE_SET_ADV_PARAM, 0, 0 },
	{ "plen",      FT_U8,  FC_LENGTH, 15, 0, 0 },
	{ "min_int",   FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "max_int",   FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "adv_type",  FT_U8,  FC_INDEX,  0, 4, 0 },
	{ "own_type",  FT_U8,  FC_OPAQUE, 0, 0, 0 },
	{ "peer_type", FT_U8,  FC_OPAQUE, 0, 0, 0 },
	{ "peer_addr", FT_BYTES, FC_OPAQUE, 0, 0, 6 },
	{ "chan_map",  FT_U8,  FC_OPAQUE, 7, 0, 0 },
	{ "filter",    FT_U8,  FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_le_adv_data[] = {	/* len byte vs 31-byte AD buf */
	{ "opcode",  FT_U16, FC_OPAQUE, OP_LE_SET_ADV_DATA, 0, 0 },
	{ "plen",    FT_U8,  FC_OPAQUE, 32, 0, 0 },
	{ "adv_len", FT_U8,  FC_LENGTH, 31, 0, 0 },	/* controller trusts this */
	{ "adv_data", FT_BYTES, FC_ARRAY, 0, 0, 31 },
};
static const struct field f_le_scan_param[] = {
	{ "opcode",   FT_U16, FC_OPAQUE, OP_LE_SET_SCAN_PARAM, 0, 0 },
	{ "plen",     FT_U8,  FC_LENGTH, 7, 0, 0 },
	{ "scan_type", FT_U8, FC_OPAQUE, 0, 0, 0 },
	{ "interval", FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "window",   FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "own_type", FT_U8,  FC_OPAQUE, 0, 0, 0 },
	{ "filter",   FT_U8,  FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_le_scan_enable[] = {
	{ "opcode",     FT_U16, FC_OPAQUE, OP_LE_SET_SCAN_EN, 0, 0 },
	{ "plen",       FT_U8,  FC_LENGTH, 2, 0, 0 },
	{ "enable",     FT_U8,  FC_OPAQUE, 0, 0, 0 },
	{ "filter_dup", FT_U8,  FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_le_ext_adv[] = {	/* nested data_len trust boundary */
	{ "opcode",    FT_U16, FC_OPAQUE, OP_LE_SET_EXT_ADV, 0, 0 },
	{ "plen",      FT_U8,  FC_LENGTH, 0, 0, 0 },
	{ "handle",    FT_U8,  FC_INDEX,  0, 0xEF, 0 },
	{ "operation", FT_U8,  FC_OPAQUE, 3, 0, 0 },
	{ "frag_pref", FT_U8,  FC_OPAQUE, 1, 0, 0 },
	{ "data_len",  FT_U8,  FC_LENGTH, 32, 0, 0 },
	{ "data",      FT_BYTES, FC_ARRAY, 0, 0, 32 },
};
static const struct field f_raw[] = {	/* sweep the standard/LE opcode space */
	{ "opcode", FT_U16, FC_INDEX, OP_RESET, 0x2800, 0 },
	{ "plen",   FT_U8,  FC_LENGTH, 0, 0, 0 },
	{ "params", FT_BYTES, FC_LENGTH, 0, 0, 16 },
};
static const struct field f_vendor[] = {	/* wide sweep incl. vendor (0xFCxx) */
	{ "opcode", FT_U16, FC_INDEX, 0xFC00, 0xFFFF, 0 },
	{ "plen",   FT_U8,  FC_LENGTH, 0, 0, 0 },
	{ "params", FT_BYTES, FC_LENGTH, 0, 0, 16 },
};

#define M(nm, flds, w) \
	{ nm, w, (int)(sizeof(flds) / sizeof(flds[0])), flds, 0 }

static const struct msg hci_msgs[] = {
	M("RESET",             f_reset,           1.0),
	M("SET_EVENT_MASK",    f_set_event_mask,  1.5),
	M("WRITE_LOCAL_NAME",  f_write_local_name, 2.5),
	M("INQUIRY",           f_inquiry,         1.5),
	M("READ_LOCAL_VER",    f_read_local_ver,  1.0),
	M("READ_BD_ADDR",      f_read_bd_addr,    0.5),
	M("LE_SET_ADV_PARAM",  f_le_adv_param,    2.0),
	M("LE_SET_ADV_DATA",   f_le_adv_data,     3.0),
	M("LE_SET_SCAN_PARAM", f_le_scan_param,   2.0),
	M("LE_SET_SCAN_ENABLE", f_le_scan_enable, 1.5),
	M("LE_SET_EXT_ADV",    f_le_ext_adv,      2.5),
	M("HCI_RAW",           f_raw,             2.0),
	M("HCI_VENDOR",        f_vendor,          1.5),
};

/* ---- transport (raw HCI User Channel) ------------------------------------- */
/* Live transport needs a controller + root, so it is out of coverage. */
/* LCOV_EXCL_START */

struct hci_priv {
	int fd;
	int dev_index;
};

static int hci_bind_user(int dev_index)
{
	struct bt_sockaddr_hci addr;
	int fd = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);

	if (fd < 0)
		return -1;
	memset(&addr, 0, sizeof(addr));
	addr.hci_family = AF_BLUETOOTH;
	addr.hci_dev = (uint16_t)dev_index;
	addr.hci_channel = HCI_CHANNEL_USER;
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static int hci_attach(struct target *t)
{
	struct hci_priv *p = t->priv;

	p->fd = hci_bind_user(p->dev_index);
	if (p->fd < 0) {
		fprintf(stderr,
			"[!] hci%d: cannot open HCI User Channel: %s\n"
			"    (need root/CAP_NET_ADMIN and the controller DOWN --\n"
			"     `sudo hciconfig hci%d down`, or stop bluetoothd / rfkill block)\n",
			p->dev_index, strerror(errno), p->dev_index);
		return -1;
	}
	return 0;
}

/* Discard any pending events so the socket buffer does not fill. */
static void hci_drain(int fd)
{
	uint8_t buf[512];
	struct pollfd pfd = { .fd = fd, .events = POLLIN };

	while (poll(&pfd, 1, 0) > 0 && (pfd.revents & POLLIN)) {
		if (read(fd, buf, sizeof(buf)) <= 0)
			break;
	}
}

static int hci_send(struct target *t, const struct msg *m,
		    const uint8_t *payload, int len)
{
	struct hci_priv *p = t->priv;
	uint8_t pkt[1 + 3 + 256];
	int n;

	(void)m;
	if (len < 3)			/* opcode(2) + plen(1) minimum */
		return 0;
	if (len > (int)sizeof(pkt) - 1)
		len = sizeof(pkt) - 1;
	pkt[0] = HCI_COMMAND_PKT;
	memcpy(pkt + 1, payload, (size_t)len);
	n = (int)write(p->fd, pkt, (size_t)len + 1);
	hci_drain(p->fd);
	if (n < 0 && (errno == ENODEV || errno == ENOTCONN))
		return -1;	/* controller vanished: transport dead */
	return 0;		/* command rejections come back as events, not here */
}

/* Read_BD_ADDR: a harmless read any live controller answers with an event. */
static int hci_probe(struct target *t)
{
	struct hci_priv *p = t->priv;
	uint8_t cmd[4] = { HCI_COMMAND_PKT, OP_READ_BD_ADDR & 0xFF,
			   (OP_READ_BD_ADDR >> 8) & 0xFF, 0 };
	struct pollfd pfd = { .fd = p->fd, .events = POLLIN };
	int i;

	hci_drain(p->fd);
	for (i = 0; i < 3; i++) {
		if (write(p->fd, cmd, sizeof(cmd)) < 0) {
			if (errno == ENODEV || errno == ENOTCONN)
				return 0;
		} else if (poll(&pfd, 1, 300) > 0 && (pfd.revents & POLLIN)) {
			hci_drain(p->fd);
			return 1;	/* controller responded */
		}
	}
	return 0;
}

static int hci_recover(struct target *t)
{
	struct hci_priv *p = t->priv;

	if (p->fd >= 0)
		close(p->fd);
	msleep_ms(1000);	/* let a reset/re-enumeration settle */
	p->fd = hci_bind_user(p->dev_index);
	if (p->fd < 0)
		return 0;
	return hci_probe(t);
}

static void hci_close(struct target *t)
{
	struct hci_priv *p = t->priv;

	if (p->fd >= 0) {
		close(p->fd);
		p->fd = -1;
	}
}

/* LCOV_EXCL_STOP */

struct target *target_hci_generic(int dev_index)
{
	static struct hci_priv priv = { .fd = -1 };
	static struct target t = {
		.name = "hci-generic",
		.big_endian = 0,
		.msgs = hci_msgs,
		.nmsgs = (int)(sizeof(hci_msgs) / sizeof(hci_msgs[0])),
		.attach = hci_attach,
		.send = hci_send,
		.probe_alive = hci_probe,
		.recover = hci_recover,
		.close = hci_close,
		.priv = &priv,
	};

	priv.dev_index = dev_index;
	return &t;
}
