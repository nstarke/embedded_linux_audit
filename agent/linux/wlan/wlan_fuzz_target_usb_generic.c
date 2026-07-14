// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Target: generic/blind USB WLAN NIC, addressed by VID:PID.
 *
 * For proprietary or otherwise-unknown USB dongles that `wlan list` flags but
 * that map to no class-directed target (no known firmware command grammar).
 * There is nothing chip-specific to model here, so instead of a real command
 * grammar this target structurally mutates the USB transport itself:
 *
 *   VENDOR_WRITE  host->device vendor control transfer (bmRequestType 0x40)
 *   VENDOR_READ   device->host vendor control transfer (bmRequestType 0xC0)
 *   BULK_OUT      bulk/interrupt OUT write to a data endpoint
 *
 * The request/value/index bytes and the payload length are the fuzzed fields.
 * Because a blind sweep provokes STALLs and endpoint errors constantly, those
 * are NOT treated as firmware death -- only a vanished device (ENODEV) is.
 * Liveness is judged out-of-band by a standard GET_DESCRIPTOR probe on ep0,
 * which any healthy device answers and a wedged/crashed controller does not.
 *
 * USB only. Proprietary PCIe/SoC radios expose no userspace command transport
 * and their driver symbols are unknown to the ela_kmod shim, so they cannot be
 * reached this way.
 *
 * AUTHORIZED USE ONLY: run against your own hardware. Crashes firmware by
 * design.
 */
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "wlan_fuzz.h"
#include "wlan_fuzz_usbfs.h"

/* wire header widths shared by the grammar layout and the send() parser */
#define CTRL_HDR   6	/* bmRequestType,bRequest,wValue(2),wIndex(2) */
#define BULK_HDR   1	/* endpoint */
#define CTRL_DATA  16	/* nominal control payload size */
#define BULK_DATA  32	/* nominal bulk payload size   */

enum { GEN_VENDOR_WRITE = 0, GEN_VENDOR_READ = 1, GEN_BULK_OUT = 2 };

/*
 * Field order defines the byte layout msg_build renders (little-endian, so
 * u16 wValue/wIndex land as two LE bytes that send() reassembles). bRequest is
 * INDEX so the mutator sweeps the request-code boundaries; wValue/wIndex are
 * OPAQUE (boundary integers); the payload is LENGTH so its size is driven
 * across the short/long boundaries where framing bugs live.
 */
static const struct field f_vendor_write[] = {
	{ "bmRequestType", FT_U8,    FC_OPAQUE, 0x40, 0,    0 },
	{ "bRequest",      FT_U8,    FC_INDEX,  0,    0xFF, 0 },
	{ "wValue",        FT_U16,   FC_OPAQUE, 0,    0,    0 },
	{ "wIndex",        FT_U16,   FC_OPAQUE, 0,    0,    0 },
	{ "data",          FT_BYTES, FC_LENGTH, 0,    0,    CTRL_DATA },
};
static const struct field f_vendor_read[] = {
	{ "bmRequestType", FT_U8,    FC_OPAQUE, 0xC0, 0,    0 },
	{ "bRequest",      FT_U8,    FC_INDEX,  0,    0xFF, 0 },
	{ "wValue",        FT_U16,   FC_OPAQUE, 0,    0,    0 },
	{ "wIndex",        FT_U16,   FC_OPAQUE, 0,    0,    0 },
	{ "data",          FT_BYTES, FC_LENGTH, 0,    0,    CTRL_DATA },
};
static const struct field f_bulk_out[] = {
	{ "endpoint", FT_U8,    FC_INDEX,  0x01, 0x0F, 0 },
	{ "data",     FT_BYTES, FC_LENGTH, 0,    0,    BULK_DATA },
};

static const struct msg usb_generic_msgs[] = {
	{ "VENDOR_WRITE", 3.0, 5, f_vendor_write, GEN_VENDOR_WRITE },
	{ "VENDOR_READ",  1.0, 5, f_vendor_read,  GEN_VENDOR_READ },
	{ "BULK_OUT",     2.0, 2, f_bulk_out,     GEN_BULK_OUT },
};

/* ---- transport ------------------------------------------------------------- */
/* Live USB transport needs the physical NIC, so it is out of coverage. */
/* LCOV_EXCL_START */

struct gen_priv {
	int      fd;
	uint16_t vid;
	uint16_t pid;
};

static int gen_attach(struct target *t)
{
	struct gen_priv *p = t->priv;

	p->fd = usbfs_open(p->vid, &p->pid, 1, NULL);
	if (p->fd < 0)
		return -1;
	/* Best-effort: unbind any kernel driver and claim interface 0 so bulk
	 * transfers are permitted. Control transfers on ep0 work regardless, so
	 * a claim failure is not fatal. */
	usbfs_detach_kernel(p->fd, 0);
	usbfs_claim(p->fd, 0);
	return 0;
}

/*
 * A blind transfer legitimately STALLs/times out on most request codes; that
 * is not firmware death. Report dead (-1) only when the device itself is gone.
 */
static int xfer_result(int r)
{
	if (r >= 0)
		return 0;
	return errno == ENODEV ? -1 : 0;
}

static int gen_send(struct target *t, const struct msg *m,
		    const uint8_t *payload, int len)
{
	struct gen_priv *p = t->priv;
	uint8_t data[FIELD_BYTES_MAX];
	int dlen, r;

	if (m->cmd_id == GEN_BULK_OUT) {
		unsigned int ep;

		if (len < BULK_HDR)
			return 0;
		dlen = len - BULK_HDR;
		if (dlen > (int)sizeof(data))
			dlen = sizeof(data);
		memcpy(data, payload + BULK_HDR, (size_t)dlen);
		ep = payload[0] & 0x0F;		/* OUT endpoint (bit7 clear) */
		return xfer_result(usbfs_xfer(p->fd, ep, data, dlen, 1000));
	}

	if (len < CTRL_HDR)
		return 0;
	dlen = len - CTRL_HDR;
	if (dlen > (int)sizeof(data))
		dlen = sizeof(data);
	memcpy(data, payload + CTRL_HDR, (size_t)dlen);	/* writable: IN fills it */
	r = usbfs_ctrl(p->fd, payload[0], payload[1],
		       (uint16_t)(payload[2] | (payload[3] << 8)),
		       (uint16_t)(payload[4] | (payload[5] << 8)),
		       data, (uint16_t)dlen, 1000);
	return xfer_result(r);
}

/* GET_DESCRIPTOR(device) on ep0: a healthy device always answers. */
static int gen_probe(struct target *t)
{
	struct gen_priv *p = t->priv;
	uint8_t desc[18];
	int i;

	for (i = 0; i < 3; i++) {
		int r = usbfs_ctrl(p->fd, 0x80, 0x06, 0x0100, 0, desc,
				   sizeof(desc), 1000);

		if (r >= (int)sizeof(desc))
			return 1;
		if (errno == ENODEV)
			return 0;
		msleep_ms(50);
	}
	return 0;
}

static int gen_recover(struct target *t)
{
	return usb_recover_generic(t, 10, 2000);
}

static void gen_close(struct target *t)
{
	struct gen_priv *p = t->priv;

	if (p->fd >= 0) {
		close(p->fd);
		p->fd = -1;
	}
}

/* LCOV_EXCL_STOP */

struct target *target_usb_generic(uint16_t vid, uint16_t pid)
{
	static struct gen_priv priv = { .fd = -1 };
	static struct target t = {
		.name = "usb-generic",
		.big_endian = 0,
		.msgs = usb_generic_msgs,
		.nmsgs = (int)(sizeof(usb_generic_msgs) / sizeof(usb_generic_msgs[0])),
		.attach = gen_attach,
		.send = gen_send,
		.probe_alive = gen_probe,
		.recover = gen_recover,
		.close = gen_close,
		.priv = &priv,
	};

	priv.vid = vid;
	priv.pid = pid;
	return &t;
}
