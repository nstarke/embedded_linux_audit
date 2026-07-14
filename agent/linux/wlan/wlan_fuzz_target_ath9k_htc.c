// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Target: Atheros AR9271/AR7010 (ath9k-htc firmware).
 *
 * Wire formats verified against target_firmware/wlan/include/htc.h, wmi.h:
 *   HTC hdr (8B, BE): u8 eid, u8 flags, u16 payload_len, u8 ctrl[4]
 *   WMI hdr (4B, BE): u16 command_id, u16 seq_no
 * EP4 0x04 int OUT = command pipe, EP3 0x83 int IN = replies.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "wlan_fuzz.h"
#include "wlan_fuzz_usbfs.h"

#define ATHEROS_VID 0x0CF3
#define EP_CMD_OUT  0x04
#define EP_REG_IN   0x83

/* WMI command ids (wmi.h enum) */
#define WMI_ECHO         0x0001
#define WMI_DRAIN_TXQ    0x000A
#define WMI_SET_MODE     0x000F
#define WMI_NODE_CREATE  0x0010
#define WMI_NODE_REMOVE  0x0011
#define WMI_VAP_REMOVE   0x0012
#define WMI_VAP_CREATE   0x0013
#define WMI_REG_READ     0x0014
#define WMI_REG_WRITE    0x0015
#define WMI_RC_STATE     0x0016
#define WMI_RC_RATE      0x0017
#define WMI_IC_UPDATE    0x0018
#define WMI_AGGR_ENABLE  0x0019
#define WMI_NODE_UPDATE  0x001B
#define WMI_BITRATE_MASK 0x001F

#define HTC_MSG_CONNECT   2
#define HTC_MSG_SETUP     4
#define HTC_MSG_CONF_PIPE 5
#define WMI_CONTROL_SVC   0x0100

#define CMDID_HTC_RAW 0xFFFF	/* pseudo-cmd: raw HTC frame, fuzz the eid */

/* ---- grammar (audit-verified layouts: sc_sta[8], sc_vap[2], txq[10]) ----- */

static const struct field f_echo[] = {
	{ "payload", FT_BYTES, FC_LENGTH, 0, 0, 32 },
};
static const struct field f_reg_read[] = {
	{ "addrs", FT_BYTES, FC_LENGTH, 0, 0, 16 },
};
static const struct field f_reg_write[] = {
	{ "pairs", FT_BYTES, FC_OPAQUE, 0, 0, 16 },
};
static const struct field f_node[] = {	/* ieee80211_node_target, 22B */
	{ "macaddr",   FT_BYTES, FC_OPAQUE, 0, 0, 6 },
	{ "bssid",     FT_BYTES, FC_OPAQUE, 0, 0, 6 },
	{ "nodeindex", FT_U8,  FC_INDEX, 0, 7, 0 },
	{ "vapindex",  FT_U8,  FC_INDEX, 0, 1, 0 },
	{ "is_vapnode", FT_U8, FC_OPAQUE, 0, 0, 0 },
	{ "flags",     FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "htcap",     FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "maxampdu",  FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "pad",       FT_U8,  FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_node_remove[] = {
	{ "node_index", FT_U8, FC_INDEX, 0, 7, 0 },
};
static const struct field f_vap_create[] = {	/* vap_target, 12B */
	{ "vapindex",     FT_U8,  FC_INDEX, 0, 1, 0 },
	{ "opmode",       FT_U8,  FC_OPAQUE, 1, 0, 0 },
	{ "myaddr",       FT_BYTES, FC_OPAQUE, 0, 0, 6 },
	{ "ath_cap",      FT_U8,  FC_OPAQUE, 0, 0, 0 },
	{ "rtsthreshold", FT_U16, FC_OPAQUE, 2346, 0, 0 },
	{ "pad",          FT_U8,  FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_vap_remove[] = {
	{ "vap_index", FT_U8, FC_INDEX, 0, 1, 0 },
};
static const struct field f_drain_txq[] = {
	{ "q", FT_U32, FC_INDEX, 0, 9, 0 },
};
static const struct field f_set_mode[] = {
	{ "mode", FT_U16, FC_INDEX, 0, 7, 0 },
};
static const struct field f_bitrate_mask[] = {
	{ "vap_index", FT_U8,  FC_INDEX, 0, 1, 0 },
	{ "band",      FT_U8,  FC_INDEX, 0, 1, 0 },
	{ "mask",      FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "pad",       FT_U16, FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_rc_rate[] = {	/* wmi_rc_rate_update_cmd, 70B */
	{ "node_index", FT_U8,  FC_INDEX, 0, 7, 0 },
	{ "isNew",      FT_U8,  FC_OPAQUE, 1, 0, 0 },
	{ "pad",        FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "capflag",    FT_U32, FC_OPAQUE, 1, 0, 0 },
	{ "leg_nrates", FT_U8,  FC_COUNT, 8, 30, 0 },
	{ "leg_rates",  FT_BYTES, FC_ARRAY, 0, 0, 30 },
	{ "ht_nrates",  FT_U8,  FC_COUNT, 8, 30, 0 },
	{ "ht_rates",   FT_BYTES, FC_ARRAY, 0, 0, 30 },
};
static const struct field f_rc_state[] = {
	{ "vap_index",  FT_U8,  FC_INDEX, 0, 1, 0 },
	{ "vap_state",  FT_U8,  FC_OPAQUE, 0, 0, 0 },
	{ "pad",        FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "capflag",    FT_U32, FC_OPAQUE, 1, 0, 0 },
	{ "leg_nrates", FT_U8,  FC_COUNT, 8, 30, 0 },
	{ "leg_rates",  FT_BYTES, FC_ARRAY, 0, 0, 30 },
	{ "ht_nrates",  FT_U8,  FC_COUNT, 8, 30, 0 },
	{ "ht_rates",   FT_BYTES, FC_ARRAY, 0, 0, 30 },
};
static const struct field f_aggr[] = {
	{ "sta_index",   FT_U8, FC_INDEX, 0, 7, 0 },
	{ "tidno",       FT_U8, FC_INDEX, 0, 7, 0 },
	{ "aggr_enable", FT_U8, FC_OPAQUE, 1, 0, 0 },
	{ "pad",         FT_U8, FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_ic_update[] = {
	{ "ampdu_limit",     FT_U32, FC_OPAQUE, 0xFFFF, 0, 0 },
	{ "ampdu_subframes", FT_U8,  FC_OPAQUE, 32, 0, 0 },
	{ "enable_coex",     FT_U8,  FC_OPAQUE, 0, 0, 0 },
	{ "tx_chainmask",    FT_U8,  FC_OPAQUE, 1, 0, 0 },
	{ "pad",             FT_U8,  FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_htc_raw[] = {	/* finding H4: eid 0..255 */
	{ "eid",     FT_U8,  FC_INDEX, 0, 21, 0 },
	{ "flags",   FT_U8,  FC_OPAQUE, 0, 0, 0 },
	{ "payload", FT_BYTES, FC_LENGTH, 0, 0, 16 },
};

#define M(nm, flds, w, id) \
	{ nm, w, (int)(sizeof(flds) / sizeof(flds[0])), flds, id }

static const struct msg ath9k_msgs[] = {
	M("ECHO",         f_echo,        2.0, WMI_ECHO),
	M("REG_READ",     f_reg_read,    3.0, WMI_REG_READ),
	M("REG_WRITE",    f_reg_write,   0.2, WMI_REG_WRITE),
	M("NODE_CREATE",  f_node,        3.0, WMI_NODE_CREATE),
	M("NODE_UPDATE",  f_node,        2.0, WMI_NODE_UPDATE),
	M("NODE_REMOVE",  f_node_remove, 2.0, WMI_NODE_REMOVE),
	M("VAP_CREATE",   f_vap_create,  3.0, WMI_VAP_CREATE),
	M("VAP_REMOVE",   f_vap_remove,  2.0, WMI_VAP_REMOVE),
	M("DRAIN_TXQ",    f_drain_txq,   2.0, WMI_DRAIN_TXQ),
	M("SET_MODE",     f_set_mode,    2.0, WMI_SET_MODE),
	M("BITRATE_MASK", f_bitrate_mask, 3.0, WMI_BITRATE_MASK),
	M("RC_RATE_UPDATE", f_rc_rate,   3.0, WMI_RC_RATE),
	M("RC_STATE_CHANGE", f_rc_state, 2.0, WMI_RC_STATE),
	M("TX_AGGR_ENABLE", f_aggr,      1.5, WMI_AGGR_ENABLE),
	M("IC_UPDATE",    f_ic_update,   1.0, WMI_IC_UPDATE),
	M("HTC_RAW_EID",  f_htc_raw,     1.5, CMDID_HTC_RAW),
};

/* ---- transport ------------------------------------------------------------- */
/* Live USB transport needs the physical NIC, so it is out of coverage. */
/* LCOV_EXCL_START */

struct ath9k_priv {
	int fd;
	int wmi_eid;
	uint16_t seq;
};

static int htc_frame(uint8_t *out, int eid, int flags, const uint8_t *pl,
		     int plen)
{
	out[0] = (uint8_t)eid;
	out[1] = (uint8_t)flags;
	out[2] = (uint8_t)(plen >> 8);
	out[3] = (uint8_t)plen;
	memset(out + 4, 0, 4);
	memcpy(out + 8, pl, (size_t)plen);
	return 8 + plen;
}

static int send_cmd(struct ath9k_priv *p, const uint8_t *data, int len)
{
	return usbfs_xfer(p->fd, EP_CMD_OUT, (void *)data, len, 1000) < 0 ?
	       -1 : 0;
}

static int recv_resp(struct ath9k_priv *p, uint8_t *buf, int cap,
		     int timeout_ms)
{
	return usbfs_xfer(p->fd, EP_REG_IN, buf, cap, timeout_ms);
}

static int ath9k_htc_setup(struct ath9k_priv *p)
{
	uint8_t frame[128], pl[64], resp[512];
	int n, r;

	/* drain stale responses */
	while (recv_resp(p, resp, sizeof(resp), 100) > 0)
		;

	/* config pipe: msgid=5, pipe=1, credits=33 */
	pl[0] = 0; pl[1] = HTC_MSG_CONF_PIPE; pl[2] = 1; pl[3] = 33;
	n = htc_frame(frame, 0, 0, pl, 4);
	if (send_cmd(p, frame, n) < 0)
		return -1;
	recv_resp(p, resp, sizeof(resp), 1000);

	/* connect WMI control service (all fields BE) */
	memset(pl, 0, 10);
	pl[1] = HTC_MSG_CONNECT;
	pl[2] = WMI_CONTROL_SVC >> 8; pl[3] = WMI_CONTROL_SVC & 0xFF;
	pl[6] = 3; pl[7] = 4;	/* dl/ul pipes */
	n = htc_frame(frame, 0, 0, pl, 10);
	if (send_cmd(p, frame, n) < 0)
		return -1;
	r = recv_resp(p, resp, sizeof(resp), 1000);
	if (r < 14 || resp[9] != 3 /* CONNECT_RESP */ || resp[12] != 0)
		return -1;
	p->wmi_eid = resp[13];
	printf("[*] WMI control service connected, endpoint ID = %d\n",
	       p->wmi_eid);

	pl[0] = 0; pl[1] = HTC_MSG_SETUP;
	n = htc_frame(frame, 0, 0, pl, 2);
	if (send_cmd(p, frame, n) < 0)
		return -1;
	msleep_ms(100);
	return 0;
}

static int ath9k_attach(struct target *t)
{
	struct ath9k_priv *p = t->priv;
	static const uint16_t pids[] = { 0x9271, 0x7010, 0x1006 };
	uint16_t got;

	p->fd = usbfs_open(ATHEROS_VID, pids, 3, &got);
	if (p->fd < 0)
		return -1;
	usbfs_detach_kernel(p->fd, 0);
	if (usbfs_claim(p->fd, 0) < 0)
		return -1;
	return ath9k_htc_setup(p);
}

static int ath9k_send(struct target *t, const struct msg *m,
		      const uint8_t *payload, int len)
{
	struct ath9k_priv *p = t->priv;
	uint8_t frame[CASE_MAX_BYTES + 16], resp[512];
	int n;

	if (m->cmd_id == CMDID_HTC_RAW) {
		/* payload = eid(1) flags(1) body -- fuzz the HTC header */
		if (len < 2)
			return 0;
		n = htc_frame(frame, payload[0], payload[1], payload + 2,
			      len - 2 > 500 ? 500 : len - 2);
	} else {
		uint8_t wmi[CASE_MAX_BYTES + 4];
		int wlen = len > 496 ? 496 : len;

		p->seq++;
		wmi[0] = (uint8_t)(m->cmd_id >> 8);
		wmi[1] = (uint8_t)m->cmd_id;
		wmi[2] = (uint8_t)(p->seq >> 8);
		wmi[3] = (uint8_t)p->seq;
		memcpy(wmi + 4, payload, (size_t)wlen);
		n = htc_frame(frame, p->wmi_eid, 0, wmi, 4 + wlen);
	}
	if (send_cmd(p, frame, n) < 0)
		return -1;
	recv_resp(p, resp, sizeof(resp), 50);	/* keep IN pipe drained */
	return 0;
}

static int ath9k_probe(struct target *t)
{
	struct ath9k_priv *p = t->priv;
	uint8_t frame[64], wmi[8 + 4], resp[512];
	int n, r;

	p->seq++;
	wmi[0] = WMI_ECHO >> 8; wmi[1] = WMI_ECHO & 0xFF;
	wmi[2] = (uint8_t)(p->seq >> 8); wmi[3] = (uint8_t)p->seq;
	memcpy(wmi + 4, "PING", 4);
	n = htc_frame(frame, p->wmi_eid, 0, wmi, 8);
	if (send_cmd(p, frame, n) < 0)
		return 0;
	r = recv_resp(p, resp, sizeof(resp), 1500);
	return r >= 16 && !memcmp(resp + 12, "PING", 4);
}

static int ath9k_recover(struct target *t)
{
	return usb_recover_generic(t, 10, 2000);
}

static void ath9k_close(struct target *t)
{
	struct ath9k_priv *p = t->priv;

	if (p->fd >= 0) {
		close(p->fd);
		p->fd = -1;
	}
}

/* LCOV_EXCL_STOP */

struct target *target_ath9k_htc(const char *fw_path)
{
	static struct ath9k_priv priv = { .fd = -1 };
	static struct target t = {
		.name = "ath9k-htc",
		.big_endian = 1,
		.msgs = ath9k_msgs,
		.nmsgs = (int)(sizeof(ath9k_msgs) / sizeof(ath9k_msgs[0])),
		.attach = ath9k_attach,
		.send = ath9k_send,
		.probe_alive = ath9k_probe,
		.recover = ath9k_recover,
		.close = ath9k_close,
		.priv = &priv,
	};

	(void)fw_path;	/* fw must be loaded (vendor driver loads it once) */
	return &t;
}

/* ---- shared USB recovery -------------------------------------------------- */
/* LCOV_EXCL_START */

int usb_recover_generic(struct target *t, int tries, int wait_ms)
{
	int i;

	t->close(t);
	for (i = 0; i < tries; i++) {
		msleep_ms(wait_ms);
		if (t->attach(t) == 0 && t->probe_alive(t))
			return 1;
		t->close(t);
	}
	return 0;
}

/* LCOV_EXCL_STOP */
