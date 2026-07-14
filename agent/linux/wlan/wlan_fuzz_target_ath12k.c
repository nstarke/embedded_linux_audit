// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Target: Qualcomm ath12k (WCN7850/QCN9274 Wi-Fi 7) WMI-TLV over the ela_kmod
 * kernel shim. Same injection path and TLV framing as the ath11k target
 * (shim descriptor ELA_WLAN_DRV_ATH12K -> ath12k_wmi_cmd_send /
 * ath12k_core_restart, reusing the shim's WMI-skb adapter); the command
 * bodies differ from ath11k in their TLV tags and a larger vdev_create.
 *
 * Grammar/tags/cmd ids extracted from drivers/net/wireless/ath/ath12k/
 * {wmi.h,hw.h} (kernel master); fixed sizes asserted by the offline
 * self-test. cmd_id-ABI and oracle caveats are as documented in wlan-fuzz.md.
 */
#include <stdio.h>
#include <string.h>

#include "wlan_fuzz.h"
#include "wlan_fuzz_kmod.h"
#include "../../../kmod/ela_ioctl.h"

/* WMI-TLV command ids (WMI_TLV_CMD(grp)=(grp<<12)|1, WMI_GRP_START=0x3) */
#define WMI_PDEV_SET_PARAM   0x4003
#define WMI_VDEV_CREATE      0x5001
#define WMI_VDEV_DELETE      0x5002
#define WMI_VDEV_SET_PARAM   0x5008
#define WMI_PEER_CREATE      0x6001
#define WMI_PEER_DELETE      0x6002

/* enum wmi_tlv_tag values (ath12k) */
#define WMI_TAG_PDEV_SET_PARAM_CMD  20
#define WMI_TAG_VDEV_CREATE_CMD     24
#define WMI_TAG_VDEV_DELETE_CMD     25
#define WMI_TAG_VDEV_SET_PARAM_CMD  33
#define WMI_TAG_PEER_CREATE_CMD     35
#define WMI_TAG_PEER_DELETE_CMD     36

#define ATH12K_WMI_RAW 0xFFFFFFFFu	/* pseudo: le32 cmd_id prefixes the body */

#define ATH12K_NUM_VDEVS 16		/* hw.h profile num_vdevs (chip-dependent) */
#define WMI_PARAM_MAX    64
#define WMI_NUM_PDEVS    3

/* ---- grammar (fixed sizes verified vs wmi.h TLV structs in the self-test) - */

static const struct field f_vdev_create[] = {	/* wmi_vdev_create_cmd, 48B */
	{ "tlv_header",   FT_U32, FC_OPAQUE, 0, 0, 0 },	/* rewritten on send */
	{ "vdev_id",      FT_U32, FC_INDEX, 0, ATH12K_NUM_VDEVS - 1, 0 },
	{ "vdev_type",    FT_U32, FC_OPAQUE, 2, 0, 0 },
	{ "vdev_subtype", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "vdev_macaddr", FT_BYTES, FC_OPAQUE, 0, 0, 8 },	/* addr[6]+pad[2] */
	{ "num_cfg_txrx_streams", FT_U32, FC_COUNT, 0, 4, 0 },
	{ "pdev_id",      FT_U32, FC_INDEX, 0, WMI_NUM_PDEVS - 1, 0 },
	{ "mbssid_flags", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "mbssid_tx_vdev_id", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "vdev_stats_id_valid", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "vdev_stats_id", FT_U32, FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_vdev_delete[] = {	/* wmi_vdev_delete_cmd, 8B */
	{ "tlv_header", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "vdev_id",    FT_U32, FC_INDEX, 0, ATH12K_NUM_VDEVS - 1, 0 },
};
static const struct field f_vdev_set_param[] = {	/* wmi_vdev_set_param_cmd, 16B */
	{ "tlv_header",  FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "vdev_id",     FT_U32, FC_INDEX, 0, ATH12K_NUM_VDEVS - 1, 0 },
	{ "param_id",    FT_U32, FC_INDEX, 0, WMI_PARAM_MAX, 0 },
	{ "param_value", FT_U32, FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_pdev_set_param[] = {	/* wmi_pdev_set_param_cmd, 16B */
	{ "tlv_header",  FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "pdev_id",     FT_U32, FC_INDEX, 0, WMI_NUM_PDEVS - 1, 0 },
	{ "param_id",    FT_U32, FC_INDEX, 0, WMI_PARAM_MAX, 0 },
	{ "param_value", FT_U32, FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_peer_create[] = {	/* wmi_peer_create_cmd, 20B */
	{ "tlv_header",   FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "vdev_id",      FT_U32, FC_INDEX, 0, ATH12K_NUM_VDEVS - 1, 0 },
	{ "peer_macaddr", FT_BYTES, FC_OPAQUE, 0, 0, 8 },
	{ "peer_type",    FT_U32, FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_peer_delete[] = {	/* wmi_peer_delete_cmd, 16B */
	{ "tlv_header",   FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "vdev_id",      FT_U32, FC_INDEX, 0, ATH12K_NUM_VDEVS - 1, 0 },
	{ "peer_macaddr", FT_BYTES, FC_OPAQUE, 0, 0, 8 },
};
static const struct field f_raw[] = {	/* fuzz cmd id + the TLV parser */
	{ "cmd_id",     FT_U32, FC_INDEX, 0x5001, 0x8000, 0 },
	{ "tlv_header", FT_U32, FC_LENGTH, 0, 0, 0 },
	{ "body",       FT_BYTES, FC_LENGTH, 0, 0, 16 },
};

#define M(nm, flds, w, id) \
	{ nm, w, (int)(sizeof(flds) / sizeof(flds[0])), flds, id }

static const struct msg ath12k_msgs[] = {
	M("VDEV_CREATE",    f_vdev_create,    3.0, WMI_VDEV_CREATE),
	M("VDEV_DELETE",    f_vdev_delete,    2.0, WMI_VDEV_DELETE),
	M("VDEV_SET_PARAM", f_vdev_set_param, 3.0, WMI_VDEV_SET_PARAM),
	M("PDEV_SET_PARAM", f_pdev_set_param, 2.0, WMI_PDEV_SET_PARAM),
	M("PEER_CREATE",    f_peer_create,    3.0, WMI_PEER_CREATE),
	M("PEER_DELETE",    f_peer_delete,    2.0, WMI_PEER_DELETE),
	M("RAW_TLV",        f_raw,            1.5, ATH12K_WMI_RAW),
};

static uint32_t tag_for_cmd(uint32_t cmd_id)
{
	switch (cmd_id) {
	case WMI_VDEV_CREATE:    return WMI_TAG_VDEV_CREATE_CMD;
	case WMI_VDEV_DELETE:    return WMI_TAG_VDEV_DELETE_CMD;
	case WMI_VDEV_SET_PARAM: return WMI_TAG_VDEV_SET_PARAM_CMD;
	case WMI_PDEV_SET_PARAM: return WMI_TAG_PDEV_SET_PARAM_CMD;
	case WMI_PEER_CREATE:    return WMI_TAG_PEER_CREATE_CMD;
	case WMI_PEER_DELETE:    return WMI_TAG_PEER_DELETE_CMD;
	default:                 return 0;
	}
}

/* ---- transport (ela_kmod shim) -------------------------------------------- */
/* LCOV_EXCL_START -- live injection needs the module + a bound driver */

struct ath12k_priv {
	int fd;
	uint64_t restart_base;
};

static int ath12k_attach(struct target *t)
{
	struct ath12k_priv *p = t->priv;
	uint64_t restarts = 0;

	p->fd = wlan_kmod_open();
	if (p->fd < 0) {
		fprintf(stderr, "[!] cannot open %s (load ela_kmod, run as root)\n",
			ELA_KMOD_DEVICE_PATH);
		return -1;
	}
	if (wlan_kmod_attach(p->fd, ELA_WLAN_DRV_ATH12K) < 0) {
		fprintf(stderr, "[!] ath12k shim attach failed (driver loaded? CONFIG_KPROBES?)\n");
		wlan_kmod_close(p->fd);
		p->fd = -1;
		return -1;
	}
	printf("[*] waiting for ath12k WMI traffic to capture driver context...\n");
	printf("    (bring the interface up or trigger a scan to generate it)\n");
	if (wlan_kmod_wait_capture(p->fd, 20000) < 0) {
		fprintf(stderr, "[!] no WMI traffic captured; is the interface up?\n");
		wlan_kmod_detach(p->fd, ELA_WLAN_DRV_ATH12K);
		wlan_kmod_close(p->fd);
		p->fd = -1;
		return -1;
	}
	wlan_kmod_status(p->fd, &restarts, NULL);
	p->restart_base = restarts;
	printf("[*] ath12k context captured; injecting WMI-TLV commands\n");
	return 0;
}

static int ath12k_send(struct target *t, const struct msg *m,
		       const uint8_t *payload, int len)
{
	struct ath12k_priv *p = t->priv;
	uint8_t buf[CASE_MAX_BYTES];
	int32_t send_ret = 0;
	int r;

	if (m->cmd_id == ATH12K_WMI_RAW) {
		uint32_t cid;

		if (len < 4)
			return 0;
		cid = payload[0] | (payload[1] << 8) | (payload[2] << 16) |
		      ((uint32_t)payload[3] << 24);
		r = wlan_kmod_inject(p->fd, cid, payload + 4, len - 4, &send_ret);
	} else {
		uint32_t tag = tag_for_cmd(m->cmd_id);
		uint32_t tlv;
		int n = len > CASE_MAX_BYTES ? CASE_MAX_BYTES : len;

		memcpy(buf, payload, (size_t)n);
		tlv = (tag << 16) | (uint32_t)((n - 4) & 0xFFFF);
		buf[0] = tlv & 0xFF;
		buf[1] = (tlv >> 8) & 0xFF;
		buf[2] = (tlv >> 16) & 0xFF;
		buf[3] = (tlv >> 24) & 0xFF;
		r = wlan_kmod_inject(p->fd, m->cmd_id, buf, n, &send_ret);
	}
	return r < 0 ? -1 : 0;
}

static int ath12k_probe(struct target *t)
{
	struct ath12k_priv *p = t->priv;
	uint64_t restarts = p->restart_base;

	if (wlan_kmod_status(p->fd, &restarts, NULL) < 0)
		return 0;
	return restarts == p->restart_base;
}

static int ath12k_recover(struct target *t)
{
	struct ath12k_priv *p = t->priv;
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

static void ath12k_close(struct target *t)
{
	struct ath12k_priv *p = t->priv;

	if (p->fd >= 0) {
		wlan_kmod_detach(p->fd, ELA_WLAN_DRV_ATH12K);
		wlan_kmod_close(p->fd);
		p->fd = -1;
	}
}

/* LCOV_EXCL_STOP */

struct target *target_ath12k(void)
{
	static struct ath12k_priv priv = { .fd = -1 };
	static struct target t = {
		.name = "ath12k",
		.big_endian = 0,
		.msgs = ath12k_msgs,
		.nmsgs = (int)(sizeof(ath12k_msgs) / sizeof(ath12k_msgs[0])),
		.attach = ath12k_attach,
		.send = ath12k_send,
		.probe_alive = ath12k_probe,
		.recover = ath12k_recover,
		.close = ath12k_close,
		.priv = &priv,
	};

	return &t;
}
