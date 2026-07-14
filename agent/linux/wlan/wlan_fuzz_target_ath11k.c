// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Target: Atheros/Qualcomm ath11k (QCA6390/WCN6855/IPQ8074/QCN9074 ...) WMI-TLV
 * over the ela_kmod kernel shim. Same PCIe/SDIO command-injection path as the
 * ath10k target (shim descriptor ELA_WLAN_DRV_ATH11K -> ath11k_wmi_cmd_send,
 * ath11k_core_restart), but ath11k WMI is TLV-encoded.
 *
 * Each command body starts with a u32 `tlv_header` = (tag << 16) | payload_len
 * (WMI_TLV_TAG = bits 31:16, WMI_TLV_LEN = bits 15:0). For the fixed commands
 * this target rewrites that word to the correct tag/len on send so the fuzzed
 * fields reach the firmware's command handler; RAW_TLV leaves it fuzzed to
 * exercise the TLV parser itself.
 *
 * Grammar + tags + cmd ids extracted from drivers/net/wireless/ath/ath11k/
 * {wmi.h,hw.h} (kernel master); fixed body sizes are asserted against the
 * struct sizes by the offline self-test. See wlan-fuzz.md and the ath10k
 * target for the cmd_id-ABI and oracle caveats (they apply here too).
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

/* enum wmi_tlv_tag values for the fixed command structs */
#define WMI_TAG_PDEV_SET_PARAM_CMD  86
#define WMI_TAG_VDEV_CREATE_CMD     90
#define WMI_TAG_VDEV_DELETE_CMD     91
#define WMI_TAG_VDEV_SET_PARAM_CMD  99
#define WMI_TAG_PEER_CREATE_CMD    101
#define WMI_TAG_PEER_DELETE_CMD    102

#define ATH11K_WMI_RAW 0xFFFFFFFFu	/* pseudo: le32 cmd_id prefixes the body */

#define ATH11K_NUM_VDEVS 16		/* hw_params.num_vdevs (chip-dependent) */
#define WMI_PARAM_MAX    64
#define WMI_NUM_PDEVS    2

/* ---- grammar (fixed sizes verified vs wmi.h TLV structs in the self-test) - */

static const struct field f_vdev_create[] = {	/* wmi_vdev_create_cmd, 40B */
	{ "tlv_header",   FT_U32, FC_OPAQUE, 0, 0, 0 },	/* rewritten on send */
	{ "vdev_id",      FT_U32, FC_INDEX, 0, ATH11K_NUM_VDEVS - 1, 0 },
	{ "vdev_type",    FT_U32, FC_OPAQUE, 2, 0, 0 },
	{ "vdev_subtype", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "vdev_macaddr", FT_BYTES, FC_OPAQUE, 0, 0, 8 },	/* wmi_mac_addr */
	{ "num_cfg_txrx_streams", FT_U32, FC_COUNT, 0, 4, 0 },	/* vs trailing TLVs */
	{ "pdev_id",      FT_U32, FC_INDEX, 0, WMI_NUM_PDEVS - 1, 0 },
	{ "mbssid_flags", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "mbssid_tx_vdev_id", FT_U32, FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_vdev_delete[] = {	/* wmi_vdev_delete_cmd, 8B */
	{ "tlv_header", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "vdev_id",    FT_U32, FC_INDEX, 0, ATH11K_NUM_VDEVS - 1, 0 },
};
static const struct field f_pdev_set_param[] = {	/* wmi_pdev_set_param_cmd, 16B */
	{ "tlv_header",  FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "pdev_id",     FT_U32, FC_INDEX, 0, WMI_NUM_PDEVS - 1, 0 },
	{ "param_id",    FT_U32, FC_INDEX, 0, WMI_PARAM_MAX, 0 },
	{ "param_value", FT_U32, FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_vdev_set_param[] = {	/* wmi_vdev_set_param_cmd, 16B */
	{ "tlv_header",  FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "vdev_id",     FT_U32, FC_INDEX, 0, ATH11K_NUM_VDEVS - 1, 0 },
	{ "param_id",    FT_U32, FC_INDEX, 0, WMI_PARAM_MAX, 0 },
	{ "param_value", FT_U32, FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_peer_create[] = {	/* wmi_peer_create_cmd, 20B */
	{ "tlv_header",   FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "vdev_id",      FT_U32, FC_INDEX, 0, ATH11K_NUM_VDEVS - 1, 0 },
	{ "peer_macaddr", FT_BYTES, FC_OPAQUE, 0, 0, 8 },
	{ "peer_type",    FT_U32, FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_peer_delete[] = {	/* wmi_peer_delete_cmd, 16B */
	{ "tlv_header",   FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "vdev_id",      FT_U32, FC_INDEX, 0, ATH11K_NUM_VDEVS - 1, 0 },
	{ "peer_macaddr", FT_BYTES, FC_OPAQUE, 0, 0, 8 },
};
static const struct field f_raw[] = {	/* fuzz cmd id + the TLV header/parser */
	{ "cmd_id",     FT_U32, FC_INDEX, 0x5001, 0x8000, 0 },
	{ "tlv_header", FT_U32, FC_LENGTH, 0, 0, 0 },	/* left fuzzed on send */
	{ "body",       FT_BYTES, FC_LENGTH, 0, 0, 16 },
};

#define M(nm, flds, w, id) \
	{ nm, w, (int)(sizeof(flds) / sizeof(flds[0])), flds, id }

static const struct msg ath11k_msgs[] = {
	M("VDEV_CREATE",    f_vdev_create,    3.0, WMI_VDEV_CREATE),
	M("VDEV_DELETE",    f_vdev_delete,    2.0, WMI_VDEV_DELETE),
	M("VDEV_SET_PARAM", f_vdev_set_param, 3.0, WMI_VDEV_SET_PARAM),
	M("PDEV_SET_PARAM", f_pdev_set_param, 2.0, WMI_PDEV_SET_PARAM),
	M("PEER_CREATE",    f_peer_create,    3.0, WMI_PEER_CREATE),
	M("PEER_DELETE",    f_peer_delete,    2.0, WMI_PEER_DELETE),
	M("RAW_TLV",        f_raw,            1.5, ATH11K_WMI_RAW),
};

/* WMI-TLV tag expected as the first word of each fixed command body. */
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
/* Live injection needs the module loaded and the driver bound, so these paths
 * run only in the field, not under the offline self-test. */
/* LCOV_EXCL_START */

struct ath11k_priv {
	int fd;
	uint64_t restart_base;
};

static int ath11k_attach(struct target *t)
{
	struct ath11k_priv *p = t->priv;
	uint64_t restarts = 0;

	p->fd = wlan_kmod_open();
	if (p->fd < 0) {
		fprintf(stderr, "[!] cannot open %s (load ela_kmod, run as root)\n",
			ELA_KMOD_DEVICE_PATH);
		return -1;
	}
	if (wlan_kmod_attach(p->fd, ELA_WLAN_DRV_ATH11K) < 0) {
		fprintf(stderr, "[!] ath11k shim attach failed (driver loaded? CONFIG_KPROBES?)\n");
		wlan_kmod_close(p->fd);
		p->fd = -1;
		return -1;
	}
	printf("[*] waiting for ath11k WMI traffic to capture driver context...\n");
	printf("    (bring the interface up or trigger a scan to generate it)\n");
	if (wlan_kmod_wait_capture(p->fd, 20000) < 0) {
		fprintf(stderr, "[!] no WMI traffic captured; is the interface up?\n");
		wlan_kmod_detach(p->fd, ELA_WLAN_DRV_ATH11K);
		wlan_kmod_close(p->fd);
		p->fd = -1;
		return -1;
	}
	wlan_kmod_status(p->fd, &restarts, NULL);
	p->restart_base = restarts;
	printf("[*] ath11k context captured; injecting WMI-TLV commands\n");
	return 0;
}

static int ath11k_send(struct target *t, const struct msg *m,
		       const uint8_t *payload, int len)
{
	struct ath11k_priv *p = t->priv;
	uint8_t buf[CASE_MAX_BYTES];
	int32_t send_ret = 0;
	int r;

	if (m->cmd_id == ATH11K_WMI_RAW) {
		uint32_t cid;

		if (len < 4)
			return 0;
		cid = payload[0] | (payload[1] << 8) | (payload[2] << 16) |
		      ((uint32_t)payload[3] << 24);
		/* body after cmd_id keeps its fuzzed tlv_header + body */
		r = wlan_kmod_inject(p->fd, cid, payload + 4, len - 4, &send_ret);
	} else {
		uint32_t tag = tag_for_cmd(m->cmd_id);
		uint32_t tlv;
		int n = len > CASE_MAX_BYTES ? CASE_MAX_BYTES : len;

		memcpy(buf, payload, (size_t)n);
		/* first word = (tag << 16) | payload_len (len minus the header) */
		tlv = (tag << 16) | (uint32_t)((n - 4) & 0xFFFF);
		buf[0] = tlv & 0xFF;
		buf[1] = (tlv >> 8) & 0xFF;
		buf[2] = (tlv >> 16) & 0xFF;
		buf[3] = (tlv >> 24) & 0xFF;
		r = wlan_kmod_inject(p->fd, m->cmd_id, buf, n, &send_ret);
	}
	return r < 0 ? -1 : 0;
}

static int ath11k_probe(struct target *t)
{
	struct ath11k_priv *p = t->priv;
	uint64_t restarts = p->restart_base;

	if (wlan_kmod_status(p->fd, &restarts, NULL) < 0)
		return 0;
	return restarts == p->restart_base;
}

static int ath11k_recover(struct target *t)
{
	struct ath11k_priv *p = t->priv;
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

static void ath11k_close(struct target *t)
{
	struct ath11k_priv *p = t->priv;

	if (p->fd >= 0) {
		wlan_kmod_detach(p->fd, ELA_WLAN_DRV_ATH11K);
		wlan_kmod_close(p->fd);
		p->fd = -1;
	}
}

/* LCOV_EXCL_STOP */

struct target *target_ath11k(void)
{
	static struct ath11k_priv priv = { .fd = -1 };
	static struct target t = {
		.name = "ath11k",
		.big_endian = 0,
		.msgs = ath11k_msgs,
		.nmsgs = (int)(sizeof(ath11k_msgs) / sizeof(ath11k_msgs[0])),
		.attach = ath11k_attach,
		.send = ath11k_send,
		.probe_alive = ath11k_probe,
		.recover = ath11k_recover,
		.close = ath11k_close,
		.priv = &priv,
	};

	return &t;
}
