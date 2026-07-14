// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Target: Atheros ath10k (QCA988x/9377/9887/6174 ...) WMI over the ela_kmod
 * kernel shim. Reaches the host->firmware WMI command path of a PCIe/SDIO/USB
 * ath10k NIC that is driven by the in-kernel driver -- the command ring lives
 * in kernel/device memory and is not reachable from userspace usbfs.
 *
 * Grammar from drivers/net/wireless/ath/ath10k/{wmi.h,hw.h} (kernel master);
 * fixed-size command bodies are asserted against their struct sizes by the
 * offline self-test. Transport = ELA_IOC_WLAN_INJECT (the shim builds the WMI
 * skb and calls the captured ath10k_wmi_cmd_send). Oracle = the shim's
 * firmware-restart counter (ath10k_core_restart fires on firmware crash).
 *
 * cmd_id numbering is the ath10k "main" WMI map (WMI_CMD_GRP(grp)=(grp<<12)|1,
 * WMI_GRP_START=0x3). Other firmware ABIs (10.x/TLV) renumber commands; the
 * shim reports the driver's observed cmd ids (STATUS.last_cmd_id) so an
 * operator can recalibrate. The field classes (what gets fuzzed) are stable
 * across ABIs even when the numbers shift.
 */
#include <stdio.h>
#include <string.h>

#include "wlan_fuzz.h"
#include "wlan_fuzz_kmod.h"
#include "../../../kmod/ela_ioctl.h"

/* "main" WMI command ids (see header note) */
#define WMI_PDEV_SET_PARAM     0x4003
#define WMI_VDEV_CREATE        0x5001
#define WMI_VDEV_DELETE        0x5002
#define WMI_VDEV_SET_PARAM     0x5008
#define WMI_VDEV_INSTALL_KEY   0x5009
#define WMI_PEER_CREATE        0x6001
#define WMI_PEER_DELETE        0x6002
#define WMI_PEER_SET_PARAM     0x6004
#define WMI_MGMT_TX            0x7006
#define WMI_SCAN_CHAN_LIST     0x3003

#define ATH10K_WMI_RAW 0xFFFFFFFFu	/* pseudo: le32 cmd_id prefixes the body */

#define TARGET_NUM_VDEVS 8		/* hw.h; vdev_id indexes fw vdev table */
#define WMI_PARAM_MAX    64		/* param dispatch tables (approx) */

/* ---- grammar (fixed sizes verified vs wmi.h structs in the self-test) ---- */

static const struct field f_vdev_create[] = {	/* wmi_vdev_create_cmd, 20B */
	{ "vdev_id",      FT_U32, FC_INDEX, 0, TARGET_NUM_VDEVS - 1, 0 },
	{ "vdev_type",    FT_U32, FC_OPAQUE, 2, 0, 0 },
	{ "vdev_subtype", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "vdev_macaddr", FT_BYTES, FC_OPAQUE, 0, 0, 8 },	/* wmi_mac_addr */
};
static const struct field f_vdev_delete[] = {	/* wmi_vdev_delete_cmd, 4B */
	{ "vdev_id", FT_U32, FC_INDEX, 0, TARGET_NUM_VDEVS - 1, 0 },
};
static const struct field f_vdev_set_param[] = {	/* wmi_vdev_set_param_cmd, 12B */
	{ "vdev_id",     FT_U32, FC_INDEX, 0, TARGET_NUM_VDEVS - 1, 0 },
	{ "param_id",    FT_U32, FC_INDEX, 0, WMI_PARAM_MAX, 0 },
	{ "param_value", FT_U32, FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_install_key[] = {	/* wmi_vdev_install_key_cmd, 92B+key */
	{ "vdev_id",      FT_U32, FC_INDEX, 0, TARGET_NUM_VDEVS - 1, 0 },
	{ "peer_macaddr", FT_BYTES, FC_OPAQUE, 0, 0, 8 },
	{ "key_idx",      FT_U32, FC_INDEX, 0, 3, 0 },
	{ "key_flags",    FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "key_cipher",   FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "seq_counters", FT_BYTES, FC_OPAQUE, 0, 0, 24 },	/* 3x key_seq_counter */
	{ "wpi_key_rsc",  FT_BYTES, FC_OPAQUE, 0, 0, 16 },
	{ "wpi_key_tsc",  FT_BYTES, FC_OPAQUE, 0, 0, 16 },
	{ "key_len",      FT_U32, FC_COUNT, 16, 32, 0 },	/* vs key_data[] */
	{ "key_txmic_len", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "key_rxmic_len", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "key_data",     FT_BYTES, FC_ARRAY, 0, 0, 16 },
};
static const struct field f_peer_create[] = {	/* wmi_peer_create_cmd, 16B */
	{ "vdev_id",      FT_U32, FC_INDEX, 0, TARGET_NUM_VDEVS - 1, 0 },
	{ "peer_macaddr", FT_BYTES, FC_OPAQUE, 0, 0, 8 },
	{ "peer_type",    FT_U32, FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_peer_delete[] = {	/* wmi_peer_delete_cmd, 12B */
	{ "vdev_id",      FT_U32, FC_INDEX, 0, TARGET_NUM_VDEVS - 1, 0 },
	{ "peer_macaddr", FT_BYTES, FC_OPAQUE, 0, 0, 8 },
};
static const struct field f_peer_set_param[] = {	/* wmi_peer_set_param_cmd, 20B */
	{ "vdev_id",      FT_U32, FC_INDEX, 0, TARGET_NUM_VDEVS - 1, 0 },
	{ "peer_macaddr", FT_BYTES, FC_OPAQUE, 0, 0, 8 },
	{ "param_id",     FT_U32, FC_INDEX, 0, WMI_PARAM_MAX, 0 },
	{ "param_value",  FT_U32, FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_pdev_set_param[] = {	/* wmi_pdev_set_param_cmd, 8B */
	{ "param_id",    FT_U32, FC_INDEX, 0, WMI_PARAM_MAX, 0 },
	{ "param_value", FT_U32, FC_OPAQUE, 0, 0, 0 },
};
static const struct field f_mgmt_tx[] = {	/* wmi_mgmt_tx_hdr (24B) + frame */
	{ "vdev_id",      FT_U32, FC_INDEX, 0, TARGET_NUM_VDEVS - 1, 0 },
	{ "peer_macaddr", FT_BYTES, FC_OPAQUE, 0, 0, 8 },
	{ "tx_rate",      FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "tx_power",     FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "buf_len",      FT_U32, FC_LENGTH, 64, 0, 0 },	/* lies vs frame */
	{ "frame",        FT_BYTES, FC_LENGTH, 0, 0, 64 },
};
static const struct field f_scan_chan_list[] = {	/* num lies vs chan array */
	{ "num_scan_chans", FT_U32, FC_COUNT, 1, 8, 0 },
	{ "chan_info",      FT_BYTES, FC_ARRAY, 0, 0, 40 },
};
static const struct field f_raw[] = {	/* fuzz arbitrary WMI command id + body */
	{ "cmd_id", FT_U32, FC_INDEX, 0x5001, 0x8000, 0 },
	{ "body",   FT_BYTES, FC_LENGTH, 0, 0, 16 },
};

#define M(nm, flds, w, id) \
	{ nm, w, (int)(sizeof(flds) / sizeof(flds[0])), flds, id }

static const struct msg ath10k_msgs[] = {
	M("VDEV_CREATE",     f_vdev_create,    3.0, WMI_VDEV_CREATE),
	M("VDEV_DELETE",     f_vdev_delete,    2.0, WMI_VDEV_DELETE),
	M("VDEV_SET_PARAM",  f_vdev_set_param, 3.0, WMI_VDEV_SET_PARAM),
	M("VDEV_INSTALL_KEY", f_install_key,   3.0, WMI_VDEV_INSTALL_KEY),
	M("PEER_CREATE",     f_peer_create,    3.0, WMI_PEER_CREATE),
	M("PEER_DELETE",     f_peer_delete,    2.0, WMI_PEER_DELETE),
	M("PEER_SET_PARAM",  f_peer_set_param, 2.5, WMI_PEER_SET_PARAM),
	M("PDEV_SET_PARAM",  f_pdev_set_param, 2.0, WMI_PDEV_SET_PARAM),
	M("MGMT_TX",         f_mgmt_tx,        2.0, WMI_MGMT_TX),
	M("SCAN_CHAN_LIST",  f_scan_chan_list, 2.0, WMI_SCAN_CHAN_LIST),
	M("RAW_WMI",         f_raw,            1.5, ATH10K_WMI_RAW),
};

/* ---- transport (ela_kmod shim) -------------------------------------------- */
/* Live injection needs the module loaded and the driver bound, so these paths
 * run only in the field, not under the offline self-test. */
/* LCOV_EXCL_START */

struct ath10k_priv {
	int fd;
	uint64_t restart_base;	/* firmware restarts seen at last good point */
};

static int ath10k_attach(struct target *t)
{
	struct ath10k_priv *p = t->priv;
	uint64_t restarts = 0;

	p->fd = wlan_kmod_open();
	if (p->fd < 0) {
		fprintf(stderr, "[!] cannot open %s (load ela_kmod, run as root)\n",
			ELA_KMOD_DEVICE_PATH);
		return -1;
	}
	if (wlan_kmod_attach(p->fd, ELA_WLAN_DRV_ATH10K) < 0) {
		fprintf(stderr, "[!] ath10k shim attach failed (driver loaded? CONFIG_KPROBES?)\n");
		wlan_kmod_close(p->fd);
		p->fd = -1;
		return -1;
	}
	printf("[*] waiting for ath10k WMI traffic to capture driver context...\n");
	printf("    (bring the interface up or trigger a scan to generate it)\n");
	if (wlan_kmod_wait_capture(p->fd, 20000) < 0) {
		fprintf(stderr, "[!] no WMI traffic captured; is the interface up?\n");
		wlan_kmod_detach(p->fd, ELA_WLAN_DRV_ATH10K);
		wlan_kmod_close(p->fd);
		p->fd = -1;
		return -1;
	}
	wlan_kmod_status(p->fd, &restarts, NULL);
	p->restart_base = restarts;
	printf("[*] ath10k context captured; injecting WMI commands\n");
	return 0;
}

static int ath10k_send(struct target *t, const struct msg *m,
		       const uint8_t *payload, int len)
{
	struct ath10k_priv *p = t->priv;
	int32_t send_ret = 0;
	int r;

	if (m->cmd_id == ATH10K_WMI_RAW) {
		uint32_t cid;

		if (len < 4)
			return 0;
		cid = payload[0] | (payload[1] << 8) | (payload[2] << 16) |
		      ((uint32_t)payload[3] << 24);
		r = wlan_kmod_inject(p->fd, cid, payload + 4, len - 4, &send_ret);
	} else {
		r = wlan_kmod_inject(p->fd, m->cmd_id, payload, len, &send_ret);
	}
	/* send_ret is the driver's return (credits/ENOMEM); not a death signal.
	 * A failed ioctl means the shim/device is gone -> transport dead. */
	return r < 0 ? -1 : 0;
}

static int ath10k_probe(struct target *t)
{
	struct ath10k_priv *p = t->priv;
	uint64_t restarts = p->restart_base;

	if (wlan_kmod_status(p->fd, &restarts, NULL) < 0)
		return 0;
	return restarts == p->restart_base;	/* a restart => firmware crashed */
}

static int ath10k_recover(struct target *t)
{
	struct ath10k_priv *p = t->priv;
	int i;

	/* ath10k auto-restarts firmware after a crash; wait for the driver to
	 * re-init and re-emit WMI so the shim recaptures the context. */
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

static void ath10k_close(struct target *t)
{
	struct ath10k_priv *p = t->priv;

	if (p->fd >= 0) {
		wlan_kmod_detach(p->fd, ELA_WLAN_DRV_ATH10K);
		wlan_kmod_close(p->fd);
		p->fd = -1;
	}
}

/* LCOV_EXCL_STOP */

struct target *target_ath10k(void)
{
	static struct ath10k_priv priv = { .fd = -1 };
	static struct target t = {
		.name = "ath10k",
		.big_endian = 0,
		.msgs = ath10k_msgs,
		.nmsgs = (int)(sizeof(ath10k_msgs) / sizeof(ath10k_msgs[0])),
		.attach = ath10k_attach,
		.send = ath10k_send,
		.probe_alive = ath10k_probe,
		.recover = ath10k_recover,
		.close = ath10k_close,
		.priv = &priv,
	};

	return &t;
}
