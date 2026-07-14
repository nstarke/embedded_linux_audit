// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Target: Broadcom brcmfmac firmware ioctls (BCDC) over the ela_kmod kernel
 * shim -- BCM43xx/4356/4359/4373/43455 etc. on SDIO/PCIe/USB. Injects through
 * the exported brcmf_fil_cmd_data_set(ifp, cmd, data, len) (the shim's
 * brcmfmac adapter, ELA_WLAN_DRV_BRCMFMAC); oracle = brcmf_fw_crashed.
 *
 * Unlike WMI/MCU, brcmfmac commands are firmware ioctls: a BRCMF_C_* command
 * id plus a fixed "_le" payload struct. The rich fuzz surface is the
 * length/count fields that firmware trusts against fixed buffers (key len vs
 * key[32], SSID_len vs SSID[32], scan channel/ssid counts). Grammar +
 * sizes from drivers/net/wireless/broadcom/brcm80211/brcmfmac/fwil_types.h
 * (kernel master), asserted by the offline self-test. Little-endian.
 */
#include <stdio.h>
#include <string.h>

#include "wlan_fuzz.h"
#include "wlan_fuzz_kmod.h"
#include "../../../kmod/ela_ioctl.h"

/* BRCMF_C_* firmware command ids (fwil.h, decimal) */
#define BRCMF_C_SET_SSID       26
#define BRCMF_C_SCAN           50
#define BRCMF_C_SET_KEY        45
#define BRCMF_C_SET_COUNTRY    84
#define BRCMF_C_SET_WSEC_PMK  268

#define BRCMF_RAW 0xFFFFFFFFu	/* pseudo: le32 cmd_id prefixes the body */

/* ---- grammar (fixed sizes verified vs fwil_types.h structs) -------------- */

static const struct field f_set_key[] = {	/* brcmf_wsec_key_le, 164B */
	{ "index", FT_U32, FC_INDEX, 0, 4, 0 },		/* key slot */
	{ "len",   FT_U32, FC_COUNT, 16, 32, 0 },	/* vs data[32] */
	{ "data",  FT_BYTES, FC_ARRAY, 0, 0, 32 },
	{ "tail",  FT_BYTES, FC_OPAQUE, 0, 0, 124 },	/* algo/flags/iv/ea ... */
};
static const struct field f_set_ssid[] = {	/* brcmf_join_params, 52B */
	{ "SSID_len",      FT_U32, FC_LENGTH, 0, 0, 0 },	/* vs SSID[32] */
	{ "SSID",          FT_BYTES, FC_OPAQUE, 0, 0, 32 },
	{ "bssid",         FT_BYTES, FC_OPAQUE, 0, 0, 6 },
	{ "pad0",          FT_BYTES, FC_OPAQUE, 0, 0, 2 },
	{ "chanspec_num",  FT_U32, FC_COUNT, 1, 8, 0 },	/* vs chanspec_list[] */
	{ "chanspec_list", FT_BYTES, FC_ARRAY, 0, 0, 2 },
	{ "pad1",          FT_BYTES, FC_OPAQUE, 0, 0, 2 },
};
static const struct field f_scan[] = {	/* brcmf_scan_params_le fixed, 64B */
	{ "SSID_len",     FT_U32, FC_LENGTH, 0, 0, 0 },
	{ "SSID",         FT_BYTES, FC_OPAQUE, 0, 0, 32 },
	{ "bssid",        FT_BYTES, FC_OPAQUE, 0, 0, 6 },
	{ "bss_type",     FT_U8,  FC_OPAQUE, 0, 0, 0 },
	{ "scan_type",    FT_U8,  FC_OPAQUE, 0, 0, 0 },
	{ "nprobes",      FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "active_time",  FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "passive_time", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "home_time",    FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "channel_num",  FT_U32, FC_COUNT, 1, 64, 0 },	/* lo16 chans | hi16 ssids */
};
static const struct field f_wsec_pmk[] = {	/* brcmf_wsec_pmk_le, 132B */
	{ "key_len", FT_U16, FC_COUNT, 32, 128, 0 },	/* vs key[128] */
	{ "flags",   FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "key",     FT_BYTES, FC_ARRAY, 0, 0, 128 },
};
static const struct field f_country[] = {	/* brcmf_fil_country_le, 12B */
	{ "country_abbrev", FT_BYTES, FC_OPAQUE, 0, 0, 4 },
	{ "rev",            FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "ccode",          FT_BYTES, FC_OPAQUE, 0, 0, 4 },
};
static const struct field f_raw[] = {	/* fuzz arbitrary BRCMF_C_* + payload */
	{ "cmd_id", FT_U32, FC_INDEX, 0, 300, 0 },
	{ "body",   FT_BYTES, FC_LENGTH, 0, 0, 16 },
};

#define M(nm, flds, w, id) \
	{ nm, w, (int)(sizeof(flds) / sizeof(flds[0])), flds, id }

static const struct msg brcmfmac_msgs[] = {
	M("SET_KEY",      f_set_key,  3.0, BRCMF_C_SET_KEY),
	M("SET_SSID",     f_set_ssid, 2.5, BRCMF_C_SET_SSID),
	M("SCAN",         f_scan,     2.5, BRCMF_C_SCAN),
	M("SET_WSEC_PMK", f_wsec_pmk, 3.0, BRCMF_C_SET_WSEC_PMK),
	M("SET_COUNTRY",  f_country,  1.5, BRCMF_C_SET_COUNTRY),
	M("RAW_IOCTL",    f_raw,      1.5, BRCMF_RAW),
};

/* ---- transport (ela_kmod shim) -------------------------------------------- */
/* LCOV_EXCL_START -- live injection needs the module + a bound driver */

struct brcmf_priv {
	int fd;
	uint64_t restart_base;
};

static int brcmf_attach(struct target *t)
{
	struct brcmf_priv *p = t->priv;
	uint64_t restarts = 0;

	p->fd = wlan_kmod_open();
	if (p->fd < 0) {
		fprintf(stderr, "[!] cannot open %s (load ela_kmod, run as root)\n",
			ELA_KMOD_DEVICE_PATH);
		return -1;
	}
	if (wlan_kmod_attach(p->fd, ELA_WLAN_DRV_BRCMFMAC) < 0) {
		fprintf(stderr, "[!] brcmfmac shim attach failed (driver loaded? CONFIG_KPROBES?)\n");
		wlan_kmod_close(p->fd);
		p->fd = -1;
		return -1;
	}
	printf("[*] waiting for brcmfmac ioctl traffic to capture driver context...\n");
	printf("    (bring the interface up or trigger a scan to generate it)\n");
	if (wlan_kmod_wait_capture(p->fd, 20000) < 0) {
		fprintf(stderr, "[!] no ioctl traffic captured; is the interface up?\n");
		wlan_kmod_detach(p->fd, ELA_WLAN_DRV_BRCMFMAC);
		wlan_kmod_close(p->fd);
		p->fd = -1;
		return -1;
	}
	wlan_kmod_status(p->fd, &restarts, NULL);
	p->restart_base = restarts;
	printf("[*] brcmfmac context captured; injecting firmware ioctls\n");
	return 0;
}

static int brcmf_send(struct target *t, const struct msg *m,
		      const uint8_t *payload, int len)
{
	struct brcmf_priv *p = t->priv;
	int32_t send_ret = 0;
	int r;

	if (m->cmd_id == BRCMF_RAW) {
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

static int brcmf_probe(struct target *t)
{
	struct brcmf_priv *p = t->priv;
	uint64_t restarts = p->restart_base;

	if (wlan_kmod_status(p->fd, &restarts, NULL) < 0)
		return 0;
	return restarts == p->restart_base;
}

static int brcmf_recover(struct target *t)
{
	struct brcmf_priv *p = t->priv;
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

static void brcmf_close(struct target *t)
{
	struct brcmf_priv *p = t->priv;

	if (p->fd >= 0) {
		wlan_kmod_detach(p->fd, ELA_WLAN_DRV_BRCMFMAC);
		wlan_kmod_close(p->fd);
		p->fd = -1;
	}
}

/* LCOV_EXCL_STOP */

struct target *target_brcmfmac(void)
{
	static struct brcmf_priv priv = { .fd = -1 };
	static struct target t = {
		.name = "brcmfmac",
		.big_endian = 0,
		.msgs = brcmfmac_msgs,
		.nmsgs = (int)(sizeof(brcmfmac_msgs) / sizeof(brcmfmac_msgs[0])),
		.attach = brcmf_attach,
		.send = brcmf_send,
		.probe_alive = brcmf_probe,
		.recover = brcmf_recover,
		.close = brcmf_close,
		.priv = &priv,
	};

	return &t;
}
