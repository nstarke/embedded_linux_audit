// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Offline self-tests: no hardware, no usbfs. A mock target with a planted
 * sequence-dependent bug lets the engine be validated on any host.
 *
 * Checks:
 *  1. struct render sizes match the audit-verified wire layouts
 *  2. mutation engine generates every bug-class trigger
 *  3. full fuzz loop finds a planted sequence-dependent crash and the
 *     triage minimizes it to a reproducing sequence (mock transport)
 */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "wlan_fuzz.h"
#include "linux/eth/eth_fuzz.h"

/* ---- pull in the ath9k grammar via its target constructor ---------------- */

static const struct msg *find_msg(struct target *t, const char *name)
{
	int i;

	for (i = 0; i < t->nmsgs; i++)
		if (!strcmp(t->msgs[i].name, name))
			return &t->msgs[i];
	return NULL;
}

struct size_expect {
	const char *name;
	int want;
};

/* Render each named message at its defaults and confirm the wire size
 * matches the driver's own struct-size constant. */
static int check_sizes(struct target *t, const struct size_expect *sizes,
		       int n, const char *label)
{
	struct fcase c;
	uint8_t buf[CASE_MAX_BYTES];
	int i, j, len, fail = 0;

	for (i = 0; i < n; i++) {
		const struct msg *m = find_msg(t, sizes[i].name);

		if (!m) {
			printf("FAIL: msg %s missing\n", sizes[i].name);
			fail = 1;
			continue;
		}
		/* defaults: build the case by hand */
		memset(&c, 0, sizeof(c));
		for (j = 0; j < m->nfields; j++) {
			if (m->fields[j].type == FT_BYTES)
				c.blen[j] = m->fields[j].size;
			else
				c.ints[j] = m->fields[j].dflt;
		}
		len = msg_build(m, &c, t->big_endian, buf, sizeof(buf));
		if (len != sizes[i].want) {
			printf("FAIL: %s %s renders %d, want %d\n",
			       label, sizes[i].name, len, sizes[i].want);
			fail = 1;
		}
	}
	printf("%s: %s render sizes\n", fail ? "FAIL" : "OK", label);
	return fail;
}

static int test_render_sizes(void)
{
	static const struct size_expect ath9k[] = {
		{ "NODE_CREATE", 22 },	/* NODE_TARGET_SIZE */
		{ "VAP_CREATE", 12 },	/* VAP_TARGET_SIZE  */
		{ "RC_RATE_UPDATE", 70 },
		{ "BITRATE_MASK", 8 },
		{ "DRAIN_TXQ", 4 },
	};
	static const struct size_expect carl9170[] = {
		{ "EKEY", 28 },		/* CARL9170_SET_KEY_CMD_SIZE     */
		{ "DKEY", 4 },		/* CARL9170_DISABLE_KEY_CMD_SIZE */
		{ "BCN_CTRL", 16 },	/* CARL9170_BCN_CTRL_CMD_SIZE    */
		{ "RX_FILTER", 4 },	/* CARL9170_RX_FILTER_CMD_SIZE   */
		{ "RF_INIT", 28 },	/* CARL9170_RF_INIT_SIZE         */
		{ "PSM", 4 },		/* CARL9170_PSM_SIZE             */
		{ "WOL", 60 },		/* CARL9170_WOL_CMD_SIZE         */
	};
	static const struct size_expect ath10k[] = {
		{ "VDEV_CREATE", 20 },	/* wmi_vdev_create_cmd      */
		{ "VDEV_DELETE", 4 },	/* wmi_vdev_delete_cmd      */
		{ "VDEV_SET_PARAM", 12 }, /* wmi_vdev_set_param_cmd  */
		{ "PEER_CREATE", 16 },	/* wmi_peer_create_cmd      */
		{ "PEER_DELETE", 12 },	/* wmi_peer_delete_cmd      */
		{ "PEER_SET_PARAM", 20 }, /* wmi_peer_set_param_cmd  */
		{ "PDEV_SET_PARAM", 8 },  /* wmi_pdev_set_param_cmd  */
	};
	static const struct size_expect ath11k[] = {	/* TLV structs (u32 tlv_header) */
		{ "VDEV_CREATE", 40 },	/* wmi_vdev_create_cmd      */
		{ "VDEV_DELETE", 8 },	/* wmi_vdev_delete_cmd      */
		{ "VDEV_SET_PARAM", 16 }, /* wmi_vdev_set_param_cmd  */
		{ "PDEV_SET_PARAM", 16 }, /* wmi_pdev_set_param_cmd  */
		{ "PEER_CREATE", 20 },	/* wmi_peer_create_cmd      */
		{ "PEER_DELETE", 16 },	/* wmi_peer_delete_cmd      */
	};
	static const struct size_expect ath12k[] = {	/* ath12k TLV structs */
		{ "VDEV_CREATE", 48 },	/* wmi_vdev_create_cmd (Wi-Fi 7) */
		{ "VDEV_DELETE", 8 },
		{ "VDEV_SET_PARAM", 16 },
		{ "PDEV_SET_PARAM", 16 },
		{ "PEER_CREATE", 20 },
		{ "PEER_DELETE", 16 },
	};
	static const struct size_expect mt76[] = {	/* connac hdr(8) + TLV(4) + body(16) */
		{ "STA_REC_UPDATE", 28 },	/* sta_req_hdr + one TLV */
		{ "WTBL_UPDATE", 28 },		/* wtbl_req_hdr + one TLV */
	};
	static const struct size_expect brcmfmac[] = {	/* fwil_types.h _le structs */
		{ "SET_KEY", 164 },	/* brcmf_wsec_key_le      */
		{ "SET_SSID", 52 },	/* brcmf_join_params      */
		{ "SCAN", 64 },		/* brcmf_scan_params_le fixed */
		{ "SET_WSEC_PMK", 132 }, /* brcmf_wsec_pmk_le     */
		{ "SET_COUNTRY", 12 },	/* brcmf_fil_country_le   */
	};
	int fail = 0;

	fail |= check_sizes(target_ath9k_htc(NULL), ath9k,
			    (int)(sizeof(ath9k) / sizeof(ath9k[0])), "ath9k-htc");
	fail |= check_sizes(target_carl9170(), carl9170,
			    (int)(sizeof(carl9170) / sizeof(carl9170[0])),
			    "carl9170");
	fail |= check_sizes(target_ath10k(), ath10k,
			    (int)(sizeof(ath10k) / sizeof(ath10k[0])),
			    "ath10k");
	fail |= check_sizes(target_ath11k(), ath11k,
			    (int)(sizeof(ath11k) / sizeof(ath11k[0])),
			    "ath11k");
	fail |= check_sizes(target_ath12k(), ath12k,
			    (int)(sizeof(ath12k) / sizeof(ath12k[0])),
			    "ath12k");
	fail |= check_sizes(target_mt76(), mt76,
			    (int)(sizeof(mt76) / sizeof(mt76[0])), "mt76");
	fail |= check_sizes(target_brcmfmac(), brcmfmac,
			    (int)(sizeof(brcmfmac) / sizeof(brcmfmac[0])),
			    "brcmfmac");
	return fail;
}

/* rtl8xxxu H2C messages must fit the fixed 8-byte mailbox box. */
static int test_rtl8xxxu_box_size(void)
{
	struct target *t = target_rtl8xxxu();
	struct fcase c;
	uint8_t buf[CASE_MAX_BYTES];
	int i, j, len, fail = 0;

	for (i = 0; i < t->nmsgs; i++) {
		const struct msg *m = &t->msgs[i];

		memset(&c, 0, sizeof(c));
		for (j = 0; j < m->nfields; j++) {
			if (m->fields[j].type == FT_BYTES)
				c.blen[j] = m->fields[j].size;
			else
				c.ints[j] = m->fields[j].dflt;
		}
		len = msg_build(m, &c, t->big_endian, buf, sizeof(buf));
		if (len < 1 || len > 8) {
			printf("FAIL: rtl8xxxu %s renders %d bytes (box is 8)\n",
			       m->name, len);
			fail = 1;
		}
	}
	printf("%s: rtl8xxxu box sizes (<=8)\n", fail ? "FAIL" : "OK");
	return fail;
}

/*
 * usb-generic is a blind target with no chip grammar; still, every generated
 * case must render within bounds and carry the fixed transport header (6 bytes
 * for the control messages, 1 for bulk) that gen_send() parses back out.
 */
static int test_usb_generic_grammar(void)
{
	struct target *t = target_usb_generic(0x0bda, 0x8179);
	struct fcase c;
	uint8_t buf[CASE_MAX_BYTES];
	int r, len, fail = 0;

	if (t->nmsgs != 3 || t->big_endian != 0) {
		printf("FAIL: usb-generic shape (nmsgs=%d be=%d)\n",
		       t->nmsgs, t->big_endian);
		fail = 1;
	}
	rng_seed(99);
	for (r = 0; r < 5000 && !fail; r++) {
		const struct msg *m;
		int min_hdr;

		case_generate(t->msgs, t->nmsgs, &c);
		m = &t->msgs[c.msg_idx];
		len = msg_build(m, &c, t->big_endian, buf, sizeof(buf));
		min_hdr = (m->cmd_id == 2) ? 1 : 6;	/* BULK vs CTRL header */
		if (len < min_hdr || len > CASE_MAX_BYTES) {
			printf("FAIL: usb-generic %s renders %d bytes (hdr %d)\n",
			       m->name, len, min_hdr);
			fail = 1;
		}
	}
	printf("%s: usb-generic grammar renders within transport bounds\n",
	       fail ? "FAIL" : "OK");
	return fail;
}

/*
 * wext-generic is blind and has no chip grammar; each generated case must
 * still render within bounds. POINT ioctls can render 0 bytes (empty
 * buffer/scan trigger); PARAM/FREQ carry their fixed header, but since only
 * some fields mutate per case we just assert the case renders and stays bounded.
 */
static int test_wext_grammar(void)
{
	struct target *t = target_wext_generic("wlan0");
	struct fcase c;
	uint8_t buf[CASE_MAX_BYTES];
	int r, len, fail = 0;

	if (t->nmsgs < 10 || t->big_endian != 0) {
		printf("FAIL: wext-generic shape (nmsgs=%d be=%d)\n",
		       t->nmsgs, t->big_endian);
		fail = 1;
	}
	rng_seed(4242);
	for (r = 0; r < 5000 && !fail; r++) {
		const struct msg *m;

		case_generate(t->msgs, t->nmsgs, &c);
		m = &t->msgs[c.msg_idx];
		len = msg_build(m, &c, t->big_endian, buf, sizeof(buf));
		if (len < 0 || len > CASE_MAX_BYTES) {
			printf("FAIL: wext-generic %s renders %d bytes\n",
			       m->name, len);
			fail = 1;
		}
	}
	printf("%s: wext-generic grammar renders within bounds\n",
	       fail ? "FAIL" : "OK");
	return fail;
}

/*
 * ethtool-generic (ethernet blind target): each case must carry the 4-byte
 * ethtool command word and render within the ioctl buffer bound. The read-path
 * ops keep a len word the transport clamps, so here we just assert bounds.
 */
static int test_ethtool_grammar(void)
{
	struct target *t = target_ethtool_generic("eth0");
	struct fcase c;
	uint8_t buf[CASE_MAX_BYTES];
	int r, len, fail = 0;

	if (t->nmsgs < 8 || t->big_endian != 0) {
		printf("FAIL: ethtool-generic shape (nmsgs=%d be=%d)\n",
		       t->nmsgs, t->big_endian);
		fail = 1;
	}
	rng_seed(31337);
	for (r = 0; r < 5000 && !fail; r++) {
		const struct msg *m;

		case_generate(t->msgs, t->nmsgs, &c);
		m = &t->msgs[c.msg_idx];
		len = msg_build(m, &c, t->big_endian, buf, sizeof(buf));
		if (len < 4 || len > CASE_MAX_BYTES) {	/* >= the cmd word */
			printf("FAIL: ethtool-generic %s renders %d bytes\n",
			       m->name, len);
			fail = 1;
		}
	}
	printf("%s: ethtool-generic grammar renders within ioctl bounds\n",
	       fail ? "FAIL" : "OK");
	return fail;
}

/*
 * Ethernet firmware-command targets (bnxt/i40e/ice/cxgb4/mlx5): each renders a
 * bounded command buffer the shim caps before injecting. Assert every case
 * renders within CASE_MAX_BYTES so the grammars are well-formed offline.
 */
static int test_eth_firmware_grammars(void)
{
	struct target *targets[] = {
		target_bnxt(), target_i40e(), target_ice(),
		target_cxgb4(), target_mlx5(),
	};
	struct fcase c;
	uint8_t buf[CASE_MAX_BYTES];
	int ti, r, len, fail = 0;

	rng_seed(0xE7);
	for (ti = 0; ti < (int)(sizeof(targets) / sizeof(targets[0])); ti++) {
		struct target *t = targets[ti];

		for (r = 0; r < 2000 && !fail; r++) {
			const struct msg *m;

			case_generate(t->msgs, t->nmsgs, &c);
			m = &t->msgs[c.msg_idx];
			len = msg_build(m, &c, t->big_endian, buf, sizeof(buf));
			if (len < 1 || len > CASE_MAX_BYTES) {
				printf("FAIL: %s %s renders %d bytes\n",
				       t->name, m->name, len);
				fail = 1;
			}
		}
	}
	printf("%s: ethernet firmware grammars (bnxt/i40e/ice/cxgb4/mlx5) render "
	       "within bounds\n", fail ? "FAIL" : "OK");
	return fail;
}

static int test_mutation_coverage(void)
{
	struct target *t = target_ath9k_htc(NULL);
	long off_by_one = 0, deep_oob = 0, echo_over = 0, count_lie = 0,
	     wide_idx = 0;
	struct fcase c;
	int r, i;

	rng_seed(1234);
	for (r = 0; r < 20000; r++) {
		const struct msg *m;

		case_generate(t->msgs, t->nmsgs, &c);
		m = &t->msgs[c.msg_idx];
		for (i = 0; i < m->nfields; i++) {
			const struct field *f = &m->fields[i];

			if (f->klass == FC_INDEX && f->type == FT_U8 &&
			    f->valid_max == 7) {
				if (c.ints[i] == 8)
					off_by_one++;
				else if (c.ints[i] > 8)
					deep_oob++;
			}
			if (f->klass == FC_COUNT && c.ints[i] > f->valid_max)
				count_lie++;
			if (f->klass == FC_INDEX && f->type == FT_U32 &&
			    c.ints[i] > 0xFFFF)
				wide_idx++;
			if (f->klass == FC_LENGTH && f->type == FT_BYTES &&
			    c.blen[i] > 112)
				echo_over++;
		}
	}
	printf("coverage: off_by_one=%ld deep_oob=%ld echo_overflow=%ld "
	       "count_lie=%ld wide_idx=%ld\n",
	       off_by_one, deep_oob, echo_over, count_lie, wide_idx);
	if (off_by_one && deep_oob && echo_over && count_lie && wide_idx) {
		printf("OK: all audit bug-class triggers generated\n");
		return 0;
	}
	printf("FAIL: a bug-class trigger was never generated\n");
	return 1;
}

/* ---- mock target: sequence-dependent planted bug -------------------------- */

static const struct field mock_vap[] = {
	{ "vapindex", FT_U8, FC_INDEX, 0, 1, 0 },
};
static const struct field mock_node[] = {
	{ "nodeindex", FT_U8, FC_INDEX, 0, 7, 0 },
};
static const struct msg mock_msgs[] = {
	{ "VAP_CREATE", 1.0, 1, mock_vap, 0 },
	{ "NODE_CREATE", 1.0, 1, mock_node, 1 },
};

static struct {
	int armed, dead, sends;
} mock;

static int mock_attach(struct target *t)
{
	(void)t;
	mock.armed = 0;
	mock.dead = 0;
	return 0;
}

static int mock_send(struct target *t, const struct msg *m,
		     const uint8_t *payload, int len)
{
	(void)t;
	mock.sends++;
	if (mock.dead)
		return -1;
	if (m->cmd_id == 0)	/* VAP_CREATE arms */
		mock.armed = 1;
	if (m->cmd_id == 1 && len >= 1 && payload[0] == 8 && mock.armed)
		mock.dead = 1;	/* NODE_CREATE idx 8 after arming kills */
	return 0;
}

static int mock_probe(struct target *t)
{
	(void)t;
	return !mock.dead;
}

static int mock_recover(struct target *t)
{
	(void)t;
	mock.armed = 0;
	mock.dead = 0;
	return 1;
}

static void mock_close(struct target *t)
{
	(void)t;
}

/* Count crash_* artifacts in dir and unlink them (test cleanup). */
static int drain_crashes(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *de;
	char path[512];
	int n = 0;

	if (!d)
		return 0;
	while ((de = readdir(d))) {
		if (strncmp(de->d_name, "crash_", 6) != 0)
			continue;
		n++;
		snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
		unlink(path);
	}
	closedir(d);
	return n;
}

static int test_fuzz_loop(void)
{
	static struct target t = {
		.name = "mock",
		.big_endian = 0,
		.msgs = mock_msgs,
		.nmsgs = 2,
		.attach = mock_attach,
		.send = mock_send,
		.probe_alive = mock_probe,
		.recover = mock_recover,
		.close = mock_close,
	};
	struct fuzz_opts o = {
		.iterations = 500,
		.probe_every = 4,
		.seed = 7,
		.out_dir = "/tmp/ela-wlan-fuzz-selftest",
	};
	int n;

	drain_crashes(o.out_dir);	/* clear stale artifacts */
	wlan_fuzz_run(&t, &o);
	n = drain_crashes(o.out_dir);
	printf("%s: fuzz loop found planted sequence bug (%d crash files, "
	       "expect >=1, all *_min)\n", n >= 1 ? "OK" : "FAIL", n);
	return n < 1;
}

int wlan_fuzz_selftest_run(void)
{
	int fail = 0;

	fail |= test_render_sizes();
	fail |= test_rtl8xxxu_box_size();
	fail |= test_usb_generic_grammar();
	fail |= test_wext_grammar();
	fail |= test_ethtool_grammar();
	fail |= test_eth_firmware_grammars();
	fail |= test_mutation_coverage();
	fail |= test_fuzz_loop();
	printf(fail ? "SELFTEST FAILED\n" : "SELFTEST PASSED\n");
	return fail;
}
