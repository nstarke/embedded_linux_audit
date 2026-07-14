// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * wifi-fw-fuzz core types: grammar model, mutation classes, target vtable.
 * Class-directed black-box fuzzer for WLAN NIC firmware host-command
 * interfaces, ported from the standalone wlan-nic-fuzz C tool.
 */
#ifndef WLAN_FUZZ_H
#define WLAN_FUZZ_H

#include <stddef.h>
#include <stdint.h>

/* ---- grammar ----------------------------------------------------------- */

enum fclass {
	FC_OPAQUE = 0,
	FC_INDEX,	/* indexes a fixed firmware array          */
	FC_LENGTH,	/* length field / length-bearing payload   */
	FC_COUNT,	/* element count for a trailing array      */
	FC_ARRAY,	/* array body: duplicates/truncate/extend  */
};

enum ftype {
	FT_U8, FT_U16, FT_U32,
	FT_BYTES,	/* raw payload, variable size (<= f->size cap grows
			   to FIELD_BYTES_MAX under LENGTH mutation) */
};

#define FIELD_BYTES_MAX 512
#define MSG_MAX_FIELDS  24
#define CASE_MAX_BYTES  1024

struct field {
	const char *name;
	enum ftype  type;
	enum fclass klass;
	uint32_t    dflt;	/* default for integer fields             */
	uint32_t    valid_max;	/* INDEX/COUNT: largest in-bounds value   */
	uint16_t    size;	/* FT_BYTES: default payload size         */
};

struct msg {
	const char  *name;
	double       weight;
	int          nfields;
	const struct field *fields;
	uint32_t     cmd_id;	/* vendor command id (target uses freely) */
};

/* one generated case, self-contained for replay */
struct fcase {
	int      msg_idx;
	uint32_t ints[MSG_MAX_FIELDS];		 /* integer field values   */
	uint8_t  bytes[MSG_MAX_FIELDS][FIELD_BYTES_MAX]; /* FT_BYTES values */
	uint16_t blen[MSG_MAX_FIELDS];
	char     note[128];
};

/* render case -> wire bytes. big_endian per target. returns length. */
int msg_build(const struct msg *m, const struct fcase *c, int big_endian,
	      uint8_t *out, int outcap);

/* fill a case with defaults, then mutate 1-2 fields by class */
void case_generate(const struct msg *msgs, int nmsgs, struct fcase *c);

/* xorshift rng (no libc rand -- reproducible across libcs via --seed) */
void rng_seed(uint64_t s);
uint64_t rng_next(void);
uint32_t rng_below(uint32_t n);

/* ---- target vtable ------------------------------------------------------ */

struct target {
	const char *name;
	int big_endian;
	const struct msg *msgs;
	int nmsgs;

	int  (*attach)(struct target *t);	 /* 0 ok, -1 fail          */
	/* send one framed case; 0 ok, -1 transport dead */
	int  (*send)(struct target *t, const struct msg *m,
		     const uint8_t *payload, int len);
	int  (*probe_alive)(struct target *t);	 /* 1 alive, 0 dead        */
	int  (*recover)(struct target *t);	 /* 1 back, 0 gone         */
	void (*close)(struct target *t);
	void *priv;
};

struct target *target_ath9k_htc(const char *fw_path);
struct target *target_rtw88(void);
struct target *target_mwifiex(void);
struct target *target_mt7601u(void);
struct target *target_carl9170(void);
struct target *target_rtl8xxxu(void);
struct target *target_ath10k(void);	/* PCIe/SDIO via the ela_kmod shim */
struct target *target_ath11k(void);	/* PCIe/SDIO via the ela_kmod shim */
struct target *target_ath12k(void);	/* PCIe/SDIO via the ela_kmod shim */
struct target *target_mt76(void);	/* PCIe/SDIO via the ela_kmod shim */
struct target *target_brcmfmac(void);	/* SDIO/PCIe/USB via the ela_kmod shim */

/* shared USB recovery: close, wait for re-enumeration, re-attach+probe */
int usb_recover_generic(struct target *t, int tries, int wait_ms);

/* ---- fuzz loop ----------------------------------------------------------- */

struct fuzz_opts {
	long iterations;
	int  probe_every;
	uint64_t seed;
	const char *out_dir;
	const char *replay_path;	/* if set: replay instead of fuzz */
};

int wlan_fuzz_run(struct target *t, const struct fuzz_opts *o);

/* offline engine self-tests (no hardware) */
int wlan_fuzz_selftest_run(void);

/* decode a crash file into a human-readable command/field breakdown (no
 * hardware); for triaging a reported finding. */
int wlan_fuzz_show(struct target *t, const char *path);

/* read the "# target=<name>" header a crash file records into out (outsz).
 * Returns 0 if found, -1 otherwise. */
int wlan_fuzz_peek_target(const char *path, char *out, size_t outsz);

void msleep_ms(int ms);

#endif
