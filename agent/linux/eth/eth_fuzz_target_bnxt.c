// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Target: Broadcom NetXtreme bnxt HWRM commands over the ela_kmod shim. The
 * shim kprobes bnxt_hwrm_do_send_msg(bp, msg, msg_len, ...) (pre-5.12 symbol),
 * captures bp, and re-calls it with a fuzzed HWRM request.
 *
 * HWRM requests are little-endian and begin with a 16-byte input header
 * (req_type, cmpl_ring, seq_id, target_id, resp_addr); the firmware dispatches
 * on req_type. This is a representative v1 grammar: it sweeps req_type over the
 * command space and fuzzes the trailing body's length/content -- the field
 * classes (the swept command id and the length-bearing body) are the stable
 * bug surface across HWRM ABI versions even as individual command layouts and
 * numbers shift. Verified offline only (no bnxt hardware here).
 */
#include "eth_fuzz_shim.h"
#include "../../../kmod/ela_ioctl.h"

#define HWRM_MAX_REQ_TYPE 0x0210	/* command-number space to sweep */

/* 16-byte HWRM input header + a fuzzed body. */
static const struct field f_hwrm[] = {
	{ "req_type",   FT_U16, FC_INDEX,  0, HWRM_MAX_REQ_TYPE, 0 },
	{ "cmpl_ring",  FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "seq_id",     FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "target_id",  FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "resp_addr",  FT_BYTES, FC_OPAQUE, 0, 0, 8 },
	{ "body",       FT_BYTES, FC_LENGTH, 0, 0, 32 },
};

/* FUNC_CFG (0x16): a big enables bitmask gates dozens of fields the firmware
 * then trusts -- a rich handler to point the length/count mutations at. */
static const struct field f_hwrm_func_cfg[] = {
	{ "req_type",   FT_U16, FC_OPAQUE, 0x0016, 0, 0 },
	{ "cmpl_ring",  FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "seq_id",     FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "target_id",  FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "resp_addr",  FT_BYTES, FC_OPAQUE, 0, 0, 8 },
	{ "fid",        FT_U16, FC_INDEX,  0, 0xFF, 0 },
	{ "enables",    FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "body",       FT_BYTES, FC_LENGTH, 0, 0, 48 },
};

/* RING_ALLOC (0x10): ring type + page-count fields the firmware validates. */
static const struct field f_hwrm_ring_alloc[] = {
	{ "req_type",   FT_U16, FC_OPAQUE, 0x0010, 0, 0 },
	{ "cmpl_ring",  FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "seq_id",     FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "target_id",  FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "resp_addr",  FT_BYTES, FC_OPAQUE, 0, 0, 8 },
	{ "enables",    FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "ring_type",  FT_U8,  FC_INDEX,  0, 8, 0 },
	{ "pad",        FT_BYTES, FC_OPAQUE, 0, 0, 3 },
	{ "page_size",  FT_U8,  FC_OPAQUE, 0, 0, 0 },
	{ "length",     FT_U32, FC_COUNT,  0, 2048, 0 },
	{ "body",       FT_BYTES, FC_LENGTH, 0, 0, 32 },
};

#define M(nm, flds, w) \
	{ nm, w, (int)(sizeof(flds) / sizeof(flds[0])), flds, 0 }

static const struct msg bnxt_msgs[] = {
	M("HWRM",           f_hwrm,           3.0),
	M("HWRM_FUNC_CFG",  f_hwrm_func_cfg,  2.0),
	M("HWRM_RING_ALLOC", f_hwrm_ring_alloc, 2.0),
};

ETH_SHIM_TARGET(target_bnxt, "bnxt", ELA_ETH_DRV_BNXT, 0, bnxt_msgs)
