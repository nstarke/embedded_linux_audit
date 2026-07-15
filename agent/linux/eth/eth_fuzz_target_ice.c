// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Target: Intel E800-series ice Admin Queue commands over the ela_kmod shim.
 * The shim kprobes ice_sq_send_cmd(hw, cq, desc, buf, buf_size, ...), capturing
 * both hw and the control queue cq (the shim's second context arg), and
 * re-calls it with a fuzzed 32-byte AQ descriptor plus an optional buffer.
 *
 * Same AQ descriptor shape as i40e (little-endian); ice renumbers the opcodes.
 * Representative v1 grammar; verified offline only (no ice hardware here).
 */
#include "eth_fuzz_shim.h"
#include "../../../kmod/ela_ioctl.h"

#define ICE_AQ_MAX_OPCODE 0x0c40

static const struct field f_aq[] = {
	{ "flags",       FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "opcode",      FT_U16, FC_INDEX,  0, ICE_AQ_MAX_OPCODE, 0 },
	{ "datalen",     FT_U16, FC_LENGTH, 0, 0, 0 },
	{ "retval",      FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "cookie_high", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "cookie_low",  FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "param0",      FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "param1",      FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "addr_high",   FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "addr_low",    FT_U32, FC_OPAQUE, 0, 0, 0 },
};

static const struct field f_aq_indirect[] = {
	{ "flags",       FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "opcode",      FT_U16, FC_INDEX,  0, ICE_AQ_MAX_OPCODE, 0 },
	{ "datalen",     FT_U16, FC_LENGTH, 64, 0, 0 },
	{ "retval",      FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "cookie_high", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "cookie_low",  FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "param0",      FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "param1",      FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "addr_high",   FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "addr_low",    FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "buffer",      FT_BYTES, FC_LENGTH, 0, 0, 64 },
};

#define M(nm, flds, w) \
	{ nm, w, (int)(sizeof(flds) / sizeof(flds[0])), flds, 0 }

static const struct msg ice_msgs[] = {
	M("AQ_CMD",      f_aq,          3.0),
	M("AQ_INDIRECT", f_aq_indirect, 2.0),
};

ETH_SHIM_TARGET(target_ice, "ice", ELA_ETH_DRV_ICE, 0, ice_msgs)
