// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Target: Intel 700-series i40e Admin Queue commands over the ela_kmod shim.
 * The shim kprobes i40e_asq_send_command(hw, desc, buff, buff_size, ...),
 * captures hw, and re-calls it with a fuzzed 32-byte AQ descriptor plus an
 * optional external buffer (the bytes after the 32-byte descriptor).
 *
 * The AQ descriptor (little-endian) is the fuzz surface: firmware dispatches on
 * `opcode` and trusts `datalen` for the external buffer. Representative v1
 * grammar; verified offline only (no i40e hardware here).
 */
#include "eth_fuzz_shim.h"
#include "../../../kmod/ela_ioctl.h"

#define I40E_AQ_MAX_OPCODE 0x0f10

/* struct i40e_aq_desc, 32 bytes: flags, opcode, datalen, retval, cookie(8),
 * params(16). `buffer` is the indirect external buffer split off by the shim. */
static const struct field f_aq[] = {
	{ "flags",       FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "opcode",      FT_U16, FC_INDEX,  0, I40E_AQ_MAX_OPCODE, 0 },
	{ "datalen",     FT_U16, FC_LENGTH, 0, 0, 0 },	/* trusted buffer length */
	{ "retval",      FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "cookie_high", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "cookie_low",  FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "param0",      FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "param1",      FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "addr_high",   FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "addr_low",    FT_U32, FC_OPAQUE, 0, 0, 0 },
};

/* Indirect variant: a larger external buffer with datalen driven against it. */
static const struct field f_aq_indirect[] = {
	{ "flags",       FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "opcode",      FT_U16, FC_INDEX,  0, I40E_AQ_MAX_OPCODE, 0 },
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

static const struct msg i40e_msgs[] = {
	M("AQ_CMD",      f_aq,          3.0),
	M("AQ_INDIRECT", f_aq_indirect, 2.0),
};

ETH_SHIM_TARGET(target_i40e, "i40e", ELA_ETH_DRV_I40E, 0, i40e_msgs)
