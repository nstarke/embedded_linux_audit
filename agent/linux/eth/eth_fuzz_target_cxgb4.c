// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Target: Chelsio T4/T5/T6 cxgb4 FW_CMD mailbox commands over the ela_kmod
 * shim. The shim kprobes t4_wr_mbox_meat_timeout(adap, mbox, cmd, size, ...),
 * captures adap and the mailbox number (the shim's second context arg), and
 * re-calls it with a fuzzed FW command (8-byte-aligned, <= 64 bytes).
 *
 * FW commands are big-endian: an 8-byte header (op_to_write with the opcode in
 * the top byte of the first word; retval_len16 in the second) followed by the
 * command body. Representative v1 grammar; verified offline only.
 */
#include "eth_fuzz_shim.h"
#include "../../../kmod/ela_ioctl.h"

/* FW_CMD header (big-endian) + body. The opcode + request/read/write bits are
 * packed into `op_to_write`; fuzzing the whole word sweeps opcode and flags. */
static const struct field f_fwcmd[] = {
	{ "op_to_write",  FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "retval_len16", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "body",         FT_BYTES, FC_LENGTH, 0, 0, 40 },
};

/* A larger body to drive the length past the driver's 64-byte mailbox bound. */
static const struct field f_fwcmd_big[] = {
	{ "op_to_write",  FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "retval_len16", FT_U32, FC_OPAQUE, 0, 0, 0 },
	{ "body",         FT_BYTES, FC_LENGTH, 48, 0, 48 },
};

#define M(nm, flds, w) \
	{ nm, w, (int)(sizeof(flds) / sizeof(flds[0])), flds, 0 }

static const struct msg cxgb4_msgs[] = {
	M("FW_CMD",     f_fwcmd,     3.0),
	M("FW_CMD_BIG", f_fwcmd_big, 1.5),
};

ETH_SHIM_TARGET(target_cxgb4, "cxgb4", ELA_ETH_DRV_CXGB4, 1, cxgb4_msgs)
