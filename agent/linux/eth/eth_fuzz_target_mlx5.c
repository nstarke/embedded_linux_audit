// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Target: Mellanox ConnectX mlx5 firmware command interface (cmdif) over the
 * ela_kmod shim. The shim kprobes mlx5_cmd_exec(dev, in, in_size, out,
 * out_size), captures dev, and re-calls it with a fuzzed input mailbox (the
 * shim allocates the output buffer).
 *
 * cmdif commands are big-endian: the input begins with a 16-bit opcode, then a
 * 16-bit op_mod a few words in, then command-specific fields. The firmware
 * dispatches on opcode. Representative v1 grammar; verified offline only.
 */
#include "eth_fuzz_shim.h"
#include "../../../kmod/ela_ioctl.h"

#define MLX5_MIN_OPCODE 0x0100	/* QUERY_HCA_CAP */
#define MLX5_MAX_OPCODE 0x0a00	/* through the object/QP/CQ command range */

/* cmdif input (big-endian): opcode, uid, reserved, op_mod, then a fuzzed body. */
static const struct field f_cmd[] = {
	{ "opcode",   FT_U16, FC_INDEX,  MLX5_MIN_OPCODE, MLX5_MAX_OPCODE, 0 },
	{ "uid",      FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "reserved", FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "op_mod",   FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "body",     FT_BYTES, FC_LENGTH, 0, 0, 48 },
};

/* Object commands (CREATE/DESTROY/MODIFY GENERAL OBJECT) carry an object type
 * and length the firmware trusts -- a larger fuzzed body drives that boundary. */
static const struct field f_cmd_obj[] = {
	{ "opcode",   FT_U16, FC_OPAQUE, 0x0a00, 0, 0 },	/* CREATE_GENERAL_OBJECT */
	{ "uid",      FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "reserved", FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "op_mod",   FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "obj_type", FT_U16, FC_INDEX,  0, 0x00FF, 0 },
	{ "reserved2", FT_U16, FC_OPAQUE, 0, 0, 0 },
	{ "body",     FT_BYTES, FC_LENGTH, 64, 0, 64 },
};

#define M(nm, flds, w) \
	{ nm, w, (int)(sizeof(flds) / sizeof(flds[0])), flds, 0 }

static const struct msg mlx5_msgs[] = {
	M("CMD",     f_cmd,     3.0),
	M("CMD_OBJ", f_cmd_obj, 2.0),
};

ETH_SHIM_TARGET(target_mlx5, "mlx5", ELA_ETH_DRV_MLX5, 1, mlx5_msgs)
