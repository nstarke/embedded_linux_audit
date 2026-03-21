// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "linux_gdbserver_util.h"
#include "../embedded_linux_audit_cmd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>

#if defined(__x86_64__)
#  include <sys/user.h>
#elif defined(__aarch64__)
#  include <sys/uio.h>
#  include <elf.h>
#  include <asm/ptrace.h>
#elif defined(__arm__)
#  include <sys/user.h>
#  include <sys/uio.h>
#  include <elf.h>
#elif defined(__mips__)
#  include <sys/uio.h>
#  include <elf.h>
/*
 * Offsets into the MIPS elf_gregset_t (unsigned long[45]) returned by
 * PTRACE_GETREGSET/NT_PRSTATUS.  Indices 0-5 are the argument-save area
 * pad from struct pt_regs; real registers begin at index 6.
 */
#  define MIPS_EF_R0       6   /* first GPR (r0/zero) */
#  define MIPS_EF_STATUS  38   /* CP0 Status */
#  define MIPS_EF_HI      39   /* HI multiply/divide result */
#  define MIPS_EF_LO      40   /* LO multiply/divide result */
#  define MIPS_EF_BADVADDR 41  /* CP0 BadVAddr */
#  define MIPS_EF_CAUSE   42   /* CP0 Cause */
#  define MIPS_EF_EPC     43   /* CP0 EPC (PC) */
#  define MIPS_ELF_NGREG  45   /* total slots in elf_gregset_t */
#elif defined(__powerpc__)
/*
 * Indices into the PPC elf_gregset_t (unsigned long[48]) returned by
 * PTRACE_GETREGSET/NT_PRSTATUS.  Layout mirrors struct pt_regs.
 * These indices are identical for PPC32 and PPC64; only the element
 * width (4 vs 8 bytes) differs.
 */
#  include <sys/uio.h>
#  include <elf.h>
#  define PPC_PT_GPR0    0   /* r0-r31 at indices 0-31 */
#  define PPC_PT_NIP    32   /* PC (next instruction pointer) */
#  define PPC_PT_MSR    33   /* machine state register */
#  define PPC_PT_CTR    35   /* count register */
#  define PPC_PT_LNK    36   /* link register */
#  define PPC_PT_XER    37   /* integer exception register */
#  define PPC_PT_CCR    38   /* condition code register (CR) */
#  define PPC_ELF_NGREG  48  /* total slots in elf_gregset_t */
#  define PPC_ELF_NFPREG 33  /* 32 FP regs + 1 FPSCR slot */
#  ifndef NT_PRFPREG
#    define NT_PRFPREG  2
#  endif
#elif defined(__riscv)
#  include <sys/uio.h>
#  include <elf.h>
/*
 * Linux struct user_regs_struct for both RV32 and RV64
 * (PTRACE_GETREGSET/NT_PRSTATUS) is a plain array of 32 unsigned longs:
 *   [0] = pc, [1] = x1(ra), [2] = x2(sp), ..., [31] = x31(t6).
 * x0 is the hard-wired zero register and is not stored by the kernel.
 * unsigned long is 4 bytes on RV32 and 8 bytes on RV64.
 */
#  define RISCV_PT_PC    0   /* program counter */
#  define RISCV_PT_X1    1   /* x1 (ra) — first non-zero GPR */
#  define RISCV_PT_NREGS 32  /* entries in the kernel regs array */
#endif

/* Maximum number of tracked software breakpoints */
#define ELA_GDB_MAX_BREAKPOINTS  64

/* Maximum byte size of the SVR4 library-list XML document */
#define ELA_GDB_SVR4_XML_MAX     16384

/* Trap instruction bytes per architecture */
#if defined(__x86_64__)
static const uint8_t k_x86_brk[1]     = { 0xCC };             /* int3 */
#elif defined(__aarch64__)
static const uint8_t k_aarch64_brk[4] = { 0x00, 0x00, 0x20, 0xd4 }; /* brk #0 */
#elif defined(__arm__)
static const uint8_t k_arm_brk[4]     = { 0xf0, 0x01, 0xf0, 0xe7 }; /* undef (ARM) */
static const uint8_t k_thumb_brk[2]   = { 0x01, 0xde };              /* undef (Thumb) */
#elif defined(__mips__)
/*
 * MIPS BREAK instruction (code=0): opcode 0 / func 0x0d = 0x0000000d.
 * Byte order depends on target endianness.
 */
#  if defined(__MIPSEB__)
static const uint8_t k_mips_brk[4]    = { 0x00, 0x00, 0x00, 0x0d }; /* BE */
#  else
static const uint8_t k_mips_brk[4]    = { 0x0d, 0x00, 0x00, 0x00 }; /* LE */
#  endif
#elif defined(__powerpc__)
/*
 * PPC trap instruction (unconditional): 'trap' = 0x7fe00008 (BE).
 * The encoding is the same for PPC32 and PPC64.
 */
static const uint8_t k_ppc_brk[4]     = { 0x7f, 0xe0, 0x00, 0x08 }; /* BE */
#elif defined(__riscv)
/*
 * ebreak (4-byte): 0x00100073 in LE byte order.  Same encoding on RV32/RV64.
 * c.ebreak (2-byte): 0x9002 in LE byte order (RVC, same on both widths).
 */
static const uint8_t k_riscv_brk[4]   = { 0x73, 0x00, 0x10, 0x00 }; /* LE */
static const uint8_t k_riscv_c_brk[2] = { 0x02, 0x90 };              /* LE */
#endif

/*
 * Per-breakpoint state.  orig_bytes holds up to 4 bytes of the original
 * instruction that was overwritten; size records how many bytes were used
 * (1 for x86, 2 for Thumb, 4 for ARM/AArch64).
 */
struct bp_entry {
	uint64_t addr;
	uint8_t  orig_bytes[4];
	int      size;
	bool     in_use;
};

/* Session globals (single-session, single-threaded) */
static struct bp_entry g_bps[ELA_GDB_MAX_BREAKPOINTS];
static pid_t           g_pid;
static volatile int    g_stop;

/* Thread list populated by qfThreadInfo and paged by qsThreadInfo */
#define ELA_GDB_MAX_THREADS  256
static pid_t g_tids[ELA_GDB_MAX_THREADS];
static int   g_tid_count;
static int   g_tid_next;

/* SVR4 library-list XML cache (rebuilt at the start of each transfer) */
static char  g_svr4_xml[ELA_GDB_SVR4_XML_MAX];
static int   g_svr4_xml_len = -1; /* -1 = not yet built for this session */

/*
 * Target XML served by qXfer:features:read:target.xml.
 * GDB uses this to know the register layout and ABI.
 */
#if defined(__x86_64__)
static const char k_target_xml[] =
	"<?xml version=\"1.0\"?>"
	"<!DOCTYPE target SYSTEM \"gdb-target.dtd\">"
	"<target><architecture>i386:x86-64</architecture></target>";
#elif defined(__aarch64__)
static const char k_target_xml[] =
	"<?xml version=\"1.0\"?>"
	"<!DOCTYPE target SYSTEM \"gdb-target.dtd\">"
	"<target><architecture>aarch64</architecture></target>";
#elif defined(__arm__)
static const char k_target_xml[] =
	"<?xml version=\"1.0\"?>"
	"<!DOCTYPE target SYSTEM \"gdb-target.dtd\">"
	"<target><architecture>arm</architecture></target>";
#elif defined(__mips__) && defined(__mips64)
static const char k_target_xml[] =
	"<?xml version=\"1.0\"?>"
	"<!DOCTYPE target SYSTEM \"gdb-target.dtd\">"
	"<target><architecture>mips:isa64</architecture></target>";
#elif defined(__mips__) && defined(__MIPSEL__)
static const char k_target_xml[] =
	"<?xml version=\"1.0\"?>"
	"<!DOCTYPE target SYSTEM \"gdb-target.dtd\">"
	"<target><architecture>mipsel</architecture></target>";
#elif defined(__mips__)
static const char k_target_xml[] =
	"<?xml version=\"1.0\"?>"
	"<!DOCTYPE target SYSTEM \"gdb-target.dtd\">"
	"<target><architecture>mips</architecture></target>";
#elif defined(__powerpc64__)
static const char k_target_xml[] =
	"<?xml version=\"1.0\"?>"
	"<!DOCTYPE target SYSTEM \"gdb-target.dtd\">"
	"<target><architecture>powerpc:common64</architecture></target>";
#elif defined(__powerpc__)
static const char k_target_xml[] =
	"<?xml version=\"1.0\"?>"
	"<!DOCTYPE target SYSTEM \"gdb-target.dtd\">"
	"<target><architecture>powerpc:common</architecture></target>";
#elif defined(__riscv) && (__riscv_xlen == 64)
static const char k_target_xml[] =
	"<?xml version=\"1.0\"?>"
	"<!DOCTYPE target SYSTEM \"gdb-target.dtd\">"
	"<target><architecture>riscv:rv64</architecture></target>";
#elif defined(__riscv) && (__riscv_xlen == 32)
static const char k_target_xml[] =
	"<?xml version=\"1.0\"?>"
	"<!DOCTYPE target SYSTEM \"gdb-target.dtd\">"
	"<target><architecture>riscv:rv32</architecture></target>";
#else
static const char k_target_xml[] =
	"<?xml version=\"1.0\"?>"
	"<!DOCTYPE target SYSTEM \"gdb-target.dtd\">"
	"<target></target>";
#endif

static void handle_signal(int sig)
{
	(void)sig;
	g_stop = 1;
}

/* -----------------------------------------------------------------------
 * RSP I/O
 * ---------------------------------------------------------------------- */

static int rsp_send(int fd, const char *data, size_t len)
{
	char buf[ELA_GDB_RSP_MAX_FRAMED + 4];
	ssize_t n;

	if (ela_gdb_rsp_frame(data, len, buf, sizeof(buf)) != 0)
		return -1;
	n = send(fd, buf, strlen(buf), 0);
	return (n < 0) ? -1 : 0;
}

static int rsp_send_str(int fd, const char *s)
{
	return rsp_send(fd, s, strlen(s));
}

/*
 * Send a binary-safe RSP qXfer response.
 *
 * RSP requires four bytes to be escaped inside packet data: $, #, *, and }.
 * Each is replaced by } followed by the byte XOR'd with 0x20.  The checksum
 * is computed over the escaped bytes (including the 'm'/'l' prefix).
 *
 * `last` true  → prefix 'l' (final or only chunk)
 * `last` false → prefix 'm' (more data follows)
 */
static int rsp_send_binary_qxfer(int fd, const uint8_t *data, size_t data_len,
				 bool last)
{
	/* Worst case: every byte needs escaping (×2) plus framing overhead. */
	char buf[ELA_GDB_RSP_MAX_PACKET * 2 + 8];
	static const char hex[] = "0123456789abcdef";
	uint8_t cksum = 0;
	size_t i, pos = 0;
	uint8_t b;
	ssize_t sent;

	if (data_len > ELA_GDB_RSP_MAX_PACKET)
		data_len = ELA_GDB_RSP_MAX_PACKET;

	buf[pos++] = '$';

	/* 'm' or 'l' prefix is part of the payload and counted in checksum */
	b = last ? (uint8_t)'l' : (uint8_t)'m';
	buf[pos++] = (char)b;
	cksum += b;

	for (i = 0; i < data_len; i++) {
		b = data[i];
		if (b == '$' || b == '#' || b == '*' || b == '}') {
			buf[pos++] = '}';
			buf[pos++] = (char)(b ^ 0x20u);
			cksum += (uint8_t)'}';
			cksum += (uint8_t)(b ^ 0x20u);
		} else {
			buf[pos++] = (char)b;
			cksum += b;
		}
	}

	buf[pos++] = '#';
	buf[pos++] = hex[cksum >> 4];
	buf[pos++] = hex[cksum & 0x0f];

	sent = send(fd, buf, pos, 0);
	return (sent < 0) ? -1 : 0;
}

/*
 * Read one RSP packet from `fd` into `payload` (NUL-terminated).
 * Skips leading '+'/'-' ACK bytes.  Sends '+' ACK on success.
 * Returns payload length on success, -1 on disconnect or error.
 */
static int rsp_recv_packet(int fd, char *payload, size_t payload_sz)
{
	char raw[ELA_GDB_RSP_MAX_FRAMED + 4];
	size_t pos = 0;
	ssize_t n;
	unsigned char c;

	/* Scan for '$' skipping ACK characters */
	while (pos < sizeof(raw) - 4) {
		n = recv(fd, &c, 1, 0);
		if (n <= 0)
			return -1;
		if (c == '+' || c == '-')
			continue;
		if (c == '$') {
			raw[pos++] = (char)c;
			break;
		}
	}
	if (pos == 0)
		return -1;

	/* Read payload up to '#' */
	while (pos < sizeof(raw) - 4) {
		n = recv(fd, &c, 1, 0);
		if (n <= 0)
			return -1;
		raw[pos++] = (char)c;
		if (c == '#')
			break;
	}

	/* Read the 2-hex checksum bytes */
	n = recv(fd, raw + pos, 2, MSG_WAITALL);
	if (n != 2)
		return -1;
	pos += 2;
	raw[pos] = '\0';

	/* ACK */
	send(fd, "+", 1, 0);

	return ela_gdb_rsp_unframe(raw, pos, payload, payload_sz);
}

/* -----------------------------------------------------------------------
 * Stop reply
 * ---------------------------------------------------------------------- */

static void send_stop_reply(int fd, int wstatus)
{
	char buf[16];

	if (WIFSTOPPED(wstatus))
		snprintf(buf, sizeof(buf), "S%02x", WSTOPSIG(wstatus));
	else if (WIFEXITED(wstatus))
		snprintf(buf, sizeof(buf), "W%02x", WEXITSTATUS(wstatus));
	else if (WIFSIGNALED(wstatus))
		snprintf(buf, sizeof(buf), "X%02x", WTERMSIG(wstatus));
	else
		return;

	rsp_send_str(fd, buf);
}

/* -----------------------------------------------------------------------
 * Register read (architecture-specific)
 * ---------------------------------------------------------------------- */

#if defined(__x86_64__)

/*
 * GDB x86-64 g-packet register order:
 *   rax rbx rcx rdx rsi rdi rbp rsp r8..r15 rip  (17 × 64-bit)
 *   eflags cs ss ds es fs gs                       (7 × 32-bit)
 * Total: 17×8 + 7×4 = 164 bytes → 328 hex chars
 */
static int regs_read(char *out, size_t out_sz)
{
	struct user_regs_struct r;
	char tmp[17];
	size_t pos = 0;

	if (ptrace(PTRACE_GETREGS, g_pid, NULL, &r) != 0)
		return -1;

#define EMIT64(v) do { \
	if (ela_gdb_encode_le64((v), tmp, sizeof(tmp)) != 0) return -1; \
	if (pos + 16 + 1 > out_sz) return -1; \
	memcpy(out + pos, tmp, 16); pos += 16; \
} while (0)

#define EMIT32(v) do { \
	if (ela_gdb_encode_le32((uint32_t)(v), tmp, sizeof(tmp)) != 0) return -1; \
	if (pos + 8 + 1 > out_sz) return -1; \
	memcpy(out + pos, tmp, 8); pos += 8; \
} while (0)

	EMIT64(r.rax); EMIT64(r.rbx); EMIT64(r.rcx); EMIT64(r.rdx);
	EMIT64(r.rsi); EMIT64(r.rdi); EMIT64(r.rbp); EMIT64(r.rsp);
	EMIT64(r.r8);  EMIT64(r.r9);  EMIT64(r.r10); EMIT64(r.r11);
	EMIT64(r.r12); EMIT64(r.r13); EMIT64(r.r14); EMIT64(r.r15);
	EMIT64(r.rip);
	EMIT32(r.eflags);
	EMIT32(r.cs); EMIT32(r.ss);
	EMIT32(r.ds); EMIT32(r.es); EMIT32(r.fs); EMIT32(r.gs);

#undef EMIT64
#undef EMIT32

	out[pos] = '\0';
	return 0;
}

static int reg_read_one(int regnum, char *out, size_t out_sz)
{
	struct user_regs_struct r;

	if (ptrace(PTRACE_GETREGS, g_pid, NULL, &r) != 0)
		return -1;

	switch (regnum) {
	case  0: return ela_gdb_encode_le64(r.rax, out, out_sz);
	case  1: return ela_gdb_encode_le64(r.rbx, out, out_sz);
	case  2: return ela_gdb_encode_le64(r.rcx, out, out_sz);
	case  3: return ela_gdb_encode_le64(r.rdx, out, out_sz);
	case  4: return ela_gdb_encode_le64(r.rsi, out, out_sz);
	case  5: return ela_gdb_encode_le64(r.rdi, out, out_sz);
	case  6: return ela_gdb_encode_le64(r.rbp, out, out_sz);
	case  7: return ela_gdb_encode_le64(r.rsp, out, out_sz);
	case  8: return ela_gdb_encode_le64(r.r8,  out, out_sz);
	case  9: return ela_gdb_encode_le64(r.r9,  out, out_sz);
	case 10: return ela_gdb_encode_le64(r.r10, out, out_sz);
	case 11: return ela_gdb_encode_le64(r.r11, out, out_sz);
	case 12: return ela_gdb_encode_le64(r.r12, out, out_sz);
	case 13: return ela_gdb_encode_le64(r.r13, out, out_sz);
	case 14: return ela_gdb_encode_le64(r.r14, out, out_sz);
	case 15: return ela_gdb_encode_le64(r.r15, out, out_sz);
	case 16: return ela_gdb_encode_le64(r.rip, out, out_sz);
	case 17: return ela_gdb_encode_le32((uint32_t)r.eflags, out, out_sz);
	case 18: return ela_gdb_encode_le32((uint32_t)r.cs,     out, out_sz);
	case 19: return ela_gdb_encode_le32((uint32_t)r.ss,     out, out_sz);
	case 20: return ela_gdb_encode_le32((uint32_t)r.ds,     out, out_sz);
	case 21: return ela_gdb_encode_le32((uint32_t)r.es,     out, out_sz);
	case 22: return ela_gdb_encode_le32((uint32_t)r.fs,     out, out_sz);
	case 23: return ela_gdb_encode_le32((uint32_t)r.gs,     out, out_sz);
	default: return -1;
	}
}

static int reg_write_one(int regnum, const char *hex_val)
{
	struct user_regs_struct r;
	uint64_t v64;
	uint32_t v32;

	if (ptrace(PTRACE_GETREGS, g_pid, NULL, &r) != 0)
		return -1;

	switch (regnum) {
	case  0: if (ela_gdb_decode_le64(hex_val, &v64)) return -1; r.rax     = v64; break;
	case  1: if (ela_gdb_decode_le64(hex_val, &v64)) return -1; r.rbx     = v64; break;
	case  2: if (ela_gdb_decode_le64(hex_val, &v64)) return -1; r.rcx     = v64; break;
	case  3: if (ela_gdb_decode_le64(hex_val, &v64)) return -1; r.rdx     = v64; break;
	case  4: if (ela_gdb_decode_le64(hex_val, &v64)) return -1; r.rsi     = v64; break;
	case  5: if (ela_gdb_decode_le64(hex_val, &v64)) return -1; r.rdi     = v64; break;
	case  6: if (ela_gdb_decode_le64(hex_val, &v64)) return -1; r.rbp     = v64; break;
	case  7: if (ela_gdb_decode_le64(hex_val, &v64)) return -1; r.rsp     = v64; break;
	case  8: if (ela_gdb_decode_le64(hex_val, &v64)) return -1; r.r8      = v64; break;
	case  9: if (ela_gdb_decode_le64(hex_val, &v64)) return -1; r.r9      = v64; break;
	case 10: if (ela_gdb_decode_le64(hex_val, &v64)) return -1; r.r10     = v64; break;
	case 11: if (ela_gdb_decode_le64(hex_val, &v64)) return -1; r.r11     = v64; break;
	case 12: if (ela_gdb_decode_le64(hex_val, &v64)) return -1; r.r12     = v64; break;
	case 13: if (ela_gdb_decode_le64(hex_val, &v64)) return -1; r.r13     = v64; break;
	case 14: if (ela_gdb_decode_le64(hex_val, &v64)) return -1; r.r14     = v64; break;
	case 15: if (ela_gdb_decode_le64(hex_val, &v64)) return -1; r.r15     = v64; break;
	case 16: if (ela_gdb_decode_le64(hex_val, &v64)) return -1; r.rip     = v64; break;
	case 17: if (ela_gdb_decode_le32(hex_val, &v32)) return -1; r.eflags  = v32; break;
	case 18: if (ela_gdb_decode_le32(hex_val, &v32)) return -1; r.cs      = v32; break;
	case 19: if (ela_gdb_decode_le32(hex_val, &v32)) return -1; r.ss      = v32; break;
	case 20: if (ela_gdb_decode_le32(hex_val, &v32)) return -1; r.ds      = v32; break;
	case 21: if (ela_gdb_decode_le32(hex_val, &v32)) return -1; r.es      = v32; break;
	case 22: if (ela_gdb_decode_le32(hex_val, &v32)) return -1; r.fs      = v32; break;
	case 23: if (ela_gdb_decode_le32(hex_val, &v32)) return -1; r.gs      = v32; break;
	default: return -1;
	}
	return ptrace(PTRACE_SETREGS, g_pid, NULL, &r) != 0 ? -1 : 0;
}

#elif defined(__aarch64__)

/*
 * GDB aarch64 g-packet register order:
 *   x0..x30 (31 × 64-bit), sp (64-bit), pc (64-bit), cpsr (32-bit)
 * Total: 33×8 + 4 = 268 bytes → 536 hex chars
 */
static int regs_read(char *out, size_t out_sz)
{
	struct user_pt_regs r;
	struct iovec iov = { &r, sizeof(r) };
	char tmp[17];
	size_t pos = 0;
	int i;

	if (ptrace(PTRACE_GETREGSET, g_pid, (void *)(uintptr_t)NT_PRSTATUS,
		   &iov) != 0)
		return -1;

#define EMIT64(v) do { \
	if (ela_gdb_encode_le64((v), tmp, sizeof(tmp)) != 0) return -1; \
	if (pos + 16 + 1 > out_sz) return -1; \
	memcpy(out + pos, tmp, 16); pos += 16; \
} while (0)

#define EMIT32(v) do { \
	if (ela_gdb_encode_le32((uint32_t)(v), tmp, sizeof(tmp)) != 0) return -1; \
	if (pos + 8 + 1 > out_sz) return -1; \
	memcpy(out + pos, tmp, 8); pos += 8; \
} while (0)

	for (i = 0; i < 31; i++)
		EMIT64(r.regs[i]);
	EMIT64(r.sp);
	EMIT64(r.pc);
	EMIT32(r.pstate);

#undef EMIT64
#undef EMIT32

	out[pos] = '\0';
	return 0;
}

static int reg_read_one(int regnum, char *out, size_t out_sz)
{
	struct user_pt_regs r;
	struct iovec iov = { &r, sizeof(r) };

	if (ptrace(PTRACE_GETREGSET, g_pid, (void *)(uintptr_t)NT_PRSTATUS,
		   &iov) != 0)
		return -1;

	if (regnum >= 0 && regnum <= 30)
		return ela_gdb_encode_le64(r.regs[regnum], out, out_sz);
	if (regnum == 31)
		return ela_gdb_encode_le64(r.sp, out, out_sz);
	if (regnum == 32)
		return ela_gdb_encode_le64(r.pc, out, out_sz);
	if (regnum == 33)
		return ela_gdb_encode_le32((uint32_t)r.pstate, out, out_sz);
	return -1;
}

static int reg_write_one(int regnum, const char *hex_val)
{
	struct user_pt_regs r;
	struct iovec iov = { &r, sizeof(r) };
	uint64_t v64;
	uint32_t v32;

	if (ptrace(PTRACE_GETREGSET, g_pid, (void *)(uintptr_t)NT_PRSTATUS,
		   &iov) != 0)
		return -1;

	if (regnum >= 0 && regnum <= 30) {
		if (ela_gdb_decode_le64(hex_val, &v64)) return -1;
		r.regs[regnum] = v64;
	} else if (regnum == 31) {
		if (ela_gdb_decode_le64(hex_val, &v64)) return -1;
		r.sp = v64;
	} else if (regnum == 32) {
		if (ela_gdb_decode_le64(hex_val, &v64)) return -1;
		r.pc = v64;
	} else if (regnum == 33) {
		if (ela_gdb_decode_le32(hex_val, &v32)) return -1;
		r.pstate = v32;
	} else {
		return -1;
	}

	iov.iov_len = sizeof(r);
	return ptrace(PTRACE_SETREGSET, g_pid, (void *)(uintptr_t)NT_PRSTATUS,
		      &iov) != 0 ? -1 : 0;
}

#elif defined(__arm__)

/*
 * GDB ARM (legacy) g-packet register order:
 *   r0-r15   (16 × 32-bit = 64 bytes)
 *   f0-f7    (8 × 96-bit FPA legacy regs = 96 bytes, zero-filled)
 *   fps      (32-bit FPA status = 4 bytes, zero)
 *   cpsr     (32-bit = 4 bytes)
 * Total: 168 bytes → 336 hex chars
 *
 * struct user_regs (from <sys/user.h> on ARM Linux):
 *   unsigned long uregs[18]:  [0..15]=r0..r15  [16]=cpsr  [17]=orig_r0
 */
static int regs_read(char *out, size_t out_sz)
{
	struct user_regs r;
	char tmp[9];
	size_t pos = 0;
	int i;

	if (ptrace(PTRACE_GETREGS, g_pid, NULL, &r) != 0)
		return -1;

	/* r0-r15 */
	for (i = 0; i < 16; i++) {
		if (ela_gdb_encode_le32((uint32_t)r.uregs[i], tmp, sizeof(tmp)) != 0)
			return -1;
		if (pos + 8 + 1 > out_sz)
			return -1;
		memcpy(out + pos, tmp, 8);
		pos += 8;
	}

	/* f0-f7: 8 legacy FPA registers, 12 bytes (24 hex chars) each */
	if (pos + 192 + 1 > out_sz)
		return -1;
	memset(out + pos, '0', 192);
	pos += 192;

	/* fps: FPA status register (4 bytes) — zero */
	if (ela_gdb_encode_le32(0, tmp, sizeof(tmp)) != 0)
		return -1;
	if (pos + 8 + 1 > out_sz)
		return -1;
	memcpy(out + pos, tmp, 8);
	pos += 8;

	/* cpsr */
	if (ela_gdb_encode_le32((uint32_t)r.uregs[16], tmp, sizeof(tmp)) != 0)
		return -1;
	if (pos + 8 + 1 > out_sz)
		return -1;
	memcpy(out + pos, tmp, 8);
	pos += 8;

	out[pos] = '\0';
	return 0;
}

static int reg_read_one(int regnum, char *out, size_t out_sz)
{
	struct user_regs r;

	if (ptrace(PTRACE_GETREGS, g_pid, NULL, &r) != 0)
		return -1;

	/* r0-r15 */
	if (regnum >= 0 && regnum <= 15)
		return ela_gdb_encode_le32((uint32_t)r.uregs[regnum], out, out_sz);

	/* f0-f7: 12-byte (24 hex char) FPA registers — zero */
	if (regnum >= 16 && regnum <= 23) {
		if (out_sz < 25)
			return -1;
		memset(out, '0', 24);
		out[24] = '\0';
		return 0;
	}

	/* fps: FPA status (4 bytes) — zero */
	if (regnum == 24)
		return ela_gdb_encode_le32(0, out, out_sz);

	/* cpsr */
	if (regnum == 25)
		return ela_gdb_encode_le32((uint32_t)r.uregs[16], out, out_sz);

	return -1;
}

static int reg_write_one(int regnum, const char *hex_val)
{
	struct user_regs r;
	uint32_t v32;

	if (ptrace(PTRACE_GETREGS, g_pid, NULL, &r) != 0)
		return -1;

	if (regnum >= 0 && regnum <= 15) {
		if (ela_gdb_decode_le32(hex_val, &v32)) return -1;
		r.uregs[regnum] = v32;
	} else if (regnum >= 16 && regnum <= 24) {
		return 0; /* legacy FPA regs / fps — silently accept */
	} else if (regnum == 25) {
		if (ela_gdb_decode_le32(hex_val, &v32)) return -1;
		r.uregs[16] = v32; /* cpsr */
	} else {
		return -1;
	}

	return ptrace(PTRACE_SETREGS, g_pid, NULL, &r) != 0 ? -1 : 0;
}

#elif defined(__mips__)

/*
 * Common MIPS ptrace helper: fetch elf_gregset_t via PTRACE_GETREGSET.
 * Used by both the 32-bit and 64-bit variants below.
 * The kernel-side elf_gregset_t is unsigned long[45]; on MIPS64 each slot
 * is 8 bytes, on MIPS32 each slot is 4 bytes.
 *
 * GDB register order (same for both widths, only element size differs):
 *   r0-r31    (GPRs,  GDB regs  0-31)
 *   status    (CP0,   GDB reg  32)
 *   lo        (GDB reg 33) — kernel elf_gregset has hi[39] before lo[40]
 *   hi        (GDB reg 34)
 *   badvaddr  (GDB reg 35)
 *   cause     (GDB reg 36)
 *   pc/epc    (GDB reg 37)
 *   f0-f31    (FPRs,  GDB regs 38-69, zero-filled for FPUless targets)
 *   fcsr      (GDB reg 70, zero)
 *   fir       (GDB reg 71, zero)
 */

#ifdef __mips64

/*
 * MIPS64 g-packet: 72 registers × 8 bytes = 576 bytes (1152 hex chars).
 * All registers including CP0 and FP control are encoded as 64-bit LE.
 */
static int regs_read(char *out, size_t out_sz)
{
	unsigned long regs[MIPS_ELF_NGREG];
	struct iovec iov = { regs, sizeof(regs) };
	char tmp[17];
	size_t pos = 0;
	int i;

	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0)
		return -1;

#define EMIT64(v) do { \
	if (ela_gdb_encode_le64((uint64_t)(v), tmp, sizeof(tmp)) != 0) return -1; \
	if (pos + 16 + 1 > out_sz) return -1; \
	memcpy(out + pos, tmp, 16); pos += 16; \
} while (0)

	for (i = 0; i < 32; i++)
		EMIT64(regs[MIPS_EF_R0 + i]);

	EMIT64(regs[MIPS_EF_STATUS]);
	EMIT64(regs[MIPS_EF_LO]);      /* GDB reg 33 = lo */
	EMIT64(regs[MIPS_EF_HI]);      /* GDB reg 34 = hi */
	EMIT64(regs[MIPS_EF_BADVADDR]);
	EMIT64(regs[MIPS_EF_CAUSE]);
	EMIT64(regs[MIPS_EF_EPC]);

#undef EMIT64

	/* f0-f31: 32 FP registers, 8 bytes each (512 hex chars) — zero */
	if (pos + 512 + 1 > out_sz)
		return -1;
	memset(out + pos, '0', 512);
	pos += 512;

	/* fcsr and fir: 8 bytes each — zero */
	if (pos + 32 + 1 > out_sz)
		return -1;
	memset(out + pos, '0', 32);
	pos += 32;

	out[pos] = '\0';
	return 0;
}

static int reg_read_one(int regnum, char *out, size_t out_sz)
{
	unsigned long regs[MIPS_ELF_NGREG];
	struct iovec iov = { regs, sizeof(regs) };

	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0)
		return -1;

	if (regnum >= 0 && regnum <= 31)
		return ela_gdb_encode_le64(
			(uint64_t)regs[MIPS_EF_R0 + regnum], out, out_sz);

	switch (regnum) {
	case 32: return ela_gdb_encode_le64(
			(uint64_t)regs[MIPS_EF_STATUS],   out, out_sz);
	case 33: return ela_gdb_encode_le64(
			(uint64_t)regs[MIPS_EF_LO],       out, out_sz);
	case 34: return ela_gdb_encode_le64(
			(uint64_t)regs[MIPS_EF_HI],       out, out_sz);
	case 35: return ela_gdb_encode_le64(
			(uint64_t)regs[MIPS_EF_BADVADDR], out, out_sz);
	case 36: return ela_gdb_encode_le64(
			(uint64_t)regs[MIPS_EF_CAUSE],    out, out_sz);
	case 37: return ela_gdb_encode_le64(
			(uint64_t)regs[MIPS_EF_EPC],      out, out_sz);
	default: break;
	}

	/* f0-f31 (38-69), fcsr (70), fir (71): zero */
	if (regnum >= 38 && regnum <= 71)
		return ela_gdb_encode_le64(0, out, out_sz);

	return -1;
}

static int reg_write_one(int regnum, const char *hex_val)
{
	unsigned long regs[MIPS_ELF_NGREG];
	struct iovec iov = { regs, sizeof(regs) };
	uint64_t v64;

	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0)
		return -1;

	if (regnum >= 0 && regnum <= 31) {
		if (ela_gdb_decode_le64(hex_val, &v64)) return -1;
		regs[MIPS_EF_R0 + regnum] = (unsigned long)v64;
	} else {
		switch (regnum) {
		case 32:
			if (ela_gdb_decode_le64(hex_val, &v64)) return -1;
			regs[MIPS_EF_STATUS] = (unsigned long)v64; break;
		case 33:
			if (ela_gdb_decode_le64(hex_val, &v64)) return -1;
			regs[MIPS_EF_LO] = (unsigned long)v64; break;
		case 34:
			if (ela_gdb_decode_le64(hex_val, &v64)) return -1;
			regs[MIPS_EF_HI] = (unsigned long)v64; break;
		case 35:
			if (ela_gdb_decode_le64(hex_val, &v64)) return -1;
			regs[MIPS_EF_BADVADDR] = (unsigned long)v64; break;
		case 36:
			if (ela_gdb_decode_le64(hex_val, &v64)) return -1;
			regs[MIPS_EF_CAUSE] = (unsigned long)v64; break;
		case 37:
			if (ela_gdb_decode_le64(hex_val, &v64)) return -1;
			regs[MIPS_EF_EPC] = (unsigned long)v64; break;
		default:
			if (regnum >= 38 && regnum <= 71)
				return 0; /* FP — silently accept */
			return -1;
		}
	}

	iov.iov_len = sizeof(regs);
	return ptrace(PTRACE_SETREGSET, g_pid,
		      (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0 ? -1 : 0;
}

#else /* MIPS32 */

/*
 * MIPS32 g-packet: 72 registers × 4 bytes = 288 bytes (576 hex chars).
 */
static int regs_read(char *out, size_t out_sz)
{
	unsigned long regs[MIPS_ELF_NGREG];
	struct iovec iov = { regs, sizeof(regs) };
	char tmp[9];
	size_t pos = 0;
	int i;

	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0)
		return -1;

#define EMIT32(v) do { \
	if (ela_gdb_encode_le32((uint32_t)(v), tmp, sizeof(tmp)) != 0) return -1; \
	if (pos + 8 + 1 > out_sz) return -1; \
	memcpy(out + pos, tmp, 8); pos += 8; \
} while (0)

	for (i = 0; i < 32; i++)
		EMIT32(regs[MIPS_EF_R0 + i]);

	EMIT32(regs[MIPS_EF_STATUS]);
	EMIT32(regs[MIPS_EF_LO]);      /* GDB reg 33 = lo */
	EMIT32(regs[MIPS_EF_HI]);      /* GDB reg 34 = hi */
	EMIT32(regs[MIPS_EF_BADVADDR]);
	EMIT32(regs[MIPS_EF_CAUSE]);
	EMIT32(regs[MIPS_EF_EPC]);

#undef EMIT32

	/* f0-f31: 32 FP registers, 4 bytes each (256 hex chars) — zero */
	if (pos + 256 + 1 > out_sz)
		return -1;
	memset(out + pos, '0', 256);
	pos += 256;

	/* fcsr and fir: 4 bytes each — zero */
	if (pos + 16 + 1 > out_sz)
		return -1;
	memset(out + pos, '0', 16);
	pos += 16;

	out[pos] = '\0';
	return 0;
}

static int reg_read_one(int regnum, char *out, size_t out_sz)
{
	unsigned long regs[MIPS_ELF_NGREG];
	struct iovec iov = { regs, sizeof(regs) };

	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0)
		return -1;

	if (regnum >= 0 && regnum <= 31)
		return ela_gdb_encode_le32(
			(uint32_t)regs[MIPS_EF_R0 + regnum], out, out_sz);

	switch (regnum) {
	case 32: return ela_gdb_encode_le32(
			(uint32_t)regs[MIPS_EF_STATUS],   out, out_sz);
	case 33: return ela_gdb_encode_le32(
			(uint32_t)regs[MIPS_EF_LO],       out, out_sz);
	case 34: return ela_gdb_encode_le32(
			(uint32_t)regs[MIPS_EF_HI],       out, out_sz);
	case 35: return ela_gdb_encode_le32(
			(uint32_t)regs[MIPS_EF_BADVADDR], out, out_sz);
	case 36: return ela_gdb_encode_le32(
			(uint32_t)regs[MIPS_EF_CAUSE],    out, out_sz);
	case 37: return ela_gdb_encode_le32(
			(uint32_t)regs[MIPS_EF_EPC],      out, out_sz);
	default: break;
	}

	/* f0-f31 (38-69), fcsr (70), fir (71): zero-filled */
	if (regnum >= 38 && regnum <= 71)
		return ela_gdb_encode_le32(0, out, out_sz);

	return -1;
}

static int reg_write_one(int regnum, const char *hex_val)
{
	unsigned long regs[MIPS_ELF_NGREG];
	struct iovec iov = { regs, sizeof(regs) };
	uint32_t v32;

	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0)
		return -1;

	if (regnum >= 0 && regnum <= 31) {
		if (ela_gdb_decode_le32(hex_val, &v32)) return -1;
		regs[MIPS_EF_R0 + regnum] = (unsigned long)v32;
	} else {
		switch (regnum) {
		case 32:
			if (ela_gdb_decode_le32(hex_val, &v32)) return -1;
			regs[MIPS_EF_STATUS] = (unsigned long)v32; break;
		case 33:
			if (ela_gdb_decode_le32(hex_val, &v32)) return -1;
			regs[MIPS_EF_LO] = (unsigned long)v32; break;
		case 34:
			if (ela_gdb_decode_le32(hex_val, &v32)) return -1;
			regs[MIPS_EF_HI] = (unsigned long)v32; break;
		case 35:
			if (ela_gdb_decode_le32(hex_val, &v32)) return -1;
			regs[MIPS_EF_BADVADDR] = (unsigned long)v32; break;
		case 36:
			if (ela_gdb_decode_le32(hex_val, &v32)) return -1;
			regs[MIPS_EF_CAUSE] = (unsigned long)v32; break;
		case 37:
			if (ela_gdb_decode_le32(hex_val, &v32)) return -1;
			regs[MIPS_EF_EPC] = (unsigned long)v32; break;
		default:
			if (regnum >= 38 && regnum <= 71)
				return 0; /* FP — silently accept */
			return -1;
		}
	}

	iov.iov_len = sizeof(regs);
	return ptrace(PTRACE_SETREGSET, g_pid,
		      (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0 ? -1 : 0;
}

#endif /* __mips64 */

#elif defined(__powerpc64__)

/*
 * GDB PPC64 g-packet register order (all big-endian):
 *   r0-r31   (32 × 64-bit = 256 bytes / 512 hex)
 *   f0-f31   (32 × 64-bit = 256 bytes / 512 hex)
 *   pc/nip   (64-bit / 16 hex)
 *   ps/msr   (64-bit / 16 hex)
 *   cr/ccr   (32-bit /  8 hex)
 *   lr/link  (64-bit / 16 hex)
 *   ctr      (64-bit / 16 hex)
 *   xer      (32-bit /  8 hex)
 *   fpscr    (32-bit /  8 hex)
 * Total: 556 bytes → 1112 hex chars
 *
 * GPRs fetched via PTRACE_GETREGSET(NT_PRSTATUS) → elf_gregset_t[48].
 * FPRs fetched via PTRACE_GETREGSET(NT_PRFPREG)  → double[33].
 */
static int regs_read(char *out, size_t out_sz)
{
	unsigned long gregs[PPC_ELF_NGREG];
	double fp_regs[PPC_ELF_NFPREG];
	struct iovec iov;
	char tmp[17];
	size_t pos = 0;
	int i;
	uint64_t fp_bits;
	uint32_t fpscr;

	iov.iov_base = gregs;
	iov.iov_len  = sizeof(gregs);
	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0)
		return -1;

	iov.iov_base = fp_regs;
	iov.iov_len  = sizeof(fp_regs);
	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRFPREG, &iov) != 0)
		return -1;

#define EMIT32BE(v) do { \
	if (ela_gdb_encode_be32((uint32_t)(v), tmp, sizeof(tmp)) != 0) return -1; \
	if (pos + 8 + 1 > out_sz) return -1; \
	memcpy(out + pos, tmp, 8); pos += 8; \
} while (0)

#define EMIT64BE(v) do { \
	if (ela_gdb_encode_be64((uint64_t)(v), tmp, sizeof(tmp)) != 0) return -1; \
	if (pos + 16 + 1 > out_sz) return -1; \
	memcpy(out + pos, tmp, 16); pos += 16; \
} while (0)

	/* r0-r31: 64-bit */
	for (i = 0; i < 32; i++)
		EMIT64BE(gregs[PPC_PT_GPR0 + i]);

	/* f0-f31: 64-bit */
	for (i = 0; i < 32; i++) {
		memcpy(&fp_bits, &fp_regs[i], 8);
		EMIT64BE(fp_bits);
	}

	/* pc, ps: 64-bit */
	EMIT64BE(gregs[PPC_PT_NIP]);
	EMIT64BE(gregs[PPC_PT_MSR]);

	/* cr: 32-bit */
	EMIT32BE(gregs[PPC_PT_CCR]);

	/* lr, ctr: 64-bit */
	EMIT64BE(gregs[PPC_PT_LNK]);
	EMIT64BE(gregs[PPC_PT_CTR]);

	/* xer: 32-bit */
	EMIT32BE(gregs[PPC_PT_XER]);

	/* fpscr: lower 32 bits of fp_regs[32] */
	memcpy(&fp_bits, &fp_regs[32], 8);
	fpscr = (uint32_t)(fp_bits & 0xffffffffULL);
	EMIT32BE(fpscr);

#undef EMIT32BE
#undef EMIT64BE

	out[pos] = '\0';
	return 0;
}

static int reg_read_one(int regnum, char *out, size_t out_sz)
{
	unsigned long gregs[PPC_ELF_NGREG];
	double fp_regs[PPC_ELF_NFPREG];
	struct iovec iov;
	uint64_t fp_bits;

	iov.iov_base = gregs;
	iov.iov_len  = sizeof(gregs);
	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0)
		return -1;

	/* r0-r31: 64-bit */
	if (regnum >= 0 && regnum <= 31)
		return ela_gdb_encode_be64(
			(uint64_t)gregs[PPC_PT_GPR0 + regnum], out, out_sz);

	/* f0-f31: 64-bit */
	if (regnum >= 32 && regnum <= 63) {
		iov.iov_base = fp_regs;
		iov.iov_len  = sizeof(fp_regs);
		if (ptrace(PTRACE_GETREGSET, g_pid,
			   (void *)(uintptr_t)NT_PRFPREG, &iov) != 0)
			return -1;
		memcpy(&fp_bits, &fp_regs[regnum - 32], 8);
		return ela_gdb_encode_be64(fp_bits, out, out_sz);
	}

	switch (regnum) {
	case 64: return ela_gdb_encode_be64((uint64_t)gregs[PPC_PT_NIP], out, out_sz);
	case 65: return ela_gdb_encode_be64((uint64_t)gregs[PPC_PT_MSR], out, out_sz);
	case 66: return ela_gdb_encode_be32((uint32_t)gregs[PPC_PT_CCR], out, out_sz);
	case 67: return ela_gdb_encode_be64((uint64_t)gregs[PPC_PT_LNK], out, out_sz);
	case 68: return ela_gdb_encode_be64((uint64_t)gregs[PPC_PT_CTR], out, out_sz);
	case 69: return ela_gdb_encode_be32((uint32_t)gregs[PPC_PT_XER], out, out_sz);
	case 70: {
		/* fpscr */
		iov.iov_base = fp_regs;
		iov.iov_len  = sizeof(fp_regs);
		if (ptrace(PTRACE_GETREGSET, g_pid,
			   (void *)(uintptr_t)NT_PRFPREG, &iov) != 0)
			return -1;
		memcpy(&fp_bits, &fp_regs[32], 8);
		return ela_gdb_encode_be32(
			(uint32_t)(fp_bits & 0xffffffffULL), out, out_sz);
	}
	default: return -1;
	}
}

static int reg_write_one(int regnum, const char *hex_val)
{
	unsigned long gregs[PPC_ELF_NGREG];
	double fp_regs[PPC_ELF_NFPREG];
	struct iovec iov;
	uint64_t v64;
	uint32_t v32;
	uint64_t slot;

	iov.iov_base = gregs;
	iov.iov_len  = sizeof(gregs);
	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0)
		return -1;

	/* r0-r31: 64-bit BE */
	if (regnum >= 0 && regnum <= 31) {
		if (ela_gdb_decode_be64(hex_val, &v64)) return -1;
		gregs[PPC_PT_GPR0 + regnum] = (unsigned long)v64;
		iov.iov_base = gregs; iov.iov_len = sizeof(gregs);
		return ptrace(PTRACE_SETREGSET, g_pid,
			      (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0 ? -1 : 0;
	}

	/* f0-f31: 64-bit BE */
	if (regnum >= 32 && regnum <= 63) {
		iov.iov_base = fp_regs; iov.iov_len = sizeof(fp_regs);
		if (ptrace(PTRACE_GETREGSET, g_pid,
			   (void *)(uintptr_t)NT_PRFPREG, &iov) != 0)
			return -1;
		if (ela_gdb_decode_be64(hex_val, &v64)) return -1;
		memcpy(&fp_regs[regnum - 32], &v64, 8);
		iov.iov_base = fp_regs; iov.iov_len = sizeof(fp_regs);
		return ptrace(PTRACE_SETREGSET, g_pid,
			      (void *)(uintptr_t)NT_PRFPREG, &iov) != 0 ? -1 : 0;
	}

	switch (regnum) {
	case 64: if (ela_gdb_decode_be64(hex_val, &v64)) return -1;
		 gregs[PPC_PT_NIP] = (unsigned long)v64; break;
	case 65: if (ela_gdb_decode_be64(hex_val, &v64)) return -1;
		 gregs[PPC_PT_MSR] = (unsigned long)v64; break;
	case 66: if (ela_gdb_decode_be32(hex_val, &v32)) return -1;
		 gregs[PPC_PT_CCR] = (unsigned long)v32; break;
	case 67: if (ela_gdb_decode_be64(hex_val, &v64)) return -1;
		 gregs[PPC_PT_LNK] = (unsigned long)v64; break;
	case 68: if (ela_gdb_decode_be64(hex_val, &v64)) return -1;
		 gregs[PPC_PT_CTR] = (unsigned long)v64; break;
	case 69: if (ela_gdb_decode_be32(hex_val, &v32)) return -1;
		 gregs[PPC_PT_XER] = (unsigned long)v32; break;
	case 70: { /* fpscr: update lower 32 bits of fp_regs[32] */
		iov.iov_base = fp_regs; iov.iov_len = sizeof(fp_regs);
		if (ptrace(PTRACE_GETREGSET, g_pid,
			   (void *)(uintptr_t)NT_PRFPREG, &iov) != 0)
			return -1;
		if (ela_gdb_decode_be32(hex_val, &v32)) return -1;
		memcpy(&slot, &fp_regs[32], 8);
		slot = (slot & 0xffffffff00000000ULL) | v32;
		memcpy(&fp_regs[32], &slot, 8);
		iov.iov_base = fp_regs; iov.iov_len = sizeof(fp_regs);
		return ptrace(PTRACE_SETREGSET, g_pid,
			      (void *)(uintptr_t)NT_PRFPREG, &iov) != 0 ? -1 : 0;
	}
	default: return -1;
	}

	iov.iov_base = gregs; iov.iov_len = sizeof(gregs);
	return ptrace(PTRACE_SETREGSET, g_pid,
		      (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0 ? -1 : 0;
}

#elif defined(__powerpc__) && !defined(__powerpc64__)

/*
 * GDB PPC32 g-packet register order (all big-endian, PPC32 only):
 *   r0-r31   (32 × 32-bit = 128 bytes / 256 hex)
 *   f0-f31   (32 × 64-bit = 256 bytes / 512 hex)
 *   pc/nip   (32-bit)
 *   ps/msr   (32-bit)
 *   cr/ccr   (32-bit)
 *   lr/link  (32-bit)
 *   ctr      (32-bit)
 *   xer      (32-bit)
 *   fpscr    (32-bit, lower 32 bits of fp_regs[32])
 * Total: 412 bytes → 824 hex chars
 *
 * GPRs fetched via PTRACE_GETREGSET(NT_PRSTATUS) → elf_gregset_t[48].
 * FPRs fetched via PTRACE_GETREGSET(NT_PRFPREG)  → double[33].
 */
static int regs_read(char *out, size_t out_sz)
{
	unsigned long gregs[PPC_ELF_NGREG];
	double fp_regs[PPC_ELF_NFPREG];
	struct iovec iov;
	char tmp[17];
	size_t pos = 0;
	int i;
	uint64_t fp_bits;
	uint32_t fpscr;

	iov.iov_base = gregs;
	iov.iov_len  = sizeof(gregs);
	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0)
		return -1;

	iov.iov_base = fp_regs;
	iov.iov_len  = sizeof(fp_regs);
	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRFPREG, &iov) != 0)
		return -1;

#define EMIT32BE(v) do { \
	if (ela_gdb_encode_be32((uint32_t)(v), tmp, sizeof(tmp)) != 0) return -1; \
	if (pos + 8 + 1 > out_sz) return -1; \
	memcpy(out + pos, tmp, 8); pos += 8; \
} while (0)

#define EMIT64BE(v) do { \
	if (ela_gdb_encode_be64((uint64_t)(v), tmp, sizeof(tmp)) != 0) return -1; \
	if (pos + 16 + 1 > out_sz) return -1; \
	memcpy(out + pos, tmp, 16); pos += 16; \
} while (0)

	/* r0-r31 */
	for (i = 0; i < 32; i++)
		EMIT32BE(gregs[PPC_PT_GPR0 + i]);

	/* f0-f31: 64-bit each */
	for (i = 0; i < 32; i++) {
		memcpy(&fp_bits, &fp_regs[i], 8);
		EMIT64BE(fp_bits);
	}

	/* pc, ps, cr, lr, ctr, xer */
	EMIT32BE(gregs[PPC_PT_NIP]);
	EMIT32BE(gregs[PPC_PT_MSR]);
	EMIT32BE(gregs[PPC_PT_CCR]);
	EMIT32BE(gregs[PPC_PT_LNK]);
	EMIT32BE(gregs[PPC_PT_CTR]);
	EMIT32BE(gregs[PPC_PT_XER]);

	/* fpscr: lower 32 bits of fp_regs[32] */
	memcpy(&fp_bits, &fp_regs[32], 8);
	fpscr = (uint32_t)(fp_bits & 0xffffffffULL);
	EMIT32BE(fpscr);

#undef EMIT32BE
#undef EMIT64BE

	out[pos] = '\0';
	return 0;
}

static int reg_read_one(int regnum, char *out, size_t out_sz)
{
	unsigned long gregs[PPC_ELF_NGREG];
	double fp_regs[PPC_ELF_NFPREG];
	struct iovec iov;
	uint64_t fp_bits;

	iov.iov_base = gregs;
	iov.iov_len  = sizeof(gregs);
	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0)
		return -1;

	/* r0-r31 */
	if (regnum >= 0 && regnum <= 31)
		return ela_gdb_encode_be32(
			(uint32_t)gregs[PPC_PT_GPR0 + regnum], out, out_sz);

	/* f0-f31 */
	if (regnum >= 32 && regnum <= 63) {
		iov.iov_base = fp_regs;
		iov.iov_len  = sizeof(fp_regs);
		if (ptrace(PTRACE_GETREGSET, g_pid,
			   (void *)(uintptr_t)NT_PRFPREG, &iov) != 0)
			return -1;
		memcpy(&fp_bits, &fp_regs[regnum - 32], 8);
		return ela_gdb_encode_be64(fp_bits, out, out_sz);
	}

	switch (regnum) {
	case 64: return ela_gdb_encode_be32((uint32_t)gregs[PPC_PT_NIP], out, out_sz);
	case 65: return ela_gdb_encode_be32((uint32_t)gregs[PPC_PT_MSR], out, out_sz);
	case 66: return ela_gdb_encode_be32((uint32_t)gregs[PPC_PT_CCR], out, out_sz);
	case 67: return ela_gdb_encode_be32((uint32_t)gregs[PPC_PT_LNK], out, out_sz);
	case 68: return ela_gdb_encode_be32((uint32_t)gregs[PPC_PT_CTR], out, out_sz);
	case 69: return ela_gdb_encode_be32((uint32_t)gregs[PPC_PT_XER], out, out_sz);
	case 70: {
		/* fpscr */
		iov.iov_base = fp_regs;
		iov.iov_len  = sizeof(fp_regs);
		if (ptrace(PTRACE_GETREGSET, g_pid,
			   (void *)(uintptr_t)NT_PRFPREG, &iov) != 0)
			return -1;
		memcpy(&fp_bits, &fp_regs[32], 8);
		return ela_gdb_encode_be32(
			(uint32_t)(fp_bits & 0xffffffffULL), out, out_sz);
	}
	default: return -1;
	}
}

static int reg_write_one(int regnum, const char *hex_val)
{
	unsigned long gregs[PPC_ELF_NGREG];
	double fp_regs[PPC_ELF_NFPREG];
	struct iovec iov;
	uint32_t v32;
	uint64_t v64;
	uint64_t slot;

	iov.iov_base = gregs;
	iov.iov_len  = sizeof(gregs);
	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0)
		return -1;

	/* r0-r31: 32-bit BE */
	if (regnum >= 0 && regnum <= 31) {
		if (ela_gdb_decode_be32(hex_val, &v32)) return -1;
		gregs[PPC_PT_GPR0 + regnum] = (unsigned long)v32;
		iov.iov_base = gregs; iov.iov_len = sizeof(gregs);
		return ptrace(PTRACE_SETREGSET, g_pid,
			      (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0 ? -1 : 0;
	}

	/* f0-f31: 64-bit BE */
	if (regnum >= 32 && regnum <= 63) {
		iov.iov_base = fp_regs; iov.iov_len = sizeof(fp_regs);
		if (ptrace(PTRACE_GETREGSET, g_pid,
			   (void *)(uintptr_t)NT_PRFPREG, &iov) != 0)
			return -1;
		if (ela_gdb_decode_be64(hex_val, &v64)) return -1;
		memcpy(&fp_regs[regnum - 32], &v64, 8);
		iov.iov_base = fp_regs; iov.iov_len = sizeof(fp_regs);
		return ptrace(PTRACE_SETREGSET, g_pid,
			      (void *)(uintptr_t)NT_PRFPREG, &iov) != 0 ? -1 : 0;
	}

	switch (regnum) {
	case 64: if (ela_gdb_decode_be32(hex_val, &v32)) return -1;
		 gregs[PPC_PT_NIP] = (unsigned long)v32; break;
	case 65: if (ela_gdb_decode_be32(hex_val, &v32)) return -1;
		 gregs[PPC_PT_MSR] = (unsigned long)v32; break;
	case 66: if (ela_gdb_decode_be32(hex_val, &v32)) return -1;
		 gregs[PPC_PT_CCR] = (unsigned long)v32; break;
	case 67: if (ela_gdb_decode_be32(hex_val, &v32)) return -1;
		 gregs[PPC_PT_LNK] = (unsigned long)v32; break;
	case 68: if (ela_gdb_decode_be32(hex_val, &v32)) return -1;
		 gregs[PPC_PT_CTR] = (unsigned long)v32; break;
	case 69: if (ela_gdb_decode_be32(hex_val, &v32)) return -1;
		 gregs[PPC_PT_XER] = (unsigned long)v32; break;
	case 70: { /* fpscr: update lower 32 bits of fp_regs[32] */
		iov.iov_base = fp_regs; iov.iov_len = sizeof(fp_regs);
		if (ptrace(PTRACE_GETREGSET, g_pid,
			   (void *)(uintptr_t)NT_PRFPREG, &iov) != 0)
			return -1;
		if (ela_gdb_decode_be32(hex_val, &v32)) return -1;
		memcpy(&slot, &fp_regs[32], 8);
		slot = (slot & 0xffffffff00000000ULL) | v32;
		memcpy(&fp_regs[32], &slot, 8);
		iov.iov_base = fp_regs; iov.iov_len = sizeof(fp_regs);
		return ptrace(PTRACE_SETREGSET, g_pid,
			      (void *)(uintptr_t)NT_PRFPREG, &iov) != 0 ? -1 : 0;
	}
	default: return -1;
	}

	iov.iov_base = gregs; iov.iov_len = sizeof(gregs);
	return ptrace(PTRACE_SETREGSET, g_pid,
		      (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0 ? -1 : 0;
}

#elif defined(__riscv) && (__riscv_xlen == 64)

/*
 * GDB RISC-V RV64 g-packet register order (little-endian):
 *   x0-x31  (32 × 64-bit = 256 bytes / 512 hex) — x0 is always zero
 *   pc       (64-bit / 16 hex)
 * Total: 33 × 8 = 264 bytes → 528 hex chars
 *
 * Linux PTRACE_GETREGSET/NT_PRSTATUS returns 32 unsigned longs (8 bytes each):
 *   [0] = pc, [1] = x1(ra), ..., [31] = x31(t6).
 */
static int regs_read(char *out, size_t out_sz)
{
	unsigned long regs[RISCV_PT_NREGS];
	struct iovec iov = { regs, sizeof(regs) };
	char tmp[17];
	size_t pos = 0;
	int i;

	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0)
		return -1;

#define EMIT64(v) do { \
	if (ela_gdb_encode_le64((uint64_t)(v), tmp, sizeof(tmp)) != 0) return -1; \
	if (pos + 16 + 1 > out_sz) return -1; \
	memcpy(out + pos, tmp, 16); pos += 16; \
} while (0)

	/* x0: hard-wired zero */
	EMIT64(0);

	/* x1-x31: kernel stores at regs[1]-regs[31] */
	for (i = RISCV_PT_X1; i < RISCV_PT_NREGS; i++)
		EMIT64(regs[i]);

	/* pc: kernel stores at regs[0] */
	EMIT64(regs[RISCV_PT_PC]);

#undef EMIT64

	out[pos] = '\0';
	return 0;
}

static int reg_read_one(int regnum, char *out, size_t out_sz)
{
	unsigned long regs[RISCV_PT_NREGS];
	struct iovec iov = { regs, sizeof(regs) };

	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0)
		return -1;

	/* x0: always zero */
	if (regnum == 0)
		return ela_gdb_encode_le64(0, out, out_sz);

	/* x1-x31 */
	if (regnum >= 1 && regnum <= 31)
		return ela_gdb_encode_le64((uint64_t)regs[regnum], out, out_sz);

	/* pc */
	if (regnum == 32)
		return ela_gdb_encode_le64((uint64_t)regs[RISCV_PT_PC], out, out_sz);

	return -1;
}

static int reg_write_one(int regnum, const char *hex_val)
{
	unsigned long regs[RISCV_PT_NREGS];
	struct iovec iov = { regs, sizeof(regs) };
	uint64_t v64;

	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0)
		return -1;

	if (regnum == 0)
		return 0; /* x0 is hard-wired zero — silently accept */

	if (ela_gdb_decode_le64(hex_val, &v64)) return -1;

	if (regnum >= 1 && regnum <= 31)
		regs[regnum] = (unsigned long)v64;
	else if (regnum == 32)
		regs[RISCV_PT_PC] = (unsigned long)v64;
	else
		return -1;

	iov.iov_len = sizeof(regs);
	return ptrace(PTRACE_SETREGSET, g_pid,
		      (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0 ? -1 : 0;
}

#elif defined(__riscv) && (__riscv_xlen == 32)

/*
 * GDB RISC-V RV32 g-packet register order (little-endian):
 *   x0-x31  (32 × 32-bit = 128 bytes / 256 hex) — x0 is always zero
 *   pc       (32-bit / 8 hex)
 * Total: 33 × 4 = 132 bytes → 264 hex chars
 *
 * Linux PTRACE_GETREGSET/NT_PRSTATUS returns 32 unsigned longs:
 *   [0] = pc, [1] = x1(ra), ..., [31] = x31(t6).
 * x0 is the hard-wired zero register and is not stored by the kernel.
 */
static int regs_read(char *out, size_t out_sz)
{
	unsigned long regs[RISCV_PT_NREGS];
	struct iovec iov = { regs, sizeof(regs) };
	char tmp[9];
	size_t pos = 0;
	int i;

	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0)
		return -1;

#define EMIT32(v) do { \
	if (ela_gdb_encode_le32((uint32_t)(v), tmp, sizeof(tmp)) != 0) return -1; \
	if (pos + 8 + 1 > out_sz) return -1; \
	memcpy(out + pos, tmp, 8); pos += 8; \
} while (0)

	/* x0: hard-wired zero */
	EMIT32(0);

	/* x1-x31: kernel stores at regs[1]-regs[31] */
	for (i = RISCV_PT_X1; i < RISCV_PT_NREGS; i++)
		EMIT32(regs[i]);

	/* pc: kernel stores at regs[0] */
	EMIT32(regs[RISCV_PT_PC]);

#undef EMIT32

	out[pos] = '\0';
	return 0;
}

static int reg_read_one(int regnum, char *out, size_t out_sz)
{
	unsigned long regs[RISCV_PT_NREGS];
	struct iovec iov = { regs, sizeof(regs) };

	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0)
		return -1;

	/* x0: always zero */
	if (regnum == 0)
		return ela_gdb_encode_le32(0, out, out_sz);

	/* x1-x31 */
	if (regnum >= 1 && regnum <= 31)
		return ela_gdb_encode_le32((uint32_t)regs[regnum], out, out_sz);

	/* pc */
	if (regnum == 32)
		return ela_gdb_encode_le32((uint32_t)regs[RISCV_PT_PC], out, out_sz);

	return -1;
}

static int reg_write_one(int regnum, const char *hex_val)
{
	unsigned long regs[RISCV_PT_NREGS];
	struct iovec iov = { regs, sizeof(regs) };
	uint32_t v32;

	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0)
		return -1;

	if (regnum == 0)
		return 0; /* x0 is hard-wired zero — silently accept */

	if (ela_gdb_decode_le32(hex_val, &v32)) return -1;

	if (regnum >= 1 && regnum <= 31)
		regs[regnum] = (unsigned long)v32;
	else if (regnum == 32)
		regs[RISCV_PT_PC] = (unsigned long)v32;
	else
		return -1;

	iov.iov_len = sizeof(regs);
	return ptrace(PTRACE_SETREGSET, g_pid,
		      (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0 ? -1 : 0;
}

#else

static int regs_read(char *out, size_t out_sz)
{
	(void)out; (void)out_sz;
	return -1;
}

static int reg_read_one(int regnum, char *out, size_t out_sz)
{
	(void)regnum; (void)out; (void)out_sz;
	return -1;
}

static int reg_write_one(int regnum, const char *hex_val)
{
	(void)regnum; (void)hex_val;
	return -1;
}

#endif /* arch */

/* -----------------------------------------------------------------------
 * Memory read/write via ptrace (word-aligned PEEKDATA/POKEDATA)
 * ---------------------------------------------------------------------- */

static int mem_read(uint64_t addr, size_t len, char *hex_out, size_t hex_sz)
{
	uint8_t buf[4096];
	size_t done = 0;
	long word;
	uint8_t *wp = (uint8_t *)&word;
	uint64_t aligned;
	size_t off, chunk;

	if (len == 0 || len > sizeof(buf) || hex_sz < 2 * len + 1)
		return -1;

	while (done < len) {
		aligned = (addr + done) & ~(uint64_t)(sizeof(long) - 1);
		off     = (size_t)((addr + done) - aligned);
		chunk   = sizeof(long) - off;
		if (chunk > len - done)
			chunk = len - done;

		errno = 0;
		word = ptrace(PTRACE_PEEKDATA, g_pid,
			      (void *)(uintptr_t)aligned, NULL);
		if (errno != 0)
			return -1;

		memcpy(buf + done, wp + off, chunk);
		done += chunk;
	}

	return ela_gdb_hex_encode(buf, len, hex_out, hex_sz);
}

static int mem_write(uint64_t addr, const uint8_t *data, size_t len)
{
	size_t done = 0;
	long word;
	uint8_t *wp = (uint8_t *)&word;
	uint64_t aligned;
	size_t off, chunk;
	size_t i;

	while (done < len) {
		aligned = (addr + done) & ~(uint64_t)(sizeof(long) - 1);
		off     = (size_t)((addr + done) - aligned);
		chunk   = sizeof(long) - off;
		if (chunk > len - done)
			chunk = len - done;

		if (off != 0 || chunk < sizeof(long)) {
			/* Partial word: read then modify */
			errno = 0;
			word = ptrace(PTRACE_PEEKDATA, g_pid,
				      (void *)(uintptr_t)aligned, NULL);
			if (errno != 0)
				return -1;
		} else {
			word = 0;
		}

		for (i = 0; i < chunk; i++)
			wp[off + i] = data[done + i];

		if (ptrace(PTRACE_POKEDATA, g_pid,
			   (void *)(uintptr_t)aligned,
			   (void *)word) != 0)
			return -1;
		done += chunk;
	}
	return 0;
}

/* -----------------------------------------------------------------------
 * Software breakpoints
 * ---------------------------------------------------------------------- */

/*
 * Insert a software breakpoint at `addr`.
 * `bp_size` is the trap instruction length in bytes:
 *   x86_64:  always 1  (kind=1 from GDB Z packet)
 *   aarch64: always 4  (kind=4)
 *   arm32:   2=Thumb, 4=ARM  (kind field from Z packet)
 *   mips32:  always 4  (kind=4)
 *   ppc32/64: always 4  (kind=4)
 *   riscv32/64: 2=c.ebreak (RVC), 4=ebreak  (kind field from Z packet)
 */
static int bp_insert(uint64_t addr, int bp_size)
{
	int i;
	char hex[4 * 2 + 2]; /* max 4 bytes → 8 hex chars + NUL */
	const uint8_t *trap_bytes;
	int trap_len;

#if defined(__x86_64__)
	(void)bp_size;
	trap_bytes = k_x86_brk;
	trap_len   = 1;
#elif defined(__aarch64__)
	(void)bp_size;
	trap_bytes = k_aarch64_brk;
	trap_len   = 4;
#elif defined(__arm__)
	if (bp_size == 2) {
		trap_bytes = k_thumb_brk;
		trap_len   = 2;
	} else {
		trap_bytes = k_arm_brk;
		trap_len   = 4;
	}
#elif defined(__mips__)
	(void)bp_size;
	trap_bytes = k_mips_brk;
	trap_len   = 4;
#elif defined(__powerpc__)
	(void)bp_size;
	trap_bytes = k_ppc_brk;
	trap_len   = 4;
#elif defined(__riscv)
	if (bp_size == 2) {
		trap_bytes = k_riscv_c_brk;
		trap_len   = 2;
	} else {
		trap_bytes = k_riscv_brk;
		trap_len   = 4;
	}
#else
	(void)bp_size;
	return -1;
#endif

	/* Idempotent: already set at this address */
	for (i = 0; i < ELA_GDB_MAX_BREAKPOINTS; i++) {
		if (g_bps[i].in_use && g_bps[i].addr == addr)
			return 0;
	}

	/* Find free slot */
	for (i = 0; i < ELA_GDB_MAX_BREAKPOINTS; i++) {
		if (!g_bps[i].in_use)
			break;
	}
	if (i == ELA_GDB_MAX_BREAKPOINTS)
		return -1;

	/* Save original bytes */
	if (mem_read(addr, (size_t)trap_len, hex, sizeof(hex)) != 0)
		return -1;
	if (ela_gdb_hex_decode(hex, g_bps[i].orig_bytes,
			       sizeof(g_bps[i].orig_bytes)) < 0)
		return -1;

	if (mem_write(addr, trap_bytes, (size_t)trap_len) != 0)
		return -1;

	g_bps[i].addr   = addr;
	g_bps[i].size   = trap_len;
	g_bps[i].in_use = true;
	return 0;
}

static int bp_remove(uint64_t addr)
{
	int i;

	for (i = 0; i < ELA_GDB_MAX_BREAKPOINTS; i++) {
		if (g_bps[i].in_use && g_bps[i].addr == addr)
			break;
	}
	if (i == ELA_GDB_MAX_BREAKPOINTS)
		return -1;

	if (mem_write(addr, g_bps[i].orig_bytes, (size_t)g_bps[i].size) != 0)
		return -1;

	g_bps[i].in_use = false;
	return 0;
}

static void bp_clear_all(void)
{
	int i;

	for (i = 0; i < ELA_GDB_MAX_BREAKPOINTS; i++) {
		if (g_bps[i].in_use) {
			bp_remove(g_bps[i].addr);
			g_bps[i].in_use = false;
		}
	}
}

/* -----------------------------------------------------------------------
 * SVR4 shared-library XML builder
 * ---------------------------------------------------------------------- */

/*
 * Build the <library-list-svr4> XML document by walking /proc/<pid>/maps.
 *
 * For every mapped file whose path contains ".so" we emit one <library>
 * element.  Duplicate entries (multiple segments of the same .so) are
 * suppressed by scanning the already-written XML for name="<path>".
 * l_addr is the lowest mapping address for that path, which equals the
 * ELF load bias for PIC shared libraries linked at virtual base 0.
 * lm and l_ld are set to 0x0 because we do not traverse the r_debug /
 * link_map chain; GDB can still find and load symbols from the file.
 *
 * Returns the byte length of the XML (excluding NUL) on success,
 * or -1 if the output buffer is too small or /proc/<pid>/maps is
 * unreadable.
 */
static int build_libraries_svr4_xml(pid_t pid, char *out, size_t out_sz)
{
	char maps_path[32];
	FILE *f;
	char line[512];
	char path[256];
	char needle[292]; /* "name=\"" (6) + path (256) + "\"" (1) + NUL */
	size_t pos = 0;
	int n;
	unsigned long long start_addr;
	char *p, *nl;
	int fields;

	n = snprintf(out, out_sz, "<library-list-svr4 version=\"1.0\">");
	if (n < 0 || (size_t)n >= out_sz)
		return -1;
	pos = (size_t)n;

	snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int)pid);
	f = fopen(maps_path, "r");
	if (!f)
		goto footer;

	while (fgets(line, sizeof(line), f)) {
		/* Parse the start address (hex, no 0x prefix). */
		if (sscanf(line, "%llx", &start_addr) != 1)
			continue;

		/*
		 * Skip to the path field.
		 * Maps line format:
		 *   start-end perms offset dev inode [path]
		 * That is 5 whitespace-delimited tokens before the path.
		 */
		p = line;
		fields = 0;
		while (*p && fields < 5) {
			while (*p && *p != ' ' && *p != '\t') p++;
			while (*p == ' ' || *p == '\t') p++;
			fields++;
		}

		if (*p == '\0' || *p == '\n' || *p == '\r')
			continue; /* anonymous or special mapping — no path */

		/* Copy path and strip trailing whitespace / newline. */
		strncpy(path, p, sizeof(path) - 1);
		path[sizeof(path) - 1] = '\0';
		nl = strchr(path, '\n');
		if (nl) *nl = '\0';
		nl = strchr(path, '\r');
		if (nl) *nl = '\0';

		/* Skip kernel-synthetic entries like [vdso], [heap], [stack]. */
		if (path[0] == '[')
			continue;

		/* Only include shared-library files. */
		if (strstr(path, ".so") == NULL)
			continue;

		/*
		 * Deduplicate: a single .so has several segments (r-x, r--,
		 * rw-) that all appear in maps.  Only emit the first
		 * (lowest-address) one by checking the already-written XML.
		 */
		snprintf(needle, sizeof(needle), "name=\"%s\"", path);
		if (strstr(out, needle) != NULL)
			continue;

		/*
		 * Leave at least 30 bytes for the closing tag.
		 * If we can't fit another entry, stop collecting.
		 */
		if (pos + 30 >= out_sz)
			break;

		n = snprintf(out + pos, out_sz - pos - 30,
			     "<library name=\"%s\""
			     " lm=\"0x0\""
			     " l_addr=\"0x%llx\""
			     " l_ld=\"0x0\"/>",
			     path, start_addr);
		if (n > 0)
			pos += (size_t)n;
	}
	fclose(f);

footer:
	n = snprintf(out + pos, out_sz - pos, "</library-list-svr4>");
	if (n < 0 || pos + (size_t)n >= out_sz)
		return -1;
	pos += (size_t)n;
	return (int)pos;
}

/* -----------------------------------------------------------------------
 * RSP binary unescape
 * ---------------------------------------------------------------------- */

/*
 * Decode RSP binary encoding from `src` into `dst`.
 * The only encoding rule: 0x7d ('}') is an escape byte; the byte that
 * follows is XOR'd with 0x20 to recover the real value.
 * Writes exactly `expected` decoded bytes; `max_src` is a hard limit on
 * how many source bytes may be consumed (prevents reading past the payload
 * buffer when the caller does not have its length).
 * Returns `expected` on success, -1 if the source is exhausted first.
 */
static int rsp_binary_unescape(const char *src, size_t max_src,
				uint8_t *dst, size_t expected)
{
	size_t in = 0, out = 0;

	while (out < expected) {
		if (in >= max_src)
			return -1;
		if ((unsigned char)src[in] == 0x7du) {
			in++;
			if (in >= max_src)
				return -1;
			dst[out++] = (uint8_t)((unsigned char)src[in] ^ 0x20u);
		} else {
			dst[out++] = (uint8_t)(unsigned char)src[in];
		}
		in++;
	}
	return (int)out;
}

/* -----------------------------------------------------------------------
 * RSP packet dispatch
 * ---------------------------------------------------------------------- */

static void handle_packet(int fd, char *pkt)
{
	char resp[ELA_GDB_RSP_MAX_FRAMED];
	char hex[ELA_GDB_RSP_MAX_PACKET];
	uint64_t addr, len_val;
	uint8_t data_buf[2048];
	char *sep, *colon;
	int wstatus, n, regnum;

	switch (pkt[0]) {

	case '?': /* Halt reason */
		rsp_send_str(fd, "S05");
		break;

	case 'g': /* Read all registers */
		if (regs_read(resp, sizeof(resp)) != 0)
			rsp_send_str(fd, "E01");
		else
			rsp_send_str(fd, resp);
		break;

	case 'G': /* Write all registers — not implemented */
		rsp_send_str(fd, "E01");
		break;

	case 'p': /* Read single register */
		regnum = (int)strtol(pkt + 1, NULL, 16);
		if (reg_read_one(regnum, resp, sizeof(resp)) != 0)
			rsp_send_str(fd, "E01");
		else
			rsp_send_str(fd, resp);
		break;

	case 'P': { /* Write single register: Pnn=r...r */
		char *eq = strchr(pkt + 1, '=');
		int rn;

		if (!eq) { rsp_send_str(fd, "E01"); break; }
		*eq = '\0';
		rn = (int)strtol(pkt + 1, NULL, 16);
		if (reg_write_one(rn, eq + 1) != 0)
			rsp_send_str(fd, "E01");
		else
			rsp_send_str(fd, "OK");
		break;
	}

	case 'm': /* Read memory: m addr,len */
		sep = strchr(pkt + 1, ',');
		if (!sep) { rsp_send_str(fd, "E01"); break; }
		*sep = '\0';
		if (ela_gdb_parse_hex_u64(pkt + 1, &addr) != 0 ||
		    ela_gdb_parse_hex_u64(sep + 1, &len_val) != 0 ||
		    len_val == 0 || len_val > 2048) {
			rsp_send_str(fd, "E02"); break;
		}
		if (mem_read(addr, (size_t)len_val, hex, sizeof(hex)) != 0)
			rsp_send_str(fd, "E03");
		else
			rsp_send_str(fd, hex);
		break;

	case 'M': /* Write memory: M addr,len:data */
		sep = strchr(pkt + 1, ',');
		if (!sep) { rsp_send_str(fd, "E01"); break; }
		colon = strchr(sep + 1, ':');
		if (!colon) { rsp_send_str(fd, "E01"); break; }
		*sep   = '\0';
		*colon = '\0';
		if (ela_gdb_parse_hex_u64(pkt + 1, &addr) != 0 ||
		    ela_gdb_parse_hex_u64(sep + 1, &len_val) != 0 ||
		    len_val == 0 || len_val > sizeof(data_buf)) {
			rsp_send_str(fd, "E02"); break;
		}
		n = ela_gdb_hex_decode(colon + 1, data_buf, sizeof(data_buf));
		if (n < 0 || (size_t)n != len_val) {
			rsp_send_str(fd, "E03"); break;
		}
		if (mem_write(addr, data_buf, (size_t)len_val) != 0)
			rsp_send_str(fd, "E04");
		else
			rsp_send_str(fd, "OK");
		break;

	case 'X': /* Binary memory write: X addr,len:data */
		sep = strchr(pkt + 1, ',');
		if (!sep) { rsp_send_str(fd, "E01"); break; }
		colon = strchr(sep + 1, ':');
		if (!colon) { rsp_send_str(fd, "E01"); break; }
		*sep   = '\0';
		*colon = '\0';
		if (ela_gdb_parse_hex_u64(pkt + 1, &addr) != 0 ||
		    ela_gdb_parse_hex_u64(sep + 1, &len_val) != 0 ||
		    len_val > sizeof(data_buf)) {
			rsp_send_str(fd, "E02"); break;
		}
		if (len_val == 0) {
			/* GDB probe — confirm X packet support */
			rsp_send_str(fd, "OK");
			break;
		}
		n = rsp_binary_unescape(colon + 1, 2 * (size_t)len_val,
					data_buf, (size_t)len_val);
		if (n < 0 || (size_t)n != len_val) {
			rsp_send_str(fd, "E03"); break;
		}
		if (mem_write(addr, data_buf, (size_t)len_val) != 0)
			rsp_send_str(fd, "E04");
		else
			rsp_send_str(fd, "OK");
		break;

	case 'c': /* Continue */
		ptrace(PTRACE_CONT, g_pid, NULL, NULL);
		waitpid(g_pid, &wstatus, 0);
		send_stop_reply(fd, wstatus);
		break;

	case 's': /* Single step */
		ptrace(PTRACE_SINGLESTEP, g_pid, NULL, NULL);
		waitpid(g_pid, &wstatus, 0);
		send_stop_reply(fd, wstatus);
		break;

	case 'v':
		if (strcmp(pkt, "vCont?") == 0) {
			rsp_send_str(fd, "vCont;c;C;s;S");
		} else if (strncmp(pkt, "vCont;c", 7) == 0) {
			ptrace(PTRACE_CONT, g_pid, NULL, NULL);
			waitpid(g_pid, &wstatus, 0);
			send_stop_reply(fd, wstatus);
		} else if (strncmp(pkt, "vCont;C", 7) == 0) {
			/* Continue with signal: vCont;C<sig>[:tid] */
			int sig = (int)strtol(pkt + 7, NULL, 16);
			ptrace(PTRACE_CONT, g_pid, NULL, (void *)(uintptr_t)sig);
			waitpid(g_pid, &wstatus, 0);
			send_stop_reply(fd, wstatus);
		} else if (strncmp(pkt, "vCont;s", 7) == 0) {
			ptrace(PTRACE_SINGLESTEP, g_pid, NULL, NULL);
			waitpid(g_pid, &wstatus, 0);
			send_stop_reply(fd, wstatus);
		} else if (strncmp(pkt, "vCont;S", 7) == 0) {
			/* Step with signal: vCont;S<sig>[:tid] */
			int sig = (int)strtol(pkt + 7, NULL, 16);
			ptrace(PTRACE_SINGLESTEP, g_pid, NULL,
			       (void *)(uintptr_t)sig);
			waitpid(g_pid, &wstatus, 0);
			send_stop_reply(fd, wstatus);
		} else {
			rsp_send_str(fd, ""); /* unknown v-packet */
		}
		break;

	case 'H': /* Set thread — ignored */
		rsp_send_str(fd, "OK");
		break;

	case 'T': /* Thread alive */
		rsp_send_str(fd, "OK");
		break;

	case 'Z': /* Insert breakpoint: Z0,addr,kind */
		if (pkt[1] == '0') { /* software breakpoint only */
			uint64_t kind = 4; /* default: 4-byte trap */
			char *ksep;

			sep = strchr(pkt + 3, ',');
			if (!sep) { rsp_send_str(fd, "E01"); break; }
			*sep = '\0';
			ksep = sep + 1;
			/* kind field: 1=x86, 2=Thumb, 4=ARM/AArch64 */
			ela_gdb_parse_hex_u64(ksep, &kind);
			if (ela_gdb_parse_hex_u64(pkt + 3, &addr) != 0 ||
			    bp_insert(addr, (int)kind) != 0)
				rsp_send_str(fd, "E01");
			else
				rsp_send_str(fd, "OK");
		} else {
			rsp_send_str(fd, ""); /* unsupported bp type */
		}
		break;

	case 'z': /* Remove breakpoint */
		if (pkt[1] == '0') {
			sep = strchr(pkt + 3, ',');
			if (!sep) { rsp_send_str(fd, "E01"); break; }
			*sep = '\0';
			if (ela_gdb_parse_hex_u64(pkt + 3, &addr) != 0 ||
			    bp_remove(addr) != 0)
				rsp_send_str(fd, "E01");
			else
				rsp_send_str(fd, "OK");
		} else {
			rsp_send_str(fd, "");
		}
		break;

	case 'q': /* Query packets */
		if (strncmp(pkt, "qSupported", 10) == 0) {
			snprintf(resp, sizeof(resp),
				 "PacketSize=%x"
				 ";qXfer:exec-file:read+"
				 ";qXfer:auxv:read+"
				 ";qXfer:features:read+"
				 ";qXfer:libraries-svr4:read+",
				 ELA_GDB_RSP_MAX_PACKET);
			rsp_send_str(fd, resp);
		} else if (strcmp(pkt, "qAttached") == 0) {
			rsp_send_str(fd, "1");
		} else if (strncmp(pkt, "qC", 2) == 0) {
			snprintf(resp, sizeof(resp), "QC%x", (unsigned)g_pid);
			rsp_send_str(fd, resp);
		} else if (strncmp(pkt, "qThreadExtraInfo,", 17) == 0) {
			/*
			 * Format: qThreadExtraInfo,<tid-hex>
			 * Response: hex-encoded thread name string.
			 * Read the name from /proc/<pid>/task/<tid>/comm
			 * (kernel truncates to 15 chars + NUL).
			 */
			unsigned long long tid_val;
			char comm_path[48];
			char comm[16];
			int comm_fd;
			ssize_t comm_len;
			char hex_out[32 + 1]; /* 16 bytes × 2 hex + NUL */

			if (sscanf(pkt + 17, "%llx", &tid_val) != 1) {
				rsp_send_str(fd, "");
				break;
			}

			snprintf(comm_path, sizeof(comm_path),
				 "/proc/%d/task/%llu/comm",
				 (int)g_pid, tid_val);
			comm_fd = open(comm_path, O_RDONLY);
			if (comm_fd < 0) {
				rsp_send_str(fd, "");
				break;
			}
			comm_len = read(comm_fd, comm, sizeof(comm) - 1);
			close(comm_fd);
			if (comm_len <= 0) {
				rsp_send_str(fd, "");
				break;
			}
			/* Strip trailing newline written by the kernel. */
			if (comm[comm_len - 1] == '\n')
				comm_len--;
			comm[comm_len] = '\0';

			if (ela_gdb_hex_encode((const uint8_t *)comm,
					       (size_t)comm_len,
					       hex_out, sizeof(hex_out)) != 0) {
				rsp_send_str(fd, "");
				break;
			}
			rsp_send_str(fd, hex_out);
		} else if (strcmp(pkt, "qfThreadInfo") == 0) {
			/*
			 * Enumerate /proc/<pid>/task/ to list all thread TIDs.
			 * Returns mTID1,TID2,... for the first (or only) batch.
			 * Remaining threads are served by qsThreadInfo.
			 */
			char task_path[32];
			DIR *dir;
			struct dirent *ent;
			int i, pos = 0;

			snprintf(task_path, sizeof(task_path),
				 "/proc/%d/task", (int)g_pid);
			g_tid_count = 0;
			g_tid_next  = 0;

			dir = opendir(task_path);
			if (dir) {
				while ((ent = readdir(dir)) != NULL &&
				       g_tid_count < ELA_GDB_MAX_THREADS) {
					char *endp;
					pid_t tid;

					if (ent->d_name[0] == '.')
						continue;
					tid = (pid_t)strtol(ent->d_name,
							    &endp, 10);
					if (*endp == '\0' && tid > 0)
						g_tids[g_tid_count++] = tid;
				}
				closedir(dir);
			}
			/* Fall back to main thread if /proc enumeration failed */
			if (g_tid_count == 0) {
				g_tids[0]   = g_pid;
				g_tid_count = 1;
			}

			resp[pos++] = 'm';
			for (i = 0;
			     i < g_tid_count && pos + 12 < (int)sizeof(resp);
			     i++) {
				if (i > 0)
					resp[pos++] = ',';
				pos += snprintf(resp + pos,
						sizeof(resp) - (size_t)pos,
						"%x", (unsigned)g_tids[i]);
			}
			g_tid_next  = i;
			resp[pos]   = '\0';
			rsp_send_str(fd, resp);
		} else if (strcmp(pkt, "qsThreadInfo") == 0) {
			/*
			 * Continue paging the thread list started by
			 * qfThreadInfo.  Returns l when all threads sent.
			 */
			if (g_tid_next >= g_tid_count) {
				rsp_send_str(fd, "l");
			} else {
				int start = g_tid_next;
				int i, pos = 0;

				resp[pos++] = 'm';
				for (i = start;
				     i < g_tid_count &&
				     pos + 12 < (int)sizeof(resp);
				     i++) {
					if (i > start)
						resp[pos++] = ',';
					pos += snprintf(
						resp + pos,
						sizeof(resp) - (size_t)pos,
						"%x", (unsigned)g_tids[i]);
				}
				g_tid_next = i;
				resp[pos]  = '\0';
				rsp_send_str(fd, resp);
			}
		} else if (strncmp(pkt, "qXfer:exec-file:read:", 21) == 0) {
			/*
			 * Format: qXfer:exec-file:read:<annex>:<offset>,<length>
			 * annex is a hex PID or empty; we always use g_pid.
			 * Response: 'l'<data> (last) or 'm'<data> (more).
			 */
			char exe_path[4096];
			char proc_link[32];
			ssize_t exe_len;
			uint64_t xfer_off, xfer_len;
			char *rest = pkt + 21;
			char *sep  = strrchr(rest, ':');
			char *comma;
			size_t avail, chunk;

			if (!sep) { rsp_send_str(fd, "E01"); break; }
			comma = strchr(sep + 1, ',');
			if (!comma) { rsp_send_str(fd, "E01"); break; }

			/* null-terminate offset field before parsing */
			*comma = '\0';
			if (ela_gdb_parse_hex_u64(sep + 1, &xfer_off) != 0 ||
			    ela_gdb_parse_hex_u64(comma + 1, &xfer_len) != 0) {
				rsp_send_str(fd, "E01");
				break;
			}

			snprintf(proc_link, sizeof(proc_link),
				 "/proc/%d/exe", (int)g_pid);
			exe_len = readlink(proc_link, exe_path,
					   sizeof(exe_path) - 1);
			if (exe_len < 0) { rsp_send_str(fd, "E01"); break; }
			exe_path[exe_len] = '\0';

			if (xfer_off >= (uint64_t)exe_len) {
				rsp_send_str(fd, "l"); /* past end */
				break;
			}

			avail = (size_t)((uint64_t)exe_len - xfer_off);
			/* cap to what fits in resp leaving room for prefix+NUL */
			if (xfer_len > (uint64_t)(sizeof(resp) - 2))
				xfer_len = (uint64_t)(sizeof(resp) - 2);
			chunk = (avail < (size_t)xfer_len)
				? avail : (size_t)xfer_len;

			resp[0] = (chunk < avail) ? 'm' : 'l';
			memcpy(resp + 1, exe_path + xfer_off, chunk);
			resp[1 + chunk] = '\0';
			rsp_send_str(fd, resp);
		} else if (strncmp(pkt, "qXfer:auxv:read:", 16) == 0) {
			/*
			 * Format: qXfer:auxv:read:<annex>:<offset>,<length>
			 * annex is always empty for auxv.
			 * /proc/<pid>/auxv is raw binary (ElfN_auxv_t array).
			 */
			uint8_t auxv_buf[4096];
			char proc_path[32];
			int auxv_fd;
			ssize_t auxv_len;
			uint64_t xfer_off, xfer_len;
			char *rest = pkt + 16;
			char *sep  = strrchr(rest, ':');
			char *comma;
			size_t avail, chunk;

			if (!sep) { rsp_send_str(fd, "E01"); break; }
			comma = strchr(sep + 1, ',');
			if (!comma) { rsp_send_str(fd, "E01"); break; }

			*comma = '\0';
			if (ela_gdb_parse_hex_u64(sep + 1, &xfer_off) != 0 ||
			    ela_gdb_parse_hex_u64(comma + 1, &xfer_len) != 0) {
				rsp_send_str(fd, "E01");
				break;
			}

			snprintf(proc_path, sizeof(proc_path),
				 "/proc/%d/auxv", (int)g_pid);
			auxv_fd = open(proc_path, O_RDONLY);
			if (auxv_fd < 0) { rsp_send_str(fd, "E01"); break; }
			auxv_len = read(auxv_fd, auxv_buf, sizeof(auxv_buf));
			close(auxv_fd);
			if (auxv_len <= 0) { rsp_send_str(fd, "E01"); break; }

			if (xfer_off >= (uint64_t)auxv_len) {
				rsp_send_str(fd, "l"); /* past end */
				break;
			}

			avail = (size_t)((uint64_t)auxv_len - xfer_off);
			if (xfer_len > (uint64_t)sizeof(auxv_buf))
				xfer_len = (uint64_t)sizeof(auxv_buf);
			chunk = (avail < (size_t)xfer_len)
				? avail : (size_t)xfer_len;

			rsp_send_binary_qxfer(fd,
					      auxv_buf + (size_t)xfer_off,
					      chunk,
					      chunk >= avail);
		} else if (strncmp(pkt, "qXfer:features:read:", 20) == 0) {
			/*
			 * Format: qXfer:features:read:<annex>:<offset>,<length>
			 * We only serve target.xml; other annexes get E00.
			 */
			char *rest = pkt + 20;
			char *sep  = strrchr(rest, ':');
			char *comma;
			uint64_t xfer_off, xfer_len;
			size_t xml_len, avail, chunk;

			if (!sep) { rsp_send_str(fd, "E00"); break; }

			/* annex is the substring before sep */
			*sep = '\0';
			if (strcmp(rest, "target.xml") != 0) {
				rsp_send_str(fd, "E00");
				break;
			}
			*sep = ':'; /* restore for comma search */

			comma = strchr(sep + 1, ',');
			if (!comma) { rsp_send_str(fd, "E00"); break; }

			*comma = '\0';
			if (ela_gdb_parse_hex_u64(sep + 1, &xfer_off) != 0 ||
			    ela_gdb_parse_hex_u64(comma + 1, &xfer_len) != 0) {
				rsp_send_str(fd, "E00");
				break;
			}

			xml_len = sizeof(k_target_xml) - 1; /* exclude NUL */

			if (xfer_off >= (uint64_t)xml_len) {
				rsp_send_str(fd, "l");
				break;
			}

			avail = (size_t)(xml_len - (size_t)xfer_off);
			if (xfer_len > (uint64_t)(sizeof(resp) - 2))
				xfer_len = (uint64_t)(sizeof(resp) - 2);
			chunk = (avail < (size_t)xfer_len)
				? avail : (size_t)xfer_len;

			resp[0] = (chunk < avail) ? 'm' : 'l';
			memcpy(resp + 1, k_target_xml + (size_t)xfer_off, chunk);
			resp[1 + chunk] = '\0';
			rsp_send_str(fd, resp);
		} else if (strncmp(pkt, "qXfer:libraries-svr4:read:", 26) == 0) {
			/*
			 * Format: qXfer:libraries-svr4:read:<annex>:<offset>,<length>
			 * annex is always empty for this object.
			 * Rebuild the XML at the start of each new transfer
			 * (offset == 0) so the list reflects the current
			 * process state (post-dlopen, post-dlclose).
			 */
			char *rest = pkt + 26;
			char *sep  = strrchr(rest, ':');
			char *comma;
			uint64_t xfer_off, xfer_len;
			size_t xml_len, avail, chunk;

			if (!sep) { rsp_send_str(fd, "E01"); break; }
			comma = strchr(sep + 1, ',');
			if (!comma) { rsp_send_str(fd, "E01"); break; }

			*comma = '\0';
			if (ela_gdb_parse_hex_u64(sep + 1, &xfer_off) != 0 ||
			    ela_gdb_parse_hex_u64(comma + 1, &xfer_len) != 0) {
				rsp_send_str(fd, "E01");
				break;
			}

			if (xfer_off == 0) {
				g_svr4_xml_len = build_libraries_svr4_xml(
					g_pid, g_svr4_xml, sizeof(g_svr4_xml));
			}

			if (g_svr4_xml_len < 0) {
				rsp_send_str(fd, "E01");
				break;
			}

			xml_len = (size_t)g_svr4_xml_len;

			if (xfer_off >= (uint64_t)xml_len) {
				rsp_send_str(fd, "l");
				break;
			}

			avail = (size_t)(xml_len - (size_t)xfer_off);
			if (xfer_len > (uint64_t)(sizeof(resp) - 2))
				xfer_len = (uint64_t)(sizeof(resp) - 2);
			chunk = (avail < (size_t)xfer_len)
				? avail : (size_t)xfer_len;

			resp[0] = (chunk < avail) ? 'm' : 'l';
			memcpy(resp + 1, g_svr4_xml + (size_t)xfer_off, chunk);
			resp[1 + chunk] = '\0';
			rsp_send_str(fd, resp);
		} else {
			rsp_send_str(fd, ""); /* unknown query */
		}
		break;

	case 'D': /* Detach */
		bp_clear_all();
		ptrace(PTRACE_DETACH, g_pid, NULL, NULL);
		rsp_send_str(fd, "OK");
		g_stop = 1;
		break;

	case 'k': /* Kill — we interpret as detach */
		bp_clear_all();
		ptrace(PTRACE_DETACH, g_pid, NULL, NULL);
		g_stop = 1;
		break;

	default:
		rsp_send_str(fd, ""); /* unknown packet */
		break;
	}
}

/* -----------------------------------------------------------------------
 * Session loop
 * ---------------------------------------------------------------------- */

static int run_session(int conn_fd, pid_t pid)
{
	char payload[ELA_GDB_RSP_MAX_PACKET + 1];
	int n;

	g_pid          = pid;
	g_stop         = 0;
	g_tid_count    = 0;
	g_tid_next     = 0;
	g_svr4_xml_len = -1;
	memset(g_bps, 0, sizeof(g_bps));

	while (!g_stop) {
		n = rsp_recv_packet(conn_fd, payload, sizeof(payload));
		if (n < 0)
			break;
		handle_packet(conn_fd, payload);
	}

	return 0;
}

/* -----------------------------------------------------------------------
 * TCP listener
 * ---------------------------------------------------------------------- */

static int tcp_listen_port(uint16_t port)
{
	int fd, opt = 1;
	struct sockaddr_in addr;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port        = htons(port);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
	    listen(fd, 1) != 0) {
		close(fd);
		return -1;
	}
	return fd;
}

/* -----------------------------------------------------------------------
 * Entry point: linux gdbserver <PID> <PORT>
 * ---------------------------------------------------------------------- */

int linux_gdbserver_main(int argc, char **argv)
{
	pid_t pid;
	uint16_t port;
	long val;
	char *endptr;
	int listen_fd, conn_fd, wstatus;
	struct sockaddr_in client;
	socklen_t client_len = sizeof(client);
	int pipefd[2];
	pid_t child;
	char result;
	int devnull;

	if (argc < 3) {
		fprintf(stderr,
			"Usage: linux gdbserver <PID> <PORT>\n"
			"  PID   : process ID to attach to\n"
			"  PORT  : TCP port for gdb-multiarch to connect on\n"
			"\n"
			"In gdb-multiarch: target remote <agent-ip>:<PORT>\n");
		return 1;
	}

	val = strtol(argv[1], &endptr, 10);
	if (endptr == argv[1] || *endptr != '\0' || val <= 0) {
		fprintf(stderr, "Invalid PID: %s\n", argv[1]);
		return 1;
	}
	pid = (pid_t)val;

	val = strtol(argv[2], &endptr, 10);
	if (endptr == argv[2] || *endptr != '\0' || val <= 0 || val > 65535) {
		fprintf(stderr, "Invalid port: %s\n", argv[2]);
		return 1;
	}
	port = (uint16_t)val;

	if (pipe(pipefd) != 0) {
		perror("pipe");
		return 1;
	}

	child = fork();
	if (child < 0) {
		perror("fork");
		close(pipefd[0]);
		close(pipefd[1]);
		return 1;
	}

	if (child > 0) {
		/* Parent: block until child signals ready or error */
		close(pipefd[1]);
		result = 'E';
		(void)read(pipefd[0], &result, 1);
		close(pipefd[0]);
		if (result == 'K') {
			fprintf(stderr,
				"gdbserver attached to PID %d, listening on port %u (background).\n"
				"  Connect with: target remote :%u\n",
				(int)pid, (unsigned)port, (unsigned)port);
			return 0;
		}
		return 1;
	}

	/* Child: become session leader and run the gdbserver */
	close(pipefd[0]);
	setsid();
	signal(SIGINT,  handle_signal);
	signal(SIGTERM, handle_signal);

	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0) {
		perror("ptrace attach");
		(void)write(pipefd[1], "E", 1);
		close(pipefd[1]);
		exit(1);
	}

	if (waitpid(pid, &wstatus, 0) < 0) {
		perror("waitpid");
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		(void)write(pipefd[1], "E", 1);
		close(pipefd[1]);
		exit(1);
	}

	listen_fd = tcp_listen_port(port);
	if (listen_fd < 0) {
		perror("bind/listen");
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		(void)write(pipefd[1], "E", 1);
		close(pipefd[1]);
		exit(1);
	}

	/* Signal parent that attach and bind succeeded */
	(void)write(pipefd[1], "K", 1);
	close(pipefd[1]);

	/* Redirect stdio to /dev/null so inherited fds don't keep sessions alive */
	devnull = open("/dev/null", O_RDWR);
	if (devnull >= 0) {
		dup2(devnull, STDIN_FILENO);
		dup2(devnull, STDOUT_FILENO);
		dup2(devnull, STDERR_FILENO);
		if (devnull > STDERR_FILENO)
			close(devnull);
	}

	conn_fd = accept(listen_fd, (struct sockaddr *)&client, &client_len);
	close(listen_fd);
	if (conn_fd < 0)
		exit(1);

	run_session(conn_fd, pid);

	close(conn_fd);
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
	exit(0);
}
