// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "linux_gdbserver_util.h"
#include "../embedded_linux_audit_cmd.h"

#include <libxml/tree.h>

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
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <elf.h>

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

/* Maximum byte sizes of on-demand XML documents */
#define ELA_GDB_TARGET_XML_MAX   8192
#define ELA_GDB_THREADS_XML_MAX  8192
#define ELA_GDB_MEMMAP_XML_MAX   32768

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
 * PPC trap instruction (unconditional): 'trap' = 0x7fe00008.
 * The encoding is the same for PPC32 and PPC64, but the byte order
 * in memory depends on whether the kernel is running BE or LE.
 * PPC64 LE (IBM POWER8+ in LE mode) stores the instruction bytes reversed.
 */
#  ifdef __LITTLE_ENDIAN__
static const uint8_t k_ppc_brk[4]     = { 0x08, 0x00, 0xe0, 0x7f }; /* LE */
#  else
static const uint8_t k_ppc_brk[4]     = { 0x7f, 0xe0, 0x00, 0x08 }; /* BE */
#  endif
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
static int             g_noack;        /* set by QStartNoAckMode */
static uint64_t        g_pass_signals; /* bitmask of signals to pass to inferior */
static pid_t           g_current_tid;  /* most-recently-set thread (H packet) */
static int             g_last_wstatus; /* wstatus from last waitpid — for '?' */
static int             g_swbreak_feature;  /* GDB negotiated swbreak+ */
static int             g_catch_syscalls;   /* QCatchSyscalls enabled */
static int             g_in_syscall;       /* 0=expecting entry, 1=expecting exit */
static uint64_t        g_last_sysno;       /* syscall# saved at entry for exit stop */

/* Syscall filter list: if cnt==0 catch all; otherwise only listed sysno */
#define ELA_GDB_MAX_CATCH_SYSCALLS 64
static uint64_t        g_catch_sysno[ELA_GDB_MAX_CATCH_SYSCALLS];
static int             g_catch_sysno_cnt;

/* Thread list populated by qfThreadInfo and paged by qsThreadInfo */
#define ELA_GDB_MAX_THREADS  256
static pid_t g_tids[ELA_GDB_MAX_THREADS];
static int   g_tid_count;
static int   g_tid_next;

/* SVR4 library-list XML cache (rebuilt at the start of each transfer) */
static char  g_svr4_xml[ELA_GDB_SVR4_XML_MAX];
static int   g_svr4_xml_len = -1; /* -1 = not yet built for this session */

/* Thread-list XML cache (rebuilt at the start of each transfer) */
static char  g_threads_xml[ELA_GDB_THREADS_XML_MAX];
static int   g_threads_xml_len = -1;

/* Memory-map XML cache (rebuilt at the start of each transfer) */
static char  g_memmap_xml[ELA_GDB_MEMMAP_XML_MAX];
static int   g_memmap_xml_len = -1;

/* Target XML cache (built once per session by build_target_xml) */
static char  g_target_xml[ELA_GDB_TARGET_XML_MAX];
static int   g_target_xml_len = -1;

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

	/* ACK (suppressed after QStartNoAckMode) */
	if (!g_noack) {
		if (send(fd, "+", 1, 0) < 0)
			return -1;
	}

	return ela_gdb_rsp_unframe(raw, pos, payload, payload_sz);
}

/* -----------------------------------------------------------------------
 * Stop reply
 * ---------------------------------------------------------------------- */

static void send_stop_reply(int fd, int wstatus)
{
	char buf[96];

	if (WIFSTOPPED(wstatus)) {
		int sig = WSTOPSIG(wstatus);
		bool is_swbreak = false;

#if defined(__x86_64__)
		/*
		 * On x86_64, a software breakpoint (INT3 / 0xCC) causes the
		 * CPU to advance the instruction pointer past the 0xCC byte
		 * before delivering SIGTRAP.  GDB expects the reported PC to
		 * point *at* the breakpoint instruction, so we must back RIP
		 * up by 1.  We distinguish software breakpoints from single-
		 * step traps using PTRACE_GETSIGINFO: TRAP_BRKPT means the
		 * process hit an INT3 (or a Z0 breakpoint we inserted),
		 * whereas TRAP_TRACE is a single-step event.
		 *
		 * TRAP_BRKPT (1) is defined in <signal.h> on Linux; provide
		 * a fallback in case the build environment omits it.
		 */
#  ifndef TRAP_BRKPT
#    define TRAP_BRKPT 1
#  endif
		if (sig == SIGTRAP) {
			siginfo_t si;
			if (ptrace(PTRACE_GETSIGINFO, g_pid, NULL, &si) == 0 &&
			    si.si_code == TRAP_BRKPT) {
				struct user_regs_struct r;
				if (ptrace(PTRACE_GETREGS, g_pid, NULL, &r) == 0) {
					r.rip -= 1;
					ptrace(PTRACE_SETREGS, g_pid, NULL, &r);
				}
				is_swbreak = true;
			}
		}
#endif

		/* T packet includes thread TID, eliminating a qC round-trip */
		if (is_swbreak && g_swbreak_feature)
			snprintf(buf, sizeof(buf), "T%02xthread:%x;swbreak:;",
				 sig, (unsigned)g_pid);
		else
			snprintf(buf, sizeof(buf), "T%02xthread:%x;",
				 sig, (unsigned)g_pid);
	} else if (WIFEXITED(wstatus)) {
		snprintf(buf, sizeof(buf), "W%02x", WEXITSTATUS(wstatus));
	} else if (WIFSIGNALED(wstatus)) {
		snprintf(buf, sizeof(buf), "X%02x", WTERMSIG(wstatus));
	} else {
		return;
	}

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

/* G packet: write all registers from hex string (inverse of regs_read) */
static int regs_write(const char *hex, size_t hex_len)
{
	struct user_regs_struct r;
	uint64_t v64;
	uint32_t v32;
	size_t pos = 0;

	if (hex_len < 328) /* 17×16 + 7×8 */
		return -1;
	if (ptrace(PTRACE_GETREGS, g_pid, NULL, &r) != 0)
		return -1;

#define LOAD64(f) do { \
	if (ela_gdb_decode_le64(hex+pos, &v64)) return -1; \
	r.f = v64; pos += 16; \
} while (0)
#define LOAD32(f) do { \
	if (ela_gdb_decode_le32(hex+pos, &v32)) return -1; \
	r.f = v32; pos += 8; \
} while (0)

	LOAD64(rax); LOAD64(rbx); LOAD64(rcx); LOAD64(rdx);
	LOAD64(rsi); LOAD64(rdi); LOAD64(rbp); LOAD64(rsp);
	LOAD64(r8);  LOAD64(r9);  LOAD64(r10); LOAD64(r11);
	LOAD64(r12); LOAD64(r13); LOAD64(r14); LOAD64(r15);
	LOAD64(rip);
	LOAD32(eflags);
	LOAD32(cs); LOAD32(ss); LOAD32(ds); LOAD32(es); LOAD32(fs); LOAD32(gs);

#undef LOAD64
#undef LOAD32

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

static int regs_write(const char *hex, size_t hex_len)
{
	struct user_pt_regs r;
	struct iovec iov = { &r, sizeof(r) };
	uint64_t v64;
	uint32_t v32;
	size_t pos = 0;
	int i;

	if (hex_len < 536) /* 33×16 + 8 */
		return -1;
	if (ptrace(PTRACE_GETREGSET, g_pid, (void *)(uintptr_t)NT_PRSTATUS,
		   &iov) != 0)
		return -1;

	for (i = 0; i < 31; i++) {
		if (ela_gdb_decode_le64(hex + pos, &v64)) return -1;
		r.regs[i] = v64;
		pos += 16;
	}
	if (ela_gdb_decode_le64(hex + pos, &v64)) return -1; r.sp = v64;     pos += 16;
	if (ela_gdb_decode_le64(hex + pos, &v64)) return -1; r.pc = v64;     pos += 16;
	if (ela_gdb_decode_le32(hex + pos, &v32)) return -1; r.pstate = v32;

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
	struct iovec iov = { &r, sizeof(r) };
	char tmp[9];
	size_t pos = 0;
	int i;

	if (ptrace(PTRACE_GETREGSET, g_pid, (void *)(uintptr_t)NT_PRSTATUS,
		   &iov) != 0)
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

	/* f0-f7: 8 legacy FPA registers, 12 bytes (24 hex chars) each — zero */
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
	struct iovec iov = { &r, sizeof(r) };

	if (ptrace(PTRACE_GETREGSET, g_pid, (void *)(uintptr_t)NT_PRSTATUS,
		   &iov) != 0)
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
	struct iovec iov = { &r, sizeof(r) };
	uint32_t v32;

	if (ptrace(PTRACE_GETREGSET, g_pid, (void *)(uintptr_t)NT_PRSTATUS,
		   &iov) != 0)
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

	iov.iov_len = sizeof(r);
	return ptrace(PTRACE_SETREGSET, g_pid, (void *)(uintptr_t)NT_PRSTATUS,
		      &iov) != 0 ? -1 : 0;
}

/*
 * ARM32 g-packet: 336 hex chars
 *   r0-r15: 16 × 8 = 128
 *   f0-f7:  8 × 24 = 192  (legacy FPA, zero in regs_read)
 *   fps:    1 × 8  = 8    (FPA status, zero in regs_read)
 *   cpsr:   1 × 8  = 8
 */
static int regs_write(const char *hex, size_t hex_len)
{
	struct user_regs r;
	struct iovec iov = { &r, sizeof(r) };
	uint32_t v32;
	size_t pos = 0;
	int i;

	if (hex_len < 336)
		return -1;
	if (ptrace(PTRACE_GETREGSET, g_pid, (void *)(uintptr_t)NT_PRSTATUS,
		   &iov) != 0)
		return -1;

	for (i = 0; i < 16; i++) {
		if (ela_gdb_decode_le32(hex + pos, &v32)) return -1;
		r.uregs[i] = v32;
		pos += 8;
	}
	pos += 192 + 8; /* skip f0-f7 (8×24) and fps (8) */
	if (ela_gdb_decode_le32(hex + pos, &v32)) return -1;
	r.uregs[16] = v32; /* cpsr */

	iov.iov_len = sizeof(r);
	return ptrace(PTRACE_SETREGSET, g_pid, (void *)(uintptr_t)NT_PRSTATUS,
		      &iov) != 0 ? -1 : 0;
}

#elif defined(__mips__)

/*
 * GDB expects register bytes in the target's native byte order.
 * Use endian-agnostic wrappers so the same code compiles correctly for
 * both MIPS big-endian and MIPS little-endian targets.
 */
#ifdef __MIPSEL__
# define mips_enc32(v, b, s) ela_gdb_encode_le32((uint32_t)(v), (b), (s))
# define mips_enc64(v, b, s) ela_gdb_encode_le64((uint64_t)(v), (b), (s))
# define mips_dec32(h, o)    ela_gdb_decode_le32((h), (o))
# define mips_dec64(h, o)    ela_gdb_decode_le64((h), (o))
#else
# define mips_enc32(v, b, s) ela_gdb_encode_be32((uint32_t)(v), (b), (s))
# define mips_enc64(v, b, s) ela_gdb_encode_be64((uint64_t)(v), (b), (s))
# define mips_dec32(h, o)    ela_gdb_decode_be32((h), (o))
# define mips_dec64(h, o)    ela_gdb_decode_be64((h), (o))
#endif

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
	if (mips_enc64((v), tmp, sizeof(tmp)) != 0) return -1; \
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
		return mips_enc64(regs[MIPS_EF_R0 + regnum], out, out_sz);

	switch (regnum) {
	case 32: return mips_enc64(regs[MIPS_EF_STATUS],   out, out_sz);
	case 33: return mips_enc64(regs[MIPS_EF_LO],       out, out_sz);
	case 34: return mips_enc64(regs[MIPS_EF_HI],       out, out_sz);
	case 35: return mips_enc64(regs[MIPS_EF_BADVADDR], out, out_sz);
	case 36: return mips_enc64(regs[MIPS_EF_CAUSE],    out, out_sz);
	case 37: return mips_enc64(regs[MIPS_EF_EPC],      out, out_sz);
	default: break;
	}

	/* f0-f31 (38-69), fcsr (70), fir (71): zero */
	if (regnum >= 38 && regnum <= 71)
		return mips_enc64(0, out, out_sz);

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
		if (mips_dec64(hex_val, &v64)) return -1;
		regs[MIPS_EF_R0 + regnum] = (unsigned long)v64;
	} else {
		switch (regnum) {
		case 32:
			if (mips_dec64(hex_val, &v64)) return -1;
			regs[MIPS_EF_STATUS] = (unsigned long)v64; break;
		case 33:
			if (mips_dec64(hex_val, &v64)) return -1;
			regs[MIPS_EF_LO] = (unsigned long)v64; break;
		case 34:
			if (mips_dec64(hex_val, &v64)) return -1;
			regs[MIPS_EF_HI] = (unsigned long)v64; break;
		case 35:
			if (mips_dec64(hex_val, &v64)) return -1;
			regs[MIPS_EF_BADVADDR] = (unsigned long)v64; break;
		case 36:
			if (mips_dec64(hex_val, &v64)) return -1;
			regs[MIPS_EF_CAUSE] = (unsigned long)v64; break;
		case 37:
			if (mips_dec64(hex_val, &v64)) return -1;
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

/* MIPS64 g-packet: 1152 hex (38 GPRs/ctl × 16 + 32 FP × 16 + 2 ctl × 16) */
static int regs_write(const char *hex, size_t hex_len)
{
	unsigned long regs[MIPS_ELF_NGREG];
	struct iovec iov = { regs, sizeof(regs) };
	uint64_t v64;
	size_t pos = 0;
	int i;

	if (hex_len < 1152)
		return -1;
	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0)
		return -1;

	for (i = 0; i < 32; i++) {
		if (mips_dec64(hex + pos, &v64)) return -1;
		regs[MIPS_EF_R0 + i] = (unsigned long)v64;
		pos += 16;
	}
	if (mips_dec64(hex+pos,&v64)) return -1; regs[MIPS_EF_STATUS]   =(unsigned long)v64; pos+=16;
	if (mips_dec64(hex+pos,&v64)) return -1; regs[MIPS_EF_LO]       =(unsigned long)v64; pos+=16;
	if (mips_dec64(hex+pos,&v64)) return -1; regs[MIPS_EF_HI]       =(unsigned long)v64; pos+=16;
	if (mips_dec64(hex+pos,&v64)) return -1; regs[MIPS_EF_BADVADDR] =(unsigned long)v64; pos+=16;
	if (mips_dec64(hex+pos,&v64)) return -1; regs[MIPS_EF_CAUSE]    =(unsigned long)v64; pos+=16;
	if (mips_dec64(hex+pos,&v64)) return -1; regs[MIPS_EF_EPC]      =(unsigned long)v64;
	/* FP registers not written to kernel */

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
	if (mips_enc32((v), tmp, sizeof(tmp)) != 0) return -1; \
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
		return mips_enc32(regs[MIPS_EF_R0 + regnum], out, out_sz);

	switch (regnum) {
	case 32: return mips_enc32(regs[MIPS_EF_STATUS],   out, out_sz);
	case 33: return mips_enc32(regs[MIPS_EF_LO],       out, out_sz);
	case 34: return mips_enc32(regs[MIPS_EF_HI],       out, out_sz);
	case 35: return mips_enc32(regs[MIPS_EF_BADVADDR], out, out_sz);
	case 36: return mips_enc32(regs[MIPS_EF_CAUSE],    out, out_sz);
	case 37: return mips_enc32(regs[MIPS_EF_EPC],      out, out_sz);
	default: break;
	}

	/* f0-f31 (38-69), fcsr (70), fir (71): zero-filled */
	if (regnum >= 38 && regnum <= 71)
		return mips_enc32(0, out, out_sz);

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
		if (mips_dec32(hex_val, &v32)) return -1;
		regs[MIPS_EF_R0 + regnum] = (unsigned long)v32;
	} else {
		switch (regnum) {
		case 32:
			if (mips_dec32(hex_val, &v32)) return -1;
			regs[MIPS_EF_STATUS] = (unsigned long)v32; break;
		case 33:
			if (mips_dec32(hex_val, &v32)) return -1;
			regs[MIPS_EF_LO] = (unsigned long)v32; break;
		case 34:
			if (mips_dec32(hex_val, &v32)) return -1;
			regs[MIPS_EF_HI] = (unsigned long)v32; break;
		case 35:
			if (mips_dec32(hex_val, &v32)) return -1;
			regs[MIPS_EF_BADVADDR] = (unsigned long)v32; break;
		case 36:
			if (mips_dec32(hex_val, &v32)) return -1;
			regs[MIPS_EF_CAUSE] = (unsigned long)v32; break;
		case 37:
			if (mips_dec32(hex_val, &v32)) return -1;
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

/* MIPS32 g-packet: 576 hex (38 GPRs/ctl × 8 + 32 FP × 8 + 2 ctl × 8) */
static int regs_write(const char *hex, size_t hex_len)
{
	unsigned long regs[MIPS_ELF_NGREG];
	struct iovec iov = { regs, sizeof(regs) };
	uint32_t v32;
	size_t pos = 0;
	int i;

	if (hex_len < 576)
		return -1;
	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0)
		return -1;

	for (i = 0; i < 32; i++) {
		if (mips_dec32(hex + pos, &v32)) return -1;
		regs[MIPS_EF_R0 + i] = (unsigned long)v32;
		pos += 8;
	}
	if (mips_dec32(hex+pos,&v32)) return -1; regs[MIPS_EF_STATUS]   =(unsigned long)v32; pos+=8;
	if (mips_dec32(hex+pos,&v32)) return -1; regs[MIPS_EF_LO]       =(unsigned long)v32; pos+=8;
	if (mips_dec32(hex+pos,&v32)) return -1; regs[MIPS_EF_HI]       =(unsigned long)v32; pos+=8;
	if (mips_dec32(hex+pos,&v32)) return -1; regs[MIPS_EF_BADVADDR] =(unsigned long)v32; pos+=8;
	if (mips_dec32(hex+pos,&v32)) return -1; regs[MIPS_EF_CAUSE]    =(unsigned long)v32; pos+=8;
	if (mips_dec32(hex+pos,&v32)) return -1; regs[MIPS_EF_EPC]      =(unsigned long)v32;
	/* FP registers not written to kernel */

	iov.iov_len = sizeof(regs);
	return ptrace(PTRACE_SETREGSET, g_pid,
		      (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0 ? -1 : 0;
}

#endif /* __mips64 */

#undef mips_enc32
#undef mips_enc64
#undef mips_dec32
#undef mips_dec64

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
		memset(fp_regs, 0, sizeof(fp_regs)); /* FPU unavailable — zero-fill */

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
			return ela_gdb_encode_be64(0, out, out_sz);
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
			return ela_gdb_encode_be32(0, out, out_sz);
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

	/* f0-f31: 64-bit BE — silently accept if FPU unavailable */
	if (regnum >= 32 && regnum <= 63) {
		iov.iov_base = fp_regs; iov.iov_len = sizeof(fp_regs);
		if (ptrace(PTRACE_GETREGSET, g_pid,
			   (void *)(uintptr_t)NT_PRFPREG, &iov) != 0)
			return 0;
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
	case 70: { /* fpscr: update lower 32 bits of fp_regs[32] — silently accept if FPU unavailable */
		iov.iov_base = fp_regs; iov.iov_len = sizeof(fp_regs);
		if (ptrace(PTRACE_GETREGSET, g_pid,
			   (void *)(uintptr_t)NT_PRFPREG, &iov) != 0)
			return 0;
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

/*
 * PPC64 g-packet: 1112 hex
 *   r0-r31:  32×16=512   f0-f31: 32×16=512
 *   pc,msr:  2×16=32     cr: 8   lr,ctr: 2×16=32   xer: 8   fpscr: 8
 */
static int regs_write(const char *hex, size_t hex_len)
{
	unsigned long gregs[PPC_ELF_NGREG];
	double fp_regs[PPC_ELF_NFPREG];
	struct iovec iov;
	uint64_t v64, fp_bits;
	uint32_t v32;
	size_t pos = 0;
	int i;

	if (hex_len < 1112)
		return -1;

	iov.iov_base = gregs; iov.iov_len = sizeof(gregs);
	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0)
		return -1;
	iov.iov_base = fp_regs; iov.iov_len = sizeof(fp_regs);
	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRFPREG, &iov) != 0)
		memset(fp_regs, 0, sizeof(fp_regs));

	for (i = 0; i < 32; i++) {
		if (ela_gdb_decode_be64(hex+pos, &v64)) return -1;
		gregs[PPC_PT_GPR0+i] = (unsigned long)v64; pos += 16;
	}
	for (i = 0; i < 32; i++) {
		if (ela_gdb_decode_be64(hex+pos, &fp_bits)) return -1;
		memcpy(&fp_regs[i], &fp_bits, 8); pos += 16;
	}
	if (ela_gdb_decode_be64(hex+pos,&v64)) return -1; gregs[PPC_PT_NIP]=(unsigned long)v64; pos+=16;
	if (ela_gdb_decode_be64(hex+pos,&v64)) return -1; gregs[PPC_PT_MSR]=(unsigned long)v64; pos+=16;
	if (ela_gdb_decode_be32(hex+pos,&v32)) return -1; gregs[PPC_PT_CCR]=(unsigned long)v32; pos+= 8;
	if (ela_gdb_decode_be64(hex+pos,&v64)) return -1; gregs[PPC_PT_LNK]=(unsigned long)v64; pos+=16;
	if (ela_gdb_decode_be64(hex+pos,&v64)) return -1; gregs[PPC_PT_CTR]=(unsigned long)v64; pos+=16;
	if (ela_gdb_decode_be32(hex+pos,&v32)) return -1; gregs[PPC_PT_XER]=(unsigned long)v32; pos+= 8;
	if (ela_gdb_decode_be32(hex+pos,&v32)) return -1; /* fpscr */ {
		uint64_t slot; memcpy(&slot,&fp_regs[32],8);
		slot = (slot & 0xffffffff00000000ULL) | v32;
		memcpy(&fp_regs[32], &slot, 8);
	}

	iov.iov_base = gregs; iov.iov_len = sizeof(gregs);
	if (ptrace(PTRACE_SETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0)
		return -1;
	iov.iov_base = fp_regs; iov.iov_len = sizeof(fp_regs);
	ptrace(PTRACE_SETREGSET, g_pid, (void *)(uintptr_t)NT_PRFPREG, &iov);
	return 0;
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
		memset(fp_regs, 0, sizeof(fp_regs)); /* FPU unavailable — zero-fill */

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
			return ela_gdb_encode_be64(0, out, out_sz);
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
			return ela_gdb_encode_be32(0, out, out_sz);
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

	/* f0-f31: 64-bit BE — silently accept if FPU unavailable */
	if (regnum >= 32 && regnum <= 63) {
		iov.iov_base = fp_regs; iov.iov_len = sizeof(fp_regs);
		if (ptrace(PTRACE_GETREGSET, g_pid,
			   (void *)(uintptr_t)NT_PRFPREG, &iov) != 0)
			return 0;
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
	case 70: { /* fpscr: update lower 32 bits of fp_regs[32] — silently accept if FPU unavailable */
		iov.iov_base = fp_regs; iov.iov_len = sizeof(fp_regs);
		if (ptrace(PTRACE_GETREGSET, g_pid,
			   (void *)(uintptr_t)NT_PRFPREG, &iov) != 0)
			return 0;
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

/*
 * PPC32 g-packet: 824 hex
 *   r0-r31:  32×8=256   f0-f31: 32×16=512
 *   pc,msr,cr,lr,ctr,xer,fpscr: 7×8=56
 */
static int regs_write(const char *hex, size_t hex_len)
{
	unsigned long gregs[PPC_ELF_NGREG];
	double fp_regs[PPC_ELF_NFPREG];
	struct iovec iov;
	uint64_t fp_bits;
	uint32_t v32;
	size_t pos = 0;
	int i;

	if (hex_len < 824)
		return -1;

	iov.iov_base = gregs; iov.iov_len = sizeof(gregs);
	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0)
		return -1;
	iov.iov_base = fp_regs; iov.iov_len = sizeof(fp_regs);
	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRFPREG, &iov) != 0)
		memset(fp_regs, 0, sizeof(fp_regs));

	for (i = 0; i < 32; i++) {
		if (ela_gdb_decode_be32(hex+pos, &v32)) return -1;
		gregs[PPC_PT_GPR0+i] = (unsigned long)v32; pos += 8;
	}
	for (i = 0; i < 32; i++) {
		if (ela_gdb_decode_be64(hex+pos, &fp_bits)) return -1;
		memcpy(&fp_regs[i], &fp_bits, 8); pos += 16;
	}
	if (ela_gdb_decode_be32(hex+pos,&v32)) return -1; gregs[PPC_PT_NIP]=(unsigned long)v32; pos+=8;
	if (ela_gdb_decode_be32(hex+pos,&v32)) return -1; gregs[PPC_PT_MSR]=(unsigned long)v32; pos+=8;
	if (ela_gdb_decode_be32(hex+pos,&v32)) return -1; gregs[PPC_PT_CCR]=(unsigned long)v32; pos+=8;
	if (ela_gdb_decode_be32(hex+pos,&v32)) return -1; gregs[PPC_PT_LNK]=(unsigned long)v32; pos+=8;
	if (ela_gdb_decode_be32(hex+pos,&v32)) return -1; gregs[PPC_PT_CTR]=(unsigned long)v32; pos+=8;
	if (ela_gdb_decode_be32(hex+pos,&v32)) return -1; gregs[PPC_PT_XER]=(unsigned long)v32; pos+=8;
	if (ela_gdb_decode_be32(hex+pos,&v32)) return -1; /* fpscr */ {
		uint64_t slot; memcpy(&slot,&fp_regs[32],8);
		slot = (slot & 0xffffffff00000000ULL) | v32;
		memcpy(&fp_regs[32], &slot, 8);
	}

	iov.iov_base = gregs; iov.iov_len = sizeof(gregs);
	if (ptrace(PTRACE_SETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0)
		return -1;
	iov.iov_base = fp_regs; iov.iov_len = sizeof(fp_regs);
	ptrace(PTRACE_SETREGSET, g_pid, (void *)(uintptr_t)NT_PRFPREG, &iov);
	return 0;
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

/* RV64 g-packet: 528 hex (33 × 16) */
static int regs_write(const char *hex, size_t hex_len)
{
	unsigned long regs[RISCV_PT_NREGS];
	struct iovec iov = { regs, sizeof(regs) };
	uint64_t v64;
	size_t pos = 0;
	int i;

	if (hex_len < 528) /* 33×16 */
		return -1;
	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0)
		return -1;

	pos += 16; /* skip x0 (hard-wired zero) */
	for (i = RISCV_PT_X1; i < RISCV_PT_NREGS; i++) {
		if (ela_gdb_decode_le64(hex + pos, &v64)) return -1;
		regs[i] = (unsigned long)v64;
		pos += 16;
	}
	if (ela_gdb_decode_le64(hex + pos, &v64)) return -1;
	regs[RISCV_PT_PC] = (unsigned long)v64;

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

/* RV32 g-packet: 264 hex (33 × 8) */
static int regs_write(const char *hex, size_t hex_len)
{
	unsigned long regs[RISCV_PT_NREGS];
	struct iovec iov = { regs, sizeof(regs) };
	uint32_t v32;
	size_t pos = 0;
	int i;

	if (hex_len < 264) /* 33×8 */
		return -1;
	if (ptrace(PTRACE_GETREGSET, g_pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0)
		return -1;

	pos += 8; /* skip x0 */
	for (i = RISCV_PT_X1; i < RISCV_PT_NREGS; i++) {
		if (ela_gdb_decode_le32(hex + pos, &v32)) return -1;
		regs[i] = (unsigned long)v32;
		pos += 8;
	}
	if (ela_gdb_decode_le32(hex + pos, &v32)) return -1;
	regs[RISCV_PT_PC] = (unsigned long)v32;

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

static int regs_write(const char *hex, size_t hex_len)
{
	(void)hex; (void)hex_len;
	return -1;
}

#endif /* arch */

/* -----------------------------------------------------------------------
 * Syscall number reader  (used by QCatchSyscalls stop detection)
 * ---------------------------------------------------------------------- */

/*
 * Read the current syscall number from the stopped inferior.
 * At both entry and exit the kernel leaves the syscall number in the
 * canonical register for each ABI:
 *   x86_64  — orig_rax
 *   aarch64 — x8  (regs[8])
 *   arm32   — r7  (uregs[7], EABI)
 *   mips    — v0  (r2, gregset index MIPS_EF_R0+2)
 *   ppc     — r0  (gregset index 0)
 *   riscv   — a7  (x17, regs[17] with regs[0]==pc)
 */
static uint64_t read_sysno(void)
{
#if defined(__x86_64__)
	struct user_regs_struct r;
	if (ptrace(PTRACE_GETREGS, g_pid, NULL, &r) == 0)
		return (uint64_t)r.orig_rax;
#elif defined(__aarch64__)
	{
		uint64_t regs[34]; /* pc + 31 gprs + sp + pstate */
		struct iovec iov = { regs, sizeof(regs) };
		if (ptrace(PTRACE_GETREGSET, g_pid,
			   (void *)NT_PRSTATUS, &iov) == 0)
			return regs[8]; /* x8 */
	}
#elif defined(__arm__)
	{
		struct user_regs r;
		struct iovec iov = { &r, sizeof(r) };
		if (ptrace(PTRACE_GETREGSET, g_pid,
			   (void *)(uintptr_t)NT_PRSTATUS, &iov) == 0)
			return (uint64_t)r.uregs[7]; /* r7 (EABI) */
	}
#elif defined(__mips__)
	{
		unsigned long regs[MIPS_ELF_NGREG];
		struct iovec iov = { regs, sizeof(regs) };
		if (ptrace(PTRACE_GETREGSET, g_pid,
			   (void *)NT_PRSTATUS, &iov) == 0)
			return (uint64_t)regs[MIPS_EF_R0 + 2]; /* v0 */
	}
#elif defined(__powerpc__)
	{
		unsigned long regs[PPC_ELF_NGREG];
		struct iovec iov = { regs, sizeof(regs) };
		if (ptrace(PTRACE_GETREGSET, g_pid,
			   (void *)NT_PRSTATUS, &iov) == 0)
			return (uint64_t)regs[0]; /* r0 */
	}
#elif defined(__riscv)
	{
		unsigned long regs[RISCV_PT_NREGS];
		struct iovec iov = { regs, sizeof(regs) };
		if (ptrace(PTRACE_GETREGSET, g_pid,
			   (void *)NT_PRSTATUS, &iov) == 0)
			return (uint64_t)regs[17]; /* a7 = x17 */
	}
#endif
	return (uint64_t)-1;
}

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
 * XML document builders using libxml2
 * ---------------------------------------------------------------------- */

/*
 * Helper: copy the xmlDocDumpMemory output into a fixed caller buffer.
 * Frees buf and returns the byte count, or -1 on overflow.
 */
static int xml_dump_to_buf(xmlChar *buf, int bufsize,
			   char *out, size_t out_sz)
{
	int ret = -1;

	if (buf && bufsize > 0 && (size_t)bufsize + 1 <= out_sz) {
		memcpy(out, buf, (size_t)bufsize);
		out[bufsize] = '\0';
		ret = bufsize;
	}
	if (buf)
		xmlFree(buf);
	return ret;
}

/*
 * Build target.xml: arch description + register layout.
 * Result is cached in g_target_xml / g_target_xml_len.
 */
static int build_target_xml(char *out, size_t out_sz)
{
	xmlDocPtr doc;
	xmlNodePtr root;
	xmlChar *buf = NULL;
	int bufsize = 0;

	doc = xmlNewDoc(BAD_CAST "1.0");
	if (!doc)
		return -1;

	xmlCreateIntSubset(doc, BAD_CAST "target", NULL,
			   BAD_CAST "gdb-target.dtd");

	root = xmlNewNode(NULL, BAD_CAST "target");
	xmlDocSetRootElement(doc, root);

#if defined(__x86_64__)
	{
		static const struct {
			const char *name, *bits, *type;
		} regs[] = {
			{"rax","64","int64"}, {"rbx","64","int64"},
			{"rcx","64","int64"}, {"rdx","64","int64"},
			{"rsi","64","int64"}, {"rdi","64","int64"},
			{"rbp","64","data_ptr"}, {"rsp","64","data_ptr"},
			{"r8","64","int64"}, {"r9","64","int64"},
			{"r10","64","int64"}, {"r11","64","int64"},
			{"r12","64","int64"}, {"r13","64","int64"},
			{"r14","64","int64"}, {"r15","64","int64"},
			{"rip","64","code_ptr"}, {"eflags","32","int32"},
			{"cs","32","int32"}, {"ss","32","int32"},
			{"ds","32","int32"}, {"es","32","int32"},
			{"fs","32","int32"}, {"gs","32","int32"},
			{NULL, NULL, NULL}
		};
		int i;
		xmlNodePtr feat;

		xmlNewChild(root, NULL, BAD_CAST "architecture",
			    BAD_CAST "i386:x86-64");
		feat = xmlNewChild(root, NULL, BAD_CAST "feature", NULL);
		xmlNewProp(feat, BAD_CAST "name",
			   BAD_CAST "org.gnu.gdb.i386.core");
		for (i = 0; regs[i].name; i++) {
			xmlNodePtr reg = xmlNewChild(feat, NULL,
						     BAD_CAST "reg", NULL);
			xmlNewProp(reg, BAD_CAST "name",
				   BAD_CAST regs[i].name);
			xmlNewProp(reg, BAD_CAST "bitsize",
				   BAD_CAST regs[i].bits);
			xmlNewProp(reg, BAD_CAST "type",
				   BAD_CAST regs[i].type);
		}
	}
#elif defined(__aarch64__)
	xmlNewChild(root, NULL, BAD_CAST "architecture", BAD_CAST "aarch64");
#elif defined(__arm__)
	xmlNewChild(root, NULL, BAD_CAST "architecture", BAD_CAST "arm");
#elif defined(__mips__) && defined(__mips64)
	xmlNewChild(root, NULL, BAD_CAST "architecture",
		    BAD_CAST "mips:isa64");
#elif defined(__mips__) && defined(__MIPSEL__)
	xmlNewChild(root, NULL, BAD_CAST "architecture", BAD_CAST "mipsel");
#elif defined(__mips__)
	xmlNewChild(root, NULL, BAD_CAST "architecture", BAD_CAST "mips");
#elif defined(__powerpc64__)
	xmlNewChild(root, NULL, BAD_CAST "architecture",
		    BAD_CAST "powerpc:common64");
#elif defined(__powerpc__)
	xmlNewChild(root, NULL, BAD_CAST "architecture",
		    BAD_CAST "powerpc:common");
#elif defined(__riscv) && (__riscv_xlen == 64)
	xmlNewChild(root, NULL, BAD_CAST "architecture",
		    BAD_CAST "riscv:rv64");
#elif defined(__riscv) && (__riscv_xlen == 32)
	xmlNewChild(root, NULL, BAD_CAST "architecture",
		    BAD_CAST "riscv:rv32");
#endif

	xmlDocDumpMemory(doc, &buf, &bufsize);
	xmlFreeDoc(doc);
	return xml_dump_to_buf(buf, bufsize, out, out_sz);
}

/*
 * Build <threads> XML by walking /proc/<pid>/task/.
 * libxml2 handles all attribute escaping automatically.
 */
static int build_threads_xml(pid_t pid, char *out, size_t out_sz)
{
	xmlDocPtr doc;
	xmlNodePtr root;
	xmlChar *buf = NULL;
	int bufsize = 0;
	char task_path[32];
	DIR *dir;
	struct dirent *ent;

	doc = xmlNewDoc(BAD_CAST "1.0");
	if (!doc)
		return -1;

	root = xmlNewNode(NULL, BAD_CAST "threads");
	xmlDocSetRootElement(doc, root);

	snprintf(task_path, sizeof(task_path), "/proc/%d/task", (int)pid);
	dir = opendir(task_path);
	if (dir) {
		while ((ent = readdir(dir)) != NULL) {
			pid_t tid;
			char *endp;
			char comm_path[64];
			char comm[16];
			int comm_fd;
			ssize_t comm_len;
			char id_buf[32];
			xmlNodePtr thr;

			if (ent->d_name[0] == '.')
				continue;
			tid = (pid_t)strtol(ent->d_name, &endp, 10);
			if (*endp != '\0' || tid <= 0)
				continue;

			snprintf(comm_path, sizeof(comm_path),
				 "/proc/%d/task/%d/comm",
				 (int)pid, (int)tid);
			comm_fd = open(comm_path, O_RDONLY);
			comm_len = 0;
			if (comm_fd >= 0) {
				comm_len = read(comm_fd, comm,
						sizeof(comm) - 1);
				close(comm_fd);
				if (comm_len > 0 &&
				    comm[comm_len - 1] == '\n')
					comm_len--;
				if (comm_len < 0)
					comm_len = 0;
			}
			comm[comm_len > 0 ? comm_len : 0] = '\0';

			thr = xmlNewChild(root, NULL, BAD_CAST "thread", NULL);
			snprintf(id_buf, sizeof(id_buf), "p%x.t%x",
				 (unsigned)pid, (unsigned)tid);
			xmlNewProp(thr, BAD_CAST "id",   BAD_CAST id_buf);
			xmlNewProp(thr, BAD_CAST "core", BAD_CAST "0");
			xmlNewProp(thr, BAD_CAST "name", BAD_CAST comm);
		}
		closedir(dir);
	}

	xmlDocDumpMemory(doc, &buf, &bufsize);
	xmlFreeDoc(doc);
	return xml_dump_to_buf(buf, bufsize, out, out_sz);
}

/*
 * Build <memory-map> XML from /proc/<pid>/maps.
 * Includes a DOCTYPE referencing the GDB memory-map DTD.
 */
static int build_memmap_xml(pid_t pid, char *out, size_t out_sz)
{
	xmlDocPtr doc;
	xmlNodePtr root;
	xmlChar *buf = NULL;
	int bufsize = 0;
	char maps_path[32];
	FILE *f;
	char line[512];

	doc = xmlNewDoc(BAD_CAST "1.0");
	if (!doc)
		return -1;

	xmlCreateIntSubset(doc, BAD_CAST "memory-map",
			   BAD_CAST "+//IDN gnu.org//DTD GDB Memory Map V1.0//EN",
			   BAD_CAST "http://sourceware.org/gdb/gdb-memory-map.dtd");

	root = xmlNewNode(NULL, BAD_CAST "memory-map");
	xmlDocSetRootElement(doc, root);

	snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int)pid);
	f = fopen(maps_path, "r");
	if (f) {
		while (fgets(line, sizeof(line), f)) {
			unsigned long long start, end, length;
			char perms[8];
			const char *type;
			char start_buf[20], len_buf[20];
			xmlNodePtr mem;

			if (sscanf(line, "%llx-%llx %7s",
				   &start, &end, perms) != 3)
				continue;
			length = end - start;
			if (length == 0)
				continue;

			type = (perms[1] == 'w') ? "ram" : "rom";
			mem = xmlNewChild(root, NULL, BAD_CAST "memory", NULL);
			xmlNewProp(mem, BAD_CAST "type", BAD_CAST type);
			snprintf(start_buf, sizeof(start_buf),
				 "0x%llx", start);
			snprintf(len_buf, sizeof(len_buf), "0x%llx", length);
			xmlNewProp(mem, BAD_CAST "start",  BAD_CAST start_buf);
			xmlNewProp(mem, BAD_CAST "length", BAD_CAST len_buf);
		}
		fclose(f);
	}

	xmlDocDumpMemory(doc, &buf, &bufsize);
	xmlFreeDoc(doc);
	return xml_dump_to_buf(buf, bufsize, out, out_sz);
}

/* -----------------------------------------------------------------------
 * SVR4 shared-library XML builder
 * ---------------------------------------------------------------------- */

/*
 * Build the <library-list-svr4> XML document by walking /proc/<pid>/maps.
 * Duplicate .so entries (multiple segments of the same file) are suppressed
 * by walking root->children and checking the "name" attribute via xmlGetProp,
 * avoiding any string-search in the serialised output.
 * The XML declaration is stripped from the output because GDB's SVR4 packet
 * handler expects bare XML content without the <?xml?> prolog.
 */
static int build_libraries_svr4_xml(pid_t pid, char *out, size_t out_sz)
{
	xmlDocPtr doc;
	xmlNodePtr root;
	xmlChar *buf = NULL;
	int bufsize = 0;
	char maps_path[32];
	FILE *f;
	char line[512];
	char path[256];
	char addr_buf[20];

	doc = xmlNewDoc(BAD_CAST "1.0");
	if (!doc)
		return -1;

	root = xmlNewNode(NULL, BAD_CAST "library-list-svr4");
	xmlDocSetRootElement(doc, root);
	xmlNewProp(root, BAD_CAST "version", BAD_CAST "1.0");

	snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int)pid);
	f = fopen(maps_path, "r");
	if (f) {
		while (fgets(line, sizeof(line), f)) {
			unsigned long long start_addr;
			char *p, *nl;
			int fields;
			xmlNodePtr child;
			int dup;

			if (sscanf(line, "%llx", &start_addr) != 1)
				continue;

			p = line;
			fields = 0;
			while (*p && fields < 5) {
				while (*p && *p != ' ' && *p != '\t') p++;
				while (*p == ' ' || *p == '\t') p++;
				fields++;
			}
			if (*p == '\0' || *p == '\n' || *p == '\r')
				continue;

			strncpy(path, p, sizeof(path) - 1);
			path[sizeof(path) - 1] = '\0';
			nl = strchr(path, '\n');
			if (nl) *nl = '\0';
			nl = strchr(path, '\r');
			if (nl) *nl = '\0';

			if (path[0] == '[')
				continue;
			if (strstr(path, ".so") == NULL)
				continue;

			/* Deduplicate via xmlGetProp instead of strstr */
			dup = 0;
			for (child = root->children; child;
			     child = child->next) {
				if (child->type == XML_ELEMENT_NODE) {
					xmlChar *existing =
						xmlGetProp(child,
							   BAD_CAST "name");
					if (existing) {
						if (xmlStrcmp(existing,
							      BAD_CAST path)
						    == 0)
							dup = 1;
						xmlFree(existing);
					}
				}
				if (dup)
					break;
			}
			if (dup)
				continue;

			child = xmlNewChild(root, NULL,
					    BAD_CAST "library", NULL);
			xmlNewProp(child, BAD_CAST "name", BAD_CAST path);
			xmlNewProp(child, BAD_CAST "lm",   BAD_CAST "0x0");
			snprintf(addr_buf, sizeof(addr_buf),
				 "0x%llx", start_addr);
			xmlNewProp(child, BAD_CAST "l_addr",
				   BAD_CAST addr_buf);
			xmlNewProp(child, BAD_CAST "l_ld",  BAD_CAST "0x0");
		}
		fclose(f);
	}

	xmlDocDumpMemory(doc, &buf, &bufsize);
	xmlFreeDoc(doc);

	if (!buf || bufsize <= 0)
		return -1;

	/* Strip the <?xml ...?> prolog — GDB expects bare SVR4 content. */
	{
		const xmlChar *start = buf;
		int copy_len;

		if (bufsize > 5 &&
		    xmlStrncmp(buf, BAD_CAST "<?xml", 5) == 0) {
			const xmlChar *p =
				(const xmlChar *)memchr(buf, '>',
							(size_t)bufsize);
			if (p) {
				start = p + 1;
				if (*start == '\n')
					start++;
			}
		}
		copy_len = bufsize - (int)(start - buf);
		if (copy_len > 0 && (size_t)copy_len + 1 <= out_sz) {
			memcpy(out, start, (size_t)copy_len);
			out[copy_len] = '\0';
			xmlFree(buf);
			return copy_len;
		}
	}
	xmlFree(buf);
	return -1;
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
 * Memory search helper  (qSearch:memory)
 * ---------------------------------------------------------------------- */

#define MEM_SEARCH_CHUNK 2048

/*
 * Scan [start, start+length) for the first occurrence of `pattern`.
 * Memory is read word-by-word via PTRACE_PEEKDATA; unreadable words are
 * treated as zero-filled so the scan continues past them.
 *
 * Chunks overlap by (patlen-1) bytes to catch patterns that span a
 * chunk boundary.
 *
 * Returns  1 and sets *found_addr on success,
 *          0 if not found,
 *         -1 on bad arguments.
 */
static int mem_search(uint64_t start, uint64_t length,
		      const uint8_t *pattern, size_t patlen,
		      uint64_t *found_addr)
{
	uint8_t buf[MEM_SEARCH_CHUNK];
	uint64_t pos = start;
	uint64_t end;
	size_t i;

	if (patlen == 0 || patlen > MEM_SEARCH_CHUNK || length == 0)
		return -1;

	end = start + length;

	while (pos < end) {
		size_t to_read = MEM_SEARCH_CHUNK;
		size_t done = 0;

		if (to_read > (size_t)(end - pos))
			to_read = (size_t)(end - pos);

		/* Read word-by-word via ptrace; zero-fill unreadable words */
		while (done < to_read) {
			uint64_t adr = (pos + done) &
				       ~(uint64_t)(sizeof(long) - 1);
			size_t   off = (size_t)((pos + done) - adr);
			size_t   chk = sizeof(long) - off;
			long     word;

			if (chk > to_read - done)
				chk = to_read - done;

			errno = 0;
			word = ptrace(PTRACE_PEEKDATA, g_pid,
				      (void *)(uintptr_t)adr, NULL);
			if (errno != 0)
				memset(buf + done, 0, chk);
			else
				memcpy(buf + done, (uint8_t *)&word + off, chk);
			done += chk;
		}

		/* Search this chunk */
		if (done >= patlen) {
			for (i = 0; i <= done - patlen; i++) {
				if (memcmp(buf + i, pattern, patlen) == 0) {
					*found_addr = pos + i;
					return 1;
				}
			}
		}

		/*
		 * Advance by (done - patlen + 1) so the last patlen-1 bytes
		 * of this chunk become the first bytes of the next, catching
		 * patterns that span a chunk boundary.
		 */
		pos += (done >= patlen) ? done - patlen + 1 : done;
	}

	return 0; /* not found */
}

/* -----------------------------------------------------------------------
 * PIE load-offset helper  (qOffsets)
 * ---------------------------------------------------------------------- */

/*
 * Compute the ASLR slide for the main executable and reply with
 * "Text=<hex>;Data=<hex>;Bss=<hex>".
 *
 * For ET_EXEC (non-PIE) the offset is always 0.
 * For ET_DYN (PIE) we find the expected load base from the lowest
 * PT_LOAD p_vaddr in the ELF and the actual base from the lowest
 * mapping of /proc/<pid>/exe in /proc/<pid>/maps.
 */
static void handle_qoffsets(int fd)
{
	char link_path[32];
	char exe_path[4096];
	char maps_path[32];
	ssize_t exe_len;
	int elf_fd;
	unsigned char e_ident[EI_NIDENT];
	uint64_t expected_base = 0;
	uint64_t actual_base   = 0;
	int      is_pie        = 0;
	int      found_base    = 0;
	FILE    *f;
	char     line[512];
	char     resp[64];

	snprintf(link_path, sizeof(link_path), "/proc/%d/exe", (int)g_pid);
	exe_len = readlink(link_path, exe_path, sizeof(exe_path) - 1);
	if (exe_len < 0) goto out_zero;
	exe_path[exe_len] = '\0';

	elf_fd = open(exe_path, O_RDONLY);
	if (elf_fd < 0) goto out_zero;

	if (read(elf_fd, e_ident, EI_NIDENT) != EI_NIDENT ||
	    e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
	    e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3) {
		close(elf_fd);
		goto out_zero;
	}

	if (e_ident[EI_CLASS] == ELFCLASS64) {
		Elf64_Ehdr ehdr;
		lseek(elf_fd, 0, SEEK_SET);
		if (read(elf_fd, &ehdr, sizeof(ehdr)) == (ssize_t)sizeof(ehdr) &&
		    ehdr.e_type == ET_DYN) {
			int i;
			int first = 1;
			is_pie = 1;
			for (i = 0; i < (int)ehdr.e_phnum; i++) {
				Elf64_Phdr phdr;
				off_t off = (off_t)ehdr.e_phoff +
					    i * (off_t)ehdr.e_phentsize;
				lseek(elf_fd, off, SEEK_SET);
				if (read(elf_fd, &phdr, sizeof(phdr)) !=
				    (ssize_t)sizeof(phdr))
					break;
				if (phdr.p_type == PT_LOAD &&
				    (first || phdr.p_vaddr < expected_base)) {
					expected_base = phdr.p_vaddr;
					first = 0;
				}
			}
		}
	} else if (e_ident[EI_CLASS] == ELFCLASS32) {
		Elf32_Ehdr ehdr;
		lseek(elf_fd, 0, SEEK_SET);
		if (read(elf_fd, &ehdr, sizeof(ehdr)) == (ssize_t)sizeof(ehdr) &&
		    ehdr.e_type == ET_DYN) {
			int i;
			int first = 1;
			is_pie = 1;
			for (i = 0; i < (int)ehdr.e_phnum; i++) {
				Elf32_Phdr phdr;
				off_t off = (off_t)ehdr.e_phoff +
					    i * (off_t)ehdr.e_phentsize;
				lseek(elf_fd, off, SEEK_SET);
				if (read(elf_fd, &phdr, sizeof(phdr)) !=
				    (ssize_t)sizeof(phdr))
					break;
				if (phdr.p_type == PT_LOAD &&
				    (first ||
				     (uint64_t)phdr.p_vaddr < expected_base)) {
					expected_base = (uint64_t)phdr.p_vaddr;
					first = 0;
				}
			}
		}
	}
	close(elf_fd);

	if (!is_pie) goto out_zero;

	/* Find actual load base: lowest mapping of the executable in maps */
	snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int)g_pid);
	f = fopen(maps_path, "r");
	if (!f) goto out_zero;

	while (fgets(line, sizeof(line), f)) {
		unsigned long long map_start, map_end;
		char perms[8], path_buf[512];
		int nm;

		path_buf[0] = '\0';
		nm = sscanf(line, "%llx-%llx %7s %*s %*s %*s %511s",
			    &map_start, &map_end, perms, path_buf);
		if (nm < 3)
			continue;
		if (strcmp(path_buf, exe_path) != 0)
			continue;
		if (!found_base || (uint64_t)map_start < actual_base) {
			actual_base = (uint64_t)map_start;
			found_base  = 1;
		}
	}
	fclose(f);

	if (!found_base) goto out_zero;

	{
		uint64_t slide = actual_base - expected_base;
		snprintf(resp, sizeof(resp),
			 "Text=%llx;Data=%llx;Bss=%llx",
			 (unsigned long long)slide,
			 (unsigned long long)slide,
			 (unsigned long long)slide);
		rsp_send_str(fd, resp);
		return;
	}

out_zero:
	rsp_send_str(fd, "Text=0;Data=0;Bss=0");
}

/* -----------------------------------------------------------------------
 * Hardware watchpoint helpers (x86_64 debug registers DR0-DR3 / DR7)
 * ---------------------------------------------------------------------- */

#if defined(__x86_64__)
/*
 * DR7 layout – per slot i (i = 0..3):
 *   Local enable:  bit  2*i
 *   Condition:     bits 16+4*i : 17+4*i  (00=exec,01=write,11=r/w)
 *   Length:        bits 18+4*i : 19+4*i  (00=1B,01=2B,10=8B,11=4B)
 *
 * Access via PTRACE_PEEKUSER / PTRACE_POKEUSER at offsetof(struct user,
 * u_debugreg[n]).
 */
#define X86_DR_OFF(n)         ((long)offsetof(struct user, u_debugreg[(n)]))
#define X86_DR7_L(i)          (1UL << (2 * (i)))
#define X86_DR7_COND_SHIFT(i) (16 + 4 * (i))
#define X86_DR7_LEN_SHIFT(i)  (18 + 4 * (i))

/* GDB watchpoint type (Z1-Z4) → DR7 condition field */
static unsigned long x86_wp_cond(int type)
{
	switch (type) {
	case 1:  return 0UL; /* execute */
	case 2:  return 1UL; /* write */
	case 3:  /* read-only hw not available; fall through to r/w */
	case 4:  return 3UL; /* read/write */
	default: return 1UL;
	}
}

/* watchpoint byte length → DR7 length field */
static unsigned long x86_wp_len(int kind)
{
	switch (kind) {
	case 1:  return 0UL;
	case 2:  return 1UL;
	case 8:  return 2UL;
	case 4:
	default: return 3UL;
	}
}

static int wp_insert_x86(uint64_t addr, int type, int kind)
{
	int slot;
	unsigned long dr7;

	errno = 0;
	dr7 = (unsigned long)ptrace(PTRACE_PEEKUSER, g_pid,
				    X86_DR_OFF(7), NULL);
	if (errno)
		return -1;

	/* Find the first free slot (local-enable bit == 0) */
	for (slot = 0; slot < 4; slot++)
		if (!(dr7 & X86_DR7_L(slot)))
			break;
	if (slot == 4)
		return -1; /* all four slots occupied */

	if (ptrace(PTRACE_POKEUSER, g_pid, X86_DR_OFF(slot),
		   (void *)(uintptr_t)addr) != 0)
		return -1;

	/* Clear old fields for this slot then apply new settings */
	dr7 &= ~(X86_DR7_L(slot)
		 | (3UL << X86_DR7_COND_SHIFT(slot))
		 | (3UL << X86_DR7_LEN_SHIFT(slot)));
	dr7 |=  X86_DR7_L(slot)
		| (x86_wp_cond(type) << X86_DR7_COND_SHIFT(slot))
		| (x86_wp_len(kind)  << X86_DR7_LEN_SHIFT(slot));
	/* Bits 8-9: LE/GE exact-breakpoint enable (legacy, harmless) */
	dr7 |= 0x300UL;

	return ptrace(PTRACE_POKEUSER, g_pid, X86_DR_OFF(7),
		      (void *)dr7) == 0 ? 0 : -1;
}

static int wp_remove_x86(uint64_t addr)
{
	int slot;
	unsigned long dr7, slot_addr;

	errno = 0;
	dr7 = (unsigned long)ptrace(PTRACE_PEEKUSER, g_pid,
				    X86_DR_OFF(7), NULL);
	if (errno)
		return -1;

	for (slot = 0; slot < 4; slot++) {
		if (!(dr7 & X86_DR7_L(slot)))
			continue;
		errno = 0;
		slot_addr = (unsigned long)ptrace(PTRACE_PEEKUSER, g_pid,
						  X86_DR_OFF(slot), NULL);
		if (errno || slot_addr != (unsigned long)addr)
			continue;

		dr7 &= ~(X86_DR7_L(slot)
			 | (3UL << X86_DR7_COND_SHIFT(slot))
			 | (3UL << X86_DR7_LEN_SHIFT(slot)));
		ptrace(PTRACE_POKEUSER, g_pid, X86_DR_OFF(slot), (void *)0UL);
		ptrace(PTRACE_POKEUSER, g_pid, X86_DR_OFF(7), (void *)dr7);
		return 0;
	}
	return -1; /* address not found in any active slot */
}
#endif /* __x86_64__ */

/* -----------------------------------------------------------------------
 * vFile helpers
 * ---------------------------------------------------------------------- */

/* Big-endian encode helpers for the GDB portable stat structure. */
static void vfile_put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >>  8); p[3] = (uint8_t)(v);
}

static void vfile_put_be64(uint8_t *p, uint64_t v)
{
	vfile_put_be32(p,     (uint32_t)(v >> 32));
	vfile_put_be32(p + 4, (uint32_t)(v));
}

/*
 * Encode a host struct stat into the 64-byte GDB fio_stat structure.
 * Fields are big-endian; layout: 7×uint32 + 3×uint64 + 3×uint32.
 */
static void vfile_encode_stat(uint8_t *buf, const struct stat *st)
{
	memset(buf, 0, 64);
	vfile_put_be32(buf +  0, (uint32_t)st->st_dev);
	vfile_put_be32(buf +  4, (uint32_t)st->st_ino);
	vfile_put_be32(buf +  8, (uint32_t)st->st_mode);
	vfile_put_be32(buf + 12, (uint32_t)st->st_nlink);
	vfile_put_be32(buf + 16, (uint32_t)st->st_uid);
	vfile_put_be32(buf + 20, (uint32_t)st->st_gid);
	vfile_put_be32(buf + 24, (uint32_t)st->st_rdev);
	vfile_put_be64(buf + 28, (uint64_t)st->st_size);
	vfile_put_be64(buf + 36, (uint64_t)st->st_blksize);
	vfile_put_be64(buf + 44, (uint64_t)st->st_blocks);
	vfile_put_be32(buf + 52, (uint32_t)st->st_atime);
	vfile_put_be32(buf + 56, (uint32_t)st->st_mtime);
	vfile_put_be32(buf + 60, (uint32_t)st->st_ctime);
}

/*
 * Translate GDB fileio open flags to Linux open flags.
 * GDB uses its own constants (from gdb/fileio.h); Linux values differ.
 */
static int vfile_gdb_flags_to_linux(int gflags)
{
	int lflags = gflags & 3; /* O_RDONLY/O_WRONLY/O_RDWR values match */
	if (gflags & 0x008) lflags |= O_APPEND;
	if (gflags & 0x200) lflags |= O_CREAT;
	if (gflags & 0x400) lflags |= O_TRUNC;
	if (gflags & 0x800) lflags |= O_EXCL;
	return lflags;
}

/* Send a vFile F-response with only a return code (no binary attachment). */
static void vfile_send_rc(int conn_fd, int retcode, int err)
{
	char buf[32];
	if (retcode < 0)
		snprintf(buf, sizeof(buf), "F-1,%x", err);
	else
		snprintf(buf, sizeof(buf), "F%x", retcode);
	rsp_send_str(conn_fd, buf);
}

/*
 * Send a vFile F-response with a binary attachment: $F<retcode>;<esc-data>#cs
 * datalen must be <= ELA_GDB_RSP_MAX_PACKET/2 to stay within the wire limit.
 */
static void vfile_send_data(int conn_fd, int retcode,
			    const uint8_t *data, size_t datalen)
{
	static const char hx[] = "0123456789abcdef";
	char buf[ELA_GDB_RSP_MAX_PACKET * 2 + 32];
	uint8_t cksum = 0;
	char hdr[24];
	int hdr_len;
	size_t i, pos = 0;
	uint8_t b;

	hdr_len = snprintf(hdr, sizeof(hdr), "F%x;", retcode);
	buf[pos++] = '$';
	for (i = 0; i < (size_t)hdr_len; i++) {
		b = (uint8_t)hdr[i];
		buf[pos++] = (char)b;
		cksum += b;
	}
	for (i = 0; i < datalen; i++) {
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
	buf[pos++] = hx[cksum >> 4];
	buf[pos++] = hx[cksum & 0x0f];
	send(conn_fd, buf, pos, 0);
}

/* -----------------------------------------------------------------------
 * RSP packet dispatch
 * ---------------------------------------------------------------------- */

/* -----------------------------------------------------------------------
 * monitor (qRcmd) console output helper
 * ---------------------------------------------------------------------- */

/* Send one line of monitor output to the GDB console via an O packet. */
static void rcmd_output(int fd, const char *msg)
{
	/* O<hex-encoded text> — up to 512 bytes of plain text */
	char buf[512 * 2 + 2]; /* 'O' + hex + NUL */
	size_t len = strlen(msg);
	if (len > 512)
		len = 512;
	buf[0] = 'O';
	if (ela_gdb_hex_encode((const uint8_t *)msg, len,
			       buf + 1, sizeof(buf) - 1) == 0)
		rsp_send_str(fd, buf);
}

/* -----------------------------------------------------------------------
 * Syscall-aware continue helper  (shared by c, C, vCont;c, vCont;C)
 * ---------------------------------------------------------------------- */

/*
 * Run the inferior with PTRACE_CONT (or PTRACE_SYSCALL when
 * QCatchSyscalls is active), looping to:
 *   • forward pass-through signals (QPassSignals)
 *   • silently skip syscall stops not in the catch filter
 *   • stop and report qualifying syscall-entry/return stops
 *
 * `initial_sig` is forwarded to the first ptrace call (0 = no signal).
 */
static void do_continue(int fd, int initial_sig)
{
	int fwd_sig = initial_sig;
	int wstatus;

	for (;;) {
		int req = g_catch_syscalls ? PTRACE_SYSCALL : PTRACE_CONT;
		ptrace(req, g_pid, NULL, (void *)(uintptr_t)fwd_sig);
		waitpid(g_pid, &wstatus, 0);
		fwd_sig = 0;

		if (!WIFSTOPPED(wstatus))
			break;

		{
			int sig = WSTOPSIG(wstatus);

			/*
			 * SIGTRAP|0x80 identifies a syscall stop when
			 * PTRACE_O_TRACESYSGOOD is set (done in run_session).
			 */
			if (g_catch_syscalls && sig == (SIGTRAP | 0x80)) {
				char stop_buf[96];
				int is_entry = (g_in_syscall == 0);
				int catch_it, i;

				if (is_entry) {
					g_last_sysno = read_sysno();
					g_in_syscall = 1;
				} else {
					g_in_syscall = 0;
				}

				/* Apply filter (cnt==0 → catch all) */
				catch_it = (g_catch_sysno_cnt == 0);
				for (i = 0; !catch_it && i < g_catch_sysno_cnt;
				     i++)
					if (g_catch_sysno[i] == g_last_sysno)
						catch_it = 1;

				if (catch_it) {
					snprintf(stop_buf, sizeof(stop_buf),
						 "T05thread:%x;%s:%llx;",
						 (unsigned)g_pid,
						 is_entry ? "syscall_entry"
							  : "syscall_return",
						 (unsigned long long)g_last_sysno);
					g_last_wstatus = wstatus;
					rsp_send_str(fd, stop_buf);
					return;
				}
				continue; /* filtered — keep running */
			}

			/* Regular signal pass-through */
			if (sig > 0 && sig < 64 &&
			    (g_pass_signals & (1ULL << sig))) {
				fwd_sig = sig;
				continue;
			}
		}

		break; /* genuine stop */
	}

	g_last_wstatus = wstatus;
	send_stop_reply(fd, wstatus);
}

static void handle_packet(int fd, char *pkt)
{
	char resp[ELA_GDB_RSP_MAX_FRAMED];
	char hex[ELA_GDB_RSP_MAX_PACKET];
	uint64_t addr, len_val;
	uint8_t data_buf[2048];
	char *sep, *colon;
	int wstatus, n, regnum;

	switch (pkt[0]) {

	case '?': /* Halt reason — report last real stop state */
		send_stop_reply(fd, g_last_wstatus);
		break;

	case 'g': /* Read all registers */
		if (regs_read(resp, sizeof(resp)) != 0)
			rsp_send_str(fd, "E01");
		else
			rsp_send_str(fd, resp);
		break;

	case 'G': /* Write all registers: Gxx...xx */
		if (regs_write(pkt + 1, strlen(pkt + 1)) != 0)
			rsp_send_str(fd, "E01");
		else
			rsp_send_str(fd, "OK");
		break;

	case 'p': /* Read single register */
		regnum = (int)strtol(pkt + 1, NULL, 16);
		if (reg_read_one(regnum, resp, sizeof(resp)) != 0) {
			/*
			 * Return register-not-available ('x' fill) rather than
			 * E01 for unknown register numbers.  E01 triggers a
			 * recursion bug in pwndbg's Python error handler.
			 * Use 8 'x' chars (4 bytes) as a conservative fallback;
			 * GDB treats any all-'x' response as "not available".
			 */
			rsp_send_str(fd, "xxxxxxxx");
		} else {
			rsp_send_str(fd, resp);
		}
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
		do_continue(fd, 0);
		break;

	case 's': /* Single step */
		if (ptrace(PTRACE_SINGLESTEP, g_pid, NULL, NULL) != 0) {
			rsp_send_str(fd, "E01");
			break;
		}
		waitpid(g_pid, &wstatus, 0);
		g_last_wstatus = wstatus;
		send_stop_reply(fd, wstatus);
		break;

	case 'C': /* Continue with signal: C<sig>[;<addr>] */
		do_continue(fd, (int)strtol(pkt + 1, NULL, 16));
		break;

	case 'S': /* Step with signal: S<sig>[;<addr>] */
	{
		int sig = (int)strtol(pkt + 1, NULL, 16);
		if (ptrace(PTRACE_SINGLESTEP, g_pid, NULL,
			   (void *)(uintptr_t)sig) != 0) {
			rsp_send_str(fd, "E01");
			break;
		}
		waitpid(g_pid, &wstatus, 0);
		g_last_wstatus = wstatus;
		send_stop_reply(fd, wstatus);
		break;
	}

	case 'v':
		if (strcmp(pkt, "vCont?") == 0) {
			rsp_send_str(fd, "vCont;c;C;s;S");
		} else if (strncmp(pkt, "vCont;c", 7) == 0) {
			do_continue(fd, 0);
		} else if (strncmp(pkt, "vCont;C", 7) == 0) {
			/* Continue with signal: vCont;C<sig>[:tid] */
			do_continue(fd, (int)strtol(pkt + 7, NULL, 16));
		} else if (strncmp(pkt, "vCont;s", 7) == 0) {
			if (ptrace(PTRACE_SINGLESTEP, g_pid, NULL, NULL) != 0) {
				rsp_send_str(fd, "E01");
				break;
			}
			waitpid(g_pid, &wstatus, 0);
			g_last_wstatus = wstatus;
			send_stop_reply(fd, wstatus);
		} else if (strncmp(pkt, "vCont;S", 7) == 0) {
			/* Step with signal: vCont;S<sig>[:tid] */
			int sig = (int)strtol(pkt + 7, NULL, 16);
			if (ptrace(PTRACE_SINGLESTEP, g_pid, NULL,
				   (void *)(uintptr_t)sig) != 0) {
				rsp_send_str(fd, "E01");
				break;
			}
			waitpid(g_pid, &wstatus, 0);
			g_last_wstatus = wstatus;
			send_stop_reply(fd, wstatus);
		} else if (strncmp(pkt, "vFile:open:", 11) == 0) {
			char *rest = pkt + 11;
			char *cm1, *cm2;
			char name_buf[1024];
			int gflags, fmode, vfd, res;

			cm1 = strchr(rest, ',');
			if (!cm1) { vfile_send_rc(fd, -1, EINVAL); break; }
			*cm1 = '\0';
			cm2 = strchr(cm1 + 1, ',');
			if (!cm2) { vfile_send_rc(fd, -1, EINVAL); break; }
			res = ela_gdb_hex_decode(rest, (uint8_t *)name_buf,
						 sizeof(name_buf) - 1);
			if (res < 0) { vfile_send_rc(fd, -1, EINVAL); break; }
			name_buf[res] = '\0';
			gflags = (int)strtol(cm1 + 1, NULL, 16);
			fmode  = (int)strtol(cm2 + 1, NULL, 16);
			errno  = 0;
			vfd    = open(name_buf,
				      vfile_gdb_flags_to_linux(gflags),
				      (mode_t)fmode);
			vfile_send_rc(fd, vfd < 0 ? -1 : vfd,
				      vfd < 0 ? errno : 0);

		} else if (strncmp(pkt, "vFile:close:", 12) == 0) {
			int vfd = (int)strtol(pkt + 12, NULL, 16);
			/* Refuse to close stdin/stdout/stderr */
			if (vfd < 3) { vfile_send_rc(fd, -1, EBADF); break; }
			errno = 0;
			vfile_send_rc(fd, close(vfd) == 0 ? 0 : -1, errno);

		} else if (strncmp(pkt, "vFile:pread:", 12) == 0) {
			char *rest = pkt + 12;
			char *cm1, *cm2;
			int vfd;
			size_t count;
			off_t offset;
			ssize_t nr;

			cm1 = strchr(rest, ',');
			if (!cm1) { vfile_send_rc(fd, -1, EINVAL); break; }
			*cm1 = '\0';
			cm2 = strchr(cm1 + 1, ',');
			if (!cm2) { vfile_send_rc(fd, -1, EINVAL); break; }
			*cm2 = '\0';
			vfd    = (int)strtol(rest, NULL, 16);
			count  = (size_t)strtoul(cm1 + 1, NULL, 16);
			offset = (off_t)strtoull(cm2 + 1, NULL, 16);
			if (count > sizeof(data_buf))
				count = sizeof(data_buf);
			errno = 0;
			nr = pread(vfd, data_buf, count, offset);
			if (nr < 0)
				vfile_send_rc(fd, -1, errno);
			else
				vfile_send_data(fd, (int)nr,
						data_buf, (size_t)nr);

		} else if (strncmp(pkt, "vFile:pwrite:", 13) == 0) {
			char *rest = pkt + 13;
			char *cm1, *cm2, *semi;
			int vfd, decoded;
			size_t count;
			off_t offset;
			ssize_t nw;

			cm1 = strchr(rest, ',');
			if (!cm1) { vfile_send_rc(fd, -1, EINVAL); break; }
			*cm1 = '\0';
			cm2 = strchr(cm1 + 1, ',');
			if (!cm2) { vfile_send_rc(fd, -1, EINVAL); break; }
			*cm2 = '\0';
			semi = strchr(cm2 + 1, ';');
			if (!semi) { vfile_send_rc(fd, -1, EINVAL); break; }
			*semi = '\0';
			vfd    = (int)strtol(rest, NULL, 16);
			count  = (size_t)strtoul(cm1 + 1, NULL, 16);
			offset = (off_t)strtoull(cm2 + 1, NULL, 16);
			if (count > sizeof(data_buf))
				count = sizeof(data_buf);
			decoded = rsp_binary_unescape(semi + 1, count * 2 + 1,
						      data_buf, count);
			if (decoded < 0) { vfile_send_rc(fd, -1, EINVAL); break; }
			errno = 0;
			nw = pwrite(vfd, data_buf, (size_t)decoded, offset);
			vfile_send_rc(fd, nw < 0 ? -1 : (int)nw,
				      nw < 0 ? errno : 0);

		} else if (strncmp(pkt, "vFile:fstat:", 12) == 0) {
			int vfd = (int)strtol(pkt + 12, NULL, 16);
			struct stat st;
			uint8_t stat_buf[64];

			errno = 0;
			if (fstat(vfd, &st) != 0) {
				vfile_send_rc(fd, -1, errno);
				break;
			}
			vfile_encode_stat(stat_buf, &st);
			vfile_send_data(fd, (int)sizeof(stat_buf),
					stat_buf, sizeof(stat_buf));

		} else if (strncmp(pkt, "vFile:stat:", 11) == 0) {
			char name_buf[1024];
			struct stat st;
			uint8_t stat_buf[64];
			int res = ela_gdb_hex_decode(pkt + 11,
						     (uint8_t *)name_buf,
						     sizeof(name_buf) - 1);
			if (res < 0) { vfile_send_rc(fd, -1, EINVAL); break; }
			name_buf[res] = '\0';
			errno = 0;
			if (stat(name_buf, &st) != 0) {
				vfile_send_rc(fd, -1, errno);
				break;
			}
			vfile_encode_stat(stat_buf, &st);
			vfile_send_data(fd, (int)sizeof(stat_buf),
					stat_buf, sizeof(stat_buf));

		} else if (strncmp(pkt, "vFile:unlink:", 13) == 0) {
			char name_buf[1024];
			int res = ela_gdb_hex_decode(pkt + 13,
						     (uint8_t *)name_buf,
						     sizeof(name_buf) - 1);
			if (res < 0) { vfile_send_rc(fd, -1, EINVAL); break; }
			name_buf[res] = '\0';
			errno = 0;
			vfile_send_rc(fd, unlink(name_buf) == 0 ? 0 : -1,
				      errno);

		} else if (strncmp(pkt, "vFile:readlink:", 15) == 0) {
			char name_buf[1024];
			ssize_t rlen;
			int res = ela_gdb_hex_decode(pkt + 15,
						     (uint8_t *)name_buf,
						     sizeof(name_buf) - 1);
			if (res < 0) { vfile_send_rc(fd, -1, EINVAL); break; }
			name_buf[res] = '\0';
			errno = 0;
			rlen = readlink(name_buf, hex, sizeof(hex) - 1);
			if (rlen < 0)
				vfile_send_rc(fd, -1, errno);
			else
				vfile_send_data(fd, (int)rlen,
						(const uint8_t *)hex,
						(size_t)rlen);

		} else if (strncmp(pkt, "vFile:setfs:", 12) == 0) {
			/* Only local filesystem is supported; accept any pid. */
			vfile_send_rc(fd, 0, 0);

		} else if (strncmp(pkt, "vAttach;", 8) == 0) {
			/*
			 * vAttach;<pid-hex> — detach from the current process
			 * and attach to a new one.  All breakpoints are removed
			 * from the old process before detaching.  Session state
			 * (breakpoints, XML caches, syscall-catch toggle) is
			 * reset for the new PID.
			 */
			pid_t new_pid = (pid_t)strtol(pkt + 8, NULL, 16);
			int new_ws;

			bp_clear_all();
			ptrace(PTRACE_DETACH, g_pid, NULL, NULL);

			if (ptrace(PTRACE_ATTACH, new_pid, NULL, NULL) != 0) {
				rsp_send_str(fd, "E01");
				g_stop = 1;
				break;
			}
			if (waitpid(new_pid, &new_ws, 0) < 0) {
				/* Attached but waitpid failed; undo attach */
				ptrace(PTRACE_DETACH, new_pid, NULL, NULL);
				rsp_send_str(fd, "E01");
				g_stop = 1;
				break;
			}

			ptrace(PTRACE_SETOPTIONS, new_pid, NULL,
			       (void *)(uintptr_t)PTRACE_O_TRACESYSGOOD);

			g_pid             = new_pid;
			g_last_wstatus    = new_ws;
			g_in_syscall      = 0;
			g_last_sysno      = 0;
			g_svr4_xml_len    = -1;
			g_threads_xml_len = -1;
			g_memmap_xml_len  = -1;
			g_target_xml_len  = -1;
			g_current_tid     = new_pid;
			memset(g_bps, 0, sizeof(g_bps));

			send_stop_reply(fd, new_ws);

		} else if (strncmp(pkt, "vKill;", 6) == 0) {
			/*
			 * vKill;<pid-hex> — hard-kill the named process.
			 * We only support killing the process we are attached
			 * to; any other PID gets an error.
			 */
			pid_t kill_pid = (pid_t)strtol(pkt + 6, NULL, 16);
			if (kill_pid == g_pid) {
				bp_clear_all();
				ptrace(PTRACE_KILL, g_pid, NULL, NULL);
				waitpid(g_pid, NULL, 0);
				rsp_send_str(fd, "OK");
				g_stop = 1;
			} else {
				rsp_send_str(fd, "E01");
			}

		} else {
			rsp_send_str(fd, ""); /* unknown v-packet */
		}
		break;

	case 'H': /* Set thread — ignored */
		rsp_send_str(fd, "OK");
		break;

	case 'T': /* Thread alive: T<tid-hex> */
	{
		unsigned long long tid_val;
		char task_path[64];
		struct stat tstat;

		if (sscanf(pkt + 1, "%llx", &tid_val) != 1) {
			rsp_send_str(fd, "E01");
			break;
		}
		snprintf(task_path, sizeof(task_path),
			 "/proc/%d/task/%llu", (int)g_pid, tid_val);
		rsp_send_str(fd, stat(task_path, &tstat) == 0 ? "OK" : "E01");
		break;
	}

	case 'Z': /* Insert breakpoint/watchpoint: Z<type>,<addr>,<kind>[;cond...] */
	{
		int ztype = pkt[1] - '0';
		uint64_t kind = 4;
		char *ksep;

		sep = strchr(pkt + 3, ',');
		if (!sep) { rsp_send_str(fd, "E01"); break; }
		*sep = '\0';
		ksep = sep + 1;
		if (ela_gdb_parse_hex_u64(pkt + 3, &addr) != 0) {
			rsp_send_str(fd, "E01"); break;
		}
		/* Use strtoul so trailing ";condition" extensions are ignored */
		if (*ksep)
			kind = (uint64_t)strtoul(ksep, NULL, 16);

		if (ztype == 0) {
			/* Software breakpoint */
			if (bp_insert(addr, (int)kind) != 0)
				rsp_send_str(fd, "E01");
			else
				rsp_send_str(fd, "OK");
#if defined(__x86_64__)
		} else if (ztype >= 1 && ztype <= 4) {
			/* Hardware watchpoint via DR0-DR3/DR7 */
			if (wp_insert_x86(addr, ztype, (int)kind) != 0)
				rsp_send_str(fd, "E01");
			else
				rsp_send_str(fd, "OK");
#endif
		} else {
			rsp_send_str(fd, ""); /* unsupported on this arch */
		}
		break;
	}

	case 'z': /* Remove breakpoint/watchpoint: z<type>,<addr>,<kind> */
	{
		int ztype = pkt[1] - '0';

		sep = strchr(pkt + 3, ',');
		if (!sep) { rsp_send_str(fd, "E01"); break; }
		*sep = '\0';
		if (ela_gdb_parse_hex_u64(pkt + 3, &addr) != 0) {
			rsp_send_str(fd, "E01"); break;
		}

		if (ztype == 0) {
			if (bp_remove(addr) != 0)
				rsp_send_str(fd, "E01");
			else
				rsp_send_str(fd, "OK");
#if defined(__x86_64__)
		} else if (ztype >= 1 && ztype <= 4) {
			if (wp_remove_x86(addr) != 0)
				rsp_send_str(fd, "E01");
			else
				rsp_send_str(fd, "OK");
#endif
		} else {
			rsp_send_str(fd, "");
		}
		break;
	}

	case 'q': /* Query packets */
		if (strncmp(pkt, "qSupported", 10) == 0) {
			/*
			 * Parse the client's feature list.  The packet format is
			 * "qSupported:feat1+;feat2+;...".  Record whether GDB
			 * supports swbreak+ so we can include "swbreak:;" in T
			 * stop replies when we hit a software breakpoint.
			 */
			const char *client_feats = pkt + 10;
			if (*client_feats == ':')
				client_feats++;
			g_swbreak_feature = (strstr(client_feats, "swbreak+") != NULL);

			snprintf(resp, sizeof(resp),
				 "PacketSize=%x"
				 ";qXfer:exec-file:read+"
				 ";qXfer:auxv:read+"
				 ";qXfer:features:read+"
				 ";qXfer:libraries-svr4:read+"
				 ";qXfer:threads:read+"
				 ";qXfer:memory-map:read+"
				 ";qXfer:siginfo:read+"
				 ";qSearch:memory+"
				 ";vFile+"
				 ";vAttach+"
				 ";QStartNoAckMode+"
				 ";QPassSignals+"
				 ";QCatchSyscalls+"
				 ";swbreak+"
#if defined(__x86_64__)
				 ";hwbreak+"
#endif
				 ,
				 ELA_GDB_RSP_MAX_PACKET);
			rsp_send_str(fd, resp);
		} else if (strcmp(pkt, "qAttached") == 0) {
			rsp_send_str(fd, "1");
		} else if (strncmp(pkt, "qSymbol", 7) == 0) {
			/*
			 * GDB sends qSymbol:: early in connection setup to
			 * offer symbol lookup services.  We don't need any
			 * symbols resolved by the client, so reply OK to end
			 * the negotiation immediately.
			 */
			rsp_send_str(fd, "OK");
		} else if (strcmp(pkt, "qOffsets") == 0) {
			/*
			 * Report the ASLR slide for the main executable so
			 * GDB can relocate its symbol table to match the
			 * actual load address.  Critical for PIE binaries.
			 */
			handle_qoffsets(fd);
		} else if (strncmp(pkt, "qRcmd,", 6) == 0) {
			/*
			 * monitor <cmd> — server-side diagnostic commands.
			 * The command is hex-encoded in the packet.
			 * Each output line is sent as O<hex-text>.
			 * The final response is always OK.
			 *
			 * Supported commands:
			 *   pid   — print PID of attached process
			 *   exe   — print executable path
			 *   maps  — print /proc/<pid>/maps
			 *   help  — list commands
			 */
			char cmd[256];
			int cmd_len;
			int ci;

			cmd_len = ela_gdb_hex_decode(pkt + 6,
						     (uint8_t *)cmd,
						     sizeof(cmd) - 1);
			if (cmd_len < 0) {
				rsp_send_str(fd, "E01"); break;
			}
			cmd[cmd_len] = '\0';
			/* Trim trailing whitespace / newline */
			for (ci = cmd_len - 1;
			     ci >= 0 && (cmd[ci] == '\n' || cmd[ci] == '\r' ||
					 cmd[ci] == ' ');
			     ci--)
				cmd[ci] = '\0';

			if (strcmp(cmd, "pid") == 0) {
				char out[32];
				snprintf(out, sizeof(out),
					 "pid: %d\n", (int)g_pid);
				rcmd_output(fd, out);

			} else if (strcmp(cmd, "exe") == 0) {
				char link[32], exe_buf[4096];
				ssize_t elen;
				snprintf(link, sizeof(link),
					 "/proc/%d/exe", (int)g_pid);
				elen = readlink(link, exe_buf,
						sizeof(exe_buf) - 2);
				if (elen < 0) {
					rcmd_output(fd, "error: readlink\n");
				} else {
					exe_buf[elen]     = '\n';
					exe_buf[elen + 1] = '\0';
					rcmd_output(fd, exe_buf);
				}

			} else if (strcmp(cmd, "maps") == 0) {
				char maps_path[32];
				FILE *mf;
				char mline[256];
				snprintf(maps_path, sizeof(maps_path),
					 "/proc/%d/maps", (int)g_pid);
				mf = fopen(maps_path, "r");
				if (!mf) {
					rcmd_output(fd, "error: open maps\n");
				} else {
					while (fgets(mline, sizeof(mline), mf))
						rcmd_output(fd, mline);
					fclose(mf);
				}

			} else if (strcmp(cmd, "help") == 0) {
				rcmd_output(fd, "commands: pid exe maps help\n");

			} else {
				char unk[280];
				snprintf(unk, sizeof(unk),
					 "unknown: %s\n", cmd);
				rcmd_output(fd, unk);
			}
			rsp_send_str(fd, "OK");
		} else if (strncmp(pkt, "qSearch:memory:", 15) == 0) {
			/*
			 * Format: qSearch:memory:<addr>;<len>;<pattern-hex>
			 * Response: 1,<found-addr>  found
			 *           0               not found
			 *           E01             error
			 */
			char *rest = pkt + 15;
			char *semi1, *semi2;
			uint64_t s_addr, s_len;
			uint8_t pattern[256];
			uint64_t found_addr = 0;
			int plen, ret;

			semi1 = strchr(rest, ';');
			if (!semi1) { rsp_send_str(fd, "E01"); break; }
			*semi1 = '\0';
			semi2 = strchr(semi1 + 1, ';');
			if (!semi2) { rsp_send_str(fd, "E01"); break; }
			*semi2 = '\0';

			if (ela_gdb_parse_hex_u64(rest, &s_addr) != 0 ||
			    ela_gdb_parse_hex_u64(semi1 + 1, &s_len) != 0) {
				rsp_send_str(fd, "E01"); break;
			}
			plen = ela_gdb_hex_decode(semi2 + 1, pattern,
						  sizeof(pattern));
			if (plen <= 0) { rsp_send_str(fd, "E01"); break; }

			ret = mem_search(s_addr, s_len,
					 pattern, (size_t)plen,
					 &found_addr);
			if (ret < 0) {
				rsp_send_str(fd, "E01");
			} else if (ret == 0) {
				rsp_send_str(fd, "0");
			} else {
				snprintf(resp, sizeof(resp), "1,%llx",
					 (unsigned long long)found_addr);
				rsp_send_str(fd, resp);
			}
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
			if (xfer_len > (uint64_t)ELA_GDB_RSP_MAX_PACKET)
				xfer_len = (uint64_t)ELA_GDB_RSP_MAX_PACKET;
			chunk = (avail < (size_t)xfer_len)
				? avail : (size_t)xfer_len;

			rsp_send_binary_qxfer(fd,
					      (const uint8_t *)exe_path +
					      (size_t)xfer_off,
					      chunk, chunk >= avail);
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

			if (g_target_xml_len < 0)
				g_target_xml_len = build_target_xml(
					g_target_xml, sizeof(g_target_xml));
			if (g_target_xml_len < 0) {
				rsp_send_str(fd, "E00");
				break;
			}
			xml_len = (size_t)g_target_xml_len;

			if (xfer_off >= (uint64_t)xml_len) {
				rsp_send_str(fd, "l");
				break;
			}

			avail = (size_t)(xml_len - (size_t)xfer_off);
			if (xfer_len > (uint64_t)ELA_GDB_RSP_MAX_PACKET)
				xfer_len = (uint64_t)ELA_GDB_RSP_MAX_PACKET;
			chunk = (avail < (size_t)xfer_len)
				? avail : (size_t)xfer_len;

			rsp_send_binary_qxfer(fd,
					      (const uint8_t *)g_target_xml +
					      (size_t)xfer_off,
					      chunk, chunk >= avail);
		} else if (strncmp(pkt, "qXfer:threads:read:", 19) == 0) {
			/*
			 * Format: qXfer:threads:read:<annex>:<offset>,<length>
			 * annex is always empty.  Rebuild at offset 0.
			 */
			char *rest = pkt + 19;
			char *sep2  = strrchr(rest, ':');
			char *comma2;
			uint64_t xfer_off, xfer_len;
			size_t xml_len, avail, chunk;

			if (!sep2) { rsp_send_str(fd, "E01"); break; }
			comma2 = strchr(sep2 + 1, ',');
			if (!comma2) { rsp_send_str(fd, "E01"); break; }

			*comma2 = '\0';
			if (ela_gdb_parse_hex_u64(sep2 + 1, &xfer_off) != 0 ||
			    ela_gdb_parse_hex_u64(comma2 + 1, &xfer_len) != 0) {
				rsp_send_str(fd, "E01");
				break;
			}

			if (xfer_off == 0) {
				g_threads_xml_len = build_threads_xml(
					g_pid,
					g_threads_xml,
					sizeof(g_threads_xml));
			}
			if (g_threads_xml_len < 0) {
				rsp_send_str(fd, "E01"); break;
			}
			xml_len = (size_t)g_threads_xml_len;
			if (xfer_off >= (uint64_t)xml_len) {
				rsp_send_str(fd, "l"); break;
			}
			avail = xml_len - (size_t)xfer_off;
			if (xfer_len > (uint64_t)ELA_GDB_RSP_MAX_PACKET)
				xfer_len = (uint64_t)ELA_GDB_RSP_MAX_PACKET;
			chunk = (avail < (size_t)xfer_len)
				? avail : (size_t)xfer_len;
			rsp_send_binary_qxfer(fd,
					      (const uint8_t *)g_threads_xml +
					      (size_t)xfer_off,
					      chunk, chunk >= avail);

		} else if (strncmp(pkt, "qXfer:memory-map:read:", 22) == 0) {
			/*
			 * Format: qXfer:memory-map:read:<annex>:<offset>,<length>
			 * annex is always empty.  Rebuild at offset 0.
			 */
			char *rest = pkt + 22;
			char *sep2  = strrchr(rest, ':');
			char *comma2;
			uint64_t xfer_off, xfer_len;
			size_t xml_len, avail, chunk;

			if (!sep2) { rsp_send_str(fd, "E01"); break; }
			comma2 = strchr(sep2 + 1, ',');
			if (!comma2) { rsp_send_str(fd, "E01"); break; }

			*comma2 = '\0';
			if (ela_gdb_parse_hex_u64(sep2 + 1, &xfer_off) != 0 ||
			    ela_gdb_parse_hex_u64(comma2 + 1, &xfer_len) != 0) {
				rsp_send_str(fd, "E01");
				break;
			}

			if (xfer_off == 0) {
				g_memmap_xml_len = build_memmap_xml(
					g_pid,
					g_memmap_xml,
					sizeof(g_memmap_xml));
			}
			if (g_memmap_xml_len < 0) {
				rsp_send_str(fd, "E01"); break;
			}
			xml_len = (size_t)g_memmap_xml_len;
			if (xfer_off >= (uint64_t)xml_len) {
				rsp_send_str(fd, "l"); break;
			}
			avail = xml_len - (size_t)xfer_off;
			if (xfer_len > (uint64_t)ELA_GDB_RSP_MAX_PACKET)
				xfer_len = (uint64_t)ELA_GDB_RSP_MAX_PACKET;
			chunk = (avail < (size_t)xfer_len)
				? avail : (size_t)xfer_len;
			rsp_send_binary_qxfer(fd,
					      (const uint8_t *)g_memmap_xml +
					      (size_t)xfer_off,
					      chunk, chunk >= avail);

		} else if (strncmp(pkt, "qXfer:siginfo:read:", 19) == 0) {
			/*
			 * Format: qXfer:siginfo:read:<annex>:<offset>,<length>
			 * annex is always empty.  Response: raw binary siginfo_t
			 * from PTRACE_GETSIGINFO — only valid when the inferior
			 * is stopped by a signal (SIGSEGV, SIGBUS, etc.).
			 */
			siginfo_t si;
			uint64_t xfer_off, xfer_len;
			char *rest = pkt + 19;
			char *sep2  = strrchr(rest, ':');
			char *comma2;
			size_t si_sz, avail, chunk;

			if (!sep2) { rsp_send_str(fd, "E01"); break; }
			comma2 = strchr(sep2 + 1, ',');
			if (!comma2) { rsp_send_str(fd, "E01"); break; }

			*comma2 = '\0';
			if (ela_gdb_parse_hex_u64(sep2 + 1, &xfer_off) != 0 ||
			    ela_gdb_parse_hex_u64(comma2 + 1, &xfer_len) != 0) {
				rsp_send_str(fd, "E01");
				break;
			}

			if (ptrace(PTRACE_GETSIGINFO, g_pid, NULL, &si) != 0) {
				rsp_send_str(fd, "E01");
				break;
			}

			si_sz = sizeof(siginfo_t);
			if (xfer_off >= (uint64_t)si_sz) {
				rsp_send_str(fd, "l"); /* past end */
				break;
			}

			avail = si_sz - (size_t)xfer_off;
			if (xfer_len > (uint64_t)avail)
				xfer_len = (uint64_t)avail;
			chunk = (size_t)xfer_len;

			rsp_send_binary_qxfer(fd,
					      (const uint8_t *)&si +
					      (size_t)xfer_off,
					      chunk,
					      (size_t)xfer_off + chunk >= si_sz);
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
			if (xfer_len > (uint64_t)ELA_GDB_RSP_MAX_PACKET)
				xfer_len = (uint64_t)ELA_GDB_RSP_MAX_PACKET;
			chunk = (avail < (size_t)xfer_len)
				? avail : (size_t)xfer_len;

			rsp_send_binary_qxfer(fd,
					      (const uint8_t *)g_svr4_xml +
					      (size_t)xfer_off,
					      chunk, chunk >= avail);
		} else {
			rsp_send_str(fd, ""); /* unknown query */
		}
		break;

	case 'Q': /* Set packets */
		if (strcmp(pkt, "QStartNoAckMode") == 0) {
			rsp_send_str(fd, "OK");
			g_noack = 1;
		} else if (strncmp(pkt, "QCatchSyscalls:", 15) == 0) {
			/*
			 * QCatchSyscalls:0             — disable
			 * QCatchSyscalls:1             — catch all syscalls
			 * QCatchSyscalls:1;n1;n2;...   — catch listed sysno
			 *
			 * Syscall stops are distinguished from breakpoint
			 * SIGTRAP by PTRACE_O_TRACESYSGOOD (set at session
			 * start), which adds 0x80 to the stop signal.
			 */
			if (pkt[15] == '0') {
				g_catch_syscalls  = 0;
				g_catch_sysno_cnt = 0;
				g_in_syscall      = 0;
				rsp_send_str(fd, "OK");
			} else if (pkt[15] == '1') {
				const char *p = pkt + 16; /* skip '1' */
				g_catch_syscalls  = 1;
				g_catch_sysno_cnt = 0;
				g_in_syscall      = 0;
				while (*p == ';' && g_catch_sysno_cnt <
				       ELA_GDB_MAX_CATCH_SYSCALLS) {
					char *end;
					uint64_t sno = strtoull(p + 1,
								&end, 16);
					if (end == p + 1)
						break;
					g_catch_sysno[g_catch_sysno_cnt++] =
						sno;
					p = end;
				}
				rsp_send_str(fd, "OK");
			} else {
				rsp_send_str(fd, "E01");
			}
		} else if (strncmp(pkt, "QPassSignals:", 13) == 0) {
			/*
			 * QPassSignals:<sig1>;<sig2>;...
			 * Each token is a signal number in hex.  Build a
			 * bitmask of signals the inferior should receive
			 * without stopping the gdbserver.
			 */
			const char *p = pkt + 13;
			uint64_t mask = 0;
			while (*p) {
				char *end;
				unsigned long sig = strtoul(p, &end, 16);
				if (end == p)
					break;
				if (sig > 0 && sig < 64)
					mask |= (1ULL << sig);
				p = (*end == ';') ? end + 1 : end;
			}
			g_pass_signals = mask;
			rsp_send_str(fd, "OK");
		} else {
			rsp_send_str(fd, ""); /* unknown Q packet */
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

static int run_session(int conn_fd, pid_t pid, int attach_wstatus)
{
	char payload[ELA_GDB_RSP_MAX_PACKET + 1];
	int n;

	g_pid              = pid;
	g_stop             = 0;
	g_tid_count        = 0;
	g_tid_next         = 0;
	g_svr4_xml_len     = -1;
	g_threads_xml_len  = -1;
	g_memmap_xml_len   = -1;
	g_target_xml_len   = -1;
	g_noack            = 0;
	g_pass_signals     = 0;
	g_current_tid      = pid;
	g_last_wstatus     = attach_wstatus;
	g_catch_syscalls   = 0;
	g_catch_sysno_cnt  = 0;
	g_in_syscall       = 0;
	g_last_sysno       = 0;
	memset(g_bps, 0, sizeof(g_bps));
	xmlInitParser();

	/*
	 * Make syscall stops distinguishable from regular SIGTRAP:
	 * PTRACE_O_TRACESYSGOOD causes the kernel to set bit 7 of the
	 * stop signal (SIGTRAP|0x80) for PTRACE_SYSCALL stops, leaving
	 * regular breakpoint/signal traps as plain SIGTRAP (5).
	 */
	ptrace(PTRACE_SETOPTIONS, pid, NULL,
	       (void *)(uintptr_t)PTRACE_O_TRACESYSGOOD);

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

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		close(fd);
		return -1;
	}

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

	run_session(conn_fd, pid, wstatus);

	close(conn_fd);
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
	exit(0);
}
