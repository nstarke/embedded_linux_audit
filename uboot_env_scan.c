// SPDX-License-Identifier: MIT License - Copyright (c) 2026 Nicholas Starke

#include "uboot_scan.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <glob.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define AUTO_SCAN_MAX_STEP 0x10000ULL

static uint32_t crc32_table[256];
static bool g_verbose;
static bool g_bruteforce;
static bool g_parse_vars;
static int g_output_sock = -1;
static FILE *g_output_config_fp = NULL;

struct env_candidate {
	uint64_t cfg_off;
	bool crc_standard;
	bool crc_redundant;
};

static int add_or_merge_candidate(struct env_candidate **cands, size_t *count,
					  uint64_t cfg_off, bool crc_standard, bool crc_redundant)
{
	struct env_candidate *tmp;

	if (!cands || !count)
		return -1;

	for (size_t i = 0; i < *count; i++) {
		if ((*cands)[i].cfg_off != cfg_off)
			continue;
		(*cands)[i].crc_standard = (*cands)[i].crc_standard || crc_standard;
		(*cands)[i].crc_redundant = (*cands)[i].crc_redundant || crc_redundant;
		return 0;
	}

	tmp = realloc(*cands, (*count + 1) * sizeof(**cands));
	if (!tmp)
		return -1;

	*cands = tmp;
	(*cands)[*count].cfg_off = cfg_off;
	(*cands)[*count].crc_standard = crc_standard;
	(*cands)[*count].crc_redundant = crc_redundant;
	(*count)++;
	return 0;
}

static void send_to_output_socket(const char *buf, size_t len)
{
	while (g_output_sock >= 0 && len) {
		ssize_t n = send(g_output_sock, buf, len, 0);
		if (n <= 0) {
			close(g_output_sock);
			g_output_sock = -1;
			return;
		}
		buf += n;
		len -= (size_t)n;
	}
}

static void emit_v(FILE *stream, const char *fmt, va_list ap)
{
	va_list aq;
	char stack[1024];
	char *dyn = NULL;
	int needed;

	va_copy(aq, ap);
	vfprintf(stream, fmt, ap);
	fflush(stream);

	needed = vsnprintf(stack, sizeof(stack), fmt, aq);
	va_end(aq);

	if (needed < 0)
		return;

	if ((size_t)needed < sizeof(stack)) {
		send_to_output_socket(stack, (size_t)needed);
		return;
	}

	dyn = malloc((size_t)needed + 1);
	if (!dyn)
		return;

	va_copy(aq, ap);
	vsnprintf(dyn, (size_t)needed + 1, fmt, aq);
	va_end(aq);
	send_to_output_socket(dyn, (size_t)needed);
	free(dyn);
}

static void out_printf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	emit_v(stdout, fmt, ap);
	va_end(ap);
}

static void err_printf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	emit_v(stderr, fmt, ap);
	va_end(ap);
}

static uint64_t parse_u64(const char *s)
{
	uint64_t v;

	if (fw_parse_u64(s, &v)) {
		err_printf("Invalid number: %s\n", s);
		exit(2);
	}
	return v;
}

static uint32_t read_le32(const uint8_t *p)
{
	return (uint32_t)p[0] |
		((uint32_t)p[1] << 8) |
		((uint32_t)p[2] << 16) |
		((uint32_t)p[3] << 24);
}

static bool has_hint_var(const uint8_t *data, size_t len, const char *hint_override)
{
	static const char *hints[] = {
		"bootcmd=", "bootargs=", "baudrate=", "ethaddr=", "stdin=",
	};

	if (hint_override && *hint_override) {
		size_t hlen = strlen(hint_override);
		for (size_t off = 0; off + hlen <= len; off++)
			if (!memcmp(data + off, hint_override, hlen))
				return true;
		return false;
	}

	for (size_t i = 0; i < ARRAY_SIZE(hints); i++) {
		size_t hlen = strlen(hints[i]);
		for (size_t off = 0; off + hlen <= len; off++)
			if (!memcmp(data + off, hints[i], hlen))
				return true;
	}

	return false;
}

static void dump_env_vars(const uint8_t *data, size_t len)
{
	size_t off = 0;
	size_t count = 0;

	out_printf("    parsed env vars:\n");
	while (off < len) {
		const char *s;
		size_t slen;
		const char *eq;
		bool printable = true;

		if (data[off] == '\0') {
			if ((off + 1 < len && data[off + 1] == '\0') || off + 1 >= len)
				break;
			off++;
			continue;
		}

		s = (const char *)(data + off);
		slen = strnlen(s, len - off);
		if (slen == len - off)
			break;

		eq = memchr(s, '=', slen);
		if (eq) {
			for (size_t i = 0; i < slen; i++) {
				if (!isprint((unsigned char)s[i]) && s[i] != '\t') {
					printable = false;
					break;
				}
			}

			if (printable) {
				out_printf("      %.*s\n", (int)slen, s);
				count++;
			}
		}

		off += slen + 1;
		if (count >= 256) {
			out_printf("      ... truncated after 256 vars ...\n");
			break;
		}
	}

	if (!count)
		out_printf("      (no parseable variables found)\n");
}

static int scan_dev(const char *dev, uint64_t step, uint64_t env_size, const char *hint_override)
{
	int fd;
	struct stat st;
	uint8_t *buf;
	off_t off;
	int hits = 0;
	uint64_t sysfs_erasesize;
	uint64_t erase_size;
	uint64_t sector_count;
	uint64_t cfg_off;
	struct env_candidate *cands = NULL;
	size_t cand_count = 0;

	fd = open(dev, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == EBUSY) {
			if (g_verbose)
				err_printf("Skipping busy device %s: %s\n", dev, strerror(errno));
			return 0;
		}
		err_printf("Cannot open %s: %s\n", dev, strerror(errno));
		return -1;
	}

	if (fstat(fd, &st) < 0) {
		close(fd);
		return -1;
	}

	if (st.st_size == 0) {
		uint64_t sz = fw_guess_size_any(dev);
		st.st_size = (off_t)sz;
	}

	if (st.st_size == 0) {
		close(fd);
		return -1;
	}

	sysfs_erasesize = fw_guess_erasesize_from_sysfs(dev);
	erase_size = sysfs_erasesize ? sysfs_erasesize : step;
	sector_count = erase_size ? ((env_size + erase_size - 1) / erase_size) : 0;

	buf = malloc((size_t)env_size);
	if (!buf) {
		close(fd);
		return -1;
	}

	for (off = 0; (uint64_t)off + env_size <= (uint64_t)st.st_size; off += (off_t)step) {
		if ((uint64_t)pread(fd, buf, (size_t)env_size, off) != env_size)
			break;

		uint32_t stored_le = read_le32(buf);
		uint32_t stored_be = fw_read_be32(buf);
		uint32_t calc = fw_crc32_calc(crc32_table, buf + 4, (size_t)env_size - 4);
		uint32_t calc_redund = (env_size > 5)
			? fw_crc32_calc(crc32_table, buf + 5, (size_t)env_size - 5)
			: 0;
		bool crc_ok_std = (calc == stored_le || calc == stored_be);
		bool crc_ok_redund = (env_size > 5) && (calc_redund == stored_le || calc_redund == stored_be);
		bool hint_ok = has_hint_var(buf + 4, (size_t)env_size - 4, hint_override);
		bool hint_ok_redund = (env_size > 5) && has_hint_var(buf + 5, (size_t)env_size - 5, hint_override);

		if (!g_bruteforce && !crc_ok_std && !crc_ok_redund)
			continue;
		if (g_bruteforce && !hint_ok && !hint_ok_redund)
			continue;

		cfg_off = erase_size ? ((uint64_t)off - ((uint64_t)off % erase_size)) : (uint64_t)off;
		(void)add_or_merge_candidate(&cands, &cand_count, cfg_off, crc_ok_std, crc_ok_redund);

		if (g_bruteforce)
			out_printf("  candidate offset=0x%jx  mode=hint-only  (has known vars)\n", (uintmax_t)off);
		else if (crc_ok_redund && !crc_ok_std)
			out_printf("  candidate offset=0x%jx  crc=%s-endian  %s (redundant-env layout)\n", (uintmax_t)off,
				(calc_redund == stored_le) ? "LE" : "BE", hint_ok_redund ? "(has known vars)" : "(crc ok)");
		else
			out_printf("  candidate offset=0x%jx  crc=%s-endian  %s\n", (uintmax_t)off,
				(calc == stored_le) ? "LE" : "BE", hint_ok ? "(has known vars)" : "(crc ok)");

		out_printf("    fw_env.config line: %s 0x%jx 0x%jx 0x%jx 0x%jx\n",
			dev, (uintmax_t)cfg_off, (uintmax_t)env_size,
			(uintmax_t)erase_size, (uintmax_t)sector_count);
		if (g_output_config_fp) {
			fprintf(g_output_config_fp, "%s 0x%jx 0x%jx 0x%jx 0x%jx\n",
				dev, (uintmax_t)cfg_off, (uintmax_t)env_size,
				(uintmax_t)erase_size, (uintmax_t)sector_count);
		}
		if (g_parse_vars) {
			if (crc_ok_redund && !crc_ok_std)
				dump_env_vars(buf + 5, (size_t)env_size - 5);
			else
				dump_env_vars(buf + 4, (size_t)env_size - 4);
		}
		hits++;
	}

	if (cand_count >= 2 && erase_size) {
		uint64_t expected = erase_size * (sector_count ? sector_count : 1);
		for (size_t i = 1; i < cand_count; i++) {
			uint64_t prev = cands[i - 1].cfg_off;
			uint64_t curr = cands[i].cfg_off;
			uint64_t diff = curr - prev;

			if (diff != erase_size && diff != expected)
				continue;

			out_printf("    redundant env candidate pair: %s 0x%jx <-> 0x%jx\n",
				dev, (uintmax_t)prev, (uintmax_t)curr);
		}
	}

	free(cands);
	free(buf);
	close(fd);
	return hits;
}

static void usage(const char *prog)
{
	err_printf("Usage: %s [--verbose] [--size <env_size>] [--hint <hint>] [--dev <dev>] [--brutefoce] [--skip-remove] [--skip-mtd] [--skip-ubi] [--output-config[=<path>]] [<dev:step> ...]\n"
		"             [--parse-vars]\n"
		"             [--output <ip:port>]\n", prog);
}

int fw_env_scan_main(int argc, char **argv)
{
	static const uint64_t common_sizes[] = { 0x1000, 0x2000, 0x4000, 0x8000, 0x10000, 0x20000, 0x40000, 0x80000 };
	bool fixed_size = false;
	uint64_t env_size = 0;
	const char *hint_override = NULL;
	const char *dev_override = NULL;
	const char *output_target = NULL;
	const char *output_config_path = NULL;
	bool skip_remove = false;
	bool skip_mtd = false;
	bool skip_ubi = false;
	char **created_mtdblock_nodes = NULL;
	size_t created_mtdblock_count = 0;
	char **created_ubi_nodes = NULL;
	size_t created_ubi_count = 0;
	int ret = 0;
	int argi;
	int opt;

	optind = 1;
	g_verbose = false;
	g_bruteforce = false;
	if (g_output_sock >= 0) {
		close(g_output_sock);
		g_output_sock = -1;
	}

	static const struct option long_opts[] = {
		{ "verbose", no_argument, NULL, 'v' },
		{ "size", required_argument, NULL, 's' },
		{ "hint", required_argument, NULL, 'H' },
		{ "dev", required_argument, NULL, 'd' },
		{ "brutefoce", no_argument, NULL, 'b' },
		{ "bruteforce", no_argument, NULL, 'b' },
		{ "skip-remove", no_argument, NULL, 'R' },
		{ "skip-mtd", no_argument, NULL, 'M' },
		{ "skip-ubi", no_argument, NULL, 'U' },
		{ "parse-vars", no_argument, NULL, 'P' },
		{ "output-config", optional_argument, NULL, 'c' },
		{ "output", required_argument, NULL, 'o' },
		{ 0, 0, 0, 0 }
	};

	while ((opt = getopt_long(argc, argv, "hvs:H:d:bo:RMUPc::", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h': usage(argv[0]); return 0;
		case 'v': g_verbose = true; break;
		case 's': env_size = parse_u64(optarg); fixed_size = true; break;
		case 'H': hint_override = optarg; break;
		case 'd': dev_override = optarg; break;
		case 'b': g_bruteforce = true; break;
		case 'R': skip_remove = true; break;
		case 'M': skip_mtd = true; break;
		case 'U': skip_ubi = true; break;
		case 'P': g_parse_vars = true; break;
		case 'c': output_config_path = optarg ? optarg : "fw_env.config"; break;
		case 'o': output_target = optarg; break;
		default: usage(argv[0]); return 2;
		}
	}

	argi = optind;
	if (geteuid() != 0) {
		err_printf("This program must be run as root.\n");
		ret = 1;
		goto out;
	}

	if (output_target && *output_target) {
		g_output_sock = fw_connect_tcp_ipv4(output_target);
		if (g_output_sock < 0) {
			err_printf("Invalid/failed output target (expected IPv4:port): %s\n", output_target);
			ret = 2;
			goto out;
		}
	}

	if (output_config_path && *output_config_path) {
		g_output_config_fp = fopen(output_config_path, "w");
		if (!g_output_config_fp) {
			err_printf("Cannot open output-config file %s: %s\n", output_config_path, strerror(errno));
			ret = 2;
			goto out;
		}
	}

	fw_crc32_init(crc32_table);
	if (!skip_mtd)
		fw_ensure_mtd_nodes_collect(g_verbose, &created_mtdblock_nodes, &created_mtdblock_count);
	if (!skip_ubi)
		fw_ensure_ubi_nodes_collect(g_verbose, &created_ubi_nodes, &created_ubi_count);

	if (dev_override) {
		if (!strncmp(dev_override, "/dev/mtd", 8) && strncmp(dev_override, "/dev/mtdblock", 13)) {
			err_printf("Refusing to scan raw MTD char device: %s (use /dev/mtdblock* instead)\n", dev_override);
			ret = 2;
			goto out;
		}

		uint64_t step = fw_guess_step_any(dev_override);
		if (!step)
			goto scan_fail;
		if (step > AUTO_SCAN_MAX_STEP)
			step = AUTO_SCAN_MAX_STEP;

		if (fixed_size)
			goto one_scan_done;

		for (size_t i = 0; i < ARRAY_SIZE(common_sizes); i++)
			if (scan_dev(dev_override, step, common_sizes[i], hint_override) < 0)
				goto scan_fail;
		ret = 0;
		goto out;

one_scan_done:
		ret = (scan_dev(dev_override, step, env_size, hint_override) < 0) ? 1 : 0;
		goto out;
	}

	if (argi >= argc) {
		glob_t g;
		unsigned int scan_flags = 0;

		if (!skip_mtd)
			scan_flags |= FW_SCAN_GLOB_MTDBLOCK;
		if (!skip_ubi)
			scan_flags |= (FW_SCAN_GLOB_UBI | FW_SCAN_GLOB_UBIBLOCK);

		if (fw_glob_scan_devices(&g, scan_flags) < 0)
			goto scan_fail;
		for (size_t gi = 0; gi < g.gl_pathc; gi++) {
			const char *dev = g.gl_pathv[gi];
			uint64_t step = fw_guess_step_any(dev);
			if (!step)
				continue;
			if (step > AUTO_SCAN_MAX_STEP)
				step = AUTO_SCAN_MAX_STEP;

			if (fixed_size) {
				if (scan_dev(dev, step, env_size, hint_override) < 0)
					goto scan_fail;
			} else {
				for (size_t i = 0; i < ARRAY_SIZE(common_sizes); i++)
					if (scan_dev(dev, step, common_sizes[i], hint_override) < 0)
						goto scan_fail;
			}
		}
		globfree(&g);
		ret = 0;
		goto out;
	}

	for (int i = argi; i < argc; i++) {
		char *arg = argv[i];
		char *colon = strrchr(arg, ':');
		if (!colon || colon == arg || *(colon + 1) == '\0')
			continue;
		*colon = '\0';
		if (!strncmp(arg, "/dev/mtd", 8) && strncmp(arg, "/dev/mtdblock", 13)) {
			err_printf("Refusing to scan raw MTD char device: %s (use /dev/mtdblock* instead)\n", arg);
			*colon = ':';
			continue;
		}
		uint64_t step = parse_u64(colon + 1);
		if (fixed_size) {
			if (scan_dev(arg, step, env_size, hint_override) < 0)
				goto scan_fail;
		} else {
			for (size_t si = 0; si < ARRAY_SIZE(common_sizes); si++)
				if (scan_dev(arg, step, common_sizes[si], hint_override) < 0)
					goto scan_fail;
		}
		*colon = ':';
	}
	ret = 0;
	goto out;

scan_fail:
	ret = 1;

out:
	if (!skip_remove) {
		for (size_t i = 0; i < created_mtdblock_count; i++) {
			if (unlink(created_mtdblock_nodes[i]) < 0 && errno != ENOENT)
				err_printf("Warning: failed to remove created node %s: %s\n",
					created_mtdblock_nodes[i], strerror(errno));
		}
		for (size_t i = 0; i < created_ubi_count; i++) {
			if (unlink(created_ubi_nodes[i]) < 0 && errno != ENOENT)
				err_printf("Warning: failed to remove created node %s: %s\n",
					created_ubi_nodes[i], strerror(errno));
		}
	}
	fw_free_created_nodes(created_mtdblock_nodes, created_mtdblock_count);
	fw_free_created_nodes(created_ubi_nodes, created_ubi_count);
	if (g_output_config_fp) {
		fclose(g_output_config_fp);
		g_output_config_fp = NULL;
	}
	if (g_output_sock >= 0)
		close(g_output_sock);
	return ret;
}
