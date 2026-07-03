// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_LINUX_KERNEL_BUILDINFO_UTIL_H
#define ELA_LINUX_KERNEL_BUILDINFO_UTIL_H

#include <stdbool.h>
#include <stddef.h>

/* Everything the server-side module builder needs to reproduce this host's
 * kernel build environment: uname release, the /proc/version banner, the
 * vermagic of an on-device module, the binary's compile-time target facts
 * (isa/bits/endianness, baked in from the build triple), and which kernel
 * config source (if any) was found. Collected by `linux modules buildinfo`
 * and uploaded as the module-buildinfo type; the config bytes themselves
 * travel separately as a kernel-config upload. */
struct ela_kernel_buildinfo {
	char kernel_release[128];
	char proc_version[1024];
	char vermagic[512];
	char module_path[1024];
	const char *isa;
	const char *bits;
	const char *endianness;
	char config_source[1024];
	bool config_available;
	bool config_compressed;
};

/* Copy the index-th kernel config candidate path into `out`, ordered by
 * preference: /proc/config.gz, /boot/config-<release>, /proc/config. `root`
 * is prefixed onto each path (empty or NULL for none) so tests can point at a
 * fixture tree. Returns 0 on success, -1 when index is out of range, the
 * release is required but missing, or `out` is too small. */
int ela_kernel_buildinfo_config_candidate(const char *root, const char *release,
					  unsigned int index,
					  char *out, size_t out_len);

/* True when `path` ends in ".gz" (config bytes are gzip-compressed). */
bool ela_kernel_buildinfo_config_is_gz(const char *path);

/* Trim one trailing newline (and optional carriage return) in place, for the
 * first line read from /proc/version. Returns `s`. */
char *ela_kernel_buildinfo_trim_line(char *s);

/* Format the buildinfo payload as json, csv, or plain text (any other
 * `format`, including NULL). Empty string fields are emitted as JSON null /
 * empty CSV fields. Returns 0 on success, -1 on truncation or bad args. */
int ela_kernel_buildinfo_format_payload(const char *format,
					const struct ela_kernel_buildinfo *info,
					char *out, size_t out_len);

#endif
