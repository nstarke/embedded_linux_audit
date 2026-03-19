// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_UBOOT_ENV_UTIL_H
#define ELA_UBOOT_ENV_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct env_kv {
	char *name;
	char *value;
};

struct uboot_cfg_entry {
	char dev[256];
	uint64_t off;
	uint64_t env_size;
	uint64_t erase_size;
	uint64_t sectors;
};

void ela_uboot_env_free_kvs(struct env_kv *kvs, size_t count);
int ela_uboot_env_set_kv(struct env_kv **kvs, size_t *count, const char *name, const char *value);
int ela_uboot_env_unset_kv(struct env_kv *kvs, size_t *count, const char *name);
int ela_uboot_parse_fw_config_line(const char *line, struct uboot_cfg_entry *out);
int ela_uboot_parse_existing_env_data(const uint8_t *buf, size_t buf_len, size_t data_off,
				      struct env_kv **kvs, size_t *count);
int ela_uboot_build_env_region(const struct env_kv *kvs, size_t count, uint8_t *out, size_t out_len);
bool ela_uboot_env_crc_matches(const uint32_t *crc32_table,
			       const uint8_t *buf,
			       size_t env_size,
			       size_t data_off,
			       bool *is_le);

#endif
