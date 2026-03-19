// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_UBOOT_ENV_RECORD_UTIL_H
#define ELA_UBOOT_ENV_RECORD_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

const char *ela_uboot_env_candidate_mode(bool bruteforce,
					 bool crc_ok_std,
					 bool crc_ok_redund);
size_t ela_uboot_env_data_offset(bool crc_ok_std, bool crc_ok_redund);
int ela_uboot_env_format_candidate_record(int fmt,
					  bool *csv_header_emitted,
					  const char *dev,
					  uint64_t off,
					  const char *crc_endian,
					  const char *mode,
					  bool has_known_vars,
					  uint64_t cfg_off,
					  uint64_t env_size,
					  uint64_t erase_size,
					  uint64_t sector_count,
					  char **out);
int ela_uboot_env_format_redundant_pair_record(int fmt,
					       bool *csv_header_emitted,
					       const char *dev,
					       uint64_t a,
					       uint64_t b,
					       char **out);
int ela_uboot_env_format_verbose_record(int fmt,
					bool verbose,
					bool *csv_header_emitted,
					const char *dev,
					uint64_t off,
					const char *msg,
					char **out);
int ela_uboot_env_format_scan_start_record(int fmt,
					   bool verbose,
					   bool *csv_header_emitted,
					   const char *dev,
					   uint64_t step,
					   uint64_t env_size,
					   uint64_t device_size,
					   char **out);
int ela_uboot_env_format_vars_dump(int fmt,
				   const char *dev,
				   uint64_t env_off,
				   const uint8_t *data,
				   size_t len,
				   char **out);

#endif
