// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#ifndef ELA_TPM2_INTERNAL_H
#define ELA_TPM2_INTERNAL_H

#if defined(ELA_HAS_TPM2)

#include <stdint.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti_device.h>
#include <tss2/tss2_tpm2_types.h>

#include "tpm2_output.h"

/* Shared utilities implemented in tpm2_util.c */
int tpm2_rc_to_exit_code(TSS2_RC rc);
int parse_u32(const char *text, uint32_t *value);
TPM2_ALG_ID parse_hash_alg(const char *name);
int tpm2_open(ESYS_CONTEXT **esys, TSS2_TCTI_CONTEXT **tcti);
void tpm2_close(ESYS_CONTEXT **esys, TSS2_TCTI_CONTEXT **tcti);

/* Per-subcommand entry points */
int cmd_getcap(int argc, char **argv);
int cmd_pcrread(int argc, char **argv);
int cmd_nvreadpublic(int argc, char **argv);
int cmd_createprimary(int argc, char **argv);

#endif /* ELA_HAS_TPM2 */

#endif /* ELA_TPM2_INTERNAL_H */
