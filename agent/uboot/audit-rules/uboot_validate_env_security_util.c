// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "uboot_validate_env_security_util.h"
#include "uboot/audit-rules/uboot_audit_util.h"

#include <stdio.h>
#include <string.h>

int ela_uboot_validate_env_security_check_vars(const char *bootdelay,
					       const char *preboot,
					       const char *boot_targets,
					       const char *bootcmd,
					       const char *altbootcmd,
					       const char *bootfile,
					       const char *serverip,
					       const char *ipaddr,
					       const char *factory_reset,
					       const char *reset_to_defaults,
					       const char *resetenv,
					       const char *eraseenv,
					       int *bootdelay_i_out,
					       char *detail,
					       size_t detail_len)
{
	int issues = 0;
	int bootdelay_i = 0;

	if (bootdelay_i_out)
		*bootdelay_i_out = 0;

	if (!bootdelay || ela_uboot_parse_int_value(bootdelay, &bootdelay_i) != 0) {
		issues++;
		if (detail && detail_len)
			snprintf(detail + strlen(detail), detail_len - strlen(detail),
				 "%sbootdelay=%s",
				 detail[0] ? "; " : "",
				 bootdelay ? bootdelay : "(missing)");
	} else if (bootdelay_i > 0) {
		issues++;
		if (detail && detail_len)
			snprintf(detail + strlen(detail), detail_len - strlen(detail),
				 "%sbootdelay=%d (>0)", detail[0] ? "; " : "", bootdelay_i);
	}

	if (bootdelay_i_out)
		*bootdelay_i_out = bootdelay_i;

	if (preboot && *preboot) {
		issues++;
		if (detail && detail_len)
			snprintf(detail + strlen(detail), detail_len - strlen(detail),
				 "%spreboot is set", detail[0] ? "; " : "");
	}

	if (boot_targets && *boot_targets) {
		if (strstr(boot_targets, "usb") || ela_uboot_value_suggests_network_boot(boot_targets)) {
			issues++;
			if (detail && detail_len)
				snprintf(detail + strlen(detail), detail_len - strlen(detail),
					 "%sboot_targets allows removable/network boot (%s)",
					 detail[0] ? "; " : "", boot_targets);
		}
	}

	if (ela_uboot_value_suggests_network_boot(bootcmd)) {
		issues++;
		if (detail && detail_len)
			snprintf(detail + strlen(detail), detail_len - strlen(detail),
				 "%sbootcmd suggests network boot", detail[0] ? "; " : "");
	}

	if (ela_uboot_value_suggests_network_boot(altbootcmd)) {
		issues++;
		if (detail && detail_len)
			snprintf(detail + strlen(detail), detail_len - strlen(detail),
				 "%saltbootcmd suggests network boot", detail[0] ? "; " : "");
	}

	if (ela_uboot_value_suggests_network_boot(preboot)) {
		issues++;
		if (detail && detail_len)
			snprintf(detail + strlen(detail), detail_len - strlen(detail),
				 "%spreboot suggests network boot", detail[0] ? "; " : "");
	}

	if ((bootfile && *bootfile) || (serverip && *serverip) || (ipaddr && *ipaddr)) {
		issues++;
		if (detail && detail_len)
			snprintf(detail + strlen(detail), detail_len - strlen(detail),
				 "%snetwork boot variables present (bootfile/serverip/ipaddr)",
				 detail[0] ? "; " : "");
	}

	if (ela_uboot_value_suggests_factory_reset(bootcmd)) {
		issues++;
		if (detail && detail_len)
			snprintf(detail + strlen(detail), detail_len - strlen(detail),
				 "%sbootcmd suggests factory reset", detail[0] ? "; " : "");
	}

	if (ela_uboot_value_suggests_factory_reset(altbootcmd)) {
		issues++;
		if (detail && detail_len)
			snprintf(detail + strlen(detail), detail_len - strlen(detail),
				 "%saltbootcmd suggests factory reset", detail[0] ? "; " : "");
	}

	if (ela_uboot_value_suggests_factory_reset(preboot)) {
		issues++;
		if (detail && detail_len)
			snprintf(detail + strlen(detail), detail_len - strlen(detail),
				 "%spreboot suggests factory reset", detail[0] ? "; " : "");
	}

	if ((factory_reset && *factory_reset) ||
	    (reset_to_defaults && *reset_to_defaults) ||
	    (resetenv && *resetenv) ||
	    (eraseenv && *eraseenv)) {
		issues++;
		if (detail && detail_len)
			snprintf(detail + strlen(detail), detail_len - strlen(detail),
				 "%sfactory-reset variables present (factory_reset/reset_to_defaults/resetenv/eraseenv)",
				 detail[0] ? "; " : "");
	}

	return issues;
}
