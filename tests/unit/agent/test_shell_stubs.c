// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "test_shell_stubs.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

int         g_dispatch_calls;
int         g_dispatch_rc;
int         g_usage_calls;
int         g_conf_update_calls;
int         g_http_get_calls;
int         g_http_get_rc       = -1;
const char *g_http_get_payload;

void ela_test_shell_stubs_reset(void)
{
	g_dispatch_calls    = 0;
	g_dispatch_rc       = 0;
	g_usage_calls       = 0;
	g_conf_update_calls = 0;
	g_http_get_calls    = 0;
	g_http_get_rc       = -1;
	g_http_get_payload  = NULL;
}

/* Stand-in for the top-level dispatcher defined in embedded_linux_audit.c. */
int embedded_linux_audit_dispatch(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	g_dispatch_calls++;
	return g_dispatch_rc;
}

/* Stand-in for the usage banner defined in embedded_linux_audit.c. */
void ela_usage(const char *prog)
{
	(void)prog;
	g_usage_calls++;
}

/* Stand-in for the conf reload defined in agent/net/ela_conf.c. */
void ela_conf_update_from_env(void)
{
	g_conf_update_calls++;
}

/*
 * Stand-in for agent/net/http_client.c's downloader.  When configured to
 * succeed (g_http_get_rc >= 0) with a payload, it writes that payload to the
 * requested path so the caller's subsequent fopen() sees a real file.
 */
int ela_http_get_to_file(const char *uri, const char *output_path,
			 bool insecure, bool verbose,
			 char *errbuf, size_t errbuf_len)
{
	(void)uri;
	(void)insecure;
	(void)verbose;

	g_http_get_calls++;
	if (errbuf && errbuf_len)
		errbuf[0] = '\0';

	if (g_http_get_rc >= 0 && g_http_get_payload && output_path) {
		FILE *fp = fopen(output_path, "w");

		if (fp) {
			fputs(g_http_get_payload, fp);
			fclose(fp);
		}
	}

	return g_http_get_rc;
}
