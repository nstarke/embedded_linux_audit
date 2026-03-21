// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "ela_conf.h"
#include "ela_conf_util.h"
#include "../util/command_parse_util.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * All functions in this file require real hardware, network I/O, or OS-level
 * services (ptrace, SSH, sockets, TPM2, EFI) and cannot be exercised in the
 * unit-test environment.
 */
/* LCOV_EXCL_START */

void ela_conf_load(struct ela_conf *conf)
{
	FILE *f;
	char  line[600];

	memset(conf, 0, sizeof(*conf));

	f = fopen(ELA_CONF_PATH, "r");
	if (!f)
		return;

	while (fgets(line, (int)sizeof(line), f)) {
		ela_conf_trim_right(line);
		ela_conf_apply_line(conf, line);
	}

	fclose(f);
}

void ela_conf_export_to_env(const struct ela_conf *conf)
{
	if (!conf)
		return;

	if (conf->output_http[0]) {
		if (!strncmp(conf->output_http, "https://", 8))
			setenv("ELA_OUTPUT_HTTPS", conf->output_http, 0);
		else
			setenv("ELA_OUTPUT_HTTP", conf->output_http, 0);
	}

	if (conf->output_format[0] && ela_output_format_is_valid(conf->output_format))
		setenv("ELA_OUTPUT_FORMAT", conf->output_format, 0);

	if (conf->insecure)
		setenv("ELA_API_INSECURE", "true", 0);
}

void ela_conf_update_from_env(void)
{
	struct ela_conf conf;
	const char *val;

	/* Start from the current persisted state so fields we don't touch
	 * (e.g. `remote`) are preserved. */
	ela_conf_load(&conf);

	/* output-http: prefer ELA_OUTPUT_HTTP, fall back to ELA_API_URL */
	val = getenv("ELA_OUTPUT_HTTP");
	if (!val || !*val)
		val = getenv("ELA_API_URL");
	if (val && *val)
		snprintf(conf.output_http, sizeof(conf.output_http), "%s", val);
	else
		conf.output_http[0] = '\0';

	/* output-format */
	val = getenv("ELA_OUTPUT_FORMAT");
	if (val && *val)
		snprintf(conf.output_format, sizeof(conf.output_format), "%s", val);
	else
		conf.output_format[0] = '\0';

	/* insecure: true if either insecure env var is set */
	{
		const char *api_ins = getenv("ELA_API_INSECURE");
		const char *out_ins = getenv("ELA_OUTPUT_INSECURE");

		conf.insecure =
			ela_conf_string_is_true(api_ins) ||
			ela_conf_string_is_true(out_ins)
			? 1 : 0;
	}

	ela_conf_save(&conf);
}

void ela_conf_save(const struct ela_conf *conf)
{
	int   fd;
	FILE *f;

	fd = open(ELA_CONF_PATH,
		  O_WRONLY | O_CREAT | O_TRUNC,
		  0600);
	if (fd < 0)
		return;

	f = fdopen(fd, "w");
	if (!f) {
		close(fd);
		return;
	}

	fprintf(f, "# ela agent configuration — written automatically\n");

	if (conf->remote[0])
		fprintf(f, "remote=%s\n", conf->remote);

	if (conf->output_http[0])
		fprintf(f, "output-http=%s\n", conf->output_http);

	if (conf->output_format[0])
		fprintf(f, "output-format=%s\n", conf->output_format);

	fprintf(f, "insecure=%s\n", conf->insecure ? "true" : "false");

	fclose(f); /* also closes fd */
}

/* LCOV_EXCL_STOP */
