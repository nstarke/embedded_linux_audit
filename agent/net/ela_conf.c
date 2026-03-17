// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "ela_conf.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * Parsing helpers
 * ---------------------------------------------------------------------- */

static void conf_trim_right(char *s)
{
	size_t n = strlen(s);

	while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' ||
			 s[n - 1] == ' '  || s[n - 1] == '\t'))
		s[--n] = '\0';
}

static void conf_apply_line(struct ela_conf *conf, const char *line)
{
	const char *eq;
	size_t      key_len;
	const char *val;

	if (!line || *line == '#' || *line == '\0')
		return;

	eq = strchr(line, '=');
	if (!eq)
		return;

	key_len = (size_t)(eq - line);
	val     = eq + 1;

	if (key_len == 6 && !strncmp(line, "remote", 6)) {
		snprintf(conf->remote, sizeof(conf->remote), "%s", val);
	} else if (key_len == 11 && !strncmp(line, "output-http", 11)) {
		snprintf(conf->output_http, sizeof(conf->output_http), "%s", val);
	} else if (key_len == 13 && !strncmp(line, "output-format", 13)) {
		snprintf(conf->output_format, sizeof(conf->output_format), "%s", val);
	} else if (key_len == 8 && !strncmp(line, "insecure", 8)) {
		conf->insecure = (!strcmp(val, "true") || !strcmp(val, "1")) ? 1 : 0;
	}
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

void ela_conf_load(struct ela_conf *conf)
{
	FILE *f;
	char  line[600];

	memset(conf, 0, sizeof(*conf));

	f = fopen(ELA_CONF_PATH, "r");
	if (!f)
		return;

	while (fgets(line, (int)sizeof(line), f)) {
		conf_trim_right(line);
		conf_apply_line(conf, line);
	}

	fclose(f);
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
			(api_ins && (!strcmp(api_ins, "true") || !strcmp(api_ins, "1"))) ||
			(out_ins && (!strcmp(out_ins, "true") || !strcmp(out_ins, "1")))
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
