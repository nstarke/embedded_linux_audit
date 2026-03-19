// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "orom_pull_cmd_util.h"
#include "../embedded_linux_audit_cmd.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int ela_orom_build_tcp_header(char *hdr, size_t hdr_sz,
			      const char *name, size_t rom_len)
{
	int n;

	if (!hdr || hdr_sz == 0 || !name)
		return -1;

	n = snprintf(hdr, hdr_sz, "OROM %s %zu\n", name, rom_len);
	if (n < 0 || (size_t)n >= hdr_sz)
		return -1;
	return n;
}

int ela_orom_build_http_payload(const char *name,
				const uint8_t *data, size_t data_len,
				uint8_t **out, size_t *out_len)
{
	size_t name_len;
	uint8_t *payload;

	if (!name || !out || !out_len || (!data && data_len))
		return -1;

	name_len = strlen(name);
	payload = malloc(name_len + 1 + data_len);
	if (!payload)
		return -1;

	memcpy(payload, name, name_len);
	payload[name_len] = '\n';
	if (data_len)
		memcpy(payload + name_len + 1, data, data_len);

	*out = payload;
	*out_len = name_len + 1 + data_len;
	return 0;
}

int ela_orom_parse_args(int argc, char **argv,
			const char *fw_mode,
			const struct ela_orom_env *env,
			struct ela_orom_parsed_args *out,
			char *errbuf, size_t errbuf_sz)
{
	const char *action;
	const char *output_http = NULL;
	const char *output_https = NULL;
	int opt;

	static const struct option long_opts[] = {
		{ "help",        no_argument,       NULL, 'h' },
		{ "output-tcp",  required_argument, NULL, 't' },
		{ "output-http", required_argument, NULL, 'O' },
		{ 0, 0, 0, 0 }
	};

	(void)fw_mode;

	if (!out || !argv)
		return 2;

	memset(out, 0, sizeof(*out));

	/* Apply env-var defaults */
	if (env) {
		out->verbose    = env->verbose  && !strcmp(env->verbose,  "1");
		out->insecure   = env->insecure && !strcmp(env->insecure, "1");
		out->output_tcp = env->output_tcp;
		output_http     = env->output_http;
		output_https    = env->output_https;
		out->fmt        = ela_orom_detect_output_format(env->output_fmt);
	}

	if (argc < 2)
		return 2;

	action = argv[1];
	if (!strcmp(action, "-h") || !strcmp(action, "--help") ||
	    !strcmp(action, "help"))
		return 1;

	if (strcmp(action, "pull") && strcmp(action, "list")) {
		if (errbuf && errbuf_sz)
			snprintf(errbuf, errbuf_sz, "unknown action: %s", action);
		return 2;
	}

	optind = 2;
	while ((opt = getopt_long(argc, argv, "ht:O:", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			return 1;
		case 't':
			out->output_tcp = optarg;
			break;
		case 'O': {
			const char *new_http = NULL;
			const char *new_https = NULL;

			if (ela_parse_http_output_uri(optarg, &new_http,
						      &new_https, NULL, 0) < 0) {
				output_http = optarg;
			} else {
				if ((output_http && new_https) ||
				    (output_https && new_http)) {
					if (errbuf && errbuf_sz)
						snprintf(errbuf, errbuf_sz,
							 "Use only one of --output-http or --output-https");
					return 2;
				}
				output_http  = new_http;
				output_https = new_https;
			}
			break;
		}
		default:
			return 2;
		}
	}

	if (optind < argc) {
		if (errbuf && errbuf_sz)
			snprintf(errbuf, errbuf_sz,
				 "unexpected argument: %s", argv[optind]);
		return 2;
	}

	/* Validate http URI scheme */
	if (output_http && !output_https &&
	    strncmp(output_http, "http://", 7) != 0) {
		if (errbuf && errbuf_sz)
			snprintf(errbuf, errbuf_sz,
				 "Invalid --output-http URI (expected http://...): %s",
				 output_http);
		return 2;
	}

	/* Reject conflicting http + https */
	if (output_http && output_https) {
		if (errbuf && errbuf_sz)
			snprintf(errbuf, errbuf_sz,
				 "Use only one of --output-http or --output-https");
		return 2;
	}

	out->output_uri = output_http ? output_http : output_https;
	out->action     = action;

	/* pull requires at least one output target */
	if (!strcmp(action, "pull") &&
	    (!out->output_tcp || !*out->output_tcp) &&
	    (!out->output_uri || !*out->output_uri)) {
		if (errbuf && errbuf_sz)
			snprintf(errbuf, errbuf_sz,
				 "pull requires one of --output-tcp or --output-http");
		return 2;
	}

	return 0;
}
