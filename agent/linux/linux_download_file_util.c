// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "linux_download_file_util.h"

#include "../embedded_linux_audit_cmd.h"
#include "../util/command_io_util.h"

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static int default_http_get_to_file(const char *uri, const char *output_path,
				    bool insecure, bool verbose,
				    char *errbuf, size_t errbuf_len)
{
#ifdef ELA_AGENT_UNIT_TESTS
	(void)uri;
	(void)output_path;
	(void)insecure;
	(void)verbose;
	if (errbuf && errbuf_len)
		errbuf[0] = '\0';
	return -1;
#else
	return ela_http_get_to_file(uri, output_path, insecure, verbose, errbuf, errbuf_len);
#endif
}

static const struct ela_download_file_ops default_download_ops = {
	.http_get_to_file_fn = default_http_get_to_file,
	.stat_fn = stat,
};

int ela_download_file_prepare_request(int argc, char **argv,
				      const struct ela_download_file_env *env,
				      struct ela_download_file_request *out,
				      char *errbuf, size_t errbuf_len)
{
	int opt;
	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ 0, 0, 0, 0 }
	};

	if (!env || !out)
		return -1;

	memset(out, 0, sizeof(*out));
	out->insecure = env->insecure;
	out->verbose = env->verbose;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "h", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			out->show_help = true;
			return 0;
		default:
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "invalid option");
			return -1;
		}
	}

	if (optind >= argc) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len,
				 "download-file requires a URL beginning with http:// or https://");
		return -1;
	}

	return ela_parse_download_file_args(argc - optind, argv + optind,
					    &out->url, &out->output_path,
					    errbuf, errbuf_len);
}

int ela_download_file_format_summary(char *buf, size_t buf_sz,
				     const struct ela_download_file_result *result,
				     const struct ela_download_file_request *request)
{
	int n;

	if (!buf || buf_sz == 0 || !result || !request || !request->url || !request->output_path)
		return -1;

	n = snprintf(buf, buf_sz,
		     "download-file downloaded %" PRIu64 " bytes success=%s url=%s output=%s\n",
		     result->downloaded_bytes,
		     result->success ? "true" : "false",
		     request->url,
		     request->output_path);
	return (n < 0 || (size_t)n >= buf_sz) ? -1 : 0;
}

int ela_download_file_run(const struct ela_download_file_request *request,
			  const struct ela_download_file_ops *ops,
			  struct ela_download_file_result *result,
			  char *errbuf, size_t errbuf_len)
{
	const struct ela_download_file_ops *effective_ops = ops ? ops : &default_download_ops;
	struct stat st;

	if (!request || !request->url || !request->output_path || !result)
		return 1;

	memset(result, 0, sizeof(*result));

	if (effective_ops->http_get_to_file_fn(request->url, request->output_path,
						request->insecure, request->verbose,
						errbuf, errbuf_len) < 0) {
		char cause[256];
		snprintf(cause, sizeof(cause), "%s",
			 (errbuf && errbuf[0]) ? errbuf : "unknown error");
		if (errbuf && errbuf_len) {
			snprintf(errbuf, errbuf_len, "Failed to download %s to %s: %s",
				 request->url, request->output_path, cause);
		}
		return 1;
	}

	if (effective_ops->stat_fn(request->output_path, &st) != 0) {
		if (errbuf && errbuf_len) {
			snprintf(errbuf, errbuf_len, "Downloaded %s but failed to stat %s: %s",
				 request->url, request->output_path, strerror(errno));
		}
		return 1;
	}

	result->downloaded_bytes = (uint64_t)st.st_size;
	result->success = true;
	if (errbuf && errbuf_len)
		errbuf[0] = '\0';
	return 0;
}
