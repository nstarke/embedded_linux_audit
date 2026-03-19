// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "remote_copy_cmd_util.h"
#include "../util/remote_copy_util.h"

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static int default_write_stderr(const char *message)
{
	if (!message)
		return -1;
	return fputs(message, stderr) < 0 ? -1 : 0;
}

static const struct ela_remote_copy_execution_ops default_execution_ops = {
	.stat_fn = stat,
	.validate_request_fn = ela_remote_copy_validate_request,
	.path_is_allowed_fn = ela_path_is_allowed,
	.stat_is_copyable_file_fn = ela_stat_is_copyable_file,
	.format_summary_fn = ela_format_remote_copy_summary,
	.write_stderr_fn = default_write_stderr,
};

int ela_remote_copy_prepare_request(int argc, char **argv,
				    const struct ela_remote_copy_env *env,
				    struct ela_remote_copy_request *out,
				    char *errbuf,
				    size_t errbuf_len)
{
	int opt;

	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "recursive", no_argument, NULL, 'r' },
		{ "allow-dev", no_argument, NULL, 'D' },
		{ "allow-sysfs", no_argument, NULL, 'S' },
		{ "allow-proc", no_argument, NULL, 'P' },
		{ "allow-symlinks", no_argument, NULL, 'L' },
		{ 0, 0, 0, 0 }
	};

	if (!env || !out)
		return -1;

	memset(out, 0, sizeof(*out));
	out->output_tcp = env->output_tcp;
	out->output_http = env->output_http;
	out->output_https = env->output_https;
	out->insecure = env->insecure;
	out->verbose = env->verbose;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "hrDSPL", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			out->show_help = true;
			return 0;
		case 'r':
			out->recursive = true;
			break;
		case 'D':
			out->allow_dev = true;
			break;
		case 'S':
			out->allow_sysfs = true;
			break;
		case 'P':
			out->allow_proc = true;
			break;
		case 'L':
			out->allow_symlinks = true;
			break;
		default:
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "invalid option");
			return -1;
		}
	}

	if (optind >= argc) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "remote-copy requires an absolute file path");
		return -1;
	}

	out->path = argv[optind];
	if (!out->path || out->path[0] != '/') {
		if (errbuf && errbuf_len) {
			snprintf(errbuf, errbuf_len, "remote-copy requires an absolute file path: %s",
				 out->path ? out->path : "(null)");
		}
		return -1;
	}

	if (optind + 1 < argc) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "Unexpected argument: %s", argv[optind + 1]);
		return -1;
	}

	if (out->output_http && out->output_https) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "Use only one of --output-http or --output-https");
		return -1;
	}

	if (out->output_http)
		out->output_uri = out->output_http;
	if (out->output_https)
		out->output_uri = out->output_https;

	return 0;
}

int ela_remote_copy_execute(const struct ela_remote_copy_request *request,
			    const struct ela_remote_copy_execution_ops *ops,
			    struct ela_remote_copy_execution_result *result,
			    char *errbuf,
			    size_t errbuf_len)
{
	const struct ela_remote_copy_execution_ops *effective_ops = ops ? ops : &default_execution_ops;
	struct stat st;

	if (!request || !request->path || !effective_ops->stat_fn || !effective_ops->validate_request_fn)
		return 1;

	if (result)
		memset(result, 0, sizeof(*result));

	if (effective_ops->stat_fn(request->path, &st) != 0) {
		if (errbuf && errbuf_len) {
			snprintf(errbuf, errbuf_len, "Cannot stat %s: %s", request->path, strerror(errno));
		}
		return 1;
	}

	if (effective_ops->validate_request_fn(request->path,
						request->output_tcp,
						request->output_http,
						request->output_https,
						st.st_mode,
						errbuf,
						errbuf_len) != 0) {
		return 2;
	}

	if (effective_ops->path_is_allowed_fn &&
	    !effective_ops->path_is_allowed_fn(request->path,
						   request->allow_dev,
						   request->allow_sysfs,
						   request->allow_proc)) {
		if (errbuf && errbuf_len) {
			snprintf(errbuf, errbuf_len,
				 "Refusing to copy restricted path without allow flag: %s",
				 request->path);
		}
		return 2;
	}

	if (request->output_tcp) {
		if (effective_ops->stat_is_copyable_file_fn &&
		    !effective_ops->stat_is_copyable_file_fn(&st)) {
			if (errbuf && errbuf_len) {
				snprintf(errbuf, errbuf_len,
					 "Path is not a supported file for TCP transfer: %s",
					 request->path);
			}
			return 1;
		}
		if (!effective_ops->send_file_to_tcp_fn ||
		    effective_ops->send_file_to_tcp_fn(request->path, request->output_tcp, request->verbose) != 0) {
			return 1;
		}
		if (result)
			result->copied_files = 1;
	} else {
		if (!effective_ops->upload_path_http_fn ||
		    effective_ops->upload_path_http_fn(request->path,
						       request->output_uri,
						       request->insecure,
						       request->verbose,
						       request->recursive,
						       request->allow_dev,
						       request->allow_sysfs,
						       request->allow_proc,
						       request->allow_symlinks,
						       result ? &result->copied_files : NULL) != 0) {
			return 1;
		}
	}

	if (request->verbose && effective_ops->format_summary_fn && effective_ops->write_stderr_fn) {
		char summary[512];

		if (effective_ops->format_summary_fn(summary, sizeof(summary), request->path,
						 result ? result->copied_files : 0) == 0 &&
		    effective_ops->write_stderr_fn(summary) == 0 &&
		    result) {
			result->emitted_summary = true;
		}
	}

	return 0;
}

int ela_remote_copy_validate_request(const char *path,
				     const char *output_tcp,
				     const char *output_http,
				     const char *output_https,
				     mode_t mode,
				     char *errbuf,
				     size_t errbuf_len)
{
	const char *output_uri = NULL;

	if (!path || path[0] != '/') {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "remote-copy requires an absolute file path: %s",
				 path ? path : "(null)");
		return -1;
	}
	if (output_http && strncmp(output_http, "http://", 7)) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len,
				 "Invalid --output-http URI (expected http://host:port/...): %s",
				 output_http);
		return -1;
	}
	if (output_https && strncmp(output_https, "https://", 8)) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len,
				 "Invalid --output-https URI (expected https://host:port/...): %s",
				 output_https);
		return -1;
	}
	if (output_http && output_https) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "Use only one of --output-http or --output-https");
		return -1;
	}
	if (output_http)
		output_uri = output_http;
	if (output_https)
		output_uri = output_https;
	if ((!output_tcp || !*output_tcp) && (!output_uri || !*output_uri)) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "remote-copy requires one of --output-tcp or --output-http");
		return -1;
	}
	if (output_tcp && output_uri) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "remote-copy accepts only one remote target at a time");
		return -1;
	}
	if (output_tcp && S_ISDIR(mode)) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "Directory uploads require --output-http");
		return -1;
	}
	if (output_tcp && S_ISLNK(mode)) {
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "Symlink uploads require --output-http");
		return -1;
	}
	return 0;
}

int ela_remote_copy_format_errno_message(char *buf,
					 size_t buf_sz,
					 const char *fmt,
					 const char *path,
					 int errnum)
{
	if (!buf || buf_sz == 0 || !fmt || !path)
		return -1;

	return snprintf(buf, buf_sz, fmt, path, strerror(errnum)) >= (int)buf_sz ? -1 : 0;
}

int ela_remote_copy_join_child_path(const char *parent,
				    const char *name,
				    char *buf,
				    size_t buf_sz)
{
	if (!parent || !name || !buf || buf_sz == 0)
		return -1;

	return snprintf(buf, buf_sz, "%s/%s", parent, name) >= (int)buf_sz ? -1 : 0;
}

bool ela_remote_copy_should_recurse(mode_t mode, bool recursive)
{
	return recursive && S_ISDIR(mode);
}
