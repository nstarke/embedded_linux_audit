// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "linux_list_symlinks_util.h"

#include "../embedded_linux_audit_cmd.h"
#include "../util/file_scan_formatter.h"

#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static int default_append_output(struct output_buffer *buf, const char *data, size_t len)
{
	return output_buffer_append_len(buf, data, len);
}

static int default_write_stdout(const char *data, size_t len)
{
	return fwrite(data, 1, len, stdout) == len ? 0 : -1;
}

#ifdef ELA_AGENT_UNIT_TESTS
static int default_parse_http_output_uri(const char *uri,
					 const char **output_http,
					 const char **output_https,
					 char *errbuf,
					 size_t errbuf_len)
{
	(void)uri;
	if (output_http)
		*output_http = NULL;
	if (output_https)
		*output_https = NULL;
	if (errbuf && errbuf_len)
		errbuf[0] = '\0';
	return -1;
}

static int default_connect_tcp_ipv4(const char *spec)
{
	(void)spec;
	return -1;
}

static int default_send_all(int sock, const uint8_t *buf, size_t len)
{
	(void)sock;
	(void)buf;
	(void)len;
	return -1;
}

static char *default_build_upload_uri(const char *base_uri, const char *upload_type, const char *file_path)
{
	(void)base_uri;
	(void)upload_type;
	(void)file_path;
	return NULL;
}

static int default_http_post(const char *uri, const uint8_t *data, size_t len,
			     const char *content_type, bool insecure, bool verbose,
			     char *errbuf, size_t errbuf_len)
{
	(void)uri;
	(void)data;
	(void)len;
	(void)content_type;
	(void)insecure;
	(void)verbose;
	if (errbuf && errbuf_len)
		errbuf[0] = '\0';
	return -1;
}

static int default_http_post_log_message(const char *base_uri, const char *message,
					 bool insecure, bool verbose,
					 char *errbuf, size_t errbuf_len)
{
	(void)base_uri;
	(void)message;
	(void)insecure;
	(void)verbose;
	if (errbuf && errbuf_len)
		errbuf[0] = '\0';
	return -1;
}
#else
static int default_parse_http_output_uri(const char *uri,
					 const char **output_http,
					 const char **output_https,
					 char *errbuf,
					 size_t errbuf_len)
{
	return ela_parse_http_output_uri(uri, output_http, output_https, errbuf, errbuf_len);
}

static int default_connect_tcp_ipv4(const char *spec)
{
	return ela_connect_tcp_ipv4(spec);
}

static int default_send_all(int sock, const uint8_t *buf, size_t len)
{
	return ela_send_all(sock, buf, len);
}

static char *default_build_upload_uri(const char *base_uri, const char *upload_type, const char *file_path)
{
	return ela_http_build_upload_uri(base_uri, upload_type, file_path);
}

static int default_http_post(const char *uri, const uint8_t *data, size_t len,
			     const char *content_type, bool insecure, bool verbose,
			     char *errbuf, size_t errbuf_len)
{
	return ela_http_post(uri, data, len, content_type, insecure, verbose, errbuf, errbuf_len);
}

static int default_http_post_log_message(const char *base_uri, const char *message,
					 bool insecure, bool verbose,
					 char *errbuf, size_t errbuf_len)
{
	return ela_http_post_log_message(base_uri, message, insecure, verbose, errbuf, errbuf_len);
}
#endif

static const struct ela_list_symlinks_prepare_ops default_prepare_ops = {
	.parse_http_output_uri_fn = default_parse_http_output_uri,
	.connect_tcp_ipv4_fn = default_connect_tcp_ipv4,
	.lstat_fn = lstat,
};

static const struct ela_list_symlinks_run_ops default_run_ops = {
	.lstat_fn = lstat,
	.readlink_fn = readlink,
	.format_symlink_record_fn = ela_format_symlink_record,
	.send_all_fn = default_send_all,
	.append_output_fn = default_append_output,
	.write_stdout_fn = default_write_stdout,
	.build_upload_uri_fn = default_build_upload_uri,
	.content_type_fn = ela_output_format_content_type,
	.http_post_fn = default_http_post,
	.http_post_log_message_fn = default_http_post_log_message,
	.close_fn = close,
};

static void set_errbuf(char *errbuf, size_t errbuf_len, const char *fmt, ...)
{
	va_list ap;

	if (!errbuf || errbuf_len == 0 || !fmt)
		return;

	va_start(ap, fmt);
	vsnprintf(errbuf, errbuf_len, fmt, ap);
	va_end(ap);
}

static bool output_format_is_valid(const char *output_format)
{
	return output_format &&
	       (!strcmp(output_format, "txt") ||
		!strcmp(output_format, "csv") ||
		!strcmp(output_format, "json"));
}

static void report_symlink_error(const struct ela_list_symlinks_request *request,
				 const struct ela_list_symlinks_run_ops *ops,
				 const char *fmt,
				 const char *path)
{
	char msg[PATH_MAX + 128];
	char errbuf[256];
	int n;

	if (!request || !fmt || !path)
		return;

	n = snprintf(msg, sizeof(msg), fmt, path, strerror(errno));
	if (n < 0)
		return;

	fputs(msg, stderr);
	if (!request->output_uri || !ops->http_post_log_message_fn)
		return;

	if (ops->http_post_log_message_fn(request->output_uri, msg, request->insecure, false,
					  errbuf, sizeof(errbuf)) < 0) {
		fprintf(stderr, "Failed HTTP(S) POST log to %s: %s\n",
			request->output_uri, errbuf[0] ? errbuf : "unknown error");
	}
}

static int emit_symlink(const struct ela_list_symlinks_request *request,
			const struct ela_list_symlinks_run_ops *ops,
			struct output_buffer *buf,
			const char *link_path,
			const char *target_path)
{
	struct output_buffer line = {0};
	int ret = -1;

	if (!request || !ops || !link_path || !target_path)
		return -1;

	if (ops->format_symlink_record_fn(&line, request->output_format, link_path, target_path) != 0)
		goto out;

	if (request->output_sock >= 0 &&
	    ops->send_all_fn(request->output_sock, (const uint8_t *)line.data, line.len) < 0)
		goto out;

	if (request->output_uri) {
		if (ops->append_output_fn(buf, line.data, line.len) != 0)
			goto out;
	} else if (ops->write_stdout_fn(line.data, line.len) != 0) {
		goto out;
	}

	ret = 0;
out:
	free(line.data);
	return ret;
}

static int list_symlinks_recursive(const struct ela_list_symlinks_request *request,
				   const struct ela_list_symlinks_run_ops *ops,
				   struct output_buffer *buf,
				   const char *dir_path)
{
	DIR *dir;
	struct dirent *de;

	dir = opendir(dir_path);
	if (!dir) {
		report_symlink_error(request, ops, "Cannot open directory %s: %s\n", dir_path);
		return -1;
	}

	while ((de = readdir(dir)) != NULL) {
		char child[PATH_MAX];
		char target[PATH_MAX];
		struct stat st;
		ssize_t target_len;
		int n;

		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;

		if (!strcmp(dir_path, "/"))
			n = snprintf(child, sizeof(child), "/%s", de->d_name);
		else
			n = snprintf(child, sizeof(child), "%s/%s", dir_path, de->d_name);
		if (n < 0 || (size_t)n >= sizeof(child)) {
			closedir(dir);
			return -1;
		}

		if (ops->lstat_fn(child, &st) != 0) {
			report_symlink_error(request, ops, "Cannot stat %s: %s\n", child);
			continue;
		}

		if (S_ISLNK(st.st_mode)) {
			target_len = ops->readlink_fn(child, target, sizeof(target) - 1);
			if (target_len < 0) {
				report_symlink_error(request, ops, "Cannot read symlink %s: %s\n", child);
				continue;
			}
			target[target_len] = '\0';

			if (emit_symlink(request, ops, buf, child, target) != 0) {
				closedir(dir);
				return -1;
			}
			continue;
		}

		if (S_ISDIR(st.st_mode) && request->recursive) {
			if (list_symlinks_recursive(request, ops, buf, child) != 0) {
				closedir(dir);
				return -1;
			}
		}
	}

	closedir(dir);
	return 0;
}

int ela_list_symlinks_prepare_request(int argc, char **argv,
				      const struct ela_list_symlinks_env *env,
				      const struct ela_list_symlinks_prepare_ops *ops,
				      struct ela_list_symlinks_request *out,
				      char *errbuf, size_t errbuf_len)
{
	const struct ela_list_symlinks_prepare_ops *effective_ops = ops ? ops : &default_prepare_ops;
	const char *parsed_output_http = NULL;
	const char *parsed_output_https = NULL;
	const char *output_format;
	struct stat st;
	int opt;

	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "recursive", no_argument, NULL, 'r' },
		{ 0, 0, 0, 0 }
	};

	if (!env || !out)
		return 1;

	memset(out, 0, sizeof(*out));
	out->dir_path = "/";
	out->output_sock = -1;
	out->insecure = env->insecure;
	output_format = env->output_format && *env->output_format ? env->output_format : "txt";

	optind = 1;
	while ((opt = getopt_long(argc, argv, "hr", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			out->show_help = true;
			out->output_format = output_format;
			return 0;
		case 'r':
			out->recursive = true;
			break;
		default:
			set_errbuf(errbuf, errbuf_len, "invalid option");
			return 2;
		}
	}

	if (optind < argc)
		out->dir_path = argv[optind++];

	if (optind < argc) {
		set_errbuf(errbuf, errbuf_len, "Unexpected argument: %s", argv[optind]);
		return 2;
	}

	if (!out->dir_path || out->dir_path[0] != '/') {
		set_errbuf(errbuf, errbuf_len, "list-symlinks requires an absolute directory path");
		return 2;
	}

	if (!output_format_is_valid(output_format)) {
		set_errbuf(errbuf, errbuf_len, "Invalid output format for list-symlinks: %s", output_format);
		return 2;
	}
	out->output_format = output_format;

	if (env->output_http && *env->output_http &&
	    effective_ops->parse_http_output_uri_fn &&
	    effective_ops->parse_http_output_uri_fn(env->output_http,
						    &parsed_output_http,
						    &parsed_output_https,
						    errbuf,
						    errbuf_len) < 0) {
		return 2;
	}

	if (env->output_http && env->output_https) {
		set_errbuf(errbuf, errbuf_len, "Use only one of --output-http or --output-https");
		return 2;
	}

	if (parsed_output_http)
		out->output_uri = parsed_output_http;
	if (parsed_output_https)
		out->output_uri = parsed_output_https;
	if (env->output_https)
		out->output_uri = env->output_https;

	if (effective_ops->lstat_fn(out->dir_path, &st) != 0) {
		set_errbuf(errbuf, errbuf_len, "Cannot stat %s: %s", out->dir_path, strerror(errno));
		return 1;
	}

	if (!S_ISDIR(st.st_mode)) {
		set_errbuf(errbuf, errbuf_len, "list-symlinks requires a directory path: %s", out->dir_path);
		return 2;
	}

	if (env->output_tcp && *env->output_tcp) {
		out->output_sock = effective_ops->connect_tcp_ipv4_fn
				 ? effective_ops->connect_tcp_ipv4_fn(env->output_tcp)
				 : -1;
		if (out->output_sock < 0) {
			set_errbuf(errbuf, errbuf_len,
				   "Invalid/failed output target (expected IPv4:port): %s",
				   env->output_tcp);
			return 2;
		}
	}

	return 0;
}

int ela_list_symlinks_run(const struct ela_list_symlinks_request *request,
			  const struct ela_list_symlinks_run_ops *ops,
			  char *errbuf, size_t errbuf_len)
{
	const struct ela_list_symlinks_run_ops *effective_ops = ops ? ops : &default_run_ops;
	struct output_buffer buf = {0};
	char *upload_uri = NULL;
	char post_err[256];
	const char *content_type;
	int ret = 0;

	if (!request || !request->dir_path || !request->output_format)
		return 1;

	if (list_symlinks_recursive(request, effective_ops, &buf, request->dir_path) != 0) {
		ret = 1;
		goto out;
	}

	if (request->output_uri) {
		upload_uri = effective_ops->build_upload_uri_fn(request->output_uri, "symlink-list",
								 request->dir_path);
		if (!upload_uri) {
			set_errbuf(errbuf, errbuf_len, "Unable to build upload URI for %s", request->dir_path);
			ret = 1;
			goto out;
		}

		content_type = effective_ops->content_type_fn(request->output_format,
							      "text/plain; charset=utf-8");
		post_err[0] = '\0';
		if (effective_ops->http_post_fn(upload_uri,
						(const uint8_t *)(buf.data ? buf.data : ""),
						buf.len,
						content_type,
						request->insecure,
						false,
						post_err,
						sizeof(post_err)) < 0) {
			set_errbuf(errbuf, errbuf_len, "Failed HTTP(S) POST to %s: %s",
				   upload_uri, post_err[0] ? post_err : "unknown error");
			ret = 1;
			goto out;
		}
	}

out:
	if (request->output_sock >= 0)
		effective_ops->close_fn(request->output_sock);
	free(upload_uri);
	free(buf.data);
	return ret;
}
