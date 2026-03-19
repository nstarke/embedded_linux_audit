// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "util/list_files_filter_util.h"
#include "util/output_buffer.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [absolute-directory] [--recursive] [--suid-only] [--permissions mode] [--user name|uid] [--group name|gid]\n"
		"  List files under the given absolute directory (default: /)\n"
		"  When --recursive is set, recurse into subdirectories\n"
		"  When --suid-only is set, only files with the SUID bit set are returned\n"
		"  When --permissions is set, filter by exact octal mode (e.g. 4755) or symbolic permissions (e.g. u+rx,g-w)\n"
		"  When --user is set, only files owned by that user name or numeric uid are returned\n"
		"  When --group is set, only files owned by that group name or numeric gid are returned\n"
		"  When global --output-http is configured, POST the list to /:mac/upload/file-list\n",
		prog);
}

static int resolve_user_filter(const char *spec, uid_t *uid_out)
{
	char *end = NULL;
	unsigned long value;
	struct passwd *pwd;

	if (!spec || !*spec || !uid_out)
		return -1;

	errno = 0;
	value = strtoul(spec, &end, 10);
	if (errno == 0 && end && *end == '\0') {
		*uid_out = (uid_t)value;
		return 0;
	}

	pwd = getpwnam(spec);
	if (!pwd)
		return -1;

	*uid_out = pwd->pw_uid;
	return 0;
}

static int resolve_group_filter(const char *spec, gid_t *gid_out)
{
	char *end = NULL;
	unsigned long value;
	struct group *grp;

	if (!spec || !*spec || !gid_out)
		return -1;

	errno = 0;
	value = strtoul(spec, &end, 10);
	if (errno == 0 && end && *end == '\0') {
		*gid_out = (gid_t)value;
		return 0;
	}

	grp = getgrnam(spec);
	if (!grp)
		return -1;

	*gid_out = grp->gr_gid;
	return 0;
}

static int emit_path(const char *path,
			     int output_sock,
			     bool capture,
			     struct output_buffer *buf)
{
	char line[PATH_MAX + 2];
	int line_len;

	if (!path)
		return -1;

	line_len = snprintf(line, sizeof(line), "%s\n", path);
	if (line_len < 0 || (size_t)line_len >= sizeof(line))
		return -1;

	if (output_sock >= 0 && ela_send_all(output_sock, (const uint8_t *)line, (size_t)line_len) < 0)
		return -1;

	if (capture)
		return output_buffer_append(buf, line);

	fputs(line, stdout);
	return 0;
}

static void report_list_error(const char *output_uri,
			      bool insecure,
			      const char *fmt,
			      const char *path)
{
	char msg[PATH_MAX + 128];
	char errbuf[256];
	int n;

	if (!fmt || !path)
		return;

	n = snprintf(msg, sizeof(msg), fmt, path, strerror(errno));
	if (n < 0)
		return;

	fputs(msg, stderr);
	if (!output_uri)
		return;

	if (ela_http_post_log_message(output_uri, msg, insecure, false, errbuf, sizeof(errbuf)) < 0)
		fprintf(stderr, "Failed HTTP(S) POST log to %s: %s\n", output_uri, errbuf[0] ? errbuf : "unknown error");
}

static int list_files_recursive(const char *dir_path,
				const char *output_uri,
				bool insecure,
				int output_sock,
				bool capture,
				struct output_buffer *buf,
				bool recursive,
				const struct list_files_filters *filters)
{
	DIR *dir;
	struct dirent *de;

	dir = opendir(dir_path);
	if (!dir) {
		report_list_error(output_uri, insecure, "Cannot open directory %s: %s\n", dir_path);
		return -1;
	}

	while ((de = readdir(dir)) != NULL) {
		char child[PATH_MAX];
		struct stat st;
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

		if (lstat(child, &st) != 0) {
			report_list_error(output_uri, insecure, "Cannot stat %s: %s\n", child);
			continue;
		}

		if (S_ISDIR(st.st_mode)) {
			if (!recursive)
				continue;

			if (list_files_recursive(child, output_uri, insecure, output_sock, capture, buf, recursive, filters) != 0)
				return -1;
			continue;
		}

		if (!ela_list_files_entry_matches_filters(&st, filters))
			continue;

		if (emit_path(child, output_sock, capture, buf) != 0) {
			closedir(dir);
			return -1;
		}
	}

	closedir(dir);
	return 0;
}

int linux_list_files_scan_main(int argc, char **argv)
{
	const char *output_tcp = getenv("ELA_OUTPUT_TCP");
	const char *output_http = getenv("ELA_OUTPUT_HTTP");
	const char *output_https = getenv("ELA_OUTPUT_HTTPS");
	const char *parsed_output_http = NULL;
	const char *parsed_output_https = NULL;
	const char *output_uri = NULL;
	const char *dir_path = "/";
	bool insecure = getenv("ELA_OUTPUT_INSECURE") && !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");
	bool recursive = false;
	const char *permissions_arg = NULL;
	const char *user_arg = NULL;
	const char *group_arg = NULL;
	int output_sock = -1;
	struct stat st;
	struct output_buffer buf = {0};
	struct list_files_filters filters = {0};
	char *upload_uri = NULL;
	char errbuf[256];
	int ret = 0;
	int opt;

	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "recursive", no_argument, NULL, 'r' },
		{ "suid-only", no_argument, NULL, 's' },
		{ "permissions", required_argument, NULL, 'p' },
		{ "user", required_argument, NULL, 'u' },
		{ "group", required_argument, NULL, 'g' },
		{ 0, 0, 0, 0 }
	};

	optind = 1;
	while ((opt = getopt_long(argc, argv, "hrsp:u:g:", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'r':
			recursive = true;
			break;
		case 's':
			filters.suid_only = true;
			break;
		case 'p':
			permissions_arg = optarg;
			break;
		case 'u':
			user_arg = optarg;
			break;
		case 'g':
			group_arg = optarg;
			break;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	if (optind < argc) {
		dir_path = argv[optind++];
	}

	if (optind < argc) {
		fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
		usage(argv[0]);
		return 2;
	}

	if (!dir_path || dir_path[0] != '/') {
		fprintf(stderr, "list-files requires an absolute directory path\n");
		return 2;
	}

	if (permissions_arg && ela_parse_permissions_filter(permissions_arg, &filters.permissions) != 0) {
		fprintf(stderr, "Invalid --permissions value: %s\n", permissions_arg);
		return 2;
	}

	if (user_arg) {
		if (resolve_user_filter(user_arg, &filters.uid) != 0) {
			fprintf(stderr, "Invalid --user value: %s\n", user_arg);
			return 2;
		}
		filters.user_set = true;
	}

	if (group_arg) {
		if (resolve_group_filter(group_arg, &filters.gid) != 0) {
			fprintf(stderr, "Invalid --group value: %s\n", group_arg);
			return 2;
		}
		filters.group_set = true;
	}

	if (output_http && *output_http &&
	    ela_parse_http_output_uri(output_http,
					    &parsed_output_http,
					    &parsed_output_https,
					    NULL,
					    0) < 0) {
		fprintf(stderr, "Invalid --output-http URI (expected http://host:port/... or https://host:port/...): %s\n", output_http);
		return 2;
	}

	if (output_http && output_https) {
		fprintf(stderr, "Use only one of --output-http or --output-https\n");
		return 2;
	}

	if (parsed_output_http)
		output_uri = parsed_output_http;
	if (output_https)
		output_uri = output_https;

	if (lstat(dir_path, &st) != 0) {
		fprintf(stderr, "Cannot stat %s: %s\n", dir_path, strerror(errno));
		return 1;
	}

	if (!S_ISDIR(st.st_mode)) {
		fprintf(stderr, "list-files requires a directory path: %s\n", dir_path);
		return 2;
	}

	if (output_tcp && *output_tcp) {
		output_sock = ela_connect_tcp_ipv4(output_tcp);
		if (output_sock < 0) {
			fprintf(stderr, "Invalid/failed output target (expected IPv4:port): %s\n", output_tcp);
			return 2;
		}
	}

	if (list_files_recursive(dir_path, output_uri, insecure, output_sock, output_uri != NULL, &buf, recursive, &filters) != 0) {
		ret = 1;
		goto out;
	}

	if (output_uri) {
		upload_uri = ela_http_build_upload_uri(output_uri, "file-list", dir_path);
		if (!upload_uri) {
			fprintf(stderr, "Unable to build upload URI for %s\n", dir_path);
			ret = 1;
			goto out;
		}

		if (ela_http_post(upload_uri,
				   (const uint8_t *)(buf.data ? buf.data : ""),
				   buf.len,
				   "text/plain; charset=utf-8",
				   insecure,
				   false,
				   errbuf,
				   sizeof(errbuf)) < 0) {
			fprintf(stderr, "Failed HTTP(S) POST to %s: %s\n", upload_uri, errbuf[0] ? errbuf : "unknown error");
			ret = 1;
			goto out;
		}

		fprintf(stderr, "HTTP POST completed successfully: %s\n", upload_uri);
	}

out:
	if (output_sock >= 0)
		close(output_sock);
	free(upload_uri);
	free(buf.data);
	return ret;
}
