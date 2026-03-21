// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "linux/remote_copy_cmd_util.h"
#include "util/remote_copy_util.h"
#include "util/str_util.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <dirent.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <curl/curl.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <absolute-path> [--recursive] [--allow-dev] [--allow-sysfs] [--allow-proc] [--allow-symlinks]\n"
		"  Copy one local file to remote destination, or upload directory contents over HTTP(S)\n"
		"  --recursive                    Recurse into subdirectories when source is a directory\n"
		"  --allow-dev                    Allow copying paths under /dev\n"
		"  --allow-sysfs                  Allow copying paths under /sys\n"
		"  --allow-proc                   Allow copying paths under /proc\n"
		"  --allow-symlinks               Upload symlinks as symlinks over HTTP(S)\n",
		prog);
}

static int write_stderr_message(const char *message)
{
	if (!message)
		return -1;
	return fputs(message, stderr) < 0 ? -1 : 0;
}

static void report_remote_copy_http_error(const char *output_uri,
					 bool insecure,
					 bool verbose,
					 const char *message)
{
	char errbuf[256];

	if (!message || !*message) {
		return;
	}

	fputs(message, stderr);
	if (!output_uri || !*output_uri) {
		return;
	}

	if (ela_http_post_log_message(output_uri, message, insecure, verbose, errbuf, sizeof(errbuf)) < 0) {
		fprintf(stderr, "Failed HTTP(S) POST log to %s: %s\n", output_uri,
			errbuf[0] ? errbuf : "unknown error");
	}
}

static void report_remote_copy_errno(const char *output_uri,
				     bool insecure,
				     bool verbose,
				     const char *fmt,
				     const char *path)
{
	char message[PATH_MAX + 128];
	int saved_errno = errno;
	int n;

	if (!fmt || !path) {
		return;
	}

	n = ela_remote_copy_format_errno_message(message, sizeof(message), fmt, path, saved_errno);
	if (n < 0) {
		return;
	}

	report_remote_copy_http_error(output_uri, insecure, verbose, message);
}

static int send_symlink_to_http(const char *path, const char *output_uri, bool insecure, bool verbose)
{
	char errbuf[256];
	char target[PATH_MAX];
	char *upload_uri = NULL;
	ssize_t target_len;

	target_len = readlink(path, target, sizeof(target) - 1);
	if (target_len < 0) {
		report_remote_copy_errno(output_uri, insecure, verbose,
			"Cannot read symlink %s: %s\n", path);
		return -1;
	}
	target[target_len] = '\0';

	upload_uri = ela_http_build_upload_uri(output_uri, "file", path);
	if (!upload_uri) {
		char message[PATH_MAX + 64];
		snprintf(message, sizeof(message), "Unable to build upload URI for symlink %s\n", path);
		report_remote_copy_http_error(output_uri, insecure, verbose, message);
		return -1;
	}

		{
			char *final_uri = ela_remote_copy_build_symlink_upload_uri(upload_uri, target);
			if (!final_uri) {
				report_remote_copy_http_error(output_uri, insecure, verbose,
					"Unable to allocate upload URI for symlink\n");
				free(upload_uri);
				return -1;
			}
			free(upload_uri);
			upload_uri = final_uri;
		}

	if (ela_http_post(upload_uri,
			   (const uint8_t *)"",
			   0,
			   "application/octet-stream",
			   insecure,
			   verbose,
			   errbuf,
			   sizeof(errbuf)) < 0) {
		char message[PATH_MAX + 384];
		snprintf(message, sizeof(message), "Failed HTTP(S) POST symlink %s to %s: %s\n",
			path, upload_uri, errbuf[0] ? errbuf : "unknown error");
		report_remote_copy_http_error(output_uri, insecure, verbose, message);
		free(upload_uri);
		return -1;
	}

	free(upload_uri);
	return 0;
}

static int send_file_to_tcp(const char *path, const char *output_tcp, bool verbose)
{
	uint8_t buf[4096];
	int fd;
	int sock;
	(void)verbose;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno));
		return -1;
	}

	sock = ela_connect_tcp_ipv4(output_tcp);
	if (sock < 0) {
		fprintf(stderr, "Invalid/failed output target (expected IPv4:port): %s\n", output_tcp);
		close(fd);
		return -1;
	}

	for (;;) {
		ssize_t n = read(fd, buf, sizeof(buf));
		if (n < 0) {
			fprintf(stderr, "Read failure on %s: %s\n", path, strerror(errno));
			close(sock);
			close(fd);
			return -1;
		}
		if (n == 0)
			break;
		if (ela_send_all(sock, buf, (size_t)n) < 0) {
			fprintf(stderr, "Failed sending bytes to %s\n", output_tcp);
			close(sock);
			close(fd);
			return -1;
		}
	}

	close(sock);
	close(fd);
	return 0;
}

static int send_file_to_http(const char *path, const char *output_uri, bool insecure, bool verbose)
{
	char errbuf[256];
	char *upload_uri = NULL;
	uint8_t *data = NULL;
	size_t data_len = 0;
	size_t data_cap = 0;
	int fd = -1;
	int rc = -1;
	(void)verbose;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		report_remote_copy_errno(output_uri, insecure, verbose,
			"Cannot open %s: %s\n", path);
		return -1;
	}

	for (;;) {
		uint8_t chunk[4096];
		ssize_t got = read(fd, chunk, sizeof(chunk));
		if (got < 0) {
			report_remote_copy_errno(output_uri, insecure, verbose,
				"Read failure on %s: %s\n", path);
			goto out;
		}
		if (got == 0)
			break;

		if (data_len + (size_t)got > data_cap) {
			size_t new_cap = data_cap ? data_cap : 4096;
			uint8_t *tmp;

			while (new_cap < data_len + (size_t)got)
				new_cap *= 2;

			tmp = realloc(data, new_cap);
			if (!tmp) {
				char message[PATH_MAX + 64];
				snprintf(message, sizeof(message), "Unable to grow upload buffer for %s\n", path);
				report_remote_copy_http_error(output_uri, insecure, verbose, message);
				goto out;
			}
			data = tmp;
			data_cap = new_cap;
		}

		memcpy(data + data_len, chunk, (size_t)got);
		data_len += (size_t)got;
	}

	upload_uri = ela_http_build_upload_uri(output_uri, "file", path);
	if (!upload_uri) {
		char message[PATH_MAX + 64];
		snprintf(message, sizeof(message), "Unable to build upload URI for %s\n", path);
		report_remote_copy_http_error(output_uri, insecure, verbose, message);
		goto out;
	}

	if (ela_http_post(upload_uri,
			   data,
			   data_len,
			   "application/octet-stream",
			   insecure,
			   verbose,
			   errbuf,
			   sizeof(errbuf)) < 0) {
		char message[PATH_MAX + 384];
		snprintf(message, sizeof(message), "Failed HTTP(S) POST file %s to %s: %s\n",
			path, upload_uri, errbuf[0] ? errbuf : "unknown error");
		report_remote_copy_http_error(output_uri, insecure, verbose, message);
		goto out;
	}

	rc = 0;

out:
	free(upload_uri);
	free(data);
	if (fd >= 0)
		close(fd);
	return rc;
}

static int upload_path_http(const char *path,
			    const char *output_uri,
			    bool insecure,
			    bool verbose,
			    bool recursive,
			    bool allow_dev,
			    bool allow_sysfs,
			    bool allow_proc,
			    bool allow_symlinks,
			    uint64_t *copied_files)
{
	struct stat st;

	if (!ela_path_is_allowed(path, allow_dev, allow_sysfs, allow_proc)) {
		char message[PATH_MAX + 96];
		snprintf(message, sizeof(message), "Refusing to copy restricted path without allow flag: %s\n", path);
		report_remote_copy_http_error(output_uri, insecure, verbose, message);
		return -1;
	}

	/* coverity[toctou] */
	if (lstat(path, &st) != 0) {
		report_remote_copy_errno(output_uri, insecure, verbose,
			"Cannot stat %s: %s\n", path);
		return -1;
	}

	if (S_ISLNK(st.st_mode)) {
		if (!allow_symlinks) {
			if (verbose)
				fprintf(stderr, "Skipping symlink without --allow-symlinks: %s\n", path);
			return 0;
		}
		if (send_symlink_to_http(path, output_uri, insecure, verbose) == 0) {
			if (copied_files)
				(*copied_files)++;
			return 0;
		}
		return -1;
	}

	if (S_ISDIR(st.st_mode)) {
		DIR *dir;
		struct dirent *de;
		int rc = 0;

		dir = opendir(path);
		if (!dir) {
			report_remote_copy_errno(output_uri, insecure, verbose,
				"Cannot open directory %s: %s\n", path);
			return -1;
		}

		while ((de = readdir(dir)) != NULL) {
			char *child;
			size_t child_len;
			int child_rc;
			struct stat child_st;

			if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
				continue;

			child_len = strlen(path) + 1 + strlen(de->d_name) + 1;
			child = malloc(child_len);
			if (!child) {
				report_remote_copy_http_error(output_uri, insecure, verbose,
					"Unable to allocate path buffer during recursive remote-copy\n");
				rc = -1;
				break;
			}
			if (ela_remote_copy_join_child_path(path, de->d_name, child, child_len) != 0) {
				report_remote_copy_http_error(output_uri, insecure, verbose,
					"Unable to format recursive child path during remote-copy\n");
				free(child);
				rc = -1;
				break;
			}

			if (lstat(child, &child_st) != 0) {
				report_remote_copy_errno(output_uri, insecure, verbose,
					"Cannot stat %s: %s\n", child);
				free(child);
				rc = -1;
				continue;
			}

			if (S_ISDIR(child_st.st_mode) && !ela_remote_copy_should_recurse(child_st.st_mode, recursive)) {
				free(child);
				continue;
			}

			child_rc = upload_path_http(child, output_uri, insecure, verbose,
				recursive, allow_dev, allow_sysfs, allow_proc, allow_symlinks,
				copied_files);
			free(child);
			if (child_rc != 0) {
				rc = -1;
				continue;
			}
		}

		closedir(dir);
		return rc;
	}

	if (!ela_stat_is_copyable_file(&st)) {
		if (verbose)
			fprintf(stderr, "Skipping unsupported file type: %s\n", path);
		return 0;
	}

	if (send_file_to_http(path, output_uri, insecure, verbose) == 0) {
		if (copied_files)
			(*copied_files)++;
		return 0;
	}

	return -1;
}

int linux_remote_copy_scan_main(int argc, char **argv)
{
	struct ela_remote_copy_env env = {
		.output_tcp = getenv("ELA_OUTPUT_TCP"),
		.output_http = getenv("ELA_OUTPUT_HTTP"),
		.output_https = getenv("ELA_OUTPUT_HTTPS"),
		.insecure = getenv("ELA_OUTPUT_INSECURE") && !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1"),
		.verbose = getenv("ELA_VERBOSE") && !strcmp(getenv("ELA_VERBOSE"), "1"),
	};
	struct ela_remote_copy_request request;
	struct ela_remote_copy_execution_result result;
	struct ela_remote_copy_execution_ops ops = {
		.stat_fn = stat,
		.validate_request_fn = ela_remote_copy_validate_request,
		.path_is_allowed_fn = ela_path_is_allowed,
		.stat_is_copyable_file_fn = ela_stat_is_copyable_file,
		.send_file_to_tcp_fn = send_file_to_tcp,
		.upload_path_http_fn = upload_path_http,
		.format_summary_fn = ela_format_remote_copy_summary,
		.write_stderr_fn = write_stderr_message,
	};
	char errbuf[256];
	int rc;

	rc = ela_remote_copy_prepare_request(argc, argv, &env, &request, errbuf, sizeof(errbuf));
	if (rc != 0) {
		fprintf(stderr, "%s\n", errbuf);
		if (strstr(errbuf, "Unexpected argument:") == NULL &&
		    strstr(errbuf, "absolute file path:") == NULL &&
		    strstr(errbuf, "Use only one of --output-http or --output-https") == NULL)
			usage(argv[0]);
		return 2;
	}

	if (request.show_help) {
		usage(argv[0]);
		return 0;
	}

	rc = ela_remote_copy_execute(&request, &ops, &result, errbuf, sizeof(errbuf));
	if (rc != 0 && errbuf[0])
		fprintf(stderr, "%s\n", errbuf);
	return rc;
}
