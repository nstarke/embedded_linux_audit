// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "linux_coredump_util.h"

#include "../embedded_linux_audit_cmd.h"
#include "../net/api_key.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static int default_mkdir(const char *path, unsigned int mode)
{
	if (mkdir(path, (mode_t)mode) == 0 || errno == EEXIST)
		return 0;
	return -1;
}

static int default_chmod(const char *path, unsigned int mode)
{
	return chmod(path, (mode_t)mode);
}

static ssize_t default_read(int fd, void *buf, size_t count)
{
	return read(fd, buf, count);
}

static ssize_t default_write(int fd, const void *buf, size_t count)
{
	return write(fd, buf, count);
}

static int default_open_file(const char *path, int flags, unsigned int mode)
{
	return open(path, flags, (mode_t)mode);
}

static int default_close(int fd)
{
	return close(fd);
}

static time_t default_time(time_t *tloc)
{
	return time(tloc);
}

static int write_all_fd(int fd, const void *buf, size_t len,
			const struct ela_coredump_ops *ops)
{
	const unsigned char *p = (const unsigned char *)buf;

	while (len) {
		ssize_t n = ops->write_fn(fd, p, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		p += (size_t)n;
		len -= (size_t)n;
	}
	return 0;
}

static int default_write_text_file(const char *path, const char *text, unsigned int mode)
{
	int fd;
	int rc = 0;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, (mode_t)mode);
	if (fd < 0)
		return -1;
	if (write_all_fd(fd, text, strlen(text), &(struct ela_coredump_ops){ .write_fn = default_write }) != 0)
		rc = -1;
	if (close(fd) != 0)
		rc = -1;
	return rc;
}

static int default_read_text_file(const char *path, char *buf, size_t buf_len)
{
	int fd;
	ssize_t n;

	if (!buf || buf_len == 0)
		return -1;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, buf, buf_len - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = '\0';
	return 0;
}

#ifdef ELA_AGENT_UNIT_TESTS
static char *default_build_upload_uri(const char *base_uri, const char *upload_type,
				      const char *file_path)
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

static void default_api_key_init(const char *api_key)
{
	(void)api_key;
}
#else
static char *default_build_upload_uri(const char *base_uri, const char *upload_type,
				      const char *file_path)
{
	return ela_http_build_upload_uri(base_uri, upload_type, file_path);
}

static int default_http_post(const char *uri, const uint8_t *data, size_t len,
			     const char *content_type, bool insecure, bool verbose,
			     char *errbuf, size_t errbuf_len)
{
	return ela_http_post(uri, data, len, content_type, insecure, verbose, errbuf, errbuf_len);
}

static void default_api_key_init(const char *api_key)
{
	ela_api_key_init(api_key);
}
#endif

static const struct ela_coredump_ops default_ops = {
	.mkdir_fn = default_mkdir,
	.chmod_fn = default_chmod,
	.write_text_file_fn = default_write_text_file,
	.read_text_file_fn = default_read_text_file,
	.read_fn = default_read,
	.write_fn = default_write,
	.open_file_fn = default_open_file,
	.close_fn = default_close,
	.time_fn = default_time,
	.build_upload_uri_fn = default_build_upload_uri,
	.http_post_fn = default_http_post,
	.api_key_init_fn = default_api_key_init,
};

static const char *nonempty_or_default(const char *value, const char *fallback)
{
	return (value && *value) ? value : fallback;
}

static bool contains_space(const char *s)
{
	for (; s && *s; s++) {
		if (isspace((unsigned char)*s))
			return true;
	}
	return false;
}

static void set_err(char *errbuf, size_t errbuf_len, const char *msg)
{
	if (errbuf && errbuf_len)
		snprintf(errbuf, errbuf_len, "%s", msg);
}

static void sanitize_component(const char *input, char *out, size_t out_len)
{
	size_t used = 0;

	if (!out || out_len == 0)
		return;
	if (!input || !*input)
		input = "unknown";
	for (; *input && used + 1 < out_len; input++) {
		unsigned char ch = (unsigned char)*input;
		out[used++] = (isalnum(ch) || ch == '.' || ch == '_' || ch == '-') ? (char)ch : '_';
	}
	out[used] = '\0';
	if (used == 0)
		snprintf(out, out_len, "unknown");
}

int ela_coredump_build_core_pattern(const char *collector_path, const char *output_dir,
				    char *out, size_t out_len)
{
	int n;

	if (!collector_path || !*collector_path || !output_dir || !*output_dir || !out || out_len == 0)
		return -1;
	if (collector_path[0] != '/' || output_dir[0] != '/' || contains_space(collector_path) ||
	    contains_space(output_dir))
		return -1;

	n = snprintf(out, out_len,
		     "|%s linux coredump collect --output-dir %s --pid %%p --signal %%s",
		     collector_path, output_dir);
	if (n < 0 || (size_t)n >= out_len)
		return -1;
	return 0;
}

int ela_coredump_write_config(const struct ela_coredump_config_request *request,
			      const struct ela_coredump_ops *ops,
			      char *errbuf, size_t errbuf_len)
{
	const struct ela_coredump_ops *effective_ops = ops ? ops : &default_ops;
	const char *config_path;
	char buf[1800];
	int n;

	if (!request)
		return -1;
	if (!request->output_uri || !*request->output_uri)
		return 0;
	if (!effective_ops->write_text_file_fn)
		return -1;

	config_path = nonempty_or_default(request->config_path, ELA_COREDUMP_DEFAULT_CONFIG_PATH);
	n = snprintf(buf, sizeof(buf), "output_uri=%s\ninsecure=%d\napi_key=%s\n",
		     request->output_uri,
		     request->insecure ? 1 : 0,
		     request->api_key ? request->api_key : "");
	if (n < 0 || (size_t)n >= sizeof(buf)) {
		set_err(errbuf, errbuf_len, "coredump: config value too long");
		return -1;
	}
	if (effective_ops->write_text_file_fn(config_path, buf, 0600) != 0) {
		set_err(errbuf, errbuf_len, "coredump: failed to write collector config");
		return -1;
	}
	return 0;
}

int ela_coredump_read_config(const char *config_path,
			     const struct ela_coredump_ops *ops,
			     struct ela_coredump_config_file *out,
			     char *errbuf, size_t errbuf_len)
{
	const struct ela_coredump_ops *effective_ops = ops ? ops : &default_ops;
	char buf[1800];
	char *line;
	char *saveptr = NULL;

	if (!out)
		return -1;
	memset(out, 0, sizeof(*out));
	if (!effective_ops->read_text_file_fn)
		return -1;
	if (effective_ops->read_text_file_fn(nonempty_or_default(config_path, ELA_COREDUMP_DEFAULT_CONFIG_PATH),
					     buf, sizeof(buf)) != 0)
		return 0;

	for (line = strtok_r(buf, "\n", &saveptr); line; line = strtok_r(NULL, "\n", &saveptr)) {
		if (!strncmp(line, "output_uri=", 11)) {
			snprintf(out->output_uri, sizeof(out->output_uri), "%s", line + 11);
		} else if (!strncmp(line, "api_key=", 8)) {
			snprintf(out->api_key, sizeof(out->api_key), "%s", line + 8);
		} else if (!strncmp(line, "insecure=", 9)) {
			out->insecure = !strcmp(line + 9, "1") || !strcmp(line + 9, "true");
		}
	}
	(void)errbuf;
	(void)errbuf_len;
	return 0;
}

int ela_coredump_configure(const struct ela_coredump_config_request *request,
			   const struct ela_coredump_ops *ops,
			   char *errbuf, size_t errbuf_len)
{
	const struct ela_coredump_ops *effective_ops = ops ? ops : &default_ops;
	const char *output_dir;
	char pattern[512];

	if (!request || !request->collector_path || !*request->collector_path) {
		set_err(errbuf, errbuf_len, "coredump: collector path is required");
		return -1;
	}
	output_dir = nonempty_or_default(request->output_dir, ELA_COREDUMP_DEFAULT_OUTPUT_DIR);

	if (ela_coredump_build_core_pattern(request->collector_path, output_dir,
					    pattern, sizeof(pattern)) != 0) {
		set_err(errbuf, errbuf_len,
			"coredump: failed to build core_pattern; use absolute paths without spaces");
		return -1;
	}

	if (effective_ops->mkdir_fn && effective_ops->mkdir_fn(output_dir, 01777) != 0) {
		set_err(errbuf, errbuf_len, "coredump: failed to create output directory");
		return -1;
	}
	if (effective_ops->chmod_fn && effective_ops->chmod_fn(output_dir, 01777) != 0) {
		set_err(errbuf, errbuf_len, "coredump: failed to chmod output directory");
		return -1;
	}
	if (effective_ops->write_text_file_fn("/proc/sys/kernel/core_pattern", pattern, 0644) != 0) {
		set_err(errbuf, errbuf_len, "coredump: failed to write /proc/sys/kernel/core_pattern");
		return -1;
	}
	(void)effective_ops->write_text_file_fn("/proc/sys/kernel/core_uses_pid", "1\n", 0644);
	(void)effective_ops->write_text_file_fn("/proc/sys/fs/suid_dumpable", "2\n", 0644);

	return ela_coredump_write_config(request, effective_ops, errbuf, errbuf_len);
}

static int append_mem(unsigned char **buf, size_t *len, size_t *cap,
		      const unsigned char *data, size_t data_len)
{
	unsigned char *new_buf;
	size_t new_cap;

	if (data_len == 0)
		return 0;
	if (*len > ((size_t)-1) - data_len)
		return -1;
	if (*len + data_len <= *cap) {
		memcpy(*buf + *len, data, data_len);
		*len += data_len;
		return 0;
	}
	new_cap = *cap ? *cap : 8192;
	while (new_cap < *len + data_len) {
		if (new_cap > ((size_t)-1) / 2)
			return -1;
		new_cap *= 2;
	}
	new_buf = realloc(*buf, new_cap);
	if (!new_buf)
		return -1;
	*buf = new_buf;
	*cap = new_cap;
	memcpy(*buf + *len, data, data_len);
	*len += data_len;
	return 0;
}

static void trim_line(char *s)
{
	size_t len;

	if (!s)
		return;
	len = strlen(s);
	while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r' ||
			   s[len - 1] == ' ' || s[len - 1] == '\t'))
		s[--len] = '\0';
}

static void read_proc_comm(const char *pid, const struct ela_coredump_ops *ops,
			   char *out, size_t out_len)
{
	char proc_path[128];

	if (!pid || !*pid || !ops->read_text_file_fn || !out || out_len == 0)
		return;
	if (snprintf(proc_path, sizeof(proc_path), "/proc/%s/comm", pid) >= (int)sizeof(proc_path))
		return;
	if (ops->read_text_file_fn(proc_path, out, out_len) == 0)
		trim_line(out);
}

/*
 * Collect a coredump payload from stdin and persist it to the configured
 * output directory, enriching metadata from /proc where available.
 *
 * Behavior summary:
 * - Uses caller-provided ops when present, otherwise falls back to defaults.
 * - Resolves configuration and output directory, then creates/permissions path.
 * - Streams coredump bytes from stdin into a dynamically grown payload buffer.
 * - Writes the final artifact and returns the selected output path via out_path.
 *
 * Error handling:
 * - Returns 0 on success, -1 on failure.
 * - errbuf is populated with a human-readable failure reason when provided.
 * - A single cleanup path (`out:`) releases transient resources.
 */
int ela_coredump_collect(const struct ela_coredump_collect_request *request,
			 const struct ela_coredump_ops *ops,
			 char *out_path, size_t out_path_len,
			 char *errbuf, size_t errbuf_len)
{
	/* Resolve dependency hooks; default_ops provides production syscalls. */
	const struct ela_coredump_ops *effective_ops = ops ? ops : &default_ops;
	struct ela_coredump_config_file config;
	const char *output_dir;
	time_t now;
	char exe[96];
	char proc_exe[96];
	char pid[32];
	char ts[32];
	char path[512];
	unsigned char tmp[8192];
	unsigned char *payload = NULL;
	size_t payload_len = 0;
	size_t payload_cap = 0;
	int fd = -1;
	int rc = -1;

	if (!request) {
		set_err(errbuf, errbuf_len, "coredump: collect request is required");
		return -1;
	}
	output_dir = nonempty_or_default(request->output_dir, ELA_COREDUMP_DEFAULT_OUTPUT_DIR);
	sanitize_component(request->pid, pid, sizeof(pid));
	proc_exe[0] = '\0';
	if (!request->exe_name || !*request->exe_name)
		read_proc_comm(pid, effective_ops, proc_exe, sizeof(proc_exe));
	sanitize_component(nonempty_or_default(request->exe_name, proc_exe), exe, sizeof(exe));
	if (request->timestamp && *request->timestamp) {
		sanitize_component(request->timestamp, ts, sizeof(ts));
	} else {
		now = effective_ops->time_fn ? effective_ops->time_fn(NULL) : time(NULL);
		snprintf(ts, sizeof(ts), "%lld", (long long)now);
	}
	if (snprintf(path, sizeof(path), "%s/core.%s.%s.%s", output_dir, exe, pid, ts) >=
	    (int)sizeof(path)) {
		set_err(errbuf, errbuf_len, "coredump: output path too long");
		return -1;
	}

	if (effective_ops->mkdir_fn && effective_ops->mkdir_fn(output_dir, 01777) != 0) {
		set_err(errbuf, errbuf_len, "coredump: failed to create output directory");
		return -1;
	}
	fd = effective_ops->open_file_fn(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0) {
		set_err(errbuf, errbuf_len, "coredump: failed to open output file");
		return -1;
	}

	for (;;) {
		ssize_t n = effective_ops->read_fn(STDIN_FILENO, tmp, sizeof(tmp));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			set_err(errbuf, errbuf_len, "coredump: failed to read core stream");
			goto out;
		}
		if (n == 0)
			break;
		if (write_all_fd(fd, tmp, (size_t)n, effective_ops) != 0) {
			set_err(errbuf, errbuf_len, "coredump: failed to write output file");
			goto out;
		}
		if (append_mem(&payload, &payload_len, &payload_cap, tmp, (size_t)n) != 0) {
			set_err(errbuf, errbuf_len, "coredump: failed to buffer core for upload");
			goto out;
		}
	}

	if (effective_ops->close_fn(fd) != 0) {
		fd = -1;
		set_err(errbuf, errbuf_len, "coredump: failed to close output file");
		goto out;
	}
	fd = -1;

	if (ela_coredump_read_config(request->config_path, effective_ops, &config,
				     errbuf, errbuf_len) != 0)
		goto out;
	if (config.output_uri[0]) {
		char *upload_uri;

		if (effective_ops->api_key_init_fn)
			effective_ops->api_key_init_fn(config.api_key[0] ? config.api_key : NULL);
		upload_uri = effective_ops->build_upload_uri_fn(config.output_uri, "coredump", path);
		if (!upload_uri) {
			set_err(errbuf, errbuf_len, "coredump: failed to build upload URI");
			goto out;
		}
		if (effective_ops->http_post_fn(upload_uri, payload ? payload : (const unsigned char *)"",
						payload_len, "application/octet-stream",
						request->insecure || config.insecure, false,
						errbuf, errbuf_len) != 0) {
			free(upload_uri);
			goto out;
		}
		free(upload_uri);
	}

	if (out_path && out_path_len)
		snprintf(out_path, out_path_len, "%s", path);
	rc = 0;

out:
	/* Unified cleanup for all success/failure paths above. */
	if (fd >= 0)
		(void)effective_ops->close_fn(fd);
	free(payload);
	/* Signal is currently informational in this implementation. */
	(void)request->signal;
	return rc;
}
