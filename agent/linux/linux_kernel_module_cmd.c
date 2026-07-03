// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "../arch/arch_target.h"
#include "linux_kernel_buildinfo_util.h"
#include "linux_kernel_module_util.h"
#include "util/command_io_util.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

/* Root searched for a .ko when `modules vermagic` is given no path. Defaults to
 * /lib; overridable via the ELA_MODULE_SEARCH_ROOT env var for unusual module
 * layouts (and to keep tests deterministic). */
#define ELA_MODULE_SEARCH_ROOT_DEFAULT "/lib"

static const char *module_search_root(void)
{
	const char *root = getenv("ELA_MODULE_SEARCH_ROOT");

	return (root && *root) ? root : ELA_MODULE_SEARCH_ROOT_DEFAULT;
}

/* Prefix prepended to the absolute /proc and /boot paths buildinfo reads.
 * Empty in production; tests point it at a fixture tree. */
static const char *buildinfo_root(void)
{
	const char *root = getenv("ELA_BUILDINFO_ROOT");

	return root ? root : "";
}

#ifndef SYS_finit_module
# if defined(__NR_finit_module)
#  define SYS_finit_module __NR_finit_module
# endif
#endif

#ifndef SYS_init_module
# if defined(__NR_init_module)
#  define SYS_init_module __NR_init_module
# endif
#endif

#ifndef SYS_delete_module
# if defined(__NR_delete_module)
#  define SYS_delete_module __NR_delete_module
# endif
#endif

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s list\n"
		"       %s load [--force] <module.ko> [param=value ...]\n"
		"       %s unload <module-name>\n"
		"       %s vermagic [<module.ko>]\n"
		"       %s buildinfo [<module.ko>]\n"
		"  list reads /proc/modules directly\n"
		"  load uses finit_module/init_module directly; --force ignores vermagic\n"
		"  unload uses delete_module directly\n"
		"  vermagic reads the module file and emits its path and kernel vermagic;\n"
		"    with no path, the first .ko found under " ELA_MODULE_SEARCH_ROOT_DEFAULT "\n"
		"    (or $ELA_MODULE_SEARCH_ROOT) is used\n"
		"  buildinfo emits the kernel release, /proc/version banner, module\n"
		"    vermagic, and kernel config so the server can compile a matching\n"
		"    module; the config bytes are uploaded separately as kernel-config\n"
		"    (tries `modprobe configs` first when /proc/config.gz is absent)\n",
		prog, prog, prog, prog, prog);
}

static int append_json_string(char *out, size_t out_len, size_t *pos, const char *value)
{
	size_t i;

	if (!out || !out_len || !pos || !value)
		return -1;

	for (i = 0; value[i]; i++) {
		unsigned char c = (unsigned char)value[i];
		const char *esc = NULL;
		char hex[7];
		size_t need;

		if (c == '"')
			esc = "\\\"";
		else if (c == '\\')
			esc = "\\\\";
		else if (c == '\n')
			esc = "\\n";
		else if (c == '\r')
			esc = "\\r";
		else if (c == '\t')
			esc = "\\t";

		if (esc) {
			need = strlen(esc);
			if (*pos + need >= out_len)
				return -1;
			memcpy(out + *pos, esc, need);
			*pos += need;
			continue;
		}

		if (c < 0x20) {
			snprintf(hex, sizeof(hex), "\\u%04x", c);
			need = strlen(hex);
			if (*pos + need >= out_len)
				return -1;
			memcpy(out + *pos, hex, need);
			*pos += need;
			continue;
		}

		if (*pos + 1U >= out_len)
			return -1;
		out[*pos] = (char)c;
		(*pos)++;
	}
	out[*pos] = '\0';
	return 0;
}

static int format_vermagic_payload(const char *format, const char *path,
				   const char *vermagic, char *out, size_t out_len)
{
	size_t pos;
	int n;

	if (!out || !out_len || !path || !vermagic)
		return -1;

	if (format && !strcmp(format, "json")) {
		n = snprintf(out, out_len, "{\"path\":\"");
		if (n < 0 || (size_t)n >= out_len)
			return -1;
		pos = (size_t)n;
		if (append_json_string(out, out_len, &pos, path) != 0)
			return -1;
		n = snprintf(out + pos, out_len - pos, "\",\"vermagic\":\"");
		if (n < 0 || (size_t)n >= out_len - pos)
			return -1;
		pos += (size_t)n;
		if (append_json_string(out, out_len, &pos, vermagic) != 0)
			return -1;
		n = snprintf(out + pos, out_len - pos, "\"}\n");
		return (n >= 0 && (size_t)n < out_len - pos) ? 0 : -1;
	}

	if (format && !strcmp(format, "csv"))
		n = snprintf(out, out_len, "\"%s\",\"%s\"\n", path, vermagic);
	else
		n = snprintf(out, out_len, "path=%s vermagic=%s\n", path, vermagic);

	return (n >= 0 && (size_t)n < out_len) ? 0 : -1;
}

static int emit_payload_remote(const char *payload, const char *upload_type)
{
	const char *output_tcp = getenv("ELA_OUTPUT_TCP");
	const char *output_http = getenv("ELA_OUTPUT_HTTP");
	const char *output_https = getenv("ELA_OUTPUT_HTTPS");
	const char *output_uri = output_http && *output_http ? output_http : output_https;
	const char *format = getenv("ELA_OUTPUT_FORMAT");
	bool insecure = getenv("ELA_OUTPUT_INSECURE") &&
		!strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");
	int rc = 0;
	size_t len;

	if (!payload)
		return -1;

	len = strlen(payload);
	if (output_tcp && *output_tcp) {
		int sock = ela_connect_tcp_ipv4(output_tcp);
		if (sock < 0 || ela_send_all(sock, (const uint8_t *)payload, len) != 0)
			rc = -1;
		if (sock >= 0)
			close(sock);
	}

	if (output_uri && *output_uri) {
		char errbuf[256];
		char *upload_uri = ela_http_build_upload_uri(output_uri, upload_type, NULL);

		if (!upload_uri) {
			rc = -1;
		} else if (ela_http_post(upload_uri, (const uint8_t *)payload, len,
					 ela_execute_command_content_type(format),
					 insecure, false, errbuf, sizeof(errbuf)) != 0) {
			fprintf(stderr, "Failed to POST module output to %s: %s\n",
				upload_uri, errbuf[0] ? errbuf : "unknown error");
			rc = -1;
		}
		free(upload_uri);
	}

	return rc;
}

static int list_modules(void)
{
	const char *format = getenv("ELA_OUTPUT_FORMAT");
	FILE *fp;
	char line[1024];
	struct ela_kernel_module_record rec;
	int first = 1;

	fp = fopen("/proc/modules", "r");
	if (!fp) {
		fprintf(stderr, "Cannot open /proc/modules: %s\n", strerror(errno));
		return 1;
	}

	if (format && !strcmp(format, "json"))
		printf("[\n");
	else if (format && !strcmp(format, "csv"))
		printf("name,size,refcount,dependencies,state,address\n");

	while (fgets(line, sizeof(line), fp)) {
		if (ela_kernel_module_parse_proc_line(line, &rec) != 0)
			continue;

		if (format && !strcmp(format, "json")) {
			printf("%s  {\"name\":\"%s\",\"size\":%lu,\"refcount\":%d,"
			       "\"dependencies\":\"%s\",\"state\":\"%s\",\"address\":\"%s\"}",
			       first ? "" : ",\n",
			       rec.name, rec.size, rec.refcount, rec.dependencies,
			       rec.state, rec.address);
			first = 0;
		} else if (format && !strcmp(format, "csv")) {
			printf("%s,%lu,%d,%s,%s,%s\n",
			       rec.name, rec.size, rec.refcount, rec.dependencies,
			       rec.state, rec.address);
		} else {
			printf("%-24s %10lu %4d %-32s %-10s %s\n",
			       rec.name, rec.size, rec.refcount,
			       rec.dependencies[0] ? rec.dependencies : "-",
			       rec.state, rec.address);
		}
	}

	if (format && !strcmp(format, "json"))
		printf("\n]\n");

	fclose(fp);
	return 0;
}

static int load_module(const struct ela_kernel_module_request *request)
{
	int fd;
	unsigned int flags;

	fd = open(request->module_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "Cannot open module %s: %s\n",
			request->module_path, strerror(errno));
		return 1;
	}

	flags = ela_kernel_module_load_flags(request);

#if defined(SYS_finit_module)
	if (syscall(SYS_finit_module, fd, request->params, flags) == 0) {
		close(fd);
		printf("module loaded: %s\n", request->module_path);
		return 0;
	}
	if (errno != ENOSYS) {
		fprintf(stderr, "finit_module(%s) failed: %s\n",
			request->module_path, strerror(errno));
		close(fd);
		return 1;
	}
#endif

	if (flags) {
		fprintf(stderr, "finit_module is unavailable; --force cannot be applied with init_module\n");
		close(fd);
		return 1;
	}

#if defined(SYS_init_module)
	{
		struct stat st;
		void *buf;
		ssize_t got;
		size_t off = 0;
		int rc = 1;

		if (fstat(fd, &st) != 0 || st.st_size < 0) {
			fprintf(stderr, "Cannot stat module %s: %s\n",
				request->module_path, strerror(errno));
			close(fd);
			return 1;
		}
		buf = malloc((size_t)st.st_size);
		if (!buf) {
			fprintf(stderr, "Cannot allocate module buffer\n");
			close(fd);
			return 1;
		}
		while (off < (size_t)st.st_size) {
			got = read(fd, (char *)buf + off, (size_t)st.st_size - off);
			if (got <= 0) {
				fprintf(stderr, "Cannot read module %s: %s\n",
					request->module_path,
					got < 0 ? strerror(errno) : "unexpected EOF");
				goto init_done;
			}
			off += (size_t)got;
		}
		if (syscall(SYS_init_module, buf, (unsigned long)st.st_size,
			    request->params) == 0) {
			printf("module loaded: %s\n", request->module_path);
			rc = 0;
		} else {
			fprintf(stderr, "init_module(%s) failed: %s\n",
				request->module_path, strerror(errno));
		}
init_done:
		free(buf);
		close(fd);
		return rc;
	}
#else
	fprintf(stderr, "module loading syscalls are unavailable on this platform\n");
	close(fd);
	return 1;
#endif
}

static int unload_module(const struct ela_kernel_module_request *request)
{
#if defined(SYS_delete_module)
	if (syscall(SYS_delete_module, request->module_name, O_NONBLOCK) == 0) {
		printf("module unloaded: %s\n", request->module_name);
		return 0;
	}
	fprintf(stderr, "delete_module(%s) failed: %s\n",
		request->module_name, strerror(errno));
	return 1;
#else
	fprintf(stderr, "delete_module syscall is unavailable on this platform\n");
	return 1;
#endif
}

/*
 * Recursively search `dir` for the first regular file whose name ends in ".ko"
 * and copy its full path into `out`. Returns 0 on success, -1 if none is found
 * or on error. Uses lstat() so symlinked directories are not descended into,
 * which avoids symlink loops. "First" follows readdir() order, so it is not
 * deterministic across filesystems — matching the caller's "the first one we
 * find" intent.
 */
static int find_first_ko(const char *dir, char *out, size_t out_len)
{
	DIR *d = opendir(dir);
	struct dirent *ent;
	int rc = -1;

	if (!d)
		return -1;

	while ((ent = readdir(d)) != NULL) {
		char path[PATH_MAX];
		struct stat st;

		if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
			continue;
		if (snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name) >= (int)sizeof(path))
			continue;
		if (lstat(path, &st) != 0)
			continue;

		if (S_ISDIR(st.st_mode)) {
			if (find_first_ko(path, out, out_len) == 0) {
				rc = 0;
				break;
			}
		} else if (S_ISREG(st.st_mode) &&
			   ela_kernel_module_has_ko_suffix(ent->d_name)) {
			if (snprintf(out, out_len, "%s", path) < (int)out_len) {
				rc = 0;
				break;
			}
		}
	}

	closedir(d);
	return rc;
}

/* Read the whole file at `path` into a malloc'd buffer. Returns NULL on
 * error (with a message on stderr); the caller frees the buffer. */
static unsigned char *read_whole_file(const char *path, size_t *len_out)
{
	int fd;
	struct stat st;
	unsigned char *buf;
	size_t off = 0;
	ssize_t got;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno));
		return NULL;
	}
	if (fstat(fd, &st) != 0 || st.st_size < 0) {
		fprintf(stderr, "Cannot stat %s: %s\n", path, strerror(errno));
		close(fd);
		return NULL;
	}
	buf = malloc((size_t)st.st_size ? (size_t)st.st_size : 1U);
	if (!buf) {
		fprintf(stderr, "Cannot allocate file buffer\n");
		close(fd);
		return NULL;
	}
	while (off < (size_t)st.st_size) {
		got = read(fd, buf + off, (size_t)st.st_size - off);
		if (got <= 0) {
			fprintf(stderr, "Cannot read %s: %s\n", path,
				got < 0 ? strerror(errno) : "unexpected EOF");
			free(buf);
			close(fd);
			return NULL;
		}
		off += (size_t)got;
	}
	close(fd);
	*len_out = off;
	return buf;
}

/* Resolve the module path (discovering the first .ko under the module tree
 * when `request_path` is NULL) and extract its vermagic. `found` backs the
 * returned path when discovery runs. Returns the resolved path, or NULL. */
static const char *resolve_module_vermagic(const char *request_path,
					   char *found, size_t found_len,
					   char *vermagic, size_t vermagic_len)
{
	unsigned char *buf;
	size_t len;
	const char *path = request_path;

	if (!path) {
		const char *root = module_search_root();

		if (find_first_ko(root, found, found_len) != 0) {
			fprintf(stderr, "No .ko module found under %s\n", root);
			return NULL;
		}
		path = found;
	}

	buf = read_whole_file(path, &len);
	if (!buf)
		return NULL;

	if (ela_kernel_module_extract_vermagic(buf, len,
					      vermagic, vermagic_len) != 0) {
		fprintf(stderr, "No vermagic found in module %s\n", path);
		free(buf);
		return NULL;
	}
	free(buf);
	return path;
}

static int print_vermagic(const struct ela_kernel_module_request *request)
{
	char vermagic[512];
	char payload[2048];
	char found[PATH_MAX];
	const char *path;
	const char *format = getenv("ELA_OUTPUT_FORMAT");

	path = resolve_module_vermagic(request->module_path, found, sizeof(found),
				       vermagic, sizeof(vermagic));
	if (!path)
		return 1;

	if (format_vermagic_payload(format, path, vermagic,
				    payload, sizeof(payload)) != 0) {
		fprintf(stderr, "Failed to format module vermagic output\n");
		return 1;
	}

	fputs(payload, stdout);
	if (emit_payload_remote(payload, "module-vermagic") != 0)
		return 1;

	return 0;
}

/* POST raw kernel config bytes as a kernel-config upload. Only runs when an
 * HTTP(S) output base is configured; the buildinfo JSON carries enough for
 * the server to know whether a config should have followed. */
static int upload_kernel_config(const char *config_path)
{
	const char *output_http = getenv("ELA_OUTPUT_HTTP");
	const char *output_https = getenv("ELA_OUTPUT_HTTPS");
	const char *output_uri = output_http && *output_http ? output_http : output_https;
	bool insecure = getenv("ELA_OUTPUT_INSECURE") &&
		!strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");
	unsigned char *buf;
	size_t len;
	char errbuf[256];
	char *upload_uri;
	int rc = 0;

	if (!output_uri || !*output_uri)
		return 0;

	buf = read_whole_file(config_path, &len);
	if (!buf)
		return -1;

	upload_uri = ela_http_build_upload_uri(output_uri, "kernel-config",
					       config_path);
	if (!upload_uri) {
		free(buf);
		return -1;
	}
	if (ela_http_post(upload_uri, buf, len, "application/octet-stream",
			  insecure, false, errbuf, sizeof(errbuf)) != 0) {
		fprintf(stderr, "Failed to POST kernel config to %s: %s\n",
			upload_uri, errbuf[0] ? errbuf : "unknown error");
		rc = -1;
	}
	free(upload_uri);
	free(buf);
	return rc;
}

/*
 * On kernels built with CONFIG_IKCONFIG=m, /proc/config.gz only exists after
 * the `configs` module is loaded. When modprobe is available, try it once
 * before giving up on the config. Only meaningful against the real /proc:
 * with a test fixture root, modprobe cannot create files there anyway.
 *
 * Detection deliberately avoids the shell (`command -v` and even /bin/sh
 * may be absent on embedded systems): walk PATH plus the conventional sbin
 * locations probing with access(X_OK), then fork+execv the absolute path.
 */
static void try_modprobe_configs(void)
{
	char candidate[PATH_MAX];
	char modprobe[PATH_MAX];
	unsigned int i;
	bool found = false;
	pid_t pid;

	for (i = 0; ela_kernel_buildinfo_tool_candidate(getenv("PATH"),
							"modprobe", i,
							candidate,
							sizeof(candidate)) == 0;
	     i++) {
		if (access(candidate, X_OK) == 0) {
			snprintf(modprobe, sizeof(modprobe), "%s", candidate);
			found = true;
			break;
		}
	}
	if (!found)
		return;

	pid = fork();
	if (pid < 0)
		return;
	if (pid == 0) {
		char *const argv[] = { modprobe, (char *)"configs", NULL };
		int devnull = open("/dev/null", O_WRONLY);

		if (devnull >= 0) {
			dup2(devnull, STDOUT_FILENO);
			dup2(devnull, STDERR_FILENO);
			close(devnull);
		}
		execv(modprobe, argv);
		_exit(127);
	}
	/* Best-effort: whether modprobe worked shows up as /proc/config.gz
	 * existing (or not) in the candidate scan that follows. */
	waitpid(pid, NULL, 0);
}

static int print_buildinfo(const struct ela_kernel_module_request *request)
{
	struct ela_kernel_buildinfo info;
	struct utsname uts;
	char payload[4096];
	char found[PATH_MAX];
	char candidate[PATH_MAX];
	const char *path;
	const char *format = getenv("ELA_OUTPUT_FORMAT");
	const char *root = buildinfo_root();
	char version_path[PATH_MAX];
	FILE *fp;
	unsigned int i;
	int rc = 0;

	memset(&info, 0, sizeof(info));
	info.isa = ARCH_ISA;
	info.bits = ARCH_BITS;
	info.endianness = ARCH_ENDIANNESS;

	if (uname(&uts) == 0)
		snprintf(info.kernel_release, sizeof(info.kernel_release),
			 "%s", uts.release);
	else
		fprintf(stderr, "uname failed: %s\n", strerror(errno));

	snprintf(version_path, sizeof(version_path), "%s/proc/version", root);
	fp = fopen(version_path, "r");
	if (fp) {
		if (fgets(info.proc_version, sizeof(info.proc_version), fp))
			ela_kernel_buildinfo_trim_line(info.proc_version);
		fclose(fp);
	}

	path = resolve_module_vermagic(request->module_path, found, sizeof(found),
				       info.vermagic, sizeof(info.vermagic));
	/* A host without an extractable .ko can still be served a best-effort
	 * build from kernel_release + config, so vermagic is not fatal. */
	if (path)
		snprintf(info.module_path, sizeof(info.module_path), "%s", path);

	/* IKCONFIG=m: surface /proc/config.gz by loading the configs module
	 * before looking for it. Skipped under a fixture root. */
	if (!root[0] && access("/proc/config.gz", R_OK) != 0)
		try_modprobe_configs();

	for (i = 0; i < 3; i++) {
		if (ela_kernel_buildinfo_config_candidate(root, info.kernel_release,
							  i, candidate,
							  sizeof(candidate)) != 0)
			continue;
		if (access(candidate, R_OK) == 0) {
			snprintf(info.config_source, sizeof(info.config_source),
				 "%s", candidate);
			info.config_available = true;
			info.config_compressed =
				ela_kernel_buildinfo_config_is_gz(candidate);
			break;
		}
	}

	if (ela_kernel_buildinfo_format_payload(format, &info,
						payload, sizeof(payload)) != 0) {
		fprintf(stderr, "Failed to format module buildinfo output\n");
		return 1;
	}

	fputs(payload, stdout);
	if (emit_payload_remote(payload, "module-buildinfo") != 0)
		rc = 1;
	if (info.config_available && upload_kernel_config(info.config_source) != 0)
		rc = 1;

	return rc;
}

int linux_kernel_module_main(int argc, char **argv)
{
	struct ela_kernel_module_request request;
	char errbuf[256];
	int ret;

	errbuf[0] = '\0';
	ret = ela_kernel_module_prepare_request(argc, argv, &request,
						errbuf, sizeof(errbuf));
	if (ret != 0) {
		if (errbuf[0])
			fprintf(stderr, "%s\n", errbuf);
		usage(argv[0]);
		return ret;
	}

	if (request.show_help) {
		usage(argv[0]);
		return 0;
	}

	if (request.action == ELA_KERNEL_MODULE_ACTION_LIST)
		return list_modules();
	if (request.action == ELA_KERNEL_MODULE_ACTION_LOAD)
		return load_module(&request);
	if (request.action == ELA_KERNEL_MODULE_ACTION_UNLOAD)
		return unload_module(&request);
	if (request.action == ELA_KERNEL_MODULE_ACTION_VERMAGIC)
		return print_vermagic(&request);
	if (request.action == ELA_KERNEL_MODULE_ACTION_BUILDINFO)
		return print_buildinfo(&request);

	usage(argv[0]);
	return 2;
}
