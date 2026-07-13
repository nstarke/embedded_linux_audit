// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "linux_filesystem_audit_cmd.h"
#include "linux_audit_util.h"
#include "util/output_buffer.h"
#include "embedded_linux_audit_cmd.h"

#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <json-c/json.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

enum audit_output_format {
	AUDIT_OUTPUT_TXT,
	AUDIT_OUTPUT_CSV,
	AUDIT_OUTPUT_JSON,
};

struct fs_finding {
	char rule[32];
	char title[64];
	char severity[16];
	char evidence[512];
	char remediation[256];
	enum ela_linux_audit_status status;
};

struct fs_context {
	const char *root;
	bool quick;
	struct fs_finding *findings;
	size_t len;
	size_t cap;
	size_t unknown;
};

static const char *fs_path(const char *root, const char *relative, char *buf, size_t len)
{
	const char *prefix = (root && strcmp(root, "/")) ? root : "";

	if (!buf || !len || !relative || snprintf(buf, len, "%s%s", prefix, relative) >= (int)len)
		return NULL;
	return buf;
}

static int add_finding(struct fs_context *ctx, const char *rule, const char *title, const char *severity,
		       enum ela_linux_audit_status status, const char *evidence, const char *remediation)
{
	struct fs_finding *tmp;

	if (!ctx || !rule || !title || !evidence || !remediation)
		return -1;
	if (ctx->len == ctx->cap) {
		size_t new_cap = ctx->cap ? ctx->cap * 2 : 64;
		tmp = realloc(ctx->findings, new_cap * sizeof(*tmp));
		if (!tmp)
			return -1;
		ctx->findings = tmp;
		ctx->cap = new_cap;
	}
	snprintf(ctx->findings[ctx->len].rule, sizeof(ctx->findings[ctx->len].rule), "%s", rule);
	snprintf(ctx->findings[ctx->len].title, sizeof(ctx->findings[ctx->len].title), "%s", title);
	snprintf(ctx->findings[ctx->len].severity, sizeof(ctx->findings[ctx->len].severity), "%s", severity);
	snprintf(ctx->findings[ctx->len].evidence, sizeof(ctx->findings[ctx->len].evidence), "%s", evidence);
	snprintf(ctx->findings[ctx->len].remediation, sizeof(ctx->findings[ctx->len].remediation), "%s", remediation);
	ctx->findings[ctx->len].status = status;
	ctx->len++;
	if (status == ELA_LINUX_AUDIT_UNKNOWN)
		ctx->unknown++;
	return 0;
}

static bool under_tree(const char *path, const char *tree)
{
	size_t len;

	if (!path || !tree)
		return false;
	len = strlen(tree);
	return !strncmp(path, tree, len) && (path[len] == '\0' || path[len] == '/');
}

static void scan_entry(struct fs_context *ctx, const char *path, const char *tree, unsigned depth);

static void scan_directory(struct fs_context *ctx, const char *path, const char *tree, unsigned depth)
{
	DIR *dir;
	struct dirent *entry;

	dir = opendir(path);
	if (!dir) {
		char evidence[512];
		snprintf(evidence, sizeof(evidence), "unable to read directory %.450s: %s", path, strerror(errno));
		(void)add_finding(ctx, "ELA-FS-900", "Filesystem traversal", "low", ELA_LINUX_AUDIT_UNKNOWN, evidence,
				  "Run the audit with sufficient read permissions.");
		return;
	}
	while ((entry = readdir(dir)) != NULL) {
		char child[PATH_MAX];
		if (entry->d_name[0] == '.')
			continue;
		if (snprintf(child, sizeof(child), "%s/%s", path, entry->d_name) >= (int)sizeof(child))
			continue;
		scan_entry(ctx, child, tree, depth);
	}
	closedir(dir);
}

static void scan_entry(struct fs_context *ctx, const char *path, const char *tree, unsigned depth)
{
	struct stat st;
	char evidence[512];

	if (lstat(path, &st) != 0) {
		snprintf(evidence, sizeof(evidence), "unable to stat %.450s: %s", path, strerror(errno));
		(void)add_finding(ctx, "ELA-FS-900", "Filesystem traversal", "low", ELA_LINUX_AUDIT_UNKNOWN, evidence,
				  "Run the audit with sufficient read permissions.");
		return;
	}
	if (S_ISLNK(st.st_mode)) {
		char resolved[PATH_MAX];
		if (!realpath(path, resolved)) {
			snprintf(evidence, sizeof(evidence), "dangling or inaccessible symlink %.430s", path);
			(void)add_finding(ctx, "ELA-FS-008", "Symlink target", "medium", ELA_LINUX_AUDIT_UNKNOWN,
					  evidence, "Remove dangling links or ensure their target is trusted.");
		} else if (!under_tree(resolved, tree)) {
			snprintf(evidence, sizeof(evidence), "symlink %.220s resolves outside trusted tree to %.220s",
				 path, resolved);
			(void)add_finding(ctx, "ELA-FS-008", "Symlink escapes trusted tree", "high",
					  ELA_LINUX_AUDIT_FAIL, evidence,
					  "Replace the link or keep its target inside the trusted directory tree.");
		}
		return;
	}
	if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode)) {
		if (st.st_mode & 0077) {
			snprintf(evidence, sizeof(evidence), "device %.300s mode=%04o", path, st.st_mode & 0777);
			(void)add_finding(ctx, "ELA-FS-007", "Insecure device node", "high", ELA_LINUX_AUDIT_FAIL,
					  evidence, "Restrict device nodes to root (normally mode 0600 or tighter).");
		}
		return;
	}
	if (S_ISDIR(st.st_mode)) {
		const char *base = strrchr(path, '/');
		if (base && (!strcmp(base + 1, "proc") || !strcmp(base + 1, "sys") || !strcmp(base + 1, "run")))
			return;
		if ((st.st_mode & 0022) && (st.st_mode & 0111)) {
			snprintf(evidence, sizeof(evidence), "writable executable directory %.400s mode=%04o", path,
				 st.st_mode & 0777);
			(void)add_finding(ctx, "ELA-FS-001", "Writable executable path", "high", ELA_LINUX_AUDIT_FAIL,
					  evidence,
					  "Remove group/other write permissions from executable directories.");
		}
		if ((st.st_mode & 0002) && !(st.st_mode & S_ISVTX)) {
			snprintf(evidence, sizeof(evidence), "world-writable directory %.400s mode=%04o", path,
				 st.st_mode & 0777);
			(void)add_finding(ctx, "ELA-FS-009", "World-writable directory", "high", ELA_LINUX_AUDIT_FAIL,
					 evidence, "Restrict directory writes or set the sticky bit for shared temporary directories.");
		}
		if (!ctx->quick || depth < 1)
			scan_directory(ctx, path, tree, depth + 1);
		return;
	}
	if (!S_ISREG(st.st_mode))
		return;
	if (st.st_mode & 0002) {
		snprintf(evidence, sizeof(evidence), "world-writable file %.420s mode=%04o", path, st.st_mode & 0777);
		(void)add_finding(ctx, "ELA-FS-010", "World-writable file", "high", ELA_LINUX_AUDIT_FAIL,
				  evidence, "Remove world-write permissions from files outside approved temporary storage.");
	}
	if (strstr(path, "/boot/") || strstr(path, "/firmware/")) {
		if (st.st_mode & 0022) {
			snprintf(evidence, sizeof(evidence), "writable boot or firmware file %.400s mode=%04o", path,
					 st.st_mode & 0777);
			(void)add_finding(ctx, "ELA-FS-016", "Writable boot or firmware file", "high", ELA_LINUX_AUDIT_FAIL,
					 evidence, "Protect bootloader, kernel, device-tree, and firmware images from non-root writes.");
		}
	}
	if ((strstr(path, "/etc/init.d/") || strstr(path, "/etc/rc.d/") || strstr(path, "/etc/systemd/system/")) &&
	    (st.st_mode & 0022)) {
		snprintf(evidence, sizeof(evidence), "writable init/service script %.400s mode=%04o", path,
			 st.st_mode & 0777);
		(void)add_finding(ctx, "ELA-FS-006", "Writable init script", "high", ELA_LINUX_AUDIT_FAIL, evidence,
				  "Remove group/other write permissions from startup scripts and unit files.");
	}
	if ((st.st_mode & 0111) && (st.st_mode & 0022)) {
		snprintf(evidence, sizeof(evidence), "writable executable %.400s mode=%04o", path, st.st_mode & 0777);
		(void)add_finding(ctx, "ELA-FS-001", "Writable executable", "high", ELA_LINUX_AUDIT_FAIL, evidence,
				  "Remove group/other write permissions from executable files.");
	}
	if (st.st_mode & (S_ISUID | S_ISGID)) {
		snprintf(evidence, sizeof(evidence), "SUID/SGID file %.400s mode=%04o", path, st.st_mode & 07777);
		(void)add_finding(ctx, "ELA-FS-002", "SUID/SGID file", "medium", ELA_LINUX_AUDIT_FAIL, evidence,
				  "Review the binary and remove SUID/SGID unless it is explicitly required.");
		if (!(strstr(path, "/bin/") || strstr(path, "/sbin/")))
			(void)add_finding(ctx, "ELA-FS-011", "SUID/SGID outside allowlist", "high", ELA_LINUX_AUDIT_FAIL,
					  evidence, "Remove the privilege bit or explicitly approve the binary location.");
	}
	if (getxattr(path, "security.capability", NULL, 0) > 0) {
		snprintf(evidence, sizeof(evidence), "file capability present on %.430s", path);
		(void)add_finding(ctx, "ELA-FS-003", "File capability", "medium", ELA_LINUX_AUDIT_FAIL, evidence,
				  "Review file capabilities and remove unnecessary privilege grants.");
		if (!(strstr(path, "/bin/") || strstr(path, "/sbin/")))
			(void)add_finding(ctx, "ELA-FS-012", "File capability outside allowlist", "high", ELA_LINUX_AUDIT_FAIL,
					  evidence, "Remove capabilities from files outside approved system binary paths.");
	}
}

static void scan_sensitive(struct fs_context *ctx)
{
	static const struct {
		const char *path;
		mode_t allowed;
		const char *name;
	} files[] = {
		{ "/etc/shadow", 0640, "Sensitive shadow file" },
		{ "/etc/gshadow", 0640, "Sensitive gshadow file" },
		{ "/etc/sudoers", 0440, "Sensitive sudoers file" },
		{ "/etc/ssh/sshd_config", 0644, "SSH daemon configuration" },
	};
	size_t i;
	char path[PATH_MAX], evidence[512];
	struct stat st;

	for (i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
		if (!fs_path(ctx->root, files[i].path, path, sizeof(path)))
			continue;
		if (stat(path, &st) != 0) {
			if (errno != ENOENT)
				(void)add_finding(ctx, "ELA-FS-900", "Sensitive file access", "low",
						  ELA_LINUX_AUDIT_UNKNOWN, path,
						  "Run the audit with sufficient read permissions.");
			continue;
		}
		if ((st.st_mode & 0777) & ~files[i].allowed) {
			snprintf(evidence, sizeof(evidence), "%.400s mode=%04o allowed=%04o", path, st.st_mode & 0777,
				 files[i].allowed);
			(void)add_finding(ctx, "ELA-FS-004", files[i].name, "high", ELA_LINUX_AUDIT_FAIL, evidence,
					  "Tighten permissions and keep sensitive configuration readable only by "
					  "trusted administrators.");
		}
	}
	{
		static const char *const library_dirs[] = { "/lib", "/lib64", "/usr/lib", "/usr/lib64", NULL };
		for (i = 0; library_dirs[i]; i++) {
			if (!fs_path(ctx->root, library_dirs[i], path, sizeof(path)) || stat(path, &st) != 0)
				continue;
			if (st.st_mode & 0022) {
				snprintf(evidence, sizeof(evidence), "writable library search path %s mode=%04o", library_dirs[i], st.st_mode & 0777);
				(void)add_finding(ctx, "ELA-FS-013", "Writable library search path", "high", ELA_LINUX_AUDIT_FAIL,
						  evidence, "Restrict library directories to trusted root-owned writers.");
				(void)add_finding(ctx, "ELA-FS-014", "Writable privileged PATH component", "high", ELA_LINUX_AUDIT_FAIL,
						  evidence, "Ensure privileged service PATH components cannot be modified by unprivileged users.");
			}
		}
	}
}

static void scan_mounts(struct fs_context *ctx)
{
	char path[PATH_MAX], line[2048];
	FILE *fp;
	if (!fs_path(ctx->root, "/proc/mounts", path, sizeof(path)))
		return;
	fp = fopen(path, "r");
	if (!fp) {
		(void)add_finding(ctx, "ELA-FS-900", "Mount table", "low", ELA_LINUX_AUDIT_UNKNOWN, path,
				  "Run the audit with access to procfs.");
		return;
	}
	while (fgets(line, sizeof(line), fp)) {
		char source[512], mountpoint[PATH_MAX], type[128], options[1024];
		bool sensitive = false;
		const char *required[] = { "nodev", "nosuid", "noexec" };
		size_t i;
		if (sscanf(line, "%511s %1023s %127s %1023s", source, mountpoint, type, options) != 4)
			continue;
		sensitive = !strcmp(mountpoint, "/tmp") || !strcmp(mountpoint, "/var/tmp") ||
			    !strcmp(mountpoint, "/dev/shm");
		if (!sensitive)
			if (!strcmp(type, "overlay")) {
				char evidence[512];
				snprintf(evidence, sizeof(evidence), "overlay filesystem mounted at %.300s", mountpoint);
				(void)add_finding(ctx, "ELA-FS-015", "Overlay filesystem", "medium", ELA_LINUX_AUDIT_FAIL,
						  evidence, "Review writable overlay layers and ensure lower layers cannot be replaced.");
			}
		if (!sensitive)
			continue;
		for (i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
			if (!strstr(options, required[i])) {
				char evidence[512];
				snprintf(evidence, sizeof(evidence), "mount %.250s missing %s (options=%s)", mountpoint,
					 required[i], options);
				(void)add_finding(ctx, "ELA-FS-005", "Unsafe mount option", "medium",
						  ELA_LINUX_AUDIT_FAIL, evidence,
						  "Use nodev,nosuid,noexec on temporary and shared-memory filesystems "
						  "where compatible.");
			}
		}
	}
	fclose(fp);
}

static void scan_trusted_trees(struct fs_context *ctx)
{
	static const char *quick_roots[] = { "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/etc/init.d", "/dev", NULL };
	static const char *full_roots[] = { "/", NULL };
	const char *const *roots = ctx->quick ? quick_roots : full_roots;
	char path[PATH_MAX], tree[PATH_MAX];
	size_t i;

	for (i = 0; roots[i]; i++) {
		if (!fs_path(ctx->root, roots[i], path, sizeof(path)))
			continue;
		if (!realpath(path, tree))
			continue;
		scan_entry(ctx, path, tree, 0);
	}
}

static int append_printf(struct output_buffer *out, const char *fmt, ...)
{
	va_list ap, copy;
	char stack[1024], *heap;
	int needed, rc;
	va_start(ap, fmt);
	va_copy(copy, ap);
	needed = vsnprintf(stack, sizeof(stack), fmt, ap);
	va_end(ap);
	if (needed < 0) {
		va_end(copy);
		return -1;
	}
	if ((size_t)needed < sizeof(stack)) {
		va_end(copy);
		return output_buffer_append_len(out, stack, (size_t)needed);
	}
	heap = malloc((size_t)needed + 1);
	if (!heap) {
		va_end(copy);
		return -1;
	}
	vsnprintf(heap, (size_t)needed + 1, fmt, copy);
	va_end(copy);
	rc = output_buffer_append_len(out, heap, (size_t)needed);
	free(heap);
	return rc;
}

static int append_finding_output(struct output_buffer *out, enum audit_output_format format,
				 const struct fs_finding *finding)
{
	if (format == AUDIT_OUTPUT_CSV) {
		if (csv_write_to_buf(out, "finding") || output_buffer_append(out, ",") ||
		    csv_write_to_buf(out, finding->rule) || output_buffer_append(out, ",") ||
		    csv_write_to_buf(out, finding->title) || output_buffer_append(out, ",") ||
		    csv_write_to_buf(out, ela_linux_audit_status_name(finding->status)) ||
		    output_buffer_append(out, ",") || csv_write_to_buf(out, finding->severity) ||
		    output_buffer_append(out, ",") || csv_write_to_buf(out, finding->evidence) ||
		    output_buffer_append(out, ",") || csv_write_to_buf(out, finding->remediation) ||
		    output_buffer_append(out, "\n"))
			return -1;
		return 0;
	}
	if (format == AUDIT_OUTPUT_JSON) {
		struct json_object *obj = json_object_new_object();
		if (!obj)
			return -1;
		json_object_object_add(obj, "record", json_object_new_string("linux_audit_finding"));
		json_object_object_add(obj, "rule_id", json_object_new_string(finding->rule));
		json_object_object_add(obj, "title", json_object_new_string(finding->title));
		json_object_object_add(obj, "status",
				       json_object_new_string(ela_linux_audit_status_name(finding->status)));
		json_object_object_add(obj, "severity", json_object_new_string(finding->severity));
		json_object_object_add(obj, "category", json_object_new_string("filesystem"));
		json_object_object_add(obj, "profile", json_object_new_string("filesystem"));
		json_object_object_add(obj, "evidence", json_object_new_string(finding->evidence));
		json_object_object_add(obj, "remediation", json_object_new_string(finding->remediation));
		if (output_buffer_append(out, json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN)) ||
		    output_buffer_append(out, "\n")) {
			json_object_put(obj);
			return -1;
		}
		json_object_put(obj);
		return 0;
	}
	return append_printf(out, "[%s] %s (%s) %s\n  Evidence: %s\n  Remediation: %s\n",
			     ela_linux_audit_status_name(finding->status), finding->rule, finding->severity,
			     finding->title, finding->evidence, finding->remediation);
}

int linux_filesystem_audit_main(int argc, char **argv)
{
	struct fs_context ctx = { .root = "/" };
	struct output_buffer out = { 0 };
	enum audit_output_format format = AUDIT_OUTPUT_TXT;
	const char *format_env = getenv("ELA_OUTPUT_FORMAT");
	const char *http = getenv("ELA_OUTPUT_HTTPS");
	const char *tcp = getenv("ELA_OUTPUT_TCP");
	char *upload_uri;
	char errbuf[256];
	int opt, rc = 0;
	size_t i;
	static const struct option options[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "quick", no_argument, NULL, 'q' },
		{ "root", required_argument, NULL, 'R' },
		{ 0, 0, 0, 0 },
	};
	if (format_env && !strcmp(format_env, "csv"))
		format = AUDIT_OUTPUT_CSV;
	else if (format_env && !strcmp(format_env, "json"))
		format = AUDIT_OUTPUT_JSON;
	optind = 1;
	while ((opt = getopt_long(argc, argv, "hqR:", options, NULL)) != -1) {
		if (opt == 'h') {
			fprintf(stderr, "Usage: %s [--quick] [--root <absolute-path>]\n", argv[0]);
			return 0;
		}
		if (opt == 'q')
			ctx.quick = true;
		else if (opt == 'R')
			ctx.root = optarg;
		else if (opt != 'h') {
			fprintf(stderr, "Usage: %s [--quick] [--root <absolute-path>]\n", argv[0]);
			return 2;
		}
	}
	if (optind != argc || !ctx.root || ctx.root[0] != '/')
		return 2;
	scan_mounts(&ctx);
	scan_trusted_trees(&ctx);
	scan_sensitive(&ctx);
	if (format == AUDIT_OUTPUT_CSV)
		output_buffer_append(&out, "record,rule_id,title,status,severity,evidence,remediation\n");
	for (i = 0; i < ctx.len; i++)
		if (append_finding_output(&out, format, &ctx.findings[i])) {
			rc = 1;
			goto done;
		}
	if (format == AUDIT_OUTPUT_JSON)
		append_printf(&out,
			      "{\"record\":\"linux_audit_summary\",\"profile\":\"filesystem\",\"findings\":%zu,"
			      "\"unknown\":%zu}\n",
			      ctx.len, ctx.unknown);
	else if (format == AUDIT_OUTPUT_CSV)
		append_printf(&out, "summary,,,,findings=%zu;unknown=%zu,,\n", ctx.len, ctx.unknown);
	else
		append_printf(&out, "Summary (filesystem): findings=%zu unknown=%zu\n", ctx.len, ctx.unknown);
	if (out.len && fwrite(out.data, 1, out.len, stdout) != out.len) {
		rc = 1;
		goto done;
	}
	if (!http)
		http = getenv("ELA_OUTPUT_HTTP");
	if (tcp && *tcp) {
		int sock = ela_connect_tcp_any(tcp);
		if (sock < 0 || ela_send_all(sock, (const uint8_t *)out.data, out.len) != 0) {
			if (sock >= 0)
				close(sock);
			rc = 1;
			goto done;
		}
		close(sock);
	}
	if (http && *http) {
		upload_uri = ela_http_build_upload_uri(http, "linux-audit", NULL);
		if (!upload_uri ||
		    ela_http_post(upload_uri, (const uint8_t *)out.data, out.len,
				  format == AUDIT_OUTPUT_JSON ? "application/x-ndjson; charset=utf-8"
							      : "text/plain; charset=utf-8",
				  getenv("ELA_OUTPUT_INSECURE") && !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1"), false,
				  errbuf, sizeof(errbuf)) < 0)
			rc = 1;
		free(upload_uri);
	}
done:
	free(ctx.findings);
	free(out.data);
	return rc;
}
