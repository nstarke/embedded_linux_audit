// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke
#include "linux_persistence_audit_cmd.h"
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
enum persist_format { PF_TXT, PF_CSV, PF_JSON };
struct persist_finding {
	const char *rule, *title, *severity, *status, *evidence, *remediation;
};
struct persist_ctx {
	const char *root;
	bool quick;
	struct persist_finding *items;
	size_t len, cap, unknown;
};
static bool path_for(const struct persist_ctx *c, const char *rel, char *out, size_t n)
{
	if (!strcmp(c->root, "/"))
		return snprintf(out, n, "%s", rel) < (int)n;
	return snprintf(out, n, "%s%s", c->root, rel) < (int)n;
}
static int add(struct persist_ctx *c, const char *rule, const char *title, const char *sev, const char *status,
	       const char *ev, const char *rem)
{
	struct persist_finding *p;
	if (c->len == c->cap) {
		size_t nc = c->cap ? c->cap * 2 : 32;
		p = realloc(c->items, nc * sizeof(*p));
		if (!p)
			return -1;
		c->items = p;
		c->cap = nc;
	}
	c->items[c->len++] = (struct persist_finding){ rule, title, sev, status, ev, rem };
	if (!strcmp(status, "unknown"))
		c->unknown++;
	return 0;
}
static bool writable(const char *path, struct stat *st)
{
	return stat(path, st) == 0 && (st->st_mode & 0022);
}
static void inspect_text(struct persist_ctx *c, const char *rel, const char *rule, const char *title)
{
	char path[PATH_MAX], line[1024], ev[512];
	FILE *fp;
	struct stat st;
	if (!path_for(c, rel, path, sizeof(path)))
		return;
	fp = fopen(path, "r");
	if (!fp) {
		if (errno != ENOENT) {
			snprintf(ev, sizeof(ev), "unable to read %s: %s", rel, strerror(errno));
			(void)add(c, "ELA-PERSIST-900", "Persistence inspection", "low", "unknown", ev,
				  "Run the audit with access to the target filesystem.");
		}
		return;
	}
	if (writable(path, &st)) {
		snprintf(ev, sizeof(ev), "%s mode=%04o", rel, st.st_mode & 07777);
		(void)add(c, rule, title, "high", "fail", ev,
			  "Remove group/other write permissions from persistence configuration.");
	}
	while (fgets(line, sizeof(line), fp)) {
		char *s = line;
		while (*s == ' ' || *s == '\t')
			s++;
		if (*s == '#' || *s == '\n' || *s == '\0')
			continue;
		if (strstr(s, "http://") || strstr(s, "https://") || strstr(s, "/tmp/") || strstr(s, "/var/tmp/") ||
		    strstr(s, "/home/")) {
			snprintf(ev, sizeof(ev), "%s contains externally sourced or transient executable: %.380s", rel,
				 s);
			(void)add(c, "ELA-PERSIST-008", "Externally sourced startup executable", "high", "fail", ev,
				  "Use a trusted, locally installed executable and verify its integrity.");
		}
	}
	fclose(fp);
}
static void scan_dir(struct persist_ctx *c, const char *rel, const char *rule, const char *title, unsigned depth)
{
	char path[PATH_MAX];
	DIR *d;
	struct dirent *e;
	if (!path_for(c, rel, path, sizeof(path)))
		return;
	d = opendir(path);
	if (!d) {
		if (errno != ENOENT) {
			char ev[512];
			snprintf(ev, sizeof(ev), "unable to enumerate %s: %s", rel, strerror(errno));
			(void)add(c, "ELA-PERSIST-900", "Persistence inspection", "low", "unknown", ev,
				  "Run the audit with access to the target filesystem.");
		}
		return;
	}
	while ((e = readdir(d))) {
		char child[PATH_MAX];
		struct stat st;
		if (e->d_name[0] == '.')
			continue;
		snprintf(child, sizeof(child), "%s/%s", rel, e->d_name);
		if (!path_for(c, child, path, sizeof(path)) || lstat(path, &st))
			continue;
		if (S_ISDIR(st.st_mode) && (!c->quick || depth == 0))
			scan_dir(c, child, rule, title, depth + 1);
		else if (S_ISREG(st.st_mode))
			inspect_text(c, child, rule, title);
	}
	closedir(d);
}
static void discover(struct persist_ctx *c)
{
	static const char *const files[] = { "/etc/inittab",
					     "/etc/rc.local",
					     "/etc/crontab",
					     "/etc/anacrontab",
					     "/etc/modules",
					     "/etc/modules-load.d/modules.conf",
					     "/etc/udev/rules.d/99-local.rules",
					     "/etc/profile",
					     "/etc/bash.bashrc",
					     NULL };
	static const struct {
		const char *rel, *rule, *title;
	} dirs[] = { { "/etc/systemd/system", "ELA-PERSIST-001", "Writable systemd unit" },
		     { "/etc/init.d", "ELA-PERSIST-002", "Writable SysV/OpenRC script" },
		     { "/etc/rc.d", "ELA-PERSIST-002", "Writable SysV/OpenRC script" },
		     { "/etc/cron.d", "ELA-PERSIST-003", "Writable cron job" },
		     { "/etc/cron.daily", "ELA-PERSIST-003", "Writable cron job" },
		     { "/etc/cron.hourly", "ELA-PERSIST-003", "Writable cron job" },
		     { "/etc/cron.weekly", "ELA-PERSIST-003", "Writable cron job" },
		     { "/etc/cron.monthly", "ELA-PERSIST-003", "Writable cron job" },
		     { "/etc/profile.d", "ELA-PERSIST-004", "Writable shell profile" },
		     { "/etc/udev/rules.d", "ELA-PERSIST-005", "Writable udev rule" },
		     { "/etc/modprobe.d", "ELA-PERSIST-006", "Writable module autoload configuration" },
		     { "/etc/modules-load.d", "ELA-PERSIST-006", "Writable module autoload configuration" },
		     { "/etc/rcS.d", "ELA-PERSIST-007", "Vendor startup mechanism" },
		     { "/etc/rc2.d", "ELA-PERSIST-007", "Vendor startup mechanism" },
		     { "/etc/rc3.d", "ELA-PERSIST-007", "Vendor startup mechanism" },
		     { "/etc/rc5.d", "ELA-PERSIST-007", "Vendor startup mechanism" },
		     { NULL, NULL, NULL } };
	size_t i;
	for (i = 0; files[i]; i++) {
		const char *r = strstr(files[i], "cron")				  ? "ELA-PERSIST-003"
				: strstr(files[i], "module")				  ? "ELA-PERSIST-006"
				: strstr(files[i], "udev")				  ? "ELA-PERSIST-005"
				: strstr(files[i], "profile") || strstr(files[i], "bash") ? "ELA-PERSIST-004"
											  : "ELA-PERSIST-007";
		inspect_text(c, files[i], r, "Writable persistence file");
	}
	for (i = 0; dirs[i].rel; i++)
		scan_dir(c, dirs[i].rel, dirs[i].rule, dirs[i].title, 0);
	if (!c->quick) {
		inspect_text(c, "/etc/rc.local", "ELA-PERSIST-007", "Vendor startup mechanism");
		inspect_text(c, "/etc/network/if-up.d/local", "ELA-PERSIST-007", "Vendor startup mechanism");
	}
}
static int appendf(struct output_buffer *o, const char *fmt, ...)
{
	va_list ap, cp;
	char b[1024], *p;
	int n, r;
	va_start(ap, fmt);
	va_copy(cp, ap);
	n = vsnprintf(b, sizeof(b), fmt, ap);
	va_end(ap);
	if (n < 0) {
		va_end(cp);
		return -1;
	}
	if ((size_t)n < sizeof(b)) {
		va_end(cp);
		return output_buffer_append_len(o, b, (size_t)n);
	}
	p = malloc((size_t)n + 1);
	if (!p) {
		va_end(cp);
		return -1;
	}
	vsnprintf(p, (size_t)n + 1, fmt, cp);
	va_end(cp);
	r = output_buffer_append_len(o, p, (size_t)n);
	free(p);
	return r;
}
static int emit(struct output_buffer *o, enum persist_format f, const struct persist_finding *x)
{
	if (f == PF_JSON) {
		struct json_object *j = json_object_new_object();
		if (!j)
			return -1;
		json_object_object_add(j, "record", json_object_new_string("linux_audit_finding"));
		json_object_object_add(j, "rule_id", json_object_new_string(x->rule));
		json_object_object_add(j, "title", json_object_new_string(x->title));
		json_object_object_add(j, "status", json_object_new_string(x->status));
		json_object_object_add(j, "severity", json_object_new_string(x->severity));
		json_object_object_add(j, "category", json_object_new_string("persistence"));
		json_object_object_add(j, "profile", json_object_new_string("persistence"));
		json_object_object_add(j, "evidence", json_object_new_string(x->evidence));
		json_object_object_add(j, "remediation", json_object_new_string(x->remediation));
		output_buffer_append(o, json_object_to_json_string_ext(j, JSON_C_TO_STRING_PLAIN));
		output_buffer_append(o, "\n");
		json_object_put(j);
		return 0;
	}
	if (f == PF_CSV)
		return appendf(o, "finding,\"%s\",\"%s\",%s,%s,\"%s\",\"%s\"\n", x->rule, x->title, x->status,
			       x->severity, x->evidence, x->remediation);
	return appendf(o, "[%s] %s (%s) %s\n  Evidence: %s\n  Remediation: %s\n", x->status, x->rule, x->severity,
		       x->title, x->evidence, x->remediation);
}
int linux_persistence_audit_main(int argc, char **argv)
{
	struct persist_ctx c = { .root = "/" };
	struct output_buffer o = { 0 };
	enum persist_format f = PF_TXT;
	const char *fe = getenv("ELA_OUTPUT_FORMAT");
	int opt;
	size_t i;
	static const struct option opts[] = { { "help", no_argument, 0, 'h' },
					      { "quick", no_argument, 0, 'q' },
					      { "root", required_argument, 0, 'R' },
					      { 0, 0, 0, 0 } };
	if (fe && !strcmp(fe, "json"))
		f = PF_JSON;
	else if (fe && !strcmp(fe, "csv"))
		f = PF_CSV;
	optind = 1;
	while ((opt = getopt_long(argc, argv, "hqR:", opts, NULL)) != -1) {
		if (opt == 'h') {
			fprintf(stderr, "Usage: %s [--quick] [--root <absolute-path>]\n", argv[0]);
			return 0;
		}
		if (opt == 'q')
			c.quick = true;
		else if (opt == 'R')
			c.root = optarg;
		else
			return 2;
	}
	if (optind != argc || c.root[0] != '/')
		return 2;
	discover(&c);
	if (f == PF_CSV)
		output_buffer_append(&o, "record,rule_id,title,status,severity,evidence,remediation\n");
	for (i = 0; i < c.len; i++)
		emit(&o, f, &c.items[i]);
	if (f == PF_JSON)
		appendf(&o,
			"{\"record\":\"linux_audit_summary\",\"profile\":\"persistence\",\"findings\":%zu,\"unknown\":%"
			"zu}\n",
			c.len, c.unknown);
	else if (f == PF_CSV)
		appendf(&o, "summary,,,,findings=%zu;unknown=%zu,,\n", c.len, c.unknown);
	else
		appendf(&o, "Summary (persistence): findings=%zu unknown=%zu\n", c.len, c.unknown);
	fwrite(o.data, 1, o.len, stdout);
	free(o.data);
	free(c.items);
	return 0;
}
