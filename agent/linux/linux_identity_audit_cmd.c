// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke
#include "linux_identity_audit_cmd.h"
#include "linux_audit_util.h"
#include "util/output_buffer.h"
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
#include <time.h>
enum id_format { ID_TXT, ID_CSV, ID_JSON };
struct id_finding {
	const char *rule, *title, *severity, *status, *evidence, *remediation;
};
struct id_ctx {
	const char *root;
	bool quick;
	struct id_finding *items;
	size_t len, cap, unknown;
};
static bool fullpath(const struct id_ctx *c, const char *rel, char *out, size_t n)
{
	return snprintf(out, n, "%s%s", !strcmp(c->root, "/") ? "" : c->root, rel) < (int)n;
}
static void finding(struct id_ctx *c, const char *r, const char *t, const char *s, const char *st, const char *e,
		    const char *m)
{
	if (c->len == c->cap) {
		size_t n = c->cap ? c->cap * 2 : 32;
		struct id_finding *p = realloc(c->items, n * sizeof(*p));
		if (!p)
			return;
		c->items = p;
		c->cap = n;
	}
	c->items[c->len++] = (struct id_finding){ strdup(r), strdup(t), strdup(s), strdup(st), strdup(e), strdup(m) };
	if (!strcmp(st, "unknown"))
		c->unknown++;
}
static FILE *open_rel(const struct id_ctx *c, const char *rel, char *path, size_t n)
{
	if (!fullpath(c, rel, path, n))
		return NULL;
	return fopen(path, "r");
}
static void check_mode(struct id_ctx *c, const char *rel, const char *rule, const char *title, mode_t allowed)
{
	char p[PATH_MAX], e[512];
	struct stat st;
	if (!fullpath(c, rel, p, sizeof(p)) || stat(p, &st))
		return;
	if ((st.st_mode & 0777) & ~allowed) {
		snprintf(e, sizeof(e), "%s mode=%04o (allowed=%04o)", rel, st.st_mode & 07777, allowed);
		finding(c, rule, title, "high", "fail", e,
			"Restrict credential files to their owner (and required administrative group) only.");
	}
}
static void accounts(struct id_ctx *c)
{
	char p[PATH_MAX], line[1024], e[512];
	FILE *fp;
	unsigned long uid;
	int uid0 = 0;
	if (!(fp = open_rel(c, "/etc/passwd", p, sizeof(p)))) {
		finding(c, "ELA-ID-900", "Identity inspection", "low", "unknown", "unable to read /etc/passwd",
			"Run the audit with access to the target filesystem.");
		return;
	}
	while (fgets(line, sizeof(line), fp)) {
		char *save = NULL, *name = strtok_r(line, ":", &save), *pw = strtok_r(NULL, ":", &save),
		     *us = strtok_r(NULL, ":", &save), *shell;
		if (!name || !pw || !us)
			continue;
		uid = strtoul(us, NULL, 10);
		shell = strtok_r(NULL, ":", &save);
		(void)strtok_r(NULL, ":", &save);
		(void)strtok_r(NULL, ":", &save);
		shell = strtok_r(NULL, ":\n", &save);
		if (uid == 0) {
			uid0++;
			if (uid0 > 1) {
				snprintf(e, sizeof(e), "additional UID 0 account %s", name);
				finding(c, "ELA-ID-002", "Duplicate UID 0 account", "high", "fail", e,
					"Keep UID 0 assigned only to the intended administrative account.");
			}
		}
		if (uid >= 1 && uid < 1000 && strcmp(name, "sync") && strcmp(name, "shutdown") &&
		    strcmp(name, "halt") && shell && strcmp(shell, "/sbin/nologin") &&
		    strcmp(shell, "/usr/sbin/nologin") && strcmp(shell, "/bin/false") &&
		    strcmp(shell, "/usr/bin/false")) {
			snprintf(e, sizeof(e), "service account %s has interactive shell %s", name, shell);
			finding(c, "ELA-ID-003", "Interactive service account", "medium", "fail", e,
				"Assign service accounts a non-interactive shell unless interactive access is "
				"required.");
		}
	}
	fclose(fp);
	if (!(fp = open_rel(c, "/etc/shadow", p, sizeof(p)))) {
		finding(c, "ELA-ID-900", "Identity inspection", "low", "unknown",
			"unable to read /etc/shadow (hashes are never emitted)",
			"Run the audit with sufficient privileges.");
		return;
	}
	while (fgets(line, sizeof(line), fp)) {
		char *colon = strchr(line, ':'), *hash;
		if (!colon)
			continue;
		hash = colon + 1;
		if (*hash == ':') {
			*colon = '\0';
			snprintf(e, sizeof(e), "account %s has an empty password field", line);
			finding(c, "ELA-ID-001", "Empty password", "high", "fail", e,
				"Disable the account or set a strong password; password hashes are not reported.");
		}
	}
	fclose(fp);
}
static void text_checks(struct id_ctx *c, const char *rel)
{
	char p[PATH_MAX], line[1024], e[512];
	FILE *fp = open_rel(c, rel, p, sizeof(p));
	if (!fp) {
		if (errno != ENOENT)
			finding(c, "ELA-ID-900", "Identity inspection", "low", "unknown", rel,
				"Run the audit with access to the target filesystem.");
		return;
	}
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(rel, "sshd_config")) {
			if (strstr(line, "PermitRootLogin yes") || strstr(line, "PermitEmptyPasswords yes") ||
			    strstr(line, "PasswordAuthentication yes") || strstr(line, "Protocol 1")) {
				snprintf(e, sizeof(e), "unsafe SSH setting in %s", rel);
				finding(c, "ELA-ID-005", "Unsafe SSH setting", "high", "fail", e,
					"Disable root/password/empty-password SSH access and obsolete protocol "
					"versions.");
			}
		}
		if (strstr(rel, "sudoers") && (strstr(line, "NOPASSWD: ALL") || strstr(line, "ALL=(ALL) ALL"))) {
			snprintf(e, sizeof(e), "permissive sudo rule in %s", rel);
			finding(c, "ELA-ID-006", "Permissive sudo rule", "high", "fail", e,
				"Restrict sudo commands and avoid unrestricted NOPASSWD rules.");
		}
	}
	fclose(fp);
}
static void keys_dir(struct id_ctx *c, const char *rel, unsigned depth)
{
	char p[PATH_MAX];
	DIR *d;
	struct dirent *de;
	if (!fullpath(c, rel, p, sizeof(p)) || (d = opendir(p)) == NULL)
		return;
	while ((de = readdir(d))) {
		char child[PATH_MAX];
		struct stat st;
		if (de->d_name[0] == '.' && strcmp(de->d_name, "."))
			continue;
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		snprintf(child, sizeof(child), "%s/%s", rel, de->d_name);
		if (!fullpath(c, child, p, sizeof(p)) || lstat(p, &st))
			continue;
		if (S_ISDIR(st.st_mode) && depth == 0)
			keys_dir(c, child, depth + 1);
		else if (S_ISREG(st.st_mode)) {
			if (!strcmp(de->d_name, "authorized_keys")) {
				if (!c->quick && time(NULL) - st.st_mtime > 180 * 24 * 3600) {
					finding(c, "ELA-ID-004", "Stale authorized key", "medium", "fail", child,
						"Review and remove unused authorized keys regularly.");
				}
			} else if (!strncmp(de->d_name, "id_", 3) && (st.st_mode & 0077)) {
				char e[512];
				snprintf(e, sizeof(e), "private key %s mode=%04o", child, st.st_mode & 0777);
				finding(c, "ELA-ID-007", "Private key permissions", "high", "fail", e,
					"Set private keys to mode 0600 or stricter.");
			}
		}
	}
	closedir(d);
}
static int out_printf(struct output_buffer *o, const char *fmt, ...)
{
	va_list a, b;
	char s[1024], *p;
	int n, r;
	va_start(a, fmt);
	va_copy(b, a);
	n = vsnprintf(s, sizeof(s), fmt, a);
	va_end(a);
	if (n < 0) {
		va_end(b);
		return -1;
	}
	if ((size_t)n < sizeof(s)) {
		va_end(b);
		return output_buffer_append_len(o, s, (size_t)n);
	}
	p = malloc((size_t)n + 1);
	if (!p) {
		va_end(b);
		return -1;
	}
	vsnprintf(p, (size_t)n + 1, fmt, b);
	va_end(b);
	r = output_buffer_append_len(o, p, (size_t)n);
	free(p);
	return r;
}
static void emit(struct output_buffer *o, enum id_format f, const struct id_finding *x)
{
	if (f == ID_JSON) {
		struct json_object *j = json_object_new_object();
		json_object_object_add(j, "record", json_object_new_string("linux_audit_finding"));
		json_object_object_add(j, "rule_id", json_object_new_string(x->rule));
		json_object_object_add(j, "title", json_object_new_string(x->title));
		json_object_object_add(j, "status", json_object_new_string(x->status));
		json_object_object_add(j, "severity", json_object_new_string(x->severity));
		json_object_object_add(j, "category", json_object_new_string("identity"));
		json_object_object_add(j, "profile", json_object_new_string("identity"));
		json_object_object_add(j, "evidence", json_object_new_string(x->evidence));
		json_object_object_add(j, "remediation", json_object_new_string(x->remediation));
		output_buffer_append(o, json_object_to_json_string_ext(j, JSON_C_TO_STRING_PLAIN));
		output_buffer_append(o, "\n");
		json_object_put(j);
	} else if (f == ID_CSV)
		out_printf(o, "finding,\"%s\",\"%s\",%s,%s,\"%s\",\"%s\"\n", x->rule, x->title, x->status, x->severity,
			   x->evidence, x->remediation);
	else
		out_printf(o, "[%s] %s (%s) %s\n  Evidence: %s\n  Remediation: %s\n", x->status, x->rule, x->severity,
			   x->title, x->evidence, x->remediation);
}
int linux_identity_audit_main(int argc, char **argv)
{
	struct id_ctx c = { .root = "/" };
	struct output_buffer o = { 0 };
	enum id_format f = ID_TXT;
	const char *fe = getenv("ELA_OUTPUT_FORMAT");
	int op;
	size_t i;
	static const struct option os[] = { { "help", no_argument, 0, 'h' },
					    { "quick", no_argument, 0, 'q' },
					    { "root", required_argument, 0, 'R' },
					    { 0, 0, 0, 0 } };
	if (fe && !strcmp(fe, "json"))
		f = ID_JSON;
	else if (fe && !strcmp(fe, "csv"))
		f = ID_CSV;
	optind = 1;
	while ((op = getopt_long(argc, argv, "hqR:", os, NULL)) != -1) {
		if (op == 'h') {
			fprintf(stderr, "Usage: %s [--quick] [--root <absolute-path>]\n", argv[0]);
			return 0;
		}
		if (op == 'q')
			c.quick = true;
		else if (op == 'R')
			c.root = optarg;
		else
			return 2;
	}
	if (optind != argc || c.root[0] != '/')
		return 2;
	accounts(&c);
	check_mode(&c, "/etc/passwd", "ELA-ID-008", "Permissive passwd permissions", 0644);
	check_mode(&c, "/etc/shadow", "ELA-ID-008", "Permissive shadow permissions", 0640);
	check_mode(&c, "/etc/sudoers", "ELA-ID-006", "Permissive sudo file", 0440);
	text_checks(&c, "/etc/ssh/sshd_config");
	text_checks(&c, "/etc/sudoers");
	keys_dir(&c, "/root/.ssh", 0);
	keys_dir(&c, "/home", 0);
	if (f == ID_CSV)
		output_buffer_append(&o, "record,rule_id,title,status,severity,evidence,remediation\n");
	for (i = 0; i < c.len; i++)
		emit(&o, f, &c.items[i]);
	if (f == ID_JSON)
		out_printf(&o,
			   "{\"record\":\"linux_audit_summary\",\"profile\":\"identity\",\"findings\":%zu,\"unknown\":%"
			   "zu}\n",
			   c.len, c.unknown);
	else if (f == ID_CSV)
		out_printf(&o, "summary,,,,findings=%zu;unknown=%zu,,\n", c.len, c.unknown);
	else
		out_printf(&o, "Summary (identity): findings=%zu unknown=%zu\n", c.len, c.unknown);
	fwrite(o.data, 1, o.len, stdout);
	for (i = 0; i < c.len; i++) {
		free((char *)c.items[i].rule);
		free((char *)c.items[i].title);
		free((char *)c.items[i].severity);
		free((char *)c.items[i].status);
		free((char *)c.items[i].evidence);
		free((char *)c.items[i].remediation);
	}
	free(o.data);
	free(c.items);
	return 0;
}
