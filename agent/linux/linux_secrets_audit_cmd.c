// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_secrets_audit_cmd.h"
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
enum secret_format { SF_TXT, SF_CSV, SF_JSON };
struct secret_finding {
	char *rule, *title, *status, *location, *fingerprint, *content;
};
struct secret_ctx {
	const char *root;
	bool quick, collect;
	struct secret_finding *items;
	size_t len, cap, unknown;
};
static bool path_for(const struct secret_ctx *c, const char *rel, char *out, size_t n)
{
	return snprintf(out, n, "%s%s", !strcmp(c->root, "/") ? "" : c->root, rel) < (int)n;
}
static unsigned long long fingerprint(const char *s)
{
	unsigned long long h = 1469598103934665603ULL;
	while (*s) {
		h ^= (unsigned char)*s++;
		h *= 1099511628211ULL;
	}
	return h;
}
static void add(struct secret_ctx *c, const char *rule, const char *title, const char *status, const char *location,
		const char *value)
{
	if (c->len == c->cap) {
		size_t n = c->cap ? c->cap * 2 : 32;
		struct secret_finding *p = realloc(c->items, n * sizeof(*p));
		if (!p)
			return;
		c->items = p;
		c->cap = n;
	}
	struct secret_finding *f = &c->items[c->len++];
	char fp[32];
	snprintf(fp, sizeof(fp), "fnv64:%016llx", fingerprint(value));
	f->rule = strdup(rule);
	f->title = strdup(title);
	f->status = strdup(status);
	f->location = strdup(location);
	f->fingerprint = strdup(fp);
	f->content = c->collect ? strdup(value) : strdup("[redacted]");
	if (!strcmp(status, "unknown"))
		c->unknown++;
}
static bool candidate(const char *name)
{
	return strstr(name, ".conf") || strstr(name, ".cfg") || strstr(name, ".ini") || strstr(name, ".env") ||
	       strstr(name, ".yaml") || strstr(name, ".yml") || strstr(name, ".json") || strstr(name, ".xml") ||
	       strstr(name, ".toml") || strstr(name, ".key") || strstr(name, ".pem") || strstr(name, ".crt") ||
	       strstr(name, ".service") || !strcmp(name, "passwd") || !strcmp(name, "shadow");
}
static void inspect_file(struct secret_ctx *c, const char *rel)
{
	char path[PATH_MAX], line[2048];
	FILE *f;
	unsigned line_no = 0;
	if (!path_for(c, rel, path, sizeof(path)) || !(f = fopen(path, "r"))) {
		if (errno != ENOENT)
			add(c, "ELA-SEC-900", "Secret inspection", "unknown", rel, "unreadable");
		return;
	}
	while (fgets(line, sizeof(line), f)) {
		char *s = line;
		bool hit = false;
		const char *rule = "ELA-SEC-001", *title = "Potential secret";
		line_no++;
		while (*s == ' ' || *s == '\t')
			s++;
		if (strstr(s, "-----BEGIN") && strstr(s, "PRIVATE KEY-----")) {
			hit = true;
			rule = "ELA-SEC-002";
			title = "Private key material";
		} else if (strstr(s, "AKIA") || strstr(s, "Authorization: Bearer") || strstr(s, "api_key") ||
			   strstr(s, "apikey") || strstr(s, "access_token") || strstr(s, "client_secret")) {
			hit = true;
			rule = "ELA-SEC-001";
			title = "API key or token";
		} else if ((strstr(s, "password=") || strstr(s, "passwd=") || strstr(s, "default_password")) &&
			   !strstr(s, "${")) {
			hit = true;
			rule = "ELA-SEC-003";
			title = "Default or embedded credential";
		} else {
			size_t n = strlen(s);
			bool upper = false, lower = false, digit = false;
			size_t i;
			for (i = 0; i < n && i < 160; i++) {
				if (s[i] >= 'A' && s[i] <= 'Z')
					upper = true;
				if (s[i] >= 'a' && s[i] <= 'z')
					lower = true;
				if (s[i] >= '0' && s[i] <= '9')
					digit = true;
			}
			if (n >= 40 && upper && lower && digit) {
				hit = true;
				rule = "ELA-SEC-004";
				title = "High-entropy string";
			}
		}
		if (hit) {
			char location[PATH_MAX + 32];
			snprintf(location, sizeof(location), "%s:%u", rel, line_no);
			add(c, rule, title, "fail", location, s);
		}
	}
	fclose(f);
}
static void scan_dir(struct secret_ctx *c, const char *rel, unsigned depth)
{
	char path[PATH_MAX];
	DIR *d;
	struct dirent *e;
	if (!path_for(c, rel, path, sizeof(path)) || !(d = opendir(path)))
		return;
	while ((e = readdir(d))) {
		char child[PATH_MAX];
		struct stat st;
		if (e->d_name[0] == '.')
			continue;
		snprintf(child, sizeof(child), "%s/%s", rel, e->d_name);
		if (!path_for(c, child, path, sizeof(path)) || lstat(path, &st))
			continue;
		if (S_ISDIR(st.st_mode) && (!c->quick || depth < 1))
			scan_dir(c, child, depth + 1);
		else if (S_ISREG(st.st_mode) && candidate(e->d_name))
			inspect_file(c, child);
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
static void emit(struct output_buffer *o, enum secret_format f, const struct secret_finding *x)
{
	if (f == SF_JSON) {
		struct json_object *j = json_object_new_object();
		json_object_object_add(j, "record", json_object_new_string("linux_audit_finding"));
		json_object_object_add(j, "rule_id", json_object_new_string(x->rule));
		json_object_object_add(j, "title", json_object_new_string(x->title));
		json_object_object_add(j, "status", json_object_new_string(x->status));
		json_object_object_add(j, "category", json_object_new_string("secrets"));
		json_object_object_add(j, "profile", json_object_new_string("secrets"));
		json_object_object_add(j, "location", json_object_new_string(x->location));
		json_object_object_add(j, "fingerprint", json_object_new_string(x->fingerprint));
		json_object_object_add(j, "content", json_object_new_string(x->content));
		output_buffer_append(o, json_object_to_json_string_ext(j, JSON_C_TO_STRING_PLAIN));
		output_buffer_append(o, "\n");
		json_object_put(j);
	} else if (f == SF_CSV)
		out_printf(o, "finding,\"%s\",\"%s\",%s,\"%s\",\"%s\"\n", x->rule, x->title, x->status, x->location,
			   x->fingerprint);
	else
		out_printf(o, "[%s] %s %s\n  Location: %s\n  Fingerprint: %s\n  Content: %s\n", x->status, x->rule,
			   x->title, x->location, x->fingerprint, x->content);
}
int linux_secrets_audit_main(int argc, char **argv)
{
	struct secret_ctx c = { .root = "/" };
	struct output_buffer o = { 0 };
	enum secret_format f = SF_TXT;
	const char *fe = getenv("ELA_OUTPUT_FORMAT");
	int op;
	size_t i;
	static const struct option options[] = { { "help", no_argument, 0, 'h' },
						 { "quick", no_argument, 0, 'q' },
						 { "collect", no_argument, 0, 'c' },
						 { "root", required_argument, 0, 'R' },
						 { 0, 0, 0, 0 } };
	if (fe && !strcmp(fe, "json"))
		f = SF_JSON;
	else if (fe && !strcmp(fe, "csv"))
		f = SF_CSV;
	optind = 1;
	while ((op = getopt_long(argc, argv, "hqcR:", options, NULL)) != -1) {
		if (op == 'h') {
			fprintf(stderr, "Usage: %s [--quick] [--collect] [--root <absolute-path>]\n", argv[0]);
			return 0;
		}
		if (op == 'q')
			c.quick = true;
		else if (op == 'c')
			c.collect = true;
		else if (op == 'R')
			c.root = optarg;
		else
			return 2;
	}
	if (optind != argc || c.root[0] != '/')
		return 2;
	const char *roots[] = { "/etc", "/root", "/home", "/opt", "/usr/local/etc", NULL };
	for (i = 0; roots[i]; i++)
		scan_dir(&c, roots[i], 0);
	if (f == SF_CSV)
		output_buffer_append(&o, "record,rule_id,title,status,location,fingerprint\n");
	for (i = 0; i < c.len; i++)
		emit(&o, f, &c.items[i]);
	if (f == SF_JSON)
		out_printf(&o,
			   "{\"record\":\"linux_audit_summary\",\"profile\":\"secrets\",\"findings\":%zu,\"unknown\":%"
			   "zu,\"collected\":%s}\n",
			   c.len, c.unknown, c.collect ? "true" : "false");
	else
		out_printf(&o, "Summary (secrets): findings=%zu unknown=%zu collected=%s\n", c.len, c.unknown,
			   c.collect ? "yes" : "no");
	fwrite(o.data, 1, o.len, stdout);
	for (i = 0; i < c.len; i++) {
		free(c.items[i].rule);
		free(c.items[i].title);
		free(c.items[i].status);
		free(c.items[i].location);
		free(c.items[i].fingerprint);
		free(c.items[i].content);
	}
	free(c.items);
	free(o.data);
	return 0;
}
