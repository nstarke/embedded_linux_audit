// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_hardware_audit_cmd.h"
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
#include <unistd.h>
enum hw_format { HW_TXT, HW_CSV, HW_JSON };
struct hw_finding {
	char *rule, *title, *status, *severity, *evidence, *remediation;
};
struct hw_ctx {
	const char *root;
	struct hw_finding *items;
	size_t len, cap, unknown;
};
static bool path_for(const struct hw_ctx *c, const char *rel, char *out, size_t n)
{
	return snprintf(out, n, "%s%s", !strcmp(c->root, "/") ? "" : c->root, rel) < (int)n;
}
static void add(struct hw_ctx *c, const char *r, const char *t, const char *st, const char *sev, const char *e,
		const char *m)
{
	if (c->len == c->cap) {
		size_t n = c->cap ? c->cap * 2 : 24;
		struct hw_finding *p = realloc(c->items, n * sizeof(*p));
		if (!p)
			return;
		c->items = p;
		c->cap = n;
	}
	struct hw_finding *f = &c->items[c->len++];
	f->rule = strdup(r);
	f->title = strdup(t);
	f->status = strdup(st);
	f->severity = strdup(sev);
	f->evidence = strdup(e);
	f->remediation = strdup(m);
	if (!strcmp(st, "unknown"))
		c->unknown++;
}
static void inventory(struct hw_ctx *c, const char *rel, const char *rule, const char *title)
{
	char p[PATH_MAX], e[512];
	struct stat st;
	if (!path_for(c, rel, p, sizeof(p)))
		return;
	if (stat(p, &st) != 0) {
		snprintf(e, sizeof(e), "%s unavailable", rel);
		add(c, "ELA-HW-900", title, "unknown", "low", e,
		    "Run the audit with the relevant sysfs, devtmpfs, and securityfs interfaces mounted.");
		return;
	}
	snprintf(e, sizeof(e), "exposed interface %s", rel);
	add(c, rule, title, "pass", "info", e,
	    "Review whether this hardware interface should be exposed in production.");
}
static void writable_firmware(struct hw_ctx *c)
{
	char p[PATH_MAX], e[512];
	DIR *d;
	struct dirent *de;
	if (!path_for(c, "/sys/firmware", p, sizeof(p)) || !(d = opendir(p))) {
		add(c, "ELA-HW-900", "Firmware interface inventory", "unknown", "low", "/sys/firmware unavailable",
		    "Mount sysfs and review firmware interfaces.");
		return;
	}
	while ((de = readdir(d))) {
		if (de->d_name[0] == '.')
			continue;
		char child[PATH_MAX];
		struct stat st;
		snprintf(child, sizeof(child), "/sys/firmware/%s", de->d_name);
		if (!path_for(c, child, p, sizeof(p)) || stat(p, &st))
			continue;
		if (st.st_mode & 0022) {
			snprintf(e, sizeof(e), "writable firmware interface %s mode=%04o", child, st.st_mode & 0777);
			add(c, "ELA-HW-011", "Writable firmware interface", "fail", "high", e,
			    "Remove group/other write access from firmware control interfaces.");
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
static void emit(struct output_buffer *o, enum hw_format f, const struct hw_finding *x)
{
	if (f == HW_JSON) {
		struct json_object *j = json_object_new_object();
		json_object_object_add(j, "record", json_object_new_string("linux_audit_finding"));
		json_object_object_add(j, "rule_id", json_object_new_string(x->rule));
		json_object_object_add(j, "title", json_object_new_string(x->title));
		json_object_object_add(j, "status", json_object_new_string(x->status));
		json_object_object_add(j, "severity", json_object_new_string(x->severity));
		json_object_object_add(j, "category", json_object_new_string("hardware"));
		json_object_object_add(j, "profile", json_object_new_string("hardware"));
		json_object_object_add(j, "evidence", json_object_new_string(x->evidence));
		json_object_object_add(j, "remediation", json_object_new_string(x->remediation));
		output_buffer_append(o, json_object_to_json_string_ext(j, JSON_C_TO_STRING_PLAIN));
		output_buffer_append(o, "\n");
		json_object_put(j);
	} else if (f == HW_CSV)
		out_printf(o, "finding,\"%s\",\"%s\",%s,%s,\"%s\",\"%s\"\n", x->rule, x->title, x->status, x->severity,
			   x->evidence, x->remediation);
	else
		out_printf(o, "[%s] %s (%s) %s\n  Evidence: %s\n  Remediation: %s\n", x->status, x->rule, x->severity,
			   x->title, x->evidence, x->remediation);
}
int linux_hardware_audit_main(int argc, char **argv)
{
	struct hw_ctx c = { .root = "/" };
	struct output_buffer o = { 0 };
	enum hw_format f = HW_TXT;
	const char *fe = getenv("ELA_OUTPUT_FORMAT");
	int op;
	size_t i;
	static const struct option os[] = { { "help", no_argument, 0, 'h' },
					    { "root", required_argument, 0, 'R' },
					    { 0, 0, 0, 0 } };
	if (fe && !strcmp(fe, "json"))
		f = HW_JSON;
	else if (fe && !strcmp(fe, "csv"))
		f = HW_CSV;
	optind = 1;
	while ((op = getopt_long(argc, argv, "hR:", os, NULL)) != -1) {
		if (op == 'h') {
			fprintf(stderr, "Usage: %s [--root <absolute-path>]\n", argv[0]);
			return 0;
		}
		if (op == 'R')
			c.root = optarg;
		else
			return 2;
	}
	if (optind != argc || c.root[0] != '/')
		return 2;
	inventory(&c, "/sys/class/gpio", "ELA-HW-001", "GPIO interface");
	inventory(&c, "/sys/bus/i2c/devices", "ELA-HW-002", "I2C interface");
	inventory(&c, "/sys/bus/spi/devices", "ELA-HW-003", "SPI interface");
	inventory(&c, "/dev/ttyS0", "ELA-HW-004", "UART interface");
	inventory(&c, "/sys/kernel/debug", "ELA-HW-005", "debugfs");
	inventory(&c, "/sys/kernel/tracing", "ELA-HW-006", "tracefs");
	inventory(&c, "/sys/class/jtag", "ELA-HW-007", "JTAG interface");
	inventory(&c, "/sys/class/watchdog", "ELA-HW-008", "Watchdog");
	inventory(&c, "/sys/class/dma", "ELA-HW-009", "DMA-capable device");
	inventory(&c, "/sys/class/udc", "ELA-HW-010", "USB gadget controller");
	writable_firmware(&c);
	if (f == HW_CSV)
		output_buffer_append(&o, "record,rule_id,title,status,severity,evidence,remediation\n");
	for (i = 0; i < c.len; i++)
		emit(&o, f, &c.items[i]);
	if (f == HW_JSON)
		out_printf(&o,
			   "{\"record\":\"linux_audit_summary\",\"profile\":\"hardware\",\"findings\":%zu,\"unknown\":%"
			   "zu}\n",
			   c.len, c.unknown);
	else if (f == HW_CSV)
		out_printf(&o, "summary,,,,findings=%zu;unknown=%zu,,\n", c.len, c.unknown);
	else
		out_printf(&o, "Summary (hardware): findings=%zu unknown=%zu\n", c.len, c.unknown);
	fwrite(o.data, 1, o.len, stdout);
	for (i = 0; i < c.len; i++) {
		free(c.items[i].rule);
		free(c.items[i].title);
		free(c.items[i].status);
		free(c.items[i].severity);
		free(c.items[i].evidence);
		free(c.items[i].remediation);
	}
	free(c.items);
	free(o.data);
	return 0;
}
