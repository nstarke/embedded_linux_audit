// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_network_audit_cmd.h"
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
#include <unistd.h>

enum net_format { NF_TXT, NF_CSV, NF_JSON };
struct net_finding {
	char *rule, *title, *severity, *status, *evidence, *remediation;
};
struct net_ctx {
	const char *root;
	struct net_finding *items;
	size_t len, cap, unknown;
};
static bool path_for(const struct net_ctx *c, const char *r, char *p, size_t n)
{
	return snprintf(p, n, "%s%s", !strcmp(c->root, "/") ? "" : c->root, r) < (int)n;
}
static void add(struct net_ctx *c, const char *r, const char *t, const char *s, const char *st, const char *e,
		const char *m)
{
	if (c->len == c->cap) {
		size_t n = c->cap ? c->cap * 2 : 32;
		struct net_finding *p = realloc(c->items, n * sizeof(*p));
		if (!p)
			return;
		c->items = p;
		c->cap = n;
	}
	struct net_finding *x = &c->items[c->len++];
	x->rule = strdup(r);
	x->title = strdup(t);
	x->severity = strdup(s);
	x->status = strdup(st);
	x->evidence = strdup(e);
	x->remediation = strdup(m);
	if (!strcmp(st, "unknown"))
		c->unknown++;
}
static FILE *open_rel(const struct net_ctx *c, const char *r, char *p, size_t n)
{
	if (!path_for(c, r, p, n))
		return NULL;
	return fopen(p, "r");
}
static void probe(struct net_ctx *c, const char *rel)
{
	char p[PATH_MAX], e[512];
	FILE *f = open_rel(c, rel, p, sizeof(p));
	if (!f) {
		if (errno != ENOENT) {
			snprintf(e, sizeof(e), "unable to read %s: %s", rel, strerror(errno));
			add(c, "ELA-NET-900", "Network inspection", "low", "unknown", e,
			    "Run the audit with access to the target runtime filesystem.");
		}
		return;
	}
	fclose(f);
}
static bool clear_text_port(bool is_tcp, unsigned int port)
{
	if (is_tcp)
		return port == 21 || port == 23 || port == 80 || port == 110 || port == 143 || port == 389 ||
		       port == 513 || port == 514;
	return port == 69 || port == 161 || port == 514 || port == 1900;
}

static void socket_table(struct net_ctx *c, const char *rel, const char *proto, bool is_tcp, bool required)
{
	char p[PATH_MAX], line[512], e[512], local[65];
	FILE *f = open_rel(c, rel, p, sizeof(p));
	if (!f) {
		if (required || errno != ENOENT) {
			snprintf(e, sizeof(e), "unable to read %s", rel);
			add(c, "ELA-NET-900", "Socket inspection", "low", "unknown", e,
			    "Run the audit with procfs available.");
		}
		return;
	}
	if (!fgets(line, sizeof(line), f)) {
		fclose(f);
		return;
	}
	while (fgets(line, sizeof(line), f)) {
		unsigned int port, state;
		bool wildcard = true, listening;
		size_t i;
		if (sscanf(line, " %*u: %64[0-9A-Fa-f]:%X %*[0-9A-Fa-f]:%*X %X", local, &port, &state) != 3)
			continue;
		for (i = 0; local[i]; i++)
			if (local[i] != '0')
				wildcard = false;
		listening = state == (is_tcp ? 0x0AU : 0x07U);
		if (listening && wildcard) {
			snprintf(e, sizeof(e), "wildcard %s listener on port %u", proto, port);
			add(c, "ELA-NET-001", "Wildcard listener", "high", "fail", e,
			    "Bind services to a specific interface or restrict them with firewall policy.");
		}
		if (listening && clear_text_port(is_tcp, port)) {
			snprintf(e, sizeof(e), "clear-text management/service listener on %s port %u", proto, port);
			add(c, "ELA-NET-002", "Clear-text network service", "high", "fail", e,
			    "Replace clear-text protocols with TLS or an authenticated secure management protocol.");
		}
		if (is_tcp && state == 0x01) {
			snprintf(e, sizeof(e), "established outbound %s connection (local port %u)", proto, port);
			add(c, "ELA-NET-005", "Unexpected outbound connection", "medium", "fail", e,
			    "Review process ownership and restrict egress to explicitly approved destinations.");
		}
	}
	fclose(f);
}

static void sockets(struct net_ctx *c)
{
	socket_table(c, "/proc/net/tcp", "tcp", true, true);
	socket_table(c, "/proc/net/tcp6", "tcp6", true, false);
	socket_table(c, "/proc/net/udp", "udp", false, false);
	socket_table(c, "/proc/net/udp6", "udp6", false, false);
}
static void firewall(struct net_ctx *c)
{
	char p[PATH_MAX], e[512];
	const char *paths[] = { "/etc/nftables.conf", "/etc/iptables/rules.v4", "/etc/firewalld/zones/public.xml",
				NULL };
	size_t i;
	for (i = 0; paths[i]; i++) {
		if (path_for(c, paths[i], p, sizeof(p)) && !access(p, F_OK))
			return;
	}
	snprintf(e, sizeof(e), "no nftables, iptables, or firewalld policy found");
	add(c, "ELA-NET-003", "Missing firewall policy", "high", "fail", e,
	    "Install and enable a default-deny host firewall appropriate for the target.");
}
static void dns(struct net_ctx *c)
{
	char p[PATH_MAX], line[512];
	FILE *f = open_rel(c, "/etc/resolv.conf", p, sizeof(p));
	if (!f) {
		add(c, "ELA-NET-900", "DNS inspection", "low", "unknown", "unable to read /etc/resolv.conf",
		    "Review DNS configuration on the target host.");
		return;
	}
	while (fgets(line, sizeof(line), f))
		if (strstr(line, "nameserver")) {
			fclose(f);
			return;
		}
	fclose(f);
	add(c, "ELA-NET-004", "DNS configuration", "medium", "fail", "/etc/resolv.conf contains no nameserver",
	    "Configure trusted DNS resolvers or an explicit local resolver.");
}
static int outfmt(struct output_buffer *o, const char *fmt, ...)
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
static void emit(struct output_buffer *o, enum net_format f, const struct net_finding *x)
{
	if (f == NF_JSON) {
		struct json_object *j = json_object_new_object();
		json_object_object_add(j, "record", json_object_new_string("linux_audit_finding"));
		json_object_object_add(j, "rule_id", json_object_new_string(x->rule));
		json_object_object_add(j, "title", json_object_new_string(x->title));
		json_object_object_add(j, "status", json_object_new_string(x->status));
		json_object_object_add(j, "severity", json_object_new_string(x->severity));
		json_object_object_add(j, "category", json_object_new_string("network"));
		json_object_object_add(j, "profile", json_object_new_string("network"));
		json_object_object_add(j, "evidence", json_object_new_string(x->evidence));
		json_object_object_add(j, "remediation", json_object_new_string(x->remediation));
		output_buffer_append(o, json_object_to_json_string_ext(j, JSON_C_TO_STRING_PLAIN));
		output_buffer_append(o, "\n");
		json_object_put(j);
	} else if (f == NF_CSV)
		outfmt(o, "finding,\"%s\",\"%s\",%s,%s,\"%s\",\"%s\"\n", x->rule, x->title, x->status, x->severity,
		       x->evidence, x->remediation);
	else
		outfmt(o, "[%s] %s (%s) %s\n  Evidence: %s\n  Remediation: %s\n", x->status, x->rule, x->severity,
		       x->title, x->evidence, x->remediation);
}
int linux_network_audit_main(int argc, char **argv)
{
	struct net_ctx c = { .root = "/" };
	struct output_buffer o = { 0 };
	enum net_format f = NF_TXT;
	const char *fe = getenv("ELA_OUTPUT_FORMAT");
	int op;
	size_t i;
	static const struct option os[] = { { "help", no_argument, 0, 'h' },
					    { "root", required_argument, 0, 'R' },
					    { 0, 0, 0, 0 } };
	if (fe && !strcmp(fe, "json"))
		f = NF_JSON;
	else if (fe && !strcmp(fe, "csv"))
		f = NF_CSV;
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
	probe(&c, "/proc/net/dev");
	probe(&c, "/proc/net/route");
	probe(&c, "/proc/1/ns/net");
	sockets(&c);
	firewall(&c);
	dns(&c);
	if (f == NF_CSV)
		output_buffer_append(&o, "record,rule_id,title,status,severity,evidence,remediation\n");
	for (i = 0; i < c.len; i++)
		emit(&o, f, &c.items[i]);
	if (f == NF_JSON)
		outfmt(&o,
		       "{\"record\":\"linux_audit_summary\",\"profile\":\"network\",\"findings\":%zu,\"unknown\":%zu}"
		       "\n",
		       c.len, c.unknown);
	else if (f == NF_CSV)
		outfmt(&o, "summary,,,,findings=%zu;unknown=%zu,,\n", c.len, c.unknown);
	else
		outfmt(&o, "Summary (network): findings=%zu unknown=%zu\n", c.len, c.unknown);
	fwrite(o.data, 1, o.len, stdout);
	for (i = 0; i < c.len; i++) {
		free(c.items[i].rule);
		free(c.items[i].title);
		free(c.items[i].severity);
		free(c.items[i].status);
		free(c.items[i].evidence);
		free(c.items[i].remediation);
	}
	free(c.items);
	free(o.data);
	return 0;
}
