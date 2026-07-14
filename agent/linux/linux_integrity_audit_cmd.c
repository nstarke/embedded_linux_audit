// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_integrity_audit_cmd.h"
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
enum integ_format { IF_TXT, IF_CSV, IF_JSON };
struct integ_finding {
	char *rule, *title, *severity, *status, *evidence, *remediation;
};
struct integ_ctx {
	const char *root;
	struct integ_finding *items;
	size_t len, cap, unknown;
};
static bool path_for(const struct integ_ctx *c, const char *rel, char *out, size_t n)
{
	return snprintf(out, n, "%s%s", !strcmp(c->root, "/") ? "" : c->root, rel) < (int)n;
}
static void add(struct integ_ctx *c, const char *rule, const char *title, const char *severity, const char *status,
		const char *evidence, const char *remediation)
{
	if (c->len == c->cap) {
		size_t n = c->cap ? c->cap * 2 : 24;
		struct integ_finding *p = realloc(c->items, n * sizeof(*p));
		if (!p)
			return;
		c->items = p;
		c->cap = n;
	}
	struct integ_finding *f = &c->items[c->len++];
	f->rule = strdup(rule);
	f->title = strdup(title);
	f->severity = strdup(severity);
	f->status = strdup(status);
	f->evidence = strdup(evidence);
	f->remediation = strdup(remediation);
	if (!strcmp(status, "unknown"))
		c->unknown++;
}
static bool exists(const struct integ_ctx *c, const char *rel)
{
	char p[PATH_MAX];
	return path_for(c, rel, p, sizeof(p)) && access(p, F_OK) == 0;
}
static void require_path(struct integ_ctx *c, const char *rel, const char *rule, const char *title,
			 const char *remediation)
{
	char e[512];
	if (!exists(c, rel)) {
		snprintf(e, sizeof(e), "%s is not present", rel);
		add(c, rule, title, "medium", "unknown", e, remediation);
	}
}
static void scan_ima(struct integ_ctx *c)
{
	char p[PATH_MAX], line[512];
	FILE *f;
	if (!path_for(c, "/sys/kernel/security/ima/policy", p, sizeof(p)) || !(f = fopen(p, "r"))) {
		add(c, "ELA-INT-001", "IMA policy", "high", "unknown", "IMA policy is unavailable",
		    "Enable securityfs and configure an enforcing IMA policy.");
		return;
	}
	bool measured = false, appraise = false;
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, "measure"))
			measured = true;
		if (strstr(line, "appraise"))
			appraise = true;
	}
	fclose(f);
	if (!measured)
		add(c, "ELA-INT-001", "IMA measurement policy", "high", "fail", "IMA policy has no measure rule",
		    "Configure IMA measurement for critical executable and configuration files.");
	if (!appraise)
		add(c, "ELA-INT-002", "IMA appraisal policy", "medium", "fail", "IMA policy has no appraise rule",
		    "Configure EVM/IMA appraisal where integrity enforcement is required.");
}
static void scan_lines(struct integ_ctx *c, const char *rel, const char *rule, const char *title)
{
	char p[PATH_MAX], line[512], e[512];
	FILE *f;
	if (!path_for(c, rel, p, sizeof(p)) || !(f = fopen(p, "r"))) {
		add(c, rule, title, "medium", "unknown", rel,
		    "Expose the relevant kernel interface or configuration for auditing.");
		return;
	}
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, "verity") || strstr(line, "crypt")) {
			snprintf(e, sizeof(e), "%s: %.380s", rel, line);
			add(c, rule, title, "info", "pass", e,
			    "Review storage integrity mappings and trusted backing devices.");
		}
	}
	fclose(f);
}
static void scan_keyring(struct integ_ctx *c)
{
	char p[PATH_MAX];
	if (!path_for(c, "/proc/keys", p, sizeof(p)) || access(p, R_OK) != 0)
		add(c, "ELA-INT-006", "Kernel keyring", "medium", "unknown", "/proc/keys is unavailable",
		    "Restrict keyring access and audit trusted platform keys.");
}
static void scan_event_log(struct integ_ctx *c)
{
	const char *paths[] = { "/sys/kernel/security/tpm0/binary_bios_measurements",
				"/sys/kernel/security/tpm0/ascii_bios_measurements",
				"/sys/kernel/security/tpm0/binary_runtime_measurements", NULL };
	size_t i;
	for (i = 0; paths[i]; i++)
		if (exists(c, paths[i])) {
			add(c, "ELA-INT-007", "TPM event log", "info", "pass", paths[i],
			    "Preserve and parse the event log when validating measured boot.");
			return;
		}
	add(c, "ELA-INT-007", "TPM event log", "high", "unknown", "No TPM event log was found",
	    "Expose the TPM event log and verify its format and digest algorithms.");
}
static void scan_pcr(struct integ_ctx *c)
{
	char p[PATH_MAX];
	if (!path_for(c, "/dev/tpmrm0", p, sizeof(p)) && !path_for(c, "/dev/tpm0", p, sizeof(p))) {
		add(c, "ELA-INT-008", "TPM PCR replay", "high", "unknown", "TPM device path unavailable",
		    "Provide TPM access for live PCR comparison.");
		return;
	}
	if (access(p, F_OK) != 0) {
		add(c, "ELA-INT-008", "TPM PCR replay", "high", "unknown", "No accessible TPM device was found",
		    "Provide TPM access for live PCR comparison.");
		return;
	}
	add(c, "ELA-INT-008", "TPM PCR replay", "medium", "unknown",
	    "TPM device is present; event-log replay/live PCR comparison requires TPM access",
	    "Replay the event log with the correct hash banks and compare each PCR against live TPM values.");
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
static void emit(struct output_buffer *o, enum integ_format format, const struct integ_finding *f)
{
	if (format == IF_JSON) {
		struct json_object *j = json_object_new_object();
		json_object_object_add(j, "record", json_object_new_string("linux_audit_finding"));
		json_object_object_add(j, "rule_id", json_object_new_string(f->rule));
		json_object_object_add(j, "title", json_object_new_string(f->title));
		json_object_object_add(j, "status", json_object_new_string(f->status));
		json_object_object_add(j, "severity", json_object_new_string(f->severity));
		json_object_object_add(j, "category", json_object_new_string("integrity"));
		json_object_object_add(j, "profile", json_object_new_string("integrity"));
		json_object_object_add(j, "evidence", json_object_new_string(f->evidence));
		json_object_object_add(j, "remediation", json_object_new_string(f->remediation));
		output_buffer_append(o, json_object_to_json_string_ext(j, JSON_C_TO_STRING_PLAIN));
		output_buffer_append(o, "\n");
		json_object_put(j);
	} else if (format == IF_CSV)
		out_printf(o, "finding,\"%s\",\"%s\",%s,%s,\"%s\",\"%s\"\n", f->rule, f->title, f->status, f->severity,
			   f->evidence, f->remediation);
	else
		out_printf(o, "[%s] %s (%s) %s\n  Evidence: %s\n  Remediation: %s\n", f->status, f->rule, f->severity,
			   f->title, f->evidence, f->remediation);
}
int linux_integrity_audit_main(int argc, char **argv)
{
	struct integ_ctx c = { .root = "/" };
	struct output_buffer o = { 0 };
	enum integ_format format = IF_TXT;
	const char *fe = getenv("ELA_OUTPUT_FORMAT");
	int op;
	size_t i;
	static const struct option options[] = { { "help", no_argument, 0, 'h' },
						 { "root", required_argument, 0, 'R' },
						 { 0, 0, 0, 0 } };
	if (fe && !strcmp(fe, "json"))
		format = IF_JSON;
	else if (fe && !strcmp(fe, "csv"))
		format = IF_CSV;
	optind = 1;
	while ((op = getopt_long(argc, argv, "hR:", options, NULL)) != -1) {
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
	scan_ima(&c);
	require_path(&c, "/sys/fs/verity", "ELA-INT-003", "fs-verity",
		     "Enable fs-verity for immutable trusted files where supported.");
	scan_lines(&c, "/proc/mounts", "ELA-INT-004", "dm-verity and dm-crypt mappings");
	scan_keyring(&c);
	scan_event_log(&c);
	scan_pcr(&c);
	if (format == IF_CSV)
		output_buffer_append(&o, "record,rule_id,title,status,severity,evidence,remediation\n");
	for (i = 0; i < c.len; i++)
		emit(&o, format, &c.items[i]);
	if (format == IF_JSON)
		out_printf(&o,
			   "{\"record\":\"linux_audit_summary\",\"profile\":\"integrity\",\"findings\":%zu,\"unknown\":"
			   "%zu}\n",
			   c.len, c.unknown);
	else if (format == IF_CSV)
		out_printf(&o, "summary,,,,findings=%zu;unknown=%zu,,\n", c.len, c.unknown);
	else
		out_printf(&o, "Summary (integrity): findings=%zu unknown=%zu\n", c.len, c.unknown);
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
