// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "linux_audit_util.h"
#include "linux_filesystem_audit_cmd.h"
#include "linux_persistence_audit_cmd.h"
#include "linux_identity_audit_cmd.h"
#include "linux_network_audit_cmd.h"
#include "linux_integrity_audit_cmd.h"
#include "linux_secrets_audit_cmd.h"
#include "linux_hardware_audit_cmd.h"
#include "util/output_buffer.h"

#include <getopt.h>
#include <json-c/json.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum audit_output_format {
	AUDIT_OUTPUT_TXT,
	AUDIT_OUTPUT_CSV,
	AUDIT_OUTPUT_JSON,
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--profile embedded|hardened] [--rule <id>] [--list-rules] [--root <path>] [--no-fail]\n"
		"  Run native Linux host security rules without external utilities.\n"
		"  --profile <name>  Select embedded (default) or hardened policy\n"
		"  --rule <id>       Run only one rule, such as ELA-LINUX-001\n"
		"  --list-rules      List all compiled rules and their profiles\n"
		"  --root <path>     Read an alternate root tree instead of /\n"
		"  --no-fail         Return success even when findings fail\n"
		"  Output honors global --output-format txt, csv, or json.\n"
		"  Remote HTTP output is uploaded as linux-audit data.\n",
		prog);
}

static int append_printf(struct output_buffer *out, const char *fmt, ...)
{
	va_list ap;
	va_list copy;
	char stack[1024];
	char *heap;
	int needed;
	int rc;

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

static enum audit_output_format detect_format(void)
{
	const char *value = getenv("ELA_OUTPUT_FORMAT");

	if (value && !strcmp(value, "csv"))
		return AUDIT_OUTPUT_CSV;
	if (value && !strcmp(value, "json"))
		return AUDIT_OUTPUT_JSON;
	return AUDIT_OUTPUT_TXT;
}

static const char *content_type(enum audit_output_format format)
{
	if (format == AUDIT_OUTPUT_CSV)
		return "text/csv; charset=utf-8";
	if (format == AUDIT_OUTPUT_JSON)
		return "application/x-ndjson; charset=utf-8";
	return "text/plain; charset=utf-8";
}

static const char *rule_profiles(const struct ela_linux_audit_rule *rule)
{
	return rule->profiles == (ELA_LINUX_AUDIT_PROFILE_EMBEDDED | ELA_LINUX_AUDIT_PROFILE_HARDENED)
		       ? "embedded,hardened"
		       : "hardened";
}

static int append_csv_rule(struct output_buffer *out, const struct ela_linux_audit_rule *rule,
			   enum ela_linux_audit_profile profile, const struct ela_linux_audit_result *result)
{
	if (csv_write_to_buf(out, "finding") || output_buffer_append(out, ",") || csv_write_to_buf(out, rule->id) ||
	    output_buffer_append(out, ",") || csv_write_to_buf(out, rule->title) || output_buffer_append(out, ",") ||
	    csv_write_to_buf(out, ela_linux_audit_status_name(result->status)) || output_buffer_append(out, ",") ||
	    csv_write_to_buf(out, rule->severity) || output_buffer_append(out, ",") ||
	    csv_write_to_buf(out, rule->category) || output_buffer_append(out, ",") ||
	    csv_write_to_buf(out, ela_linux_audit_profile_name(profile)) || output_buffer_append(out, ",") ||
	    csv_write_to_buf(out, result->evidence) || output_buffer_append(out, ",") ||
	    csv_write_to_buf(out, rule->remediation) || output_buffer_append(out, "\n"))
		return -1;
	return 0;
}

static int append_json_object(struct output_buffer *out, struct json_object *obj)
{
	const char *text;
	int rc;

	if (!obj)
		return -1;
	text = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN);
	rc = output_buffer_append(out, text);
	if (!rc)
		rc = output_buffer_append(out, "\n");
	json_object_put(obj);
	return rc;
}

static int append_finding(struct output_buffer *out, enum audit_output_format format,
			  const struct ela_linux_audit_rule *rule, enum ela_linux_audit_profile profile,
			  const struct ela_linux_audit_result *result)
{
	if (format == AUDIT_OUTPUT_CSV)
		return append_csv_rule(out, rule, profile, result);
	if (format == AUDIT_OUTPUT_JSON) {
		struct json_object *obj = json_object_new_object();
		if (!obj)
			return -1;
		json_object_object_add(obj, "record", json_object_new_string("linux_audit_finding"));
		json_object_object_add(obj, "rule_id", json_object_new_string(rule->id));
		json_object_object_add(obj, "title", json_object_new_string(rule->title));
		json_object_object_add(obj, "status",
				       json_object_new_string(ela_linux_audit_status_name(result->status)));
		json_object_object_add(obj, "severity", json_object_new_string(rule->severity));
		json_object_object_add(obj, "category", json_object_new_string(rule->category));
		json_object_object_add(obj, "profile", json_object_new_string(ela_linux_audit_profile_name(profile)));
		json_object_object_add(obj, "evidence", json_object_new_string(result->evidence));
		json_object_object_add(obj, "remediation", json_object_new_string(rule->remediation));
		return append_json_object(out, obj);
	}
	return append_printf(out, "[%s] %s (%s/%s) %s\n  Evidence: %s\n  Remediation: %s\n",
			     ela_linux_audit_status_name(result->status), rule->id, rule->severity, rule->category,
			     rule->title, result->evidence, rule->remediation);
}

static int append_listing(struct output_buffer *out, enum audit_output_format format,
			  const struct ela_linux_audit_rule *rule)
{
	if (format == AUDIT_OUTPUT_CSV) {
		if (csv_write_to_buf(out, "rule") || output_buffer_append(out, ",") ||
		    csv_write_to_buf(out, rule->id) || output_buffer_append(out, ",") ||
		    csv_write_to_buf(out, rule->title) || output_buffer_append(out, ",") ||
		    csv_write_to_buf(out, rule->severity) || output_buffer_append(out, ",") ||
		    csv_write_to_buf(out, rule->category) || output_buffer_append(out, ",") ||
		    csv_write_to_buf(out, rule_profiles(rule)) || output_buffer_append(out, ",") ||
		    csv_write_to_buf(out, rule->description) || output_buffer_append(out, ",") ||
		    csv_write_to_buf(out, rule->remediation) || output_buffer_append(out, "\n"))
			return -1;
		return 0;
	}
	if (format == AUDIT_OUTPUT_JSON) {
		struct json_object *obj = json_object_new_object();
		if (!obj)
			return -1;
		json_object_object_add(obj, "record", json_object_new_string("linux_audit_rule"));
		json_object_object_add(obj, "rule_id", json_object_new_string(rule->id));
		json_object_object_add(obj, "title", json_object_new_string(rule->title));
		json_object_object_add(obj, "severity", json_object_new_string(rule->severity));
		json_object_object_add(obj, "category", json_object_new_string(rule->category));
		json_object_object_add(obj, "profiles", json_object_new_string(rule_profiles(rule)));
		json_object_object_add(obj, "description", json_object_new_string(rule->description));
		json_object_object_add(obj, "remediation", json_object_new_string(rule->remediation));
		return append_json_object(out, obj);
	}
	return append_printf(out, "%s [%s] %s (profiles: %s)\n  %s\n", rule->id, rule->severity, rule->title,
			     rule_profiles(rule), rule->description);
}

static int append_summary(struct output_buffer *out, enum audit_output_format format,
			  enum ela_linux_audit_profile profile, size_t pass, size_t fail, size_t unknown,
			  size_t not_applicable)
{
	if (format == AUDIT_OUTPUT_CSV)
		return append_printf(out, "summary,,,,,,%s,pass=%zu; fail=%zu; unknown=%zu; not-applicable=%zu,\n",
				     ela_linux_audit_profile_name(profile), pass, fail, unknown, not_applicable);
	if (format == AUDIT_OUTPUT_JSON) {
		struct json_object *obj = json_object_new_object();
		if (!obj)
			return -1;
		json_object_object_add(obj, "record", json_object_new_string("linux_audit_summary"));
		json_object_object_add(obj, "profile", json_object_new_string(ela_linux_audit_profile_name(profile)));
		json_object_object_add(obj, "pass", json_object_new_int64((int64_t)pass));
		json_object_object_add(obj, "fail", json_object_new_int64((int64_t)fail));
		json_object_object_add(obj, "unknown", json_object_new_int64((int64_t)unknown));
		json_object_object_add(obj, "not_applicable", json_object_new_int64((int64_t)not_applicable));
		return append_json_object(out, obj);
	}
	return append_printf(out, "Summary (%s): pass=%zu fail=%zu unknown=%zu not-applicable=%zu\n",
			     ela_linux_audit_profile_name(profile), pass, fail, unknown, not_applicable);
}

static int emit_remote(const struct output_buffer *out, enum audit_output_format format)
{
	const char *output_tcp = getenv("ELA_OUTPUT_TCP");
	const char *output_http = getenv("ELA_OUTPUT_HTTPS");
	char errbuf[256];
	char *upload_uri;
	int sock;
	bool insecure = getenv("ELA_OUTPUT_INSECURE") && !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");

	if (!output_http)
		output_http = getenv("ELA_OUTPUT_HTTP");
	if (output_tcp && *output_tcp) {
		sock = ela_connect_tcp_any(output_tcp);
		if (sock < 0 || ela_send_all(sock, (const uint8_t *)out->data, out->len) != 0) {
			if (sock >= 0)
				close(sock);
			fprintf(stderr, "linux audit: failed to send output to %s\n", output_tcp);
			return 1;
		}
		close(sock);
	}
	if (output_http && *output_http) {
		upload_uri = ela_http_build_upload_uri(output_http, "linux-audit", NULL);
		if (!upload_uri)
			return 1;
		if (ela_http_post(upload_uri, (const uint8_t *)out->data, out->len, content_type(format), insecure,
				  false, errbuf, sizeof(errbuf)) < 0) {
			fprintf(stderr, "linux audit: failed to POST to %s: %s\n", upload_uri,
				errbuf[0] ? errbuf : "unknown error");
			free(upload_uri);
			return 1;
		}
		free(upload_uri);
	}
	return 0;
}

/* Entry point for `audit ...`: `audit all` fans out to the kernel rule engine
 * plus every subsystem auditor and returns the worst exit code seen; a named
 * subsystem argument delegates to that auditor directly; with no subcommand
 * the kernel rule engine runs against the options parsed below. */
int linux_audit_main(int argc, char **argv)
{
	if (argc > 1 && !strcmp(argv[1], "all")) {
		const char *root = "/";
		bool quick = false;
		int i, rc = 0, result;
		char *kernel_argv[4] = { "audit", NULL, NULL, NULL };
		char *sub_argv[6] = { NULL, NULL, NULL, NULL, NULL, NULL };
		const char *commands[] = { "filesystem", "persistence", "identity", "network", "integrity", "secrets", "hardware" };
		for (i = 2; i < argc; i++) {
			if (!strcmp(argv[i], "--quick")) quick = true;
			else if (!strcmp(argv[i], "--root") && i + 1 < argc) root = argv[++i];
			else if (!strncmp(argv[i], "--root=", 7)) root = argv[i] + 7;
			else return 2;
		}
		if (root[0] != '/') return 2;
		kernel_argv[1] = "--root"; kernel_argv[2] = (char *)root;
		result = linux_audit_main(3, kernel_argv); if (result > rc) rc = result;
		for (i = 0; i < (int)(sizeof(commands) / sizeof(commands[0])); i++) {
			int n = 0;
			sub_argv[n++] = (char *)commands[i];
			/* --quick is only forwarded to auditors where a reduced scan is meaningful. */
			if (quick && strcmp(commands[i], "network") != 0 && strcmp(commands[i], "integrity") != 0 && strcmp(commands[i], "hardware") != 0) sub_argv[n++] = "--quick";
			sub_argv[n++] = "--root"; sub_argv[n++] = (char *)root; sub_argv[n] = NULL;
			if (!strcmp(commands[i], "filesystem")) result = linux_filesystem_audit_main(n, sub_argv);
			else if (!strcmp(commands[i], "persistence")) result = linux_persistence_audit_main(n, sub_argv);
			else if (!strcmp(commands[i], "identity")) result = linux_identity_audit_main(n, sub_argv);
			else if (!strcmp(commands[i], "network")) result = linux_network_audit_main(n, sub_argv);
			else if (!strcmp(commands[i], "integrity")) result = linux_integrity_audit_main(n, sub_argv);
			else if (!strcmp(commands[i], "secrets")) result = linux_secrets_audit_main(n, sub_argv);
			else result = linux_hardware_audit_main(n, sub_argv);
			if (result > rc) rc = result;
		}
		return rc;
	}
	if (argc > 1 && !strcmp(argv[1], "filesystem"))
		return linux_filesystem_audit_main(argc - 1, argv + 1);
	if (argc > 1 && !strcmp(argv[1], "persistence"))
		return linux_persistence_audit_main(argc - 1, argv + 1);
	if (argc > 1 && !strcmp(argv[1], "identity"))
		return linux_identity_audit_main(argc - 1, argv + 1);
	if (argc > 1 && !strcmp(argv[1], "network"))
		return linux_network_audit_main(argc - 1, argv + 1);
	if (argc > 1 && !strcmp(argv[1], "integrity"))
		return linux_integrity_audit_main(argc - 1, argv + 1);
	if (argc > 1 && !strcmp(argv[1], "secrets"))
		return linux_secrets_audit_main(argc - 1, argv + 1);
	if (argc > 1 && !strcmp(argv[1], "hardware"))
		return linux_hardware_audit_main(argc - 1, argv + 1);
	enum ela_linux_audit_profile profile = ELA_LINUX_AUDIT_PROFILE_EMBEDDED;
	enum audit_output_format format = detect_format();
	const char *rule_id = NULL;
	const char *root = "/";
	struct output_buffer out = { 0 };
	bool list_rules = false;
	bool no_fail = false;
	size_t pass = 0, fail = 0, unknown = 0, not_applicable = 0;
	size_t i;
	int opt;
	int rc = 0;
	static const struct option options[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "profile", required_argument, NULL, 'p' },
		{ "rule", required_argument, NULL, 'r' },
		{ "list-rules", no_argument, NULL, 'l' },
		{ "root", required_argument, NULL, 'R' },
		{ "no-fail", no_argument, NULL, 'n' },
		{ 0, 0, 0, 0 },
	};

	optind = 1;
	while ((opt = getopt_long(argc, argv, "hp:r:lR:n", options, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'p':
			if (ela_linux_audit_parse_profile(optarg, &profile)) {
				fprintf(stderr, "linux audit: unknown profile: %s\n", optarg);
				return 2;
			}
			break;
		case 'r':
			rule_id = optarg;
			break;
		case 'l':
			list_rules = true;
			break;
		case 'R':
			root = optarg;
			break;
		case 'n':
			no_fail = true;
			break;
		default:
			usage(argv[0]);
			return 2;
		}
	}
	if (optind != argc) {
		fprintf(stderr, "linux audit: unexpected argument: %s\n", argv[optind]);
		return 2;
	}
	if (!root || root[0] != '/') {
		fprintf(stderr, "linux audit: --root must be an absolute path\n");
		return 2;
	}
	if (rule_id && !ela_linux_audit_find_rule(rule_id)) {
		fprintf(stderr, "linux audit: unknown rule: %s\n", rule_id);
		return 2;
	}

	if (format == AUDIT_OUTPUT_CSV) {
		if (list_rules)
			output_buffer_append(
				&out, "record,rule_id,title,severity,category,profiles,description,remediation\n");
		else
			output_buffer_append(
				&out, "record,rule_id,title,status,severity,category,profile,evidence,remediation\n");
	}

	for (i = 0; i < ela_linux_audit_rule_count; i++) {
		const struct ela_linux_audit_rule *rule = &ela_linux_audit_rules[i];
		struct ela_linux_audit_result result;

		if (rule_id && strcmp(rule_id, rule->id))
			continue;
		if (list_rules) {
			if (append_listing(&out, format, rule))
				goto output_error;
			continue;
		}
		if (!ela_linux_audit_rule_enabled(rule, profile)) {
			if (rule_id) {
				fprintf(stderr, "linux audit: rule %s is not part of the %s profile\n", rule_id,
					ela_linux_audit_profile_name(profile));
				free(out.data);
				return 2;
			}
			continue;
		}
		memset(&result, 0, sizeof(result));
		if (ela_linux_audit_run_rule(rule, profile, root, &result))
			goto output_error;
		if (result.status == ELA_LINUX_AUDIT_PASS)
			pass++;
		else if (result.status == ELA_LINUX_AUDIT_FAIL)
			fail++;
		else if (result.status == ELA_LINUX_AUDIT_NOT_APPLICABLE)
			not_applicable++;
		else
			unknown++;
		if (append_finding(&out, format, rule, profile, &result))
			goto output_error;
	}
	if (!list_rules && append_summary(&out, format, profile, pass, fail, unknown, not_applicable))
		goto output_error;
	if (out.len && fwrite(out.data, 1, out.len, stdout) != out.len)
		goto output_error;
	rc = emit_remote(&out, format);
	if (!rc && !list_rules && fail && !no_fail)
		rc = 1;
	free(out.data);
	return rc;

output_error:
	fprintf(stderr, "linux audit: failed to format or write output\n");
	free(out.data);
	return 1;
}
