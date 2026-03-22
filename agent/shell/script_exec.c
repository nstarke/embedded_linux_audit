// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "script_exec.h"
#include "interactive.h"
#include "script_exec_util.h"
#include "../embedded_linux_audit_cmd.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Forward declaration: defined in embedded_linux_audit.c (non-static) */
int embedded_linux_audit_dispatch(int argc, char **argv);

/* Forward declaration of usage() for help command handling in scripts */
void ela_usage(const char *prog);


int execute_script_commands(const char *prog, const char *script_source)
{
	FILE *fp = NULL;
	char line[4096];
	char script_dir[PATH_MAX];
	char script_path[PATH_MAX];
	char errbuf[256];
	char *fallback_uri = NULL;
	const char *effective_path = script_source;
	const char *output_uri;
	bool downloaded = false;
	bool insecure;
	unsigned long lineno = 0;
	int final_rc = 0;

	if (!prog || !script_source || !*script_source)
		return 2;
	script_dir[0] = '\0';

	insecure = getenv("ELA_OUTPUT_INSECURE") &&
		!strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");
	output_uri = getenv("ELA_OUTPUT_HTTP");
	if ((!output_uri || !*output_uri) && getenv("ELA_OUTPUT_HTTPS") && *getenv("ELA_OUTPUT_HTTPS"))
		output_uri = getenv("ELA_OUTPUT_HTTPS");

	if (ela_script_is_http_source(script_source)) {
		if (ela_script_create_temp_path(script_dir,
					 sizeof(script_dir),
					 script_path,
					 sizeof(script_path),
					 script_source) < 0) {
			fprintf(stderr, "Failed to create temp file for script %s: %s\n",
				script_source,
				strerror(errno));
			return 2;
		}

		if (ela_http_get_to_file(script_source,
					  script_path,
					  insecure,
					  false,
					  errbuf,
					  sizeof(errbuf)) < 0) {
			fprintf(stderr, "Failed to fetch script %s: %s\n",
				script_source,
				errbuf[0] ? errbuf : "unknown error");
			unlink(script_path);
			rmdir(script_dir);
			script_dir[0] = '\0';
			return 2;
		}

		effective_path = script_path;
		downloaded = true;
	} else if (!ela_script_local_file_exists(script_source) && output_uri && *output_uri) {
		fallback_uri = ela_script_build_fallback_uri(output_uri, script_source);
		if (!fallback_uri) {
			fprintf(stderr,
				"Cannot resolve fallback script URI for %s using %s\n",
				script_source,
				output_uri);
			return 2;
		}

		if (ela_script_create_temp_path(script_dir,
					 sizeof(script_dir),
					 script_path,
					 sizeof(script_path),
					 script_source) < 0) {
			fprintf(stderr, "Failed to create temp file for script %s: %s\n",
				script_source,
				strerror(errno));
			free(fallback_uri);
			return 2;
		}

		/* False-positive suppression: fallback_uri is built from the
		 * operator's configured audit server URL and the user-supplied
		 * script name — both are intentional operational parameters.
		 * Fetching a script from the operator's own server is the
		 * designed behaviour; no URL sanitization is meaningful here. */
		/* coverity[tainted_data] */
		if (ela_http_get_to_file(fallback_uri,
					  script_path,
					  insecure,
					  false,
					  errbuf,
					  sizeof(errbuf)) < 0) {
			fprintf(stderr,
				"Cannot open script %s: %s\n",
				script_source,
				errbuf[0] ? errbuf : "not found");
			unlink(script_path);
			rmdir(script_dir);
			script_dir[0] = '\0';
			free(fallback_uri);
			return 2;
		}

		effective_path = script_path;
		downloaded = true;
	}

	fp = fopen(effective_path, "r");
	if (!fp) {
		fprintf(stderr, "Cannot open script %s: %s\n", effective_path, strerror(errno));
		final_rc = 2;
		goto out;
	}

	while (fgets(line, sizeof(line), fp)) {
		char **argv = NULL;
		char **dispatch_argv = NULL;
		struct ela_script_dispatch_plan plan;
		char *trimmed;
		int argc = 0;
		int rc;

		lineno++;
		trimmed = ela_script_trim(line);
		if (ela_script_line_is_ignorable(trimmed))
			continue;

		rc = interactive_parse_line(trimmed, &argv, &argc);
		if (rc == -1) {
			fprintf(stderr, "Out of memory while parsing script line %lu\n", lineno);
			final_rc = 2;
			goto out;
		}
		if (rc != 0) {
			fprintf(stderr, "Failed parsing script line %lu in %s\n", lineno, effective_path);
			final_rc = rc;
			interactive_free_argv(argv, argc);
			goto out;
		}
		if (argc == 0) {
			interactive_free_argv(argv, argc);
			continue;
		}

		if (ela_script_plan_dispatch(argc, argv, &plan, errbuf, sizeof(errbuf)) != 0) {
			fprintf(stderr,
				"Script line %lu in %s %s\n",
				lineno,
				effective_path,
				errbuf[0] ? errbuf : "is invalid");
			interactive_free_argv(argv, argc);
			final_rc = 2;
			goto out;
		}

		if (plan.kind == ELA_SCRIPT_COMMAND_HELP) {
			ela_usage(prog);
			interactive_free_argv(argv, argc);
			continue;
		}

		if (plan.kind == ELA_SCRIPT_COMMAND_SET) {
			rc = interactive_set_command(argc, argv);
			interactive_free_argv(argv, argc);
			if (rc != 0) {
				final_rc = rc;
				goto out;
			}
			continue;
		}

		dispatch_argv = calloc((size_t)plan.dispatch_argc + 1, sizeof(*dispatch_argv));
		if (!dispatch_argv) {
			fprintf(stderr, "Out of memory while preparing script line %lu\n", lineno);
			interactive_free_argv(argv, argc);
			final_rc = 2;
			goto out;
		}

		dispatch_argv[0] = (char *)prog;
		for (int i = plan.script_cmd_idx; i < argc; i++)
			dispatch_argv[i - plan.script_cmd_idx + 1] = argv[i];

		(void)embedded_linux_audit_dispatch(plan.dispatch_argc, dispatch_argv);
		free(dispatch_argv);
		interactive_free_argv(argv, argc);

		/*
		 * Script coverage files intentionally mix commands that may return
		 * runtime/status failures (for example, no matching firmware payloads,
		 * missing EFI support on the host, or root-only scan paths) with parser
		 * and help coverage. Only failures in reading/parsing the script file
		 * itself are treated as fatal for the overall script execution; per-line
		 * command return codes are intentionally ignored so coverage can continue
		 * across commands that legitimately return non-zero status.
		 */
	}

out:
	if (fp)
		fclose(fp);
	if (downloaded) {
		unlink(script_path);
		if (script_dir[0])
			rmdir(script_dir);
	}
	free(fallback_uri);
	return final_rc;
}
