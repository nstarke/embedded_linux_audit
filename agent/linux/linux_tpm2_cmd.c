// SPDX-License-Identifier: MIT License - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"

#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

struct tpm2_out_ctx {
	const char *format;
	const char *http_uri;
	bool insecure;
	bool verbose;
	int sock;
};

struct tpm2_buf {
	char *data;
	size_t len;
	size_t cap;
};

static int tpm2_buf_append(struct tpm2_buf *b, const char *s, size_t n)
{
	size_t need;
	char *tmp;
	size_t new_cap;

	if (!b || (!s && n))
		return -1;

	need = b->len + n + 1;
	if (need > b->cap) {
		new_cap = b->cap ? b->cap : 1024;
		while (new_cap < need)
			new_cap *= 2;
		tmp = realloc(b->data, new_cap);
		if (!tmp)
			return -1;
		b->data = tmp;
		b->cap = new_cap;
	}

	if (n)
		memcpy(b->data + b->len, s, n);
	b->len += n;
	b->data[b->len] = '\0';
	return 0;
}

static int tpm2_buf_appends(struct tpm2_buf *b, const char *s)
{
	return s ? tpm2_buf_append(b, s, strlen(s)) : -1;
}

static int json_escape_append(struct tpm2_buf *b, const char *s)
{
	const unsigned char *p = (const unsigned char *)s;
	char esc[7];

	if (!b || !s)
		return -1;

	while (*p) {
		switch (*p) {
		case '\\': if (tpm2_buf_appends(b, "\\\\") != 0) return -1; break;
		case '"':  if (tpm2_buf_appends(b, "\\\"") != 0) return -1; break;
		case '\b': if (tpm2_buf_appends(b, "\\b")  != 0) return -1; break;
		case '\f': if (tpm2_buf_appends(b, "\\f")  != 0) return -1; break;
		case '\n': if (tpm2_buf_appends(b, "\\n")  != 0) return -1; break;
		case '\r': if (tpm2_buf_appends(b, "\\r")  != 0) return -1; break;
		case '\t': if (tpm2_buf_appends(b, "\\t")  != 0) return -1; break;
		default:
			if (*p < 0x20) {
				int n = snprintf(esc, sizeof(esc), "\\u%04x", (unsigned int)*p);
				if (n < 0 || (size_t)n >= sizeof(esc) || tpm2_buf_append(b, esc, (size_t)n) != 0)
					return -1;
			} else if (tpm2_buf_append(b, (const char *)p, 1) != 0) {
				return -1;
			}
			break;
		}
		p++;
	}
	return 0;
}

static int csv_escape_append(struct tpm2_buf *b, const char *s)
{
	const char *p = s;

	if (!b || !s)
		return -1;

	if (tpm2_buf_appends(b, "\"") != 0)
		return -1;

	while (*p) {
		if (*p == '"') {
			if (tpm2_buf_appends(b, "\"\"") != 0)
				return -1;
		} else if (tpm2_buf_append(b, p, 1) != 0) {
			return -1;
		}
		p++;
	}

	return tpm2_buf_appends(b, "\"");
}

static int format_tpm2_output(const char *command_name,
			      const char *raw,
			      const char *format,
			      struct tpm2_buf *out)
{
	if (!strcmp(format, "txt")) {
		return (tpm2_buf_appends(out, command_name) != 0 ||
			tpm2_buf_appends(out, "\n") != 0 ||
			tpm2_buf_appends(out, raw) != 0) ? -1 : 0;
	}

	if (!strcmp(format, "csv")) {
		return (csv_escape_append(out, command_name) != 0 ||
			tpm2_buf_appends(out, ",") != 0 ||
			csv_escape_append(out, raw) != 0 ||
			tpm2_buf_appends(out, "\n") != 0) ? -1 : 0;
	}

	if (!strcmp(format, "json")) {
		return (tpm2_buf_appends(out, "{\"command\":\"") != 0 ||
			json_escape_append(out, command_name) != 0 ||
			tpm2_buf_appends(out, "\",\"output\":\"") != 0 ||
			json_escape_append(out, raw) != 0 ||
			tpm2_buf_appends(out, "\"}\n") != 0) ? -1 : 0;
	}

	return -1;
}

static int send_tpm2_output(struct tpm2_out_ctx *ctx,
			    const struct tpm2_buf *formatted,
			    const char *upload_type)
{
	char errbuf[256];
	char *upload_uri;
	const char *content_type;
	int ret = 0;

	if (!formatted->len)
		return 0;

	if (fwrite(formatted->data, 1, formatted->len, stdout) != formatted->len)
		return -1;

	if (ctx->sock >= 0 &&
	    uboot_send_all(ctx->sock, (const uint8_t *)formatted->data, formatted->len) < 0)
		ret = -1;

	if (ctx->http_uri) {
		upload_uri = uboot_http_build_upload_uri(ctx->http_uri, upload_type, NULL);
		if (!upload_uri)
			return -1;

		content_type = !strcmp(ctx->format, "csv") ? "text/csv; charset=utf-8" :
			(!strcmp(ctx->format, "json") ? "application/json; charset=utf-8" :
						       "text/plain; charset=utf-8");

		if (uboot_http_post(upload_uri,
				    (const uint8_t *)formatted->data,
				    formatted->len,
				    content_type,
				    ctx->insecure,
				    ctx->verbose,
				    errbuf,
				    sizeof(errbuf)) < 0) {
			fprintf(stderr, "linux tpm2: failed HTTP(S) POST to %s: %s\n",
				upload_uri, errbuf[0] ? errbuf : "unknown error");
			free(upload_uri);
			return -1;
		}
		free(upload_uri);
	}

	return ret;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <tpm2-command> [command-arguments...]\n"
		"       %s list-commands\n"
		"\n"
		"Dispatches TPM2 commands using the installed tpm2-tools style executable\n"
		"naming convention: `tpm2_<tpm2-command>`. For example:\n"
		"  %s getcap properties-fixed\n"
		"  %s pcrread sha256:0,1,2\n"
		"\n"
		"Notes:\n"
		"  - This command is a generic wrapper, so any installed `tpm2_*` tool is\n"
		"    available as `linux tpm2 <command>`.\n"
		"  - `list-commands` scans PATH for available `tpm2_*` executables.\n"
		"  - Output is formatted and transported according to global --output-format,\n"
		"    --output-tcp, --output-http, --insecure, and --quiet options.\n",
		prog, prog, prog, prog);
}

static int cmp_strings(const void *lhs, const void *rhs)
{
	const char *const *a = (const char *const *)lhs;
	const char *const *b = (const char *const *)rhs;

	return strcmp(*a, *b);
}

static bool path_entry_has_command(const char *dir, const char *name)
{
	char full_path[PATH_MAX];
	struct stat st;
	int n;

	if (!dir || !*dir || !name || !*name)
		return false;

	n = snprintf(full_path, sizeof(full_path), "%s/%s", dir, name);
	if (n < 0 || (size_t)n >= sizeof(full_path))
		return false;

	if (stat(full_path, &st) != 0)
		return false;

	if (!S_ISREG(st.st_mode))
		return false;

	return access(full_path, X_OK) == 0;
}

static bool command_exists_in_path(const char *name)
{
	const char *path_env;
	char *path_copy;
	char *saveptr = NULL;
	char *entry;
	bool found = false;

	if (!name || !*name)
		return false;

	path_env = getenv("PATH");
	if (!path_env || !*path_env)
		return false;

	path_copy = strdup(path_env);
	if (!path_copy)
		return false;

	for (entry = strtok_r(path_copy, ":", &saveptr);
	     entry;
	     entry = strtok_r(NULL, ":", &saveptr)) {
		if (!*entry)
			entry = ".";
		if (path_entry_has_command(entry, name)) {
			found = true;
			break;
		}
	}

	free(path_copy);
	return found;
}

static int append_command_name(char ***names, size_t *count, size_t *cap, const char *name)
{
	char **tmp;
	char *dup;
	size_t i;

	if (!names || !count || !cap || !name || !*name)
		return -1;

	for (i = 0; i < *count; i++) {
		if (!strcmp((*names)[i], name))
			return 0;
	}

	dup = strdup(name);
	if (!dup)
		return -1;

	if (*count == *cap) {
		size_t new_cap = *cap ? (*cap * 2) : 32;
		tmp = realloc(*names, new_cap * sizeof(*tmp));
		if (!tmp) {
			free(dup);
			return -1;
		}
		*names = tmp;
		*cap = new_cap;
	}

	(*names)[*count] = dup;
	(*count)++;
	return 0;
}

static void free_command_names(char **names, size_t count)
{
	size_t i;

	if (!names)
		return;

	for (i = 0; i < count; i++)
		free(names[i]);
	free(names);
}

static int linux_tpm2_list_commands(struct tpm2_out_ctx *ctx)
{
	const char *path_env;
	char *path_copy;
	char *saveptr = NULL;
	char *entry;
	char **names = NULL;
	size_t count = 0;
	size_t cap = 0;
	struct tpm2_buf raw = {0};
	struct tpm2_buf formatted = {0};
	size_t i;
	int ret = 0;

	path_env = getenv("PATH");
	if (!path_env || !*path_env) {
		fprintf(stderr, "linux tpm2: PATH is empty\n");
		return 1;
	}

	path_copy = strdup(path_env);
	if (!path_copy)
		return 1;

	for (entry = strtok_r(path_copy, ":", &saveptr);
	     entry;
	     entry = strtok_r(NULL, ":", &saveptr)) {
		DIR *dir;
		struct dirent *de;

		if (!*entry)
			entry = ".";

		dir = opendir(entry);
		if (!dir)
			continue;

		while ((de = readdir(dir)) != NULL) {
			if (strncmp(de->d_name, "tpm2_", 5))
				continue;
			if (!path_entry_has_command(entry, de->d_name))
				continue;
			if (append_command_name(&names, &count, &cap, de->d_name + 5) != 0) {
				closedir(dir);
				free(path_copy);
				free_command_names(names, count);
				return 1;
			}
		}

		closedir(dir);
	}

	free(path_copy);

	if (count == 0) {
		fprintf(stderr, "linux tpm2: no tpm2_* commands found in PATH\n");
		free_command_names(names, count);
		return 1;
	}

	qsort(names, count, sizeof(*names), cmp_strings);

	for (i = 0; i < count; i++) {
		if (tpm2_buf_appends(&raw, names[i]) != 0 ||
		    tpm2_buf_appends(&raw, "\n") != 0) {
			fprintf(stderr, "linux tpm2: out of memory building command list\n");
			ret = 1;
			goto out;
		}
	}

	if (format_tpm2_output("list-commands",
			       raw.data ? raw.data : "",
			       ctx->format,
			       &formatted) != 0) {
		fprintf(stderr, "linux tpm2: failed to format command list\n");
		ret = 1;
		goto out;
	}

	if (send_tpm2_output(ctx, &formatted, "tpm2") != 0)
		ret = 1;

out:
	free_command_names(names, count);
	free(raw.data);
	free(formatted.data);
	return ret;
}

static int linux_tpm2_exec_command(struct tpm2_out_ctx *ctx,
				   const char *subcommand,
				   int argc,
				   char **argv)
{
	char command_name[PATH_MAX];
	char **child_argv;
	struct tpm2_buf raw = {0};
	struct tpm2_buf formatted = {0};
	int pipefd[2] = {-1, -1};
	pid_t pid;
	int status;
	int i;
	int ret = 0;

	if (!subcommand || !*subcommand)
		return 2;

	if (snprintf(command_name, sizeof(command_name), "tpm2_%s", subcommand) >= (int)sizeof(command_name)) {
		fprintf(stderr, "linux tpm2: command name too long: %s\n", subcommand);
		return 2;
	}

	if (!command_exists_in_path(command_name)) {
		fprintf(stderr,
			"linux tpm2: command `%s` was not found in PATH (expected executable `%s`)\n",
			subcommand,
			command_name);
		return 127;
	}

	child_argv = calloc((size_t)argc + 1, sizeof(*child_argv));
	if (!child_argv)
		return 1;

	child_argv[0] = command_name;
	for (i = 2; i < argc; i++)
		child_argv[i - 1] = argv[i];
	child_argv[argc - 1] = NULL;

	if (pipe(pipefd) != 0) {
		fprintf(stderr, "linux tpm2: pipe failed: %s\n", strerror(errno));
		free(child_argv);
		return 1;
	}

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "linux tpm2: fork failed: %s\n", strerror(errno));
		close(pipefd[0]);
		close(pipefd[1]);
		free(child_argv);
		return 1;
	}

	if (pid == 0) {
		close(pipefd[0]);
		if (dup2(pipefd[1], STDOUT_FILENO) < 0)
			_exit(127);
		close(pipefd[1]);
		execvp(command_name, child_argv);
		fprintf(stderr, "linux tpm2: exec failed for %s: %s\n", command_name, strerror(errno));
		_exit(127);
	}

	close(pipefd[1]);
	pipefd[1] = -1;
	free(child_argv);

	for (;;) {
		char chunk[4096];
		ssize_t got = read(pipefd[0], chunk, sizeof(chunk));
		if (got < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "linux tpm2: read from pipe failed: %s\n", strerror(errno));
			ret = 1;
			break;
		}
		if (got == 0)
			break;
		if (tpm2_buf_append(&raw, chunk, (size_t)got) != 0) {
			fprintf(stderr, "linux tpm2: out of memory capturing output\n");
			ret = 1;
			break;
		}
	}

	close(pipefd[0]);
	pipefd[0] = -1;

	if (waitpid(pid, &status, 0) < 0) {
		fprintf(stderr, "linux tpm2: waitpid failed: %s\n", strerror(errno));
		ret = 1;
	}

	if (ret == 0) {
		if (format_tpm2_output(command_name,
				       raw.data ? raw.data : "",
				       ctx->format,
				       &formatted) != 0) {
			fprintf(stderr, "linux tpm2: failed to format output\n");
			ret = 1;
		} else if (send_tpm2_output(ctx, &formatted, "tpm2") != 0) {
			ret = 1;
		}
	}

	free(raw.data);
	free(formatted.data);

	if (ret != 0)
		return ret;

	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	if (WIFSIGNALED(status))
		return 128 + WTERMSIG(status);
	return 1;
}

int linux_tpm2_scan_main(int argc, char **argv)
{
	struct tpm2_out_ctx ctx = {0};
	const char *output_tcp;
	const char *output_http_target = getenv("FW_AUDIT_OUTPUT_HTTP");
	const char *output_https_target = getenv("FW_AUDIT_OUTPUT_HTTPS");
	const char *parsed_output_http = NULL;
	const char *parsed_output_https = NULL;
	char errbuf[256];
	int opt;
	int ret;

	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ 0, 0, 0, 0 }
	};

	ctx.format = getenv("FW_AUDIT_OUTPUT_FORMAT");
	if (!ctx.format || !*ctx.format)
		ctx.format = "txt";

	ctx.verbose = getenv("FW_AUDIT_VERBOSE") && !strcmp(getenv("FW_AUDIT_VERBOSE"), "1");
	ctx.insecure = getenv("FW_AUDIT_OUTPUT_INSECURE") && !strcmp(getenv("FW_AUDIT_OUTPUT_INSECURE"), "1");
	ctx.sock = -1;

	if (strcmp(ctx.format, "txt") && strcmp(ctx.format, "csv") && strcmp(ctx.format, "json")) {
		fprintf(stderr, "linux tpm2: invalid output format: %s\n", ctx.format);
		return 2;
	}

	output_tcp = getenv("FW_AUDIT_OUTPUT_TCP");
	if (output_tcp && *output_tcp) {
		ctx.sock = uboot_connect_tcp_ipv4(output_tcp);
		if (ctx.sock < 0) {
			fprintf(stderr, "linux tpm2: invalid/failed TCP output target (expected IPv4:port): %s\n",
				output_tcp);
			return 2;
		}
	}

	if (output_http_target && *output_http_target) {
		if (fw_audit_parse_http_output_uri(output_http_target,
						  &parsed_output_http,
						  &parsed_output_https,
						  errbuf,
						  sizeof(errbuf)) < 0) {
			fprintf(stderr, "linux tpm2: %s\n", errbuf);
			if (ctx.sock >= 0)
				close(ctx.sock);
			return 2;
		}
		ctx.http_uri = parsed_output_http ? parsed_output_http : parsed_output_https;
	}

	if (output_https_target && *output_https_target) {
		if (ctx.http_uri) {
			fprintf(stderr, "linux tpm2: use only one of --output-http or --output-https\n");
			if (ctx.sock >= 0)
				close(ctx.sock);
			return 2;
		}
		if (strncmp(output_https_target, "https://", 8)) {
			fprintf(stderr, "linux tpm2: invalid --output-https URI (expected https://...): %s\n",
				output_https_target);
			if (ctx.sock >= 0)
				close(ctx.sock);
			return 2;
		}
		ctx.http_uri = output_https_target;
	}

	optind = 1;
	while ((opt = getopt_long(argc, argv, "h", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			if (ctx.sock >= 0)
				close(ctx.sock);
			return 0;
		default:
			usage(argv[0]);
			if (ctx.sock >= 0)
				close(ctx.sock);
			return 2;
		}
	}

	if (optind >= argc) {
		usage(argv[0]);
		if (ctx.sock >= 0)
			close(ctx.sock);
		return 2;
	}

	if (!strcmp(argv[optind], "help") || !strcmp(argv[optind], "--help") || !strcmp(argv[optind], "-h")) {
		usage(argv[0]);
		if (ctx.sock >= 0)
			close(ctx.sock);
		return 0;
	}

	if (!strcmp(argv[optind], "list-commands")) {
		if (optind + 1 != argc) {
			fprintf(stderr, "linux tpm2: list-commands does not accept additional arguments\n");
			usage(argv[0]);
			if (ctx.sock >= 0)
				close(ctx.sock);
			return 2;
		}
		ret = linux_tpm2_list_commands(&ctx);
	} else {
		ret = linux_tpm2_exec_command(&ctx, argv[optind], argc, argv);
	}

	if (ctx.sock >= 0)
		close(ctx.sock);

	return ret;
}
