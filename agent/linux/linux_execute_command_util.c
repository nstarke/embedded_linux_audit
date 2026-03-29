// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "linux_execute_command_util.h"

#include "../embedded_linux_audit_cmd.h"
#include "../util/command_io_util.h"
#include "../util/command_parse_util.h"
#include "../util/record_formatter.h"

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __linux__
#include <pty.h>
#endif

static int default_write_stdout(const char *data, size_t len)
{
	return fwrite(data, 1, len, stdout) == len ? 0 : -1;
}

static int default_append_output(struct output_buffer *buf, const char *data, size_t len)
{
	return output_buffer_append_len(buf, data, len);
}

static void default_flush_stdout(void)
{
	fflush(stdout);
}

static void default_flush_stderr(void)
{
	fflush(stderr);
}

#ifdef __linux__
static pid_t default_forkpty(int *master_fd, char *name, const void *termios_p, const void *winsize_p)
{
	return forkpty(master_fd,
		       name,
		       (const struct termios *)termios_p,
		       (const struct winsize *)winsize_p);
}
#else
static pid_t default_fork(void)
{
	return fork();
}
#endif

static int default_exec_shell(const char *command)
{
	execl("/bin/sh", "/bin/sh", "-c", command, NULL);
	return -1;
}

#ifdef ELA_AGENT_UNIT_TESTS
static int default_parse_http_output_uri(const char *uri,
					 const char **output_http,
					 const char **output_https,
					 char *errbuf,
					 size_t errbuf_len)
{
	(void)uri;
	if (output_http)
		*output_http = NULL;
	if (output_https)
		*output_https = NULL;
	if (errbuf && errbuf_len)
		errbuf[0] = '\0';
	return -1;
}

static int default_connect_tcp_ipv4(const char *spec)
{
	(void)spec;
	return -1;
}

static int default_send_all(int sock, const uint8_t *buf, size_t len)
{
	(void)sock;
	(void)buf;
	(void)len;
	return -1;
}

static char *default_build_upload_uri(const char *base_uri, const char *upload_type, const char *file_path)
{
	(void)base_uri;
	(void)upload_type;
	(void)file_path;
	return NULL;
}

static int default_http_post(const char *uri, const uint8_t *data, size_t len,
			     const char *content_type, bool insecure, bool verbose,
			     char *errbuf, size_t errbuf_len)
{
	(void)uri;
	(void)data;
	(void)len;
	(void)content_type;
	(void)insecure;
	(void)verbose;
	if (errbuf && errbuf_len)
		errbuf[0] = '\0';
	return -1;
}
#else
static int default_parse_http_output_uri(const char *uri,
					 const char **output_http,
					 const char **output_https,
					 char *errbuf,
					 size_t errbuf_len)
{
	return ela_parse_http_output_uri(uri, output_http, output_https, errbuf, errbuf_len);
}

static int default_connect_tcp_ipv4(const char *spec)
{
	return ela_connect_tcp_ipv4(spec);
}

static int default_send_all(int sock, const uint8_t *buf, size_t len)
{
	return ela_send_all(sock, buf, len);
}

static char *default_build_upload_uri(const char *base_uri, const char *upload_type, const char *file_path)
{
	return ela_http_build_upload_uri(base_uri, upload_type, file_path);
}

static int default_http_post(const char *uri, const uint8_t *data, size_t len,
			     const char *content_type, bool insecure, bool verbose,
			     char *errbuf, size_t errbuf_len)
{
	return ela_http_post(uri, data, len, content_type, insecure, verbose, errbuf, errbuf_len);
}
#endif

static const struct ela_execute_command_prepare_ops default_prepare_ops = {
	.parse_http_output_uri_fn = default_parse_http_output_uri,
	.connect_tcp_ipv4_fn = default_connect_tcp_ipv4,
};

static const struct ela_execute_command_capture_ops default_capture_ops = {
	.popen_fn = popen,
	.fread_fn = fread,
	.ferror_fn = ferror,
	.pclose_fn = pclose,
	.append_output_fn = default_append_output,
	.format_record_fn = ela_format_execute_command_record,
	.write_stdout_fn = default_write_stdout,
	.send_all_fn = default_send_all,
	.build_upload_uri_fn = default_build_upload_uri,
	.content_type_fn = ela_execute_command_content_type,
	.http_post_fn = default_http_post,
	.close_fn = close,
};

static const struct ela_execute_command_interactive_ops default_interactive_ops = {
	.flush_stdout_fn = default_flush_stdout,
	.flush_stderr_fn = default_flush_stderr,
#ifdef __linux__
	.forkpty_fn = default_forkpty,
#else
	.fork_fn = default_fork,
#endif
	.waitpid_fn = waitpid,
	.select_fn = select,
	.read_fn = read,
	.write_fn = write,
	.close_fn = close,
	.exec_shell_fn = default_exec_shell,
};

bool ela_execute_command_should_run_interactive(const struct ela_execute_command_request *request,
						bool stdout_is_tty)
{
	if (!request)
		return false;

	return request->output_uri == NULL && request->output_sock < 0 && stdout_is_tty;
}

int ela_execute_command_prepare_request(int argc, char **argv,
					const struct ela_execute_command_env *env,
					bool stdout_is_tty,
					const struct ela_execute_command_prepare_ops *ops,
					struct ela_execute_command_request *out,
					char *errbuf, size_t errbuf_len)
{
	const struct ela_execute_command_prepare_ops *effective_ops = ops ? ops : &default_prepare_ops;
	const char *parsed_output_http = NULL;
	const char *parsed_output_https = NULL;
	const char *output_format;
	const char *output_http;
	const char *output_https;
	const char *output_tcp;
	int opt;

	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ 0, 0, 0, 0 }
	};

	if (!env || !out)
		return -1;

	memset(out, 0, sizeof(*out));
	out->output_sock = -1;

	output_format = ela_output_format_or_default(env->output_format, "txt");
	output_http = env->output_http;
	output_https = env->output_https;
	output_tcp = env->output_tcp;
	out->insecure = env->insecure;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "h", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			out->show_help = true;
			out->output_format = output_format;
			return 0;
		default:
			if (errbuf && errbuf_len) {
				snprintf(errbuf, errbuf_len, "invalid option");
			}
			return -1;
		}
	}

	if (optind >= argc) {
		if (errbuf && errbuf_len) {
			snprintf(errbuf, errbuf_len, "execute-command requires a command string");
		}
		return -1;
	}

	out->command = argv[optind++];
	if (optind < argc) {
		if (errbuf && errbuf_len) {
			snprintf(errbuf, errbuf_len, "Unexpected argument: %s", argv[optind]);
		}
		return -1;
	}

	if (!ela_output_format_is_valid(output_format)) {
		if (errbuf && errbuf_len) {
			snprintf(errbuf, errbuf_len, "Invalid output format for execute-command: %s", output_format);
		}
		return -1;
	}

	if (output_http && *output_http &&
	    effective_ops->parse_http_output_uri_fn &&
	    effective_ops->parse_http_output_uri_fn(output_http,
						     &parsed_output_http,
						     &parsed_output_https,
						     errbuf,
						     errbuf_len) < 0) {
		return -1;
	}

	if (output_http && output_https) {
		if (errbuf && errbuf_len) {
			snprintf(errbuf, errbuf_len, "Use only one of --output-http or --output-https");
		}
		return -1;
	}

	if (parsed_output_http)
		out->output_uri = parsed_output_http;
	if (parsed_output_https)
		out->output_uri = parsed_output_https;
	if (output_https)
		out->output_uri = output_https;

	if (output_tcp && *output_tcp) {
		out->output_sock = effective_ops->connect_tcp_ipv4_fn
				 ? effective_ops->connect_tcp_ipv4_fn(output_tcp)
				 : -1;
		if (out->output_sock < 0) {
			if (errbuf && errbuf_len) {
				snprintf(errbuf, errbuf_len,
					 "Invalid/failed output target (expected IPv4:port): %s",
					 output_tcp);
			}
			return -1;
		}
	}

	out->output_format = output_format;
	out->output_tcp = output_tcp;

	(void)stdout_is_tty;
	return 0;
}

int ela_execute_command_run_capture(const struct ela_execute_command_request *request,
				    const struct ela_execute_command_capture_ops *ops,
				    char *errbuf, size_t errbuf_len)
{
	const struct ela_execute_command_capture_ops *effective_ops = ops ? ops : &default_capture_ops;
	struct output_buffer raw = {0};
	struct output_buffer formatted = {0};
	FILE *fp = NULL;
	char *upload_uri = NULL;
	int ret = 0;

	if (!request || !request->command || !request->output_format)
		return 1;

	fp = effective_ops->popen_fn(request->command, "r");
	if (!fp) {
		if (errbuf && errbuf_len) {
			snprintf(errbuf, errbuf_len, "Failed to execute command '%s': %s",
				 request->command, strerror(errno));
		}
		ret = 1;
		goto out;
	}

	for (;;) {
		char chunk[4096];
		size_t got = effective_ops->fread_fn(chunk, 1, sizeof(chunk), fp);
		if (got > 0 && effective_ops->append_output_fn(&raw, chunk, got) != 0) {
			if (errbuf && errbuf_len) {
				snprintf(errbuf, errbuf_len, "Out of memory while capturing command output");
			}
			ret = 1;
			goto out;
		}
		if (got < sizeof(chunk)) {
			if (effective_ops->ferror_fn(fp)) {
				if (errbuf && errbuf_len) {
					snprintf(errbuf, errbuf_len,
						 "Failed while reading command output for '%s'",
						 request->command);
				}
				ret = 1;
				goto out;
			}
			break;
		}
	}

	if (effective_ops->format_record_fn(&formatted,
					      request->output_format,
					      request->command,
					      raw.data ? raw.data : "") != 0) {
		if (errbuf && errbuf_len) {
			snprintf(errbuf, errbuf_len, "Failed to format command output");
		}
		ret = 1;
		goto out;
	}

	if (formatted.len && effective_ops->write_stdout_fn(formatted.data, formatted.len) != 0) {
		if (errbuf && errbuf_len) {
			snprintf(errbuf, errbuf_len, "Failed to write formatted command output");
		}
		ret = 1;
		goto out;
	}

	if (request->output_sock >= 0 && formatted.len &&
	    effective_ops->send_all_fn(request->output_sock,
					 (const uint8_t *)formatted.data,
					 formatted.len) < 0) {
		if (errbuf && errbuf_len) {
			snprintf(errbuf, errbuf_len, "Failed sending bytes to %s",
				 request->output_tcp ? request->output_tcp : "(null)");
		}
		ret = 1;
		goto out;
	}

	if (request->output_uri) {
		const char *content_type;

		upload_uri = effective_ops->build_upload_uri_fn(request->output_uri, "cmd", NULL);
		if (!upload_uri) {
			if (errbuf && errbuf_len) {
				snprintf(errbuf, errbuf_len, "Unable to build upload URI for command output");
			}
			ret = 1;
			goto out;
		}

		content_type = effective_ops->content_type_fn(request->output_format);
		if (effective_ops->http_post_fn(upload_uri,
						 (const uint8_t *)(formatted.data ? formatted.data : ""),
						 formatted.len,
						 content_type,
						 request->insecure,
						 false,
						 errbuf,
						 errbuf_len) < 0) {
			if (errbuf && errbuf_len) {
				char cause[256];
				snprintf(cause, sizeof(cause), "%s", errbuf[0] ? errbuf : "unknown error");
				snprintf(errbuf, errbuf_len, "Failed HTTP(S) POST to %s: %s",
					 upload_uri, cause);
			}
			ret = 1;
			goto out;
		}
	}

	if (fp) {
		int status = effective_ops->pclose_fn(fp);
		fp = NULL;
		if (status == -1 || (WIFEXITED(status) && WEXITSTATUS(status) != 0) || WIFSIGNALED(status))
			ret = 1;
	}

out:
	if (fp)
		(void)effective_ops->pclose_fn(fp);
	if (request->output_sock >= 0 && effective_ops->close_fn)
		effective_ops->close_fn(request->output_sock);
	free(upload_uri);
	free(raw.data);
	free(formatted.data);
	return ret;
}

int ela_execute_command_run_interactive_with_ops(const char *command,
						 const struct ela_execute_command_interactive_ops *ops)
{
	const struct ela_execute_command_interactive_ops *effective_ops = ops ? ops : &default_interactive_ops;
	int status = 0;
	/* cppcheck-suppress unusedVariable - used inside #ifdef __linux__ below */
	char buf[4096];
	/* cppcheck-suppress unusedVariable - used inside #ifdef __linux__ below */
	ssize_t n;

	if (!command)
		return 1;

	effective_ops->flush_stdout_fn();
	effective_ops->flush_stderr_fn();

#ifdef __linux__
	{
		int master_fd = -1;
		pid_t pid = effective_ops->forkpty_fn(&master_fd, NULL, NULL, NULL);

		if (pid < 0)
			return 1;

		if (pid == 0) {
			if (effective_ops->exec_shell_fn(command) < 0)
				_exit(127);
		}

		/* forkpty sets master_fd on success; guard against it staying -1 */
		if (master_fd < 0) {
			effective_ops->waitpid_fn(pid, &status, 0);
			goto done_linux;
		}

		for (;;) {
			fd_set rfds;
			struct timeval tv;
			int sel;
			int maxfd;

			if (effective_ops->waitpid_fn(pid, &status, WNOHANG) > 0) {
				while ((n = effective_ops->read_fn(master_fd, buf, sizeof(buf))) > 0)
					(void)effective_ops->write_fn(STDOUT_FILENO, buf, (size_t)n);
				goto done_linux;
			}

			FD_ZERO(&rfds);
			FD_SET(STDIN_FILENO, &rfds);
			FD_SET(master_fd, &rfds);
			maxfd = master_fd > STDIN_FILENO ? master_fd : STDIN_FILENO;
			tv.tv_sec = 0;
			tv.tv_usec = 100000;

			sel = effective_ops->select_fn(maxfd + 1, &rfds, NULL, NULL, &tv);
			if (sel < 0) {
				if (errno == EINTR)
					continue;
				break;
			}

			if (FD_ISSET(master_fd, &rfds)) {
				n = effective_ops->read_fn(master_fd, buf, sizeof(buf));
				if (n <= 0)
					break;
				if (effective_ops->write_fn(STDOUT_FILENO, buf, (size_t)n) < 0)
					break;
			}

			if (FD_ISSET(STDIN_FILENO, &rfds)) {
				n = effective_ops->read_fn(STDIN_FILENO, buf, sizeof(buf));
				if (n <= 0)
					break;
				if (effective_ops->write_fn(master_fd, buf, (size_t)n) < 0)
					break;
			}
		}

		effective_ops->waitpid_fn(pid, &status, 0);
done_linux:
		effective_ops->close_fn(master_fd);
	}
#else
	{
		pid_t pid = effective_ops->fork_fn();
		if (pid < 0)
			return 1;
		if (pid == 0) {
			if (effective_ops->exec_shell_fn(command) < 0)
				_exit(127);
		}
		while (effective_ops->waitpid_fn(pid, &status, 0) < 0 && errno == EINTR)
			;
	}
#endif

	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	if (WIFSIGNALED(status))
		return 128 + WTERMSIG(status);
	return 0;
}
