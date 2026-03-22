// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "net/api_key.h"
#include "net/ela_conf.h"
#include "net/ws_client.h"
#include "net/ws_url_util.h"
#include "shell/interactive.h"
#include "shell/script_exec.h"
#include "util/command_parse_util.h"
#include "util/dispatch_util.h"
#include "util/dispatch_parse_util.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define ELA_RETRY_DELAY_SECS 60

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--output-format <csv|json|txt>] [--quiet] [--insecure] [--output-tcp <IPv4:port>] [--output-http <http(s)://host:port/path>] [--script <path|http(s)://...>] <group> <subcommand> [options]\n"
		"       %s --remote <host:port>\n"
		"       %s --interactive\n"
		"\n"
		"Run without arguments or with --interactive (-i) to enter interactive mode.\n"
		"\n"
		"Global options:\n"
		"  --output-format <csv|json|txt>  Set output format for subcommands\n"
		"  --quiet                         Disable verbose mode for commands/subcommands\n"
		"  --insecure                      Disable TLS certificate/hostname verification for HTTPS\n"
	"  --api-key <key>                 Bearer token for Authorization header (also: ELA_API_KEY env,\n"
	"                                  /tmp/ela.key file; multiple sources tried in order)\n"
		"  --output-tcp <IPv4:port>         Configure TCP remote output for commands/subcommands\n"
		"  --output-http <http(s)://...>    Configure HTTP or HTTPS remote output for commands/subcommands\n"
		"  --script <path|http(s)://...>    Execute commands from a local or remote script file\n"
		"  --remote <host:port>             Connect out to host:port, daemonize, and serve an interactive\n"
		"                                   session over the TCP or WebSocket connection\n"
		"  --retry-attempts <n>             For WebSocket --remote: reconnect up to n times on disconnect\n"
		"                                   (default: 5, 0=no retry; each retry waits 60s)\n"
		"\n"
		"Groups and subcommands:\n"
		"  uboot env          Scan for U-Boot environment candidates\n"
		"  uboot image        Scan or extract U-Boot images\n"
		"  uboot audit        Run U-Boot audit rules\n"
		"  linux dmesg        Dump kernel ring buffer output\n"
		"  linux download-file Download a file from HTTP(S) to a local path\n"
		"  linux execute-command Execute a shell command and capture/upload its output\n"
		"  linux grep         Search files in a directory for a string\n"
		"  linux list-files   List files under a directory (use --recursive to recurse)\n"
		"  linux list-symlinks List symlinks under a directory (use --recursive to recurse)\n"
		"  linux remote-copy  Copy a local file to remote destination\n"
		"  linux ssh          SSH client/copy/tunnel operations\n"
		"  linux process      Watch for process restarts matching a needle string\n"
		"  linux gdbserver    GDB RSP server; attach gdb-multiarch with target remote\n"
		"  tpm2               Run built-in TPM2 commands through the TPM2-TSS library\n"
		"  efi orom           EFI option ROM utilities (pull/list)\n"
		"  efi dump-vars      Dump EFI variables with txt/csv/json formatting\n"
		"  bios orom          BIOS option ROM utilities (pull/list)\n"
		"  transfer <host:port>  Transfer (send) this binary to a receiver at host:port\n"
		"\n"
		"Interactive-only helper:\n"
		"  set ELA_API_URL <http(s)://...>\n"
		"  set ELA_API_INSECURE <true|false>\n"
		"  set ELA_QUIET <true|false>\n"
		"  set ELA_OUTPUT_FORMAT <txt|csv|json>\n"
		"  set ELA_OUTPUT_TCP <IPv4:port>\n"
		"  set ELA_SCRIPT <path|http(s)://...>\n"
		"\n"
		"Examples:\n"
		"  %s uboot env\n"
		"  %s uboot image --dev /dev/mtdblock4 --step 0x1000\n"
		"  %s uboot audit --dev /dev/mtdblock4 --offset 0x0 --size 0x10000\n"
		"  %s --output-http http://127.0.0.1:5000/dmesg linux dmesg\n"
		"  %s linux download-file https://example.com/fw.bin /tmp/fw.bin\n"
		"  %s --output-format json --output-http http://127.0.0.1:5000 linux execute-command \"uname -a\"\n"
		"  %s --output-http http://127.0.0.1:5000 linux grep --search root --path /etc --recursive\n"
		"  %s --output-http http://127.0.0.1:5000 linux list-files /etc\n"
		"  %s --output-format json --output-http http://127.0.0.1:5000 linux list-symlinks /etc --recursive\n"
		"  %s --output-http https://127.0.0.1:5443 linux remote-copy /tmp/fw.bin\n"
		"  %s linux ssh client 192.168.1.10 --port 22\n"
		"  %s tpm2 getcap properties-fixed\n"
		"  %s --quiet --output-http http://127.0.0.1:5000/orom efi orom pull\n"
		"  %s --output-format json --output-http http://127.0.0.1:5000 efi dump-vars\n"
		"  %s --quiet --output-tcp 127.0.0.1:5001 bios orom list\n"
		"  %s --output-format json --script ./commands.txt\n"
		"  %s --remote 192.168.1.10:4444\n"
		"  %s transfer 192.168.1.10:4445\n",
		prog, prog, prog, prog,
		prog, prog, prog, prog,
		prog, prog, prog, prog,
		prog, prog, prog, prog,
		prog, prog, prog, prog,
		prog);
}

/* Declared non-static so interactive.c and script_exec.c can call it. */
void ela_usage(const char *prog)
{
	usage(prog);
}

/* Declared non-static so shell/interactive.c and shell/script_exec.c can call it. */
int embedded_linux_audit_dispatch(int argc, char **argv)
{
	struct ela_dispatch_env env;
	struct ela_dispatch_opts opts;
	struct ela_conf ela_conf = {0};
	char errbuf[256];
	int ret;
	char *command_summary;
	bool emit_lifecycle_events;

	/* Populate env snapshot */
	env.output_format   = getenv("ELA_OUTPUT_FORMAT");
	env.output_tcp      = getenv("ELA_OUTPUT_TCP");
	env.output_http     = getenv("ELA_OUTPUT_HTTP");
	env.output_https    = getenv("ELA_OUTPUT_HTTPS");
	env.quiet           = getenv("ELA_QUIET");
	env.output_insecure = getenv("ELA_OUTPUT_INSECURE");
	env.ws_retry        = getenv("ELA_WS_RETRY_ATTEMPTS");
	env.api_url         = getenv("ELA_API_URL");
	env.api_insecure    = getenv("ELA_API_INSECURE");
	env.script          = getenv("ELA_SCRIPT");

	/*
	 * Load /tmp/.ela.conf and apply as defaults before CLI parsing.
	 * Priority (highest to lowest): CLI args > env vars > conf file > built-ins.
	 */
	ela_conf_load(&ela_conf);

	if (ela_conf.output_format[0] && !env.output_format)
		env.output_format = ela_conf.output_format;

	if (ela_conf.insecure && !opts.insecure)
		env.output_insecure = "1";

	if (ela_conf.output_http[0] &&
	    (!env.output_http  || !*env.output_http) &&
	    (!env.output_https || !*env.output_https))
		env.api_url = ela_conf.output_http;

	ret = ela_dispatch_parse_args(argc, argv, &env, &opts, errbuf, sizeof(errbuf));
	if (ret != 0) {
		fprintf(stderr, "%s\n\n", errbuf);
		usage(argv[0]);
		return ret;
	}

	if (opts.show_help) {
		usage(argv[0]);
		return 0;
	}

	/*
	 * Load --remote from conf only when the binary is invoked with no
	 * commands and no script (auto-connect mode).
	 */
	if (ela_conf.remote[0] && !opts.remote_target &&
	    opts.cmd_idx >= argc && !opts.script_path &&
	    !opts.output_explicit)
		opts.remote_target = ela_conf.remote;

	if (strcmp(opts.output_format, "txt") &&
	    strcmp(opts.output_format, "csv") &&
	    strcmp(opts.output_format, "json")) {
		fprintf(stderr,
			"Invalid --output-format: %s (expected: csv, json, txt)\n\n",
			opts.output_format);
		usage(argv[0]);
		return 2;
	}

	if (opts.conf_needs_save) {
		struct ela_conf save_conf = {0};

		if (opts.remote_target && *opts.remote_target)
			snprintf(save_conf.remote, sizeof(save_conf.remote),
				 "%s", opts.remote_target);
		snprintf(save_conf.output_format, sizeof(save_conf.output_format),
			 "%s", opts.output_format ? opts.output_format : "txt");
		save_conf.insecure = opts.insecure ? 1 : 0;
		ela_conf_save(&save_conf);
	}

	ela_api_key_init(opts.api_key);

	if (opts.output_http && strncmp(opts.output_http, "http://", 7)) {
		fprintf(stderr,
			"Invalid internal HTTP output URI: %s\n\n",
			opts.output_http);
		usage(argv[0]);
		return 2;
	}

	if (opts.output_https && strncmp(opts.output_https, "https://", 8)) {
		fprintf(stderr,
			"Invalid internal HTTPS output URI: %s\n\n",
			opts.output_https);
		usage(argv[0]);
		return 2;
	}

	if (opts.output_http && opts.output_https) {
		fprintf(stderr, "Use only one of --output-http or --output-https\n\n");
		usage(argv[0]);
		return 2;
	}

	if (opts.output_tcp && *opts.output_tcp &&
	    !ela_is_valid_tcp_output_target(opts.output_tcp)) {
		fprintf(stderr,
			"Invalid --output-tcp target (expected IPv4:port): %s\n\n",
			opts.output_tcp);
		usage(argv[0]);
		return 2;
	}

	if (opts.cmd_idx >= argc && !opts.script_path && !opts.remote_target) {
		usage(argv[0]);
		return 2;
	}

	{
		/* Resolve to a string literal so taint analysis sees a safe value.
		 * opts.output_format is already validated against this whitelist above. */
		const char *safe_fmt =
			!strcmp(opts.output_format, "csv")  ? "csv"  :
			!strcmp(opts.output_format, "json") ? "json" : "txt";
		if (setenv("ELA_OUTPUT_FORMAT", safe_fmt, 1) != 0) {
			fprintf(stderr, "Failed to set ELA_OUTPUT_FORMAT\n");
			return 2;
		}
	}
	if (setenv("ELA_VERBOSE", opts.verbose ? "1" : "0", 1) != 0) {
		fprintf(stderr, "Failed to set ELA_VERBOSE\n");
		return 2;
	}
	if (setenv("ELA_OUTPUT_INSECURE", opts.insecure ? "1" : "0", 1) != 0) {
		fprintf(stderr, "Failed to set ELA_OUTPUT_INSECURE\n");
		return 2;
	}

	if (opts.output_tcp && *opts.output_tcp) {
		if (setenv("ELA_OUTPUT_TCP", opts.output_tcp, 1) != 0) {
			fprintf(stderr, "Failed to set ELA_OUTPUT_TCP\n");
			return 2;
		}
	} else {
		unsetenv("ELA_OUTPUT_TCP");
	}

	if (opts.output_http && *opts.output_http) {
		if (setenv("ELA_OUTPUT_HTTP", opts.output_http, 1) != 0) {
			fprintf(stderr, "Failed to set ELA_OUTPUT_HTTP\n");
			return 2;
		}
	} else {
		unsetenv("ELA_OUTPUT_HTTP");
	}

	if (opts.output_https && *opts.output_https) {
		if (setenv("ELA_OUTPUT_HTTPS", opts.output_https, 1) != 0) {
			fprintf(stderr, "Failed to set ELA_OUTPUT_HTTPS\n");
			return 2;
		}
	} else {
		unsetenv("ELA_OUTPUT_HTTPS");
	}

	if (opts.cmd_idx < argc &&
	    (!strcmp(argv[opts.cmd_idx], "-h") ||
	     !strcmp(argv[opts.cmd_idx], "--help") ||
	     !strcmp(argv[opts.cmd_idx], "help"))) {
		usage(argv[0]);
		return 0;
	}

	if (opts.remote_target && *opts.remote_target) {
		pid_t pid;

		if (opts.cmd_idx < argc) {
			fprintf(stderr, "--remote cannot be combined with a command\n\n");
			usage(argv[0]);
			return 2;
		}

		if (ela_is_ws_url(opts.remote_target)) {
			struct ela_ws_conn ws;

			if (ela_ws_connect(opts.remote_target, opts.insecure, &ws) != 0) {
				fprintf(stderr, "--remote: failed to connect to %s\n",
					opts.remote_target);
				return 1;
			}

			pid = fork();
			if (pid < 0) {
				ela_ws_close_parent_fd(&ws);
				fprintf(stderr, "--remote: fork failed: %s\n",
					strerror(errno));
				return 1;
			}

			if (pid > 0) {
				ela_ws_close_parent_fd(&ws);
				fprintf(stdout, "Remote session started (pid=%ld)\n",
					(long)pid);
				return 0;
			}

			setsid();
			{
				bool reconnect = true;
				int failed_attempts = 0;

				for (;;) {
					if (ela_ws_run_interactive(&ws, argv[0]) ==
					    ELA_WS_EXIT_CLEAN) {
						ela_ws_close(&ws);
						exit(0);
					}
					ela_ws_close(&ws);

					if (opts.retry_attempts == 0)
						break;

					reconnect = false;
					for (;;) {
						failed_attempts++;
						if (failed_attempts > opts.retry_attempts)
							break;
						fprintf(stderr,
							"--remote: reconnect attempt %d/%d, waiting %ds\n",
							failed_attempts,
							opts.retry_attempts,
							ELA_RETRY_DELAY_SECS);
						sleep(ELA_RETRY_DELAY_SECS);
						if (ela_ws_connect(opts.remote_target,
								   opts.insecure,
								   &ws) == 0) {
							failed_attempts = 0;
							reconnect = true;
							break;
						}
						fprintf(stderr,
							"--remote: failed to connect to %s\n",
							opts.remote_target);
					}
					if (!reconnect)
						break;
				}
				fprintf(stderr,
					"--remote: max retry attempts (%d) reached, exiting\n",
					opts.retry_attempts);
				exit(1);
			}
		}

		{
			int sock = ela_connect_tcp_any(opts.remote_target);

			if (sock < 0) {
				fprintf(stderr, "--remote: failed to connect to %s\n",
					opts.remote_target);
				return 1;
			}

			pid = fork();
			if (pid < 0) {
				fprintf(stderr, "--remote: fork failed: %s\n",
					strerror(errno));
				close(sock);
				return 1;
			}

			if (pid > 0) {
				close(sock);
				fprintf(stdout, "Remote session started (pid=%ld)\n",
					(long)pid);
				return 0;
			}

			setsid();
			dup2(sock, STDIN_FILENO);
			dup2(sock, STDOUT_FILENO);
			dup2(sock, STDERR_FILENO);
			close(sock);
			exit(interactive_loop(argv[0]));
		}
	}

	if (opts.script_path && opts.cmd_idx < argc) {
		fprintf(stderr, "Use either --script or a direct command, not both\n\n");
		usage(argv[0]);
		return 2;
	}

	command_summary = opts.script_path
		? ela_build_command_summary(argc, argv, 1)
		: ela_build_command_summary(argc, argv, opts.cmd_idx);
	emit_lifecycle_events = ela_command_should_emit_lifecycle_events(
		argc, argv, opts.cmd_idx, opts.script_path);
	if (!command_summary)
		command_summary = strdup("unknown");
	if (command_summary && emit_lifecycle_events)
		(void)ela_emit_lifecycle_event(opts.output_format,
					       opts.output_tcp,
					       opts.output_http,
					       opts.output_https,
					       opts.insecure,
					       command_summary,
					       "start",
					       0);

	if (opts.script_path) {
		/* False-positive suppression: opts.script_path is a user-supplied
		 * CLI argument (--script <path>) or the ELA_SCRIPT env var.  This
		 * tool runs unprivileged as the invoking user; there is no security
		 * boundary between the caller and the path value, so no whitelisting
		 * of an arbitrary file path is meaningful or possible here. */
		/* coverity[tainted_data] */
		ret = execute_script_commands(argv[0], opts.script_path);
		goto done;
	}

	if (!strcmp(argv[opts.cmd_idx], "uboot")) {
		int sub_idx = opts.cmd_idx + 1;

		if (sub_idx >= argc || !strcmp(argv[sub_idx], "-h") ||
		    !strcmp(argv[sub_idx], "--help") ||
		    !strcmp(argv[sub_idx], "help")) {
			usage(argv[0]);
			ret = 0;
			goto done;
		}

		if (!strcmp(argv[sub_idx], "env"))
			ret = uboot_env_scan_main(argc - sub_idx, argv + sub_idx);
		else if (!strcmp(argv[sub_idx], "image"))
			ret = uboot_image_scan_main(argc - sub_idx, argv + sub_idx);
		else if (!strcmp(argv[sub_idx], "audit"))
			ret = embedded_linux_audit_scan_main(argc - sub_idx,
							     argv + sub_idx);
		else {
			fprintf(stderr, "Unknown uboot subcommand: %s\n\n",
				argv[sub_idx]);
			usage(argv[0]);
			ret = 2;
		}

		goto done;
	}

	if (!strcmp(argv[opts.cmd_idx], "linux")) {
		int sub_idx = opts.cmd_idx + 1;

		if (sub_idx >= argc || !strcmp(argv[sub_idx], "-h") ||
		    !strcmp(argv[sub_idx], "--help") ||
		    !strcmp(argv[sub_idx], "help")) {
			usage(argv[0]);
			ret = 0;
			goto done;
		}

		if (!strcmp(argv[sub_idx], "dmesg")) {
			bool dmesg_watch = (sub_idx + 1 < argc &&
					    !strcmp(argv[sub_idx + 1], "watch"));
			if (opts.output_format_explicit && !dmesg_watch)
				fprintf(stderr,
					"Warning: --output-format has no effect for dmesg; remote output is always text/plain\n");
			ret = linux_dmesg_scan_main(argc - sub_idx, argv + sub_idx);
			goto done;
		}

		if (!strcmp(argv[sub_idx], "download-file")) {
			if (opts.output_format_explicit)
				fprintf(stderr,
					"Warning: --output-format has no effect for download-file; downloaded data is written to a local file\n");
			ret = linux_download_file_scan_main(argc - sub_idx,
							    argv + sub_idx);
		} else if (!strcmp(argv[sub_idx], "execute-command"))
			ret = linux_execute_command_scan_main(argc - sub_idx,
							      argv + sub_idx);
		else if (!strcmp(argv[sub_idx], "grep")) {
			if (opts.output_format_explicit)
				fprintf(stderr,
					"Warning: --output-format has no effect for grep; output is always text/plain\n");
			ret = linux_grep_scan_main(argc - sub_idx, argv + sub_idx);
		} else if (!strcmp(argv[sub_idx], "remote-copy")) {
			if (opts.output_format_explicit)
				fprintf(stderr,
					"Warning: --output-format has no effect for remote-copy; file transfer is raw bytes\n");
			ret = linux_remote_copy_scan_main(argc - sub_idx,
							  argv + sub_idx);
		} else if (!strcmp(argv[sub_idx], "ssh")) {
			if (opts.output_format_explicit)
				fprintf(stderr,
					"Warning: --output-format has no effect for ssh; output is always plain text\n");
			ret = linux_ssh_scan_main(argc - sub_idx, argv + sub_idx);
		} else if (!strcmp(argv[sub_idx], "list-files")) {
			if (opts.output_format_explicit)
				fprintf(stderr,
					"Warning: --output-format has no effect for list-files; output is always text/plain\n");
			ret = linux_list_files_scan_main(argc - sub_idx,
							 argv + sub_idx);
		} else if (!strcmp(argv[sub_idx], "list-symlinks"))
			ret = linux_list_symlinks_scan_main(argc - sub_idx,
							    argv + sub_idx);
		else if (!strcmp(argv[sub_idx], "process"))
			ret = linux_process_main(argc - sub_idx, argv + sub_idx);
		else if (!strcmp(argv[sub_idx], "gdbserver"))
			ret = linux_gdbserver_main(argc - sub_idx, argv + sub_idx);
		else {
			fprintf(stderr, "Unknown linux subcommand: %s\n\n",
				argv[sub_idx]);
			usage(argv[0]);
			ret = 2;
		}

		goto done;
	}

	if (!strcmp(argv[opts.cmd_idx], "efi")) {
		int sub_idx = opts.cmd_idx + 1;

		if (sub_idx >= argc || !strcmp(argv[sub_idx], "-h") ||
		    !strcmp(argv[sub_idx], "--help") ||
		    !strcmp(argv[sub_idx], "help")) {
			usage(argv[0]);
			ret = 0;
			goto done;
		}

		if (!strcmp(argv[sub_idx], "orom"))
			ret = efi_orom_main(argc - sub_idx, argv + sub_idx);
		else if (!strcmp(argv[sub_idx], "dump-vars"))
			ret = efi_dump_vars_main(argc - sub_idx, argv + sub_idx);
		else {
			fprintf(stderr, "Unknown efi subcommand: %s\n\n",
				argv[sub_idx]);
			usage(argv[0]);
			ret = 2;
		}

		goto done;
	}

	if (!strcmp(argv[opts.cmd_idx], "bios")) {
		int sub_idx = opts.cmd_idx + 1;

		if (sub_idx >= argc || !strcmp(argv[sub_idx], "-h") ||
		    !strcmp(argv[sub_idx], "--help") ||
		    !strcmp(argv[sub_idx], "help")) {
			usage(argv[0]);
			ret = 0;
			goto done;
		}

		if (!strcmp(argv[sub_idx], "orom"))
			ret = bios_orom_main(argc - sub_idx, argv + sub_idx);
		else {
			fprintf(stderr, "Unknown bios subcommand: %s\n\n",
				argv[sub_idx]);
			usage(argv[0]);
			ret = 2;
		}

		goto done;
	}

	if (!strcmp(argv[opts.cmd_idx], "tpm2")) {
		ret = tpm2_scan_main(argc - opts.cmd_idx, argv + opts.cmd_idx);
		goto done;
	}

	if (!strcmp(argv[opts.cmd_idx], "transfer")) {
		ret = transfer_main(argc - opts.cmd_idx, argv + opts.cmd_idx);
		goto done;
	}

	if (!strcmp(argv[opts.cmd_idx], "arch")) {
		ret = arch_main(argc - opts.cmd_idx, argv + opts.cmd_idx);
		goto done;
	}

	fprintf(stderr, "Unknown command group: %s\n\n", argv[opts.cmd_idx]);
	usage(argv[0]);
	ret = 2;

done:
	if (command_summary && emit_lifecycle_events) {
		(void)ela_emit_lifecycle_event(opts.output_format,
					       opts.output_tcp,
					       opts.output_http,
					       opts.output_https,
					       opts.insecure,
					       command_summary,
					       "complete",
					       ret);
	}
	free(command_summary);
	return ret;
}

int main(int argc, char **argv)
{
	struct ela_conf boot_conf = {0};

	ela_conf_load(&boot_conf);
	/* Validate conf fields against their whitelists before exporting to the
	 * environment.  ela_conf_apply_line() already enforces these at store
	 * time, but making the checks explicit here keeps taint-analysis tools
	 * happy: fields are derived from a file and must be whitelisted before
	 * being passed to any function that touches the environment. */
	if (!ela_output_format_is_valid(boot_conf.output_format))
		boot_conf.output_format[0] = '\0';
	/* output_http must be an http:// or https:// URL; anything else is
	 * rejected to prevent untrusted file content reaching setenv(). */
	if (boot_conf.output_http[0] &&
	    strncmp(boot_conf.output_http, "http://",  7) != 0 &&
	    strncmp(boot_conf.output_http, "https://", 8) != 0)
		boot_conf.output_http[0] = '\0';
	ela_conf_export_to_env(&boot_conf);

	if (argc < 2 && !(getenv("ELA_SCRIPT") && *getenv("ELA_SCRIPT")))
		return interactive_loop(argv[0]);

	if (argc == 2 && (!strcmp(argv[1], "--interactive") ||
			  !strcmp(argv[1], "-i")))
		return interactive_loop(argv[0]);

	return embedded_linux_audit_dispatch(argc, argv);
}
