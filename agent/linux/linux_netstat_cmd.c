// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"

#include "util/output_buffer.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * All functions in this file require real hardware, network I/O, or OS-level
 * services (ptrace, SSH, sockets, TPM2, EFI) and cannot be exercised in the
 * unit-test environment.
 */
/* LCOV_EXCL_START */

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s\n"
		"  List TCP/UDP listening sockets and established connections with PID/program data\n"
		"  Reads socket data from /proc/net and PID/program data from /proc/<pid>/fd\n"
		"  Output format is always text/plain\n"
		"  When global --output-http is configured, POST output to /:mac/upload/netstat\n",
		prog);
}

struct inode_owner {
	uint64_t inode;
	pid_t pid;
	char program[256];
};

struct inode_owner_list {
	struct inode_owner *items;
	size_t len;
	size_t cap;
};

static int append_printf(struct output_buffer *out, const char *fmt, ...)
{
	va_list ap;
	va_list ap2;
	char stack[512];
	char *heap = NULL;
	int needed;
	int ret;

	va_start(ap, fmt);
	va_copy(ap2, ap);
	needed = vsnprintf(stack, sizeof(stack), fmt, ap);
	va_end(ap);
	if (needed < 0) {
		va_end(ap2);
		return -1;
	}

	if ((size_t)needed < sizeof(stack)) {
		va_end(ap2);
		return output_buffer_append_len(out, stack, (size_t)needed);
	}

	heap = malloc((size_t)needed + 1);
	if (!heap) {
		va_end(ap2);
		return -1;
	}
	ret = vsnprintf(heap, (size_t)needed + 1, fmt, ap2);
	va_end(ap2);
	if (ret < 0) {
		free(heap);
		return -1;
	}
	ret = output_buffer_append_len(out, heap, (size_t)needed);
	free(heap);
	return ret;
}

static int owner_list_add(struct inode_owner_list *list, uint64_t inode, pid_t pid, const char *program)
{
	struct inode_owner *tmp;
	size_t new_cap;

	if (!list || inode == 0)
		return 0;

	if (list->len == list->cap) {
		new_cap = list->cap ? list->cap * 2 : 256;
		tmp = realloc(list->items, new_cap * sizeof(*list->items));
		if (!tmp)
			return -1;
		list->items = tmp;
		list->cap = new_cap;
	}

	list->items[list->len].inode = inode;
	list->items[list->len].pid = pid;
	snprintf(list->items[list->len].program,
		 sizeof(list->items[list->len].program),
		 "%s",
		 program && *program ? program : "-");
	list->len++;
	return 0;
}

static const struct inode_owner *owner_list_find(const struct inode_owner_list *list, uint64_t inode)
{
	size_t i;

	if (!list || inode == 0)
		return NULL;

	for (i = 0; i < list->len; i++) {
		if (list->items[i].inode == inode)
			return &list->items[i];
	}
	return NULL;
}

static bool parse_pid_name(const char *name, pid_t *pid_out)
{
	char *end = NULL;
	long pid;

	if (!name || !isdigit((unsigned char)name[0]))
		return false;

	errno = 0;
	pid = strtol(name, &end, 10);
	if (errno != 0 || !end || *end != '\0' || pid <= 0)
		return false;

	*pid_out = (pid_t)pid;
	return true;
}

static void read_process_name(pid_t pid, char *buf, size_t buflen)
{
	char path[64];
	FILE *fp;
	size_t len;

	if (!buf || buflen == 0)
		return;

	buf[0] = '\0';
	snprintf(path, sizeof(path), "/proc/%ld/comm", (long)pid);
	fp = fopen(path, "r");
	if (!fp)
		return;

	if (fgets(buf, buflen, fp)) {
		len = strlen(buf);
		while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
			buf[--len] = '\0';
	}
	fclose(fp);
}

static int collect_inode_owners(struct inode_owner_list *owners)
{
	DIR *proc_dir;
	struct dirent *proc_ent;

	proc_dir = opendir("/proc");
	if (!proc_dir)
		return -1;

	while ((proc_ent = readdir(proc_dir)) != NULL) {
		DIR *fd_dir;
		struct dirent *fd_ent;
		pid_t pid;
		char fd_path[128];
		char program[256];

		if (!parse_pid_name(proc_ent->d_name, &pid))
			continue;

		snprintf(fd_path, sizeof(fd_path), "/proc/%ld/fd", (long)pid);
		fd_dir = opendir(fd_path);
		if (!fd_dir)
			continue;

		read_process_name(pid, program, sizeof(program));
		while ((fd_ent = readdir(fd_dir)) != NULL) {
			char link_path[512];
			char target[128];
			ssize_t target_len;
			unsigned long long inode;

			if (fd_ent->d_name[0] == '.')
				continue;

			snprintf(link_path, sizeof(link_path),
				 "/proc/%ld/fd/%s", (long)pid, fd_ent->d_name);
			target_len = readlink(link_path, target, sizeof(target) - 1);
			if (target_len < 0)
				continue;
			target[target_len] = '\0';

			if (sscanf(target, "socket:[%llu]", &inode) == 1) {
				if (owner_list_add(owners, (uint64_t)inode, pid, program) != 0) {
					closedir(fd_dir);
					closedir(proc_dir);
					return -1;
				}
			}
		}
		closedir(fd_dir);
	}

	closedir(proc_dir);
	return 0;
}

static const char *tcp_state_name(unsigned int state)
{
	switch (state) {
	case 0x01: return "ESTABLISHED";
	case 0x02: return "SYN_SENT";
	case 0x03: return "SYN_RECV";
	case 0x04: return "FIN_WAIT1";
	case 0x05: return "FIN_WAIT2";
	case 0x06: return "TIME_WAIT";
	case 0x07: return "CLOSE";
	case 0x08: return "CLOSE_WAIT";
	case 0x09: return "LAST_ACK";
	case 0x0A: return "LISTEN";
	case 0x0B: return "CLOSING";
	default: return "";
	}
}

static int format_ipv4_endpoint(const char *token, char *out, size_t outlen)
{
	unsigned int b1, b2, b3, b4, port;

	if (sscanf(token, "%2x%2x%2x%2x:%x", &b1, &b2, &b3, &b4, &port) != 5)
		return -1;

	snprintf(out, outlen, "%u.%u.%u.%u:%u", b4, b3, b2, b1, port);
	return 0;
}

static int format_ipv6_endpoint(const char *token, char *out, size_t outlen)
{
	unsigned int words[4];
	unsigned int groups[8];
	unsigned int port;
	int ret;

	ret = sscanf(token, "%8x%8x%8x%8x:%x",
		     &words[0], &words[1], &words[2], &words[3], &port);
	if (ret != 5)
		return -1;

	for (ret = 0; ret < 4; ret++) {
		unsigned int w = words[ret];
		groups[ret * 2] = ((w & 0x000000ffU) << 8) | ((w & 0x0000ff00U) >> 8);
		groups[(ret * 2) + 1] = (((w & 0x00ff0000U) >> 16) << 8) |
					  ((w & 0xff000000U) >> 24);
	}

	snprintf(out, outlen,
		 "[%x:%x:%x:%x:%x:%x:%x:%x]:%u",
		 groups[0], groups[1], groups[2], groups[3],
		 groups[4], groups[5], groups[6], groups[7], port);
	return 0;
}

static int format_endpoint(const char *token, bool ipv6, char *out, size_t outlen)
{
	if (ipv6)
		return format_ipv6_endpoint(token, out, outlen);
	return format_ipv4_endpoint(token, out, outlen);
}

static int append_proc_net_table(struct output_buffer *out,
				 const struct inode_owner_list *owners,
				 const char *path,
				 const char *proto,
				 bool ipv6,
				 bool tcp)
{
	FILE *fp;
	char line[512];

	fp = fopen(path, "r");
	if (!fp) {
		if (errno == ENOENT)
			return 0;
		return -1;
	}

	if (!fgets(line, sizeof(line), fp)) {
		fclose(fp);
		return 0;
	}
	while (fgets(line, sizeof(line), fp)) {
		char local_token[128];
		char remote_token[128];
		char state_token[16];
		char queue_token[64];
		char local_addr[128];
		char remote_addr[128];
		unsigned int state = 0;
		unsigned int sendq = 0;
		unsigned int recvq = 0;
		unsigned long long inode = 0;
		const struct inode_owner *owner;
		char owner_text[320];
		int fields;

		fields = sscanf(line,
				" %*d: %127s %127s %15s %63s %*s %*s %*s %*s %llu",
				local_token, remote_token, state_token, queue_token, &inode);
		if (fields != 5)
			continue;

		if (sscanf(queue_token, "%x:%x", &sendq, &recvq) != 2) {
			sendq = 0;
			recvq = 0;
		}
		(void)sscanf(state_token, "%x", &state);

		if (format_endpoint(local_token, ipv6, local_addr, sizeof(local_addr)) != 0)
			snprintf(local_addr, sizeof(local_addr), "%s", local_token);
		if (format_endpoint(remote_token, ipv6, remote_addr, sizeof(remote_addr)) != 0)
			snprintf(remote_addr, sizeof(remote_addr), "%s", remote_token);

		owner = owner_list_find(owners, (uint64_t)inode);
		if (owner) {
			snprintf(owner_text, sizeof(owner_text), "%ld/%s",
				 (long)owner->pid, owner->program);
		} else {
			snprintf(owner_text, sizeof(owner_text), "-");
		}

		if (append_printf(out, "%-5s %6u %6u %-45s %-45s %-12s %s\n",
				  proto,
				  recvq,
				  sendq,
				  local_addr,
				  remote_addr,
				  tcp ? tcp_state_name(state) : "",
				  owner_text) != 0) {
			fclose(fp);
			return -1;
		}
	}

	fclose(fp);
	return 0;
}

static int collect_netstat_from_proc(struct output_buffer *out)
{
	struct inode_owner_list owners = {0};
	int rc = 0;

	if (collect_inode_owners(&owners) != 0)
		return -1;

	if (output_buffer_append(out,
				 "Proto Recv-Q Send-Q Local Address                                 Foreign Address                               State        PID/Program name\n") != 0) {
		rc = -1;
		goto out;
	}

	if (append_proc_net_table(out, &owners, "/proc/net/tcp", "tcp", false, true) != 0 ||
	    append_proc_net_table(out, &owners, "/proc/net/tcp6", "tcp6", true, true) != 0 ||
	    append_proc_net_table(out, &owners, "/proc/net/udp", "udp", false, false) != 0 ||
	    append_proc_net_table(out, &owners, "/proc/net/udp6", "udp6", true, false) != 0)
		rc = -1;

out:
	free(owners.items);
	return rc;
}

static int emit_remote_outputs(const struct output_buffer *out,
			       const char *output_tcp,
			       const char *output_http,
			       const char *output_https,
			       bool insecure)
{
	const char *output_uri = output_https ? output_https : output_http;
	char errbuf[256];
	int sock;
	char *upload_uri;

	if (output_tcp && *output_tcp) {
		sock = ela_connect_tcp_any(output_tcp);
		if (sock < 0 || ela_send_all(sock, (const uint8_t *)out->data, out->len) != 0) {
			if (sock >= 0)
				close(sock);
			fprintf(stderr, "Failed to send netstat output to %s\n", output_tcp);
			return 1;
		}
		close(sock);
	}

	if (output_uri && *output_uri) {
		upload_uri = ela_http_build_upload_uri(output_uri, "netstat", NULL);
		if (!upload_uri) {
			fprintf(stderr, "Failed to build netstat upload URI\n");
			return 1;
		}
		if (ela_http_post(upload_uri,
				  (const uint8_t *)(out->data ? out->data : ""),
				  out->len,
				  "text/plain; charset=utf-8",
				  insecure,
				  false,
				  errbuf,
				  sizeof(errbuf)) < 0) {
			fprintf(stderr, "Failed to POST netstat output to %s: %s\n",
				upload_uri, errbuf[0] ? errbuf : "unknown error");
			free(upload_uri);
			return 1;
		}
		free(upload_uri);
	}

	return 0;
}

int linux_netstat_scan_main(int argc, char **argv)
{
	struct output_buffer out = {0};
	const char *output_tcp;
	const char *output_http;
	const char *output_https;
	bool insecure;
	int rc;

	if (argc > 1 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ||
			 !strcmp(argv[1], "help"))) {
		usage(argv[0]);
		return 0;
	}
	if (argc > 1) {
		fprintf(stderr, "netstat: unexpected argument: %s\n", argv[1]);
		usage(argv[0]);
		return 2;
	}

	rc = collect_netstat_from_proc(&out);
	if (rc != 0) {
		fprintf(stderr, "netstat: failed to collect socket table from /proc: %s\n",
			strerror(errno));
		free(out.data);
		return 1;
	}

	if (out.len > 0 && fwrite(out.data, 1, out.len, stdout) != out.len) {
		fprintf(stderr, "netstat: failed to write output\n");
		free(out.data);
		return 1;
	}

	output_tcp = getenv("ELA_OUTPUT_TCP");
	output_http = getenv("ELA_OUTPUT_HTTP");
	output_https = getenv("ELA_OUTPUT_HTTPS");
	insecure = getenv("ELA_OUTPUT_INSECURE") && !strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");
	rc = emit_remote_outputs(&out, output_tcp, output_http, output_https, insecure);

	free(out.data);
	return rc;
}

/* LCOV_EXCL_STOP */
