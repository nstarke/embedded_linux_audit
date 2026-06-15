// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "linux_kernel_module_util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_finit_module
# if defined(__NR_finit_module)
#  define SYS_finit_module __NR_finit_module
# endif
#endif

#ifndef SYS_init_module
# if defined(__NR_init_module)
#  define SYS_init_module __NR_init_module
# endif
#endif

#ifndef SYS_delete_module
# if defined(__NR_delete_module)
#  define SYS_delete_module __NR_delete_module
# endif
#endif

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s list\n"
		"       %s load [--force] <module.ko> [param=value ...]\n"
		"       %s unload <module-name>\n"
		"  list reads /proc/modules directly\n"
		"  load uses finit_module/init_module directly; --force ignores vermagic\n"
		"  unload uses delete_module directly\n",
		prog, prog, prog);
}

static int list_modules(void)
{
	const char *format = getenv("ELA_OUTPUT_FORMAT");
	FILE *fp;
	char line[1024];
	struct ela_kernel_module_record rec;
	int first = 1;

	fp = fopen("/proc/modules", "r");
	if (!fp) {
		fprintf(stderr, "Cannot open /proc/modules: %s\n", strerror(errno));
		return 1;
	}

	if (format && !strcmp(format, "json"))
		printf("[\n");
	else if (format && !strcmp(format, "csv"))
		printf("name,size,refcount,dependencies,state,address\n");

	while (fgets(line, sizeof(line), fp)) {
		if (ela_kernel_module_parse_proc_line(line, &rec) != 0)
			continue;

		if (format && !strcmp(format, "json")) {
			printf("%s  {\"name\":\"%s\",\"size\":%lu,\"refcount\":%d,"
			       "\"dependencies\":\"%s\",\"state\":\"%s\",\"address\":\"%s\"}",
			       first ? "" : ",\n",
			       rec.name, rec.size, rec.refcount, rec.dependencies,
			       rec.state, rec.address);
			first = 0;
		} else if (format && !strcmp(format, "csv")) {
			printf("%s,%lu,%d,%s,%s,%s\n",
			       rec.name, rec.size, rec.refcount, rec.dependencies,
			       rec.state, rec.address);
		} else {
			printf("%-24s %10lu %4d %-32s %-10s %s\n",
			       rec.name, rec.size, rec.refcount,
			       rec.dependencies[0] ? rec.dependencies : "-",
			       rec.state, rec.address);
		}
	}

	if (format && !strcmp(format, "json"))
		printf("\n]\n");

	fclose(fp);
	return 0;
}

static int load_module(const struct ela_kernel_module_request *request)
{
	int fd;
	unsigned int flags;

	fd = open(request->module_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "Cannot open module %s: %s\n",
			request->module_path, strerror(errno));
		return 1;
	}

	flags = ela_kernel_module_load_flags(request);

#if defined(SYS_finit_module)
	if (syscall(SYS_finit_module, fd, request->params, flags) == 0) {
		close(fd);
		printf("module loaded: %s\n", request->module_path);
		return 0;
	}
	if (errno != ENOSYS) {
		fprintf(stderr, "finit_module(%s) failed: %s\n",
			request->module_path, strerror(errno));
		close(fd);
		return 1;
	}
#endif

	if (flags) {
		fprintf(stderr, "finit_module is unavailable; --force cannot be applied with init_module\n");
		close(fd);
		return 1;
	}

#if defined(SYS_init_module)
	{
		struct stat st;
		void *buf;
		ssize_t got;
		size_t off = 0;
		int rc = 1;

		if (fstat(fd, &st) != 0 || st.st_size < 0) {
			fprintf(stderr, "Cannot stat module %s: %s\n",
				request->module_path, strerror(errno));
			close(fd);
			return 1;
		}
		buf = malloc((size_t)st.st_size);
		if (!buf) {
			fprintf(stderr, "Cannot allocate module buffer\n");
			close(fd);
			return 1;
		}
		while (off < (size_t)st.st_size) {
			got = read(fd, (char *)buf + off, (size_t)st.st_size - off);
			if (got <= 0) {
				fprintf(stderr, "Cannot read module %s: %s\n",
					request->module_path,
					got < 0 ? strerror(errno) : "unexpected EOF");
				goto init_done;
			}
			off += (size_t)got;
		}
		if (syscall(SYS_init_module, buf, (unsigned long)st.st_size,
			    request->params) == 0) {
			printf("module loaded: %s\n", request->module_path);
			rc = 0;
		} else {
			fprintf(stderr, "init_module(%s) failed: %s\n",
				request->module_path, strerror(errno));
		}
init_done:
		free(buf);
		close(fd);
		return rc;
	}
#else
	fprintf(stderr, "module loading syscalls are unavailable on this platform\n");
	close(fd);
	return 1;
#endif
}

static int unload_module(const struct ela_kernel_module_request *request)
{
#if defined(SYS_delete_module)
	if (syscall(SYS_delete_module, request->module_name, O_NONBLOCK) == 0) {
		printf("module unloaded: %s\n", request->module_name);
		return 0;
	}
	fprintf(stderr, "delete_module(%s) failed: %s\n",
		request->module_name, strerror(errno));
	return 1;
#else
	fprintf(stderr, "delete_module syscall is unavailable on this platform\n");
	return 1;
#endif
}

int linux_kernel_module_main(int argc, char **argv)
{
	struct ela_kernel_module_request request;
	char errbuf[256];
	int ret;

	errbuf[0] = '\0';
	ret = ela_kernel_module_prepare_request(argc, argv, &request,
						errbuf, sizeof(errbuf));
	if (ret != 0) {
		if (errbuf[0])
			fprintf(stderr, "%s\n", errbuf);
		usage(argv[0]);
		return ret;
	}

	if (request.show_help) {
		usage(argv[0]);
		return 0;
	}

	if (request.action == ELA_KERNEL_MODULE_ACTION_LIST)
		return list_modules();
	if (request.action == ELA_KERNEL_MODULE_ACTION_LOAD)
		return load_module(&request);
	if (request.action == ELA_KERNEL_MODULE_ACTION_UNLOAD)
		return unload_module(&request);

	usage(argv[0]);
	return 2;
}
