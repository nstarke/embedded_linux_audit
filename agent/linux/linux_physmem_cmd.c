// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "embedded_linux_audit_cmd.h"
#include "linux_physmem_util.h"
#include "../../kmod/ela_ioctl.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* Device node override for tests (a fake node cannot service the ioctl, but
 * open/arg failure paths become reachable without root). */
static const char *physmem_device_path(void)
{
	const char *path = getenv("ELA_PHYSMEM_DEVICE");

	return (path && *path) ? path : ELA_KMOD_DEVICE_PATH;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s memread <phys-addr> <length> [--uncached]\n"
		"       %s memwrite <phys-addr> <hex-bytes> [--uncached]\n"
		"  memread dumps physical memory via " ELA_KMOD_DEVICE_PATH " (ela_kmod\n"
		"    module; deliver and load it first) and uploads the raw bytes as a\n"
		"    physmem upload\n"
		"  memwrite writes the given hex bytes (e.g. deadbeef or de:ad:be:ef)\n"
		"    to physical memory; DANGEROUS — no target validation is performed\n"
		"  addresses and lengths accept decimal or 0x-prefixed hex\n"
		"  --uncached forces an uncached mapping (device/MMIO ranges)\n",
		prog, prog);
}

/* Open the ela_kmod device with the standard missing-module hint. */
static int physmem_open_device(void)
{
	int fd = open(physmem_device_path(), O_RDWR | O_CLOEXEC);

	if (fd < 0)
		fprintf(stderr, "Cannot open %s: %s%s\n",
			physmem_device_path(), strerror(errno),
			errno == ENOENT ? " (is the ela_kmod module loaded?)" : "");
	return fd;
}

static int upload_physmem_bytes(const unsigned char *data, size_t len,
				uint64_t phys_addr)
{
	const char *output_http = getenv("ELA_OUTPUT_HTTP");
	const char *output_https = getenv("ELA_OUTPUT_HTTPS");
	const char *output_uri = output_http && *output_http ? output_http : output_https;
	bool insecure = getenv("ELA_OUTPUT_INSECURE") &&
		!strcmp(getenv("ELA_OUTPUT_INSECURE"), "1");
	char range[64];
	char errbuf[256];
	char *upload_uri;
	int rc = 0;

	if (!output_uri || !*output_uri)
		return 0;

	/* filePath doubles as the range descriptor so the artifact filename on
	 * the server carries what was read. */
	snprintf(range, sizeof(range), "0x%llx-%zu",
		 (unsigned long long)phys_addr, len);
	upload_uri = ela_http_build_upload_uri(output_uri, "physmem", range);
	if (!upload_uri)
		return -1;
	if (ela_http_post(upload_uri, data, len, "application/octet-stream",
			  insecure, false, errbuf, sizeof(errbuf)) != 0) {
		fprintf(stderr, "Failed to POST physmem bytes to %s: %s\n",
			upload_uri, errbuf[0] ? errbuf : "unknown error");
		rc = -1;
	}
	free(upload_uri);
	return rc;
}

static int do_memread(const struct ela_physmem_request *request)
{
	struct ela_kmod_read_phys req;
	unsigned char *buf;
	char line[128];
	size_t off;
	int fd;

	if (request->length > ELA_KMOD_MAX_READ) {
		fprintf(stderr, "Read length exceeds per-call maximum (%lu bytes)\n",
			(unsigned long)ELA_KMOD_MAX_READ);
		return 1;
	}

	buf = malloc(request->length);
	if (!buf) {
		fprintf(stderr, "Cannot allocate read buffer\n");
		return 1;
	}

	fd = physmem_open_device();
	if (fd < 0) {
		free(buf);
		return 1;
	}

	memset(&req, 0, sizeof(req));
	req.abi_version = ELA_KMOD_ABI_VERSION;
	req.flags = request->uncached ? ELA_KMOD_READ_F_UNCACHED : 0;
	req.phys_addr = request->phys_addr;
	req.length = request->length;
	req.buf = (uint64_t)(uintptr_t)buf;

	if (ioctl(fd, ELA_IOC_READ_PHYS, &req) != 0) {
		fprintf(stderr, "ELA_IOC_READ_PHYS failed: %s\n", strerror(errno));
		close(fd);
		free(buf);
		return 1;
	}
	close(fd);

	for (off = 0; off < request->length; off += 16) {
		size_t chunk = request->length - off;

		if (chunk > 16)
			chunk = 16;
		if (ela_physmem_format_dump_line(request->phys_addr, buf, off,
						 chunk, line, sizeof(line)) == 0)
			fputs(line, stdout);
	}

	if (upload_physmem_bytes(buf, request->length, request->phys_addr) != 0) {
		free(buf);
		return 1;
	}

	free(buf);
	return 0;
}

static int do_memwrite(const struct ela_physmem_request *request)
{
	struct ela_kmod_write_phys req;
	unsigned char data[4096];
	int len;
	int fd;

	len = ela_physmem_decode_hex(request->hex_data, data, sizeof(data));
	if (len < 0) {
		fprintf(stderr, "Invalid hex data (max %zu bytes per call)\n",
			sizeof(data));
		return 1;
	}

	fd = physmem_open_device();
	if (fd < 0)
		return 1;

	memset(&req, 0, sizeof(req));
	req.abi_version = ELA_KMOD_ABI_VERSION;
	req.flags = request->uncached ? ELA_KMOD_READ_F_UNCACHED : 0;
	req.phys_addr = request->phys_addr;
	req.length = (uint64_t)len;
	req.buf = (uint64_t)(uintptr_t)data;

	if (ioctl(fd, ELA_IOC_WRITE_PHYS, &req) != 0) {
		fprintf(stderr, "ELA_IOC_WRITE_PHYS failed: %s\n", strerror(errno));
		close(fd);
		return 1;
	}
	close(fd);

	printf("wrote %d byte%s to 0x%llx\n", len, len == 1 ? "" : "s",
	       (unsigned long long)request->phys_addr);
	return 0;
}

static void mmio_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s read <phys-addr> <width>\n"
		"       %s write <phys-addr> <width> <value>\n"
		"  one naturally-aligned uncached device register access via\n"
		"  " ELA_KMOD_DEVICE_PATH "; width is 1, 2, 4, or 8 bytes\n"
		"  write is DANGEROUS - device registers act on writes\n",
		prog, prog);
}

int linux_mmio_main(int argc, char **argv)
{
	struct ela_mmio_request request;
	struct ela_kmod_mmio req;
	char errbuf[256];
	int ret;
	int fd;

	errbuf[0] = '\0';
	ret = ela_mmio_prepare_request(argc, argv, &request,
				       errbuf, sizeof(errbuf));
	if (ret != 0 || request.show_help) {
		if (errbuf[0])
			fprintf(stderr, "%s\n", errbuf);
		mmio_usage(argv[0]);
		return ret;
	}

	fd = physmem_open_device();
	if (fd < 0)
		return 1;

	memset(&req, 0, sizeof(req));
	req.abi_version = ELA_KMOD_ABI_VERSION;
	req.width = request.width;
	req.phys_addr = request.phys_addr;
	req.value = request.value;

	if (ioctl(fd, request.write ? ELA_IOC_WRITE_MMIO : ELA_IOC_READ_MMIO,
		  &req) != 0) {
		fprintf(stderr, "%s failed: %s\n",
			request.write ? "ELA_IOC_WRITE_MMIO" : "ELA_IOC_READ_MMIO",
			strerror(errno));
		close(fd);
		return 1;
	}
	close(fd);

	if (request.write)
		printf("mmio write 0x%llx width %u value 0x%llx\n",
		       (unsigned long long)request.phys_addr, request.width,
		       (unsigned long long)request.value);
	else
		printf("mmio read 0x%llx width %u value 0x%0*llx\n",
		       (unsigned long long)request.phys_addr, request.width,
		       (int)(request.width * 2), (unsigned long long)req.value);
	return 0;
}

static void pci_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s read <bdf> <offset> <width>\n"
		"       %s write <bdf> <offset> <width> <value>\n"
		"  PCI config space access via " ELA_KMOD_DEVICE_PATH "\n"
		"  bdf is [domain:]bus:device.function in hex (e.g. 00:1f.3)\n"
		"  offset is 0-4095 (extended config where the bus supports it);\n"
		"  width is 1, 2, or 4 bytes\n",
		prog, prog);
}

int linux_pci_main(int argc, char **argv)
{
	struct ela_pci_request request;
	struct ela_kmod_pci_cfg req;
	char errbuf[256];
	int ret;
	int fd;

	errbuf[0] = '\0';
	ret = ela_pci_prepare_request(argc, argv, &request,
				      errbuf, sizeof(errbuf));
	if (ret != 0 || request.show_help) {
		if (errbuf[0])
			fprintf(stderr, "%s\n", errbuf);
		pci_usage(argv[0]);
		return ret;
	}

	fd = physmem_open_device();
	if (fd < 0)
		return 1;

	memset(&req, 0, sizeof(req));
	req.abi_version = ELA_KMOD_ABI_VERSION;
	req.width = request.width;
	req.domain = request.domain;
	req.bus = request.bus;
	req.device = request.device;
	req.function = request.function;
	req.offset = request.offset;
	req.value = request.value;

	if (ioctl(fd, request.write ? ELA_IOC_PCI_WRITE : ELA_IOC_PCI_READ,
		  &req) != 0) {
		fprintf(stderr, "%s failed: %s%s\n",
			request.write ? "ELA_IOC_PCI_WRITE" : "ELA_IOC_PCI_READ",
			strerror(errno),
			errno == ENODEV ? " (no such PCI device)" : "");
		close(fd);
		return 1;
	}
	close(fd);

	if (request.write)
		printf("pci write %04x:%02x:%02x.%x offset 0x%x width %u value 0x%x\n",
		       request.domain, request.bus, request.device,
		       request.function, request.offset, request.width,
		       request.value);
	else
		printf("pci read %04x:%02x:%02x.%x offset 0x%x width %u value 0x%0*x\n",
		       request.domain, request.bus, request.device,
		       request.function, request.offset, request.width,
		       (int)(request.width * 2), req.value);
	return 0;
}

static void physctl_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s alloc <bytes> [max-phys-addr]\n"
		"       %s free <phys-addr>\n"
		"       %s va2pa <kernel-virt-addr>\n"
		"  alloc reserves a zeroed physically-contiguous kernel buffer and\n"
		"    prints its physical address (freed automatically when unused\n"
		"    fds close; access it with memread/memwrite)\n"
		"  free releases an allocation made by this agent\n"
		"  va2pa translates a kernel linear-map virtual address\n",
		prog, prog, prog);
}

int linux_physctl_main(int argc, char **argv)
{
	struct ela_physctl_request request;
	char errbuf[256];
	int ret;
	int fd;

	errbuf[0] = '\0';
	ret = ela_physctl_prepare_request(argc, argv, &request,
					  errbuf, sizeof(errbuf));
	if (ret != 0 || request.show_help) {
		if (errbuf[0])
			fprintf(stderr, "%s\n", errbuf);
		physctl_usage(argv[0]);
		return ret;
	}

	fd = physmem_open_device();
	if (fd < 0)
		return 1;

	if (request.action == ELA_PHYSCTL_ACTION_ALLOC) {
		struct ela_kmod_alloc_phys req;

		memset(&req, 0, sizeof(req));
		req.abi_version = ELA_KMOD_ABI_VERSION;
		req.length = request.length;
		req.max_phys_addr = request.max_phys_addr;
		if (ioctl(fd, ELA_IOC_ALLOC_PHYS, &req) != 0) {
			fprintf(stderr, "ELA_IOC_ALLOC_PHYS failed: %s\n",
				strerror(errno));
			close(fd);
			return 1;
		}
		printf("allocated %llu bytes at phys 0x%llx\n",
		       (unsigned long long)request.length,
		       (unsigned long long)req.phys_addr);
		/* NOTE: the allocation belongs to this (now closing) fd and
		 * the kernel frees it on close. Warn so the output is not
		 * mistaken for a persistent reservation; a long-lived
		 * reservation needs a persistent holder process. */
		fprintf(stderr,
			"warning: allocation is freed when this command exits; "
			"use from a persistent session for lasting reservations\n");
	} else if (request.action == ELA_PHYSCTL_ACTION_FREE) {
		struct ela_kmod_free_phys req;

		memset(&req, 0, sizeof(req));
		req.abi_version = ELA_KMOD_ABI_VERSION;
		req.phys_addr = request.addr;
		if (ioctl(fd, ELA_IOC_FREE_PHYS, &req) != 0) {
			fprintf(stderr, "ELA_IOC_FREE_PHYS failed: %s%s\n",
				strerror(errno),
				errno == ENOENT ? " (not an allocation of this process)" : "");
			close(fd);
			return 1;
		}
		printf("freed phys 0x%llx\n", (unsigned long long)request.addr);
	} else {
		struct ela_kmod_va2pa req;

		memset(&req, 0, sizeof(req));
		req.abi_version = ELA_KMOD_ABI_VERSION;
		req.virt_addr = request.addr;
		if (ioctl(fd, ELA_IOC_VA2PA, &req) != 0) {
			fprintf(stderr, "ELA_IOC_VA2PA failed: %s%s\n",
				strerror(errno),
				errno == EINVAL ? " (not a kernel linear-map address)" : "");
			close(fd);
			return 1;
		}
		printf("virt 0x%llx -> phys 0x%llx\n",
		       (unsigned long long)request.addr,
		       (unsigned long long)req.phys_addr);
	}

	close(fd);
	return 0;
}

int linux_physmem_main(int argc, char **argv)
{
	struct ela_physmem_request request;
	char errbuf[256];
	int ret;

	errbuf[0] = '\0';
	ret = ela_physmem_prepare_request(argc, argv, &request,
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

	if (request.action == ELA_PHYSMEM_ACTION_READ)
		return do_memread(&request);
	if (request.action == ELA_PHYSMEM_ACTION_WRITE)
		return do_memwrite(&request);

	usage(argv[0]);
	return 2;
}
