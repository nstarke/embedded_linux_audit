// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "orom_kmod_util.h"
#include "../../kmod/ela_ioctl.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static void orom_kmod_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s list\n"
		"       %s dump <DUMP_FILE_PATH> [DEVICE_INDEX]\n"
		"  list  Enumerate kernel-mappable PCI option ROMs via ela_kmod\n"
		"  dump  Read the selected PCI option ROM via ela_kmod\n"
		"        DEVICE_INDEX defaults to the largest unambiguous ROM\n",
		prog, prog);
}

static int orom_open_kmod(void)
{
	int fd = open(ELA_KMOD_DEVICE_PATH, O_RDWR | O_CLOEXEC);

	if (fd < 0)
		fprintf(stderr, "Cannot open %s: %s (load ela_kmod first)\n",
			ELA_KMOD_DEVICE_PATH, strerror(errno));
	return fd;
}

static int orom_collect(int fd, bool print,
			struct ela_orom_kmod_candidate **items_out,
			size_t *count_out)
{
	struct ela_orom_kmod_candidate *items = NULL;
	size_t count = 0;
	size_t capacity = 0;
	uint32_t ordinal;

	for (ordinal = 0; ; ordinal++) {
		struct ela_kmod_orom_device req;
		struct ela_orom_kmod_candidate *tmp;

		memset(&req, 0, sizeof(req));
		req.abi_version = ELA_KMOD_ABI_VERSION;
		req.ordinal = ordinal;
		if (ioctl(fd, ELA_IOC_OROM_GET, &req) != 0) {
			if (errno == ENOENT)
				break;
			fprintf(stderr, "ELA_IOC_OROM_GET failed: %s\n", strerror(errno));
			free(items);
			return -1;
		}
		if (print)
			printf("index=%u bdf=%04x:%02x:%02x.%x vendor=%04x device=%04x class=%06x size=%llu\n",
			       ordinal, req.domain, req.bus, req.device, req.function,
			       req.vendor_id, req.device_id, req.class_code & 0xffffffU,
			       (unsigned long long)req.size);
		if (!items_out) {
			count++;
			continue;
		}
		if (count == capacity) {
			size_t new_capacity = capacity ? capacity * 2 : 8;

			tmp = realloc(items, new_capacity * sizeof(*items));
			if (!tmp) {
				fprintf(stderr, "Cannot allocate option ROM device list\n");
				free(items);
				return -1;
			}
			items = tmp;
			capacity = new_capacity;
		}
		items[count].domain = req.domain;
		items[count].bus = req.bus;
		items[count].device = req.device;
		items[count].function = req.function;
		items[count].size = req.size;
		count++;
	}
	if (print && !count && !items_out)
		printf("No kernel-mappable PCI option ROMs found.\n");
	if (items_out)
		*items_out = items;
	if (count_out)
		*count_out = count;
	return 0;
}

static int write_all(int fd, const unsigned char *data, size_t len)
{
	size_t offset = 0;

	while (offset < len) {
		ssize_t written;

		do {
			written = write(fd, data + offset, len - offset);
		} while (written < 0 && errno == EINTR);
		if (written <= 0)
			return -1;
		offset += (size_t)written;
	}
	return 0;
}

static int orom_dump(int kmod_fd, const char *output_path,
		     bool index_set, size_t requested_index)
{
	struct ela_orom_kmod_candidate *items = NULL;
	unsigned char *buf = NULL;
	size_t count = 0;
	size_t selected;
	uint64_t offset = 0;
	char errbuf[256];
	int output_fd = -1;
	int ret = 1;

	if (orom_collect(kmod_fd, false, &items, &count) < 0)
		goto out;
	if (index_set) {
		selected = requested_index;
		if (selected >= count) {
			fprintf(stderr,
				"Option ROM index %zu is not available; run 'orom list' to inspect candidates\n",
				selected);
			goto out;
		}
	} else if (ela_orom_kmod_select_candidate(items, count, &selected,
						      errbuf, sizeof(errbuf)) < 0) {
		fprintf(stderr, "%s; run 'orom list' to inspect candidates\n", errbuf);
		goto out;
	}

	output_fd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (output_fd < 0) {
		fprintf(stderr, "Unable to open dump file %s: %s\n", output_path,
			strerror(errno));
		goto out;
	}
	buf = malloc(ELA_KMOD_OROM_MAX_READ);
	if (!buf) {
		fprintf(stderr, "Cannot allocate option ROM dump buffer\n");
		goto out;
	}

	while (offset < items[selected].size) {
		struct ela_kmod_orom_read req;
		size_t chunk = ELA_KMOD_OROM_MAX_READ;

		if (items[selected].size - offset < chunk)
			chunk = (size_t)(items[selected].size - offset);
		memset(&req, 0, sizeof(req));
		req.abi_version = ELA_KMOD_ABI_VERSION;
		req.domain = items[selected].domain;
		req.bus = items[selected].bus;
		req.device = items[selected].device;
		req.function = items[selected].function;
		req.offset = offset;
		req.length = chunk;
		req.buf = (uint64_t)(uintptr_t)buf;
		if (ioctl(kmod_fd, ELA_IOC_OROM_READ, &req) != 0) {
			fprintf(stderr, "ELA_IOC_OROM_READ failed at offset %llu: %s\n",
				(unsigned long long)offset, strerror(errno));
			goto out;
		}
		if (write_all(output_fd, buf, chunk) < 0) {
			fprintf(stderr, "Writing dump file %s failed: %s\n",
				output_path, strerror(errno));
			goto out;
		}
		offset += chunk;
	}
	if (fsync(output_fd) < 0) {
		fprintf(stderr, "Unable to sync dump file %s: %s\n", output_path,
			strerror(errno));
		goto out;
	}
	printf("Dumped index %zu, %04x:%02x:%02x.%x (%llu bytes) to %s\n",
	       selected, items[selected].domain, items[selected].bus,
	       items[selected].device, items[selected].function,
	       (unsigned long long)items[selected].size, output_path);
	ret = 0;
out:
	if (output_fd >= 0)
		close(output_fd);
	free(buf);
	free(items);
	return ret;
}

int orom_main(int argc, char **argv)
{
	char errbuf[128];
	size_t index = 0;
	bool index_set = false;
	int fd;
	int ret;

	if (argc < 2 || !strcmp(argv[1], "help") || !strcmp(argv[1], "-h") ||
	    !strcmp(argv[1], "--help")) {
		orom_kmod_usage(argv[0]);
		return argc < 2 ? 2 : 0;
	}
	if (strcmp(argv[1], "list") && strcmp(argv[1], "dump")) {
		fprintf(stderr, "Unknown orom action: %s\n", argv[1]);
		orom_kmod_usage(argv[0]);
		return 2;
	}
	if (!strcmp(argv[1], "list") && argc != 2) {
		fprintf(stderr, "orom list does not accept additional arguments\n");
		orom_kmod_usage(argv[0]);
		return 2;
	}
	if (!strcmp(argv[1], "dump") && (argc < 3 || argc > 4)) {
		fprintf(stderr,
			"orom dump requires DUMP_FILE_PATH and an optional DEVICE_INDEX\n");
		orom_kmod_usage(argv[0]);
		return 2;
	}
	if (!strcmp(argv[1], "dump") && argc == 4) {
		if (ela_orom_kmod_parse_index(argv[3], &index, errbuf,
					      sizeof(errbuf)) < 0) {
			fprintf(stderr, "%s\n", errbuf);
			return 2;
		}
		index_set = true;
	}

	fd = orom_open_kmod();
	if (fd < 0)
		return 1;
	if (!strcmp(argv[1], "list"))
		ret = orom_collect(fd, true, NULL, NULL);
	else
		ret = orom_dump(fd, argv[2], index_set, index);
	close(fd);
	return ret < 0 ? 1 : ret;
}
