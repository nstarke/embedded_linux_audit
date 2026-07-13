// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "spi_util.h"
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

static void spi_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s list\n"
		"       %s dump <DUMP_FILE_PATH> [DEVICE_INDEX]\n"
		"  list  Enumerate SPI and SPI-backed MTD devices via ela_kmod\n"
		"  dump  Read the indexed SPI-backed MTD via ela_kmod; when omitted,\n"
		"        DEVICE_INDEX defaults to the largest unambiguous device\n",
		prog, prog);
}

static int spi_open_kmod(void)
{
	int fd = open(ELA_KMOD_DEVICE_PATH, O_RDWR | O_CLOEXEC);

	if (fd < 0)
		fprintf(stderr, "Cannot open %s: %s (load ela_kmod first)\n",
			ELA_KMOD_DEVICE_PATH, strerror(errno));
	return fd;
}

static int spi_list_devices(int fd)
{
	uint32_t ordinal;
	int found = 0;

	for (ordinal = 0; ; ordinal++) {
		struct ela_kmod_spi_device req;

		memset(&req, 0, sizeof(req));
		req.abi_version = ELA_KMOD_ABI_VERSION;
		req.ordinal = ordinal;
		if (ioctl(fd, ELA_IOC_SPI_GET, &req) != 0) {
			if (errno == ENOENT)
				break;
			fprintf(stderr, "ELA_IOC_SPI_GET failed: %s\n", strerror(errno));
			return -1;
		}
		printf("%s driver=%s modalias=%s mode=0x%x max-speed-hz=%u bits-per-word=%u\n",
		       req.device_name, req.driver[0] ? req.driver : "-",
		       req.modalias[0] ? req.modalias : "-", req.mode,
		       req.max_speed_hz, req.bits_per_word);
		found++;
	}
	if (!found)
		printf("No SPI devices found.\n");
	return 0;
}

static int spi_collect_mtd(int fd, bool print,
			   struct ela_spi_mtd_candidate **items_out,
			   size_t *count_out)
{
	struct ela_spi_mtd_candidate *items = NULL;
	size_t count = 0;
	size_t capacity = 0;
	uint32_t ordinal;

	for (ordinal = 0; ; ordinal++) {
		struct ela_kmod_spi_mtd req;
		struct ela_spi_mtd_candidate *tmp;

		memset(&req, 0, sizeof(req));
		req.abi_version = ELA_KMOD_ABI_VERSION;
		req.ordinal = ordinal;
		if (ioctl(fd, ELA_IOC_SPI_MTD_GET, &req) != 0) {
			if (errno == ENOENT)
				break;
			fprintf(stderr, "ELA_IOC_SPI_MTD_GET failed: %s\n", strerror(errno));
			free(items);
			return -1;
		}
		if (print)
			printf("index=%u mtd%u spi=%s name=%s size=%llu erase-size=%u write-size=%u\n",
			       ordinal, req.mtd_index, req.spi_name,
			       req.mtd_name[0] ? req.mtd_name : "-",
			       (unsigned long long)req.size, req.erasesize,
			       req.writesize);
		if (!items_out)
			continue;
		if (count == capacity) {
			size_t new_capacity = capacity ? capacity * 2 : 8;

			tmp = realloc(items, new_capacity * sizeof(*items));
			if (!tmp) {
				fprintf(stderr, "Cannot allocate SPI MTD list\n");
				free(items);
				return -1;
			}
			items = tmp;
			capacity = new_capacity;
		}
		memset(&items[count], 0, sizeof(items[count]));
		snprintf(items[count].spi_name, sizeof(items[count].spi_name), "%s",
			 req.spi_name);
		snprintf(items[count].mtd_name, sizeof(items[count].mtd_name), "%s",
			 req.mtd_name);
		items[count].mtd_index = req.mtd_index;
		items[count].size = req.size;
		count++;
	}

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

static int spi_dump(int kmod_fd, const char *output_path,
		    bool device_index_set, size_t device_index)
{
	struct ela_spi_mtd_candidate *items = NULL;
	unsigned char *buf = NULL;
	size_t count = 0;
	size_t selected;
	uint64_t offset = 0;
	char errbuf[256];
	int output_fd = -1;
	int ret = 1;

	if (spi_collect_mtd(kmod_fd, false, &items, &count) < 0)
		goto out;
	if (device_index_set) {
		selected = device_index;
		if (selected >= count) {
			fprintf(stderr,
				"SPI device index %zu is not available; run 'spi list' to inspect candidates\n",
				selected);
			goto out;
		}
		if (!items[selected].size) {
			fprintf(stderr, "SPI device index %zu has no readable size\n",
				selected);
			goto out;
		}
	} else {
		if (ela_spi_select_dump_candidate(items, count, &selected,
						  errbuf, sizeof(errbuf)) < 0) {
			fprintf(stderr, "%s; run 'spi list' to inspect candidates\n", errbuf);
			goto out;
		}
	}
	output_fd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (output_fd < 0) {
		fprintf(stderr, "Unable to open dump file %s: %s\n", output_path,
			strerror(errno));
		goto out;
	}
	buf = malloc(ELA_KMOD_SPI_MAX_READ);
	if (!buf) {
		fprintf(stderr, "Cannot allocate SPI dump buffer\n");
		goto out;
	}

	while (offset < items[selected].size) {
		struct ela_kmod_spi_mtd_read req;
		size_t chunk = ELA_KMOD_SPI_MAX_READ;

		if (items[selected].size - offset < chunk)
			chunk = (size_t)(items[selected].size - offset);
		memset(&req, 0, sizeof(req));
		req.abi_version = ELA_KMOD_ABI_VERSION;
		req.mtd_index = items[selected].mtd_index;
		req.offset = offset;
		req.length = chunk;
		req.buf = (uint64_t)(uintptr_t)buf;
		if (ioctl(kmod_fd, ELA_IOC_SPI_MTD_READ, &req) != 0) {
			fprintf(stderr, "ELA_IOC_SPI_MTD_READ failed at offset %llu: %s\n",
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
	printf("Dumped index %zu, mtd%u (%llu bytes, SPI device %s) to %s\n",
	       selected, items[selected].mtd_index,
	       (unsigned long long)items[selected].size,
	       items[selected].spi_name, output_path);
	ret = 0;
out:
	if (output_fd >= 0)
		close(output_fd);
	free(buf);
	free(items);
	return ret;
}

int spi_main(int argc, char **argv)
{
	char errbuf[128];
	size_t device_index = 0;
	bool device_index_set = false;
	int fd;
	int ret;

	if (argc < 2 || !strcmp(argv[1], "help") || !strcmp(argv[1], "-h") ||
	    !strcmp(argv[1], "--help")) {
		spi_usage(argv[0]);
		return argc < 2 ? 2 : 0;
	}
	if (strcmp(argv[1], "list") && strcmp(argv[1], "dump")) {
		fprintf(stderr, "Unknown spi subcommand: %s\n", argv[1]);
		spi_usage(argv[0]);
		return 2;
	}
	if (!strcmp(argv[1], "list") && argc != 2) {
		fprintf(stderr, "spi list does not accept additional arguments\n");
		spi_usage(argv[0]);
		return 2;
	}
	if (!strcmp(argv[1], "dump") && (argc < 3 || argc > 4)) {
		fprintf(stderr,
			"spi dump requires DUMP_FILE_PATH and an optional DEVICE_INDEX\n");
		spi_usage(argv[0]);
		return 2;
	}
	if (!strcmp(argv[1], "dump") && argc == 4) {
		if (ela_spi_parse_device_index(argv[3], &device_index,
					       errbuf, sizeof(errbuf)) < 0) {
			fprintf(stderr, "%s\n", errbuf);
			return 2;
		}
		device_index_set = true;
	}

	fd = spi_open_kmod();
	if (fd < 0)
		return 1;
	if (!strcmp(argv[1], "list")) {
		ret = spi_list_devices(fd);
		if (!ret)
			ret = spi_collect_mtd(fd, true, NULL, NULL);
	} else {
		ret = spi_dump(fd, argv[2], device_index_set, device_index);
	}
	close(fd);
	return ret < 0 ? 1 : ret;
}
