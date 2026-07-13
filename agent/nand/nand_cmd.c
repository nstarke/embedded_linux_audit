// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "nand_util.h"
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

#define ELA_MTD_NANDFLASH 4U
#define ELA_MTD_MLCNANDFLASH 8U

static void nand_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s flash list\n"
		"       %s flash dump <DUMP_FILE_PATH> [DEVICE_INDEX]\n"
		"  list  Enumerate NAND MTD devices via ela_kmod\n"
		"  dump  Read corrected main-area data via ela_kmod; marked bad\n"
		"        eraseblocks are padded with 0xff and OOB is not included\n"
		"        DEVICE_INDEX defaults to the largest unambiguous device\n",
		prog, prog);
}

static int nand_open_kmod(void)
{
	int fd = open(ELA_KMOD_DEVICE_PATH, O_RDWR | O_CLOEXEC);

	if (fd < 0)
		fprintf(stderr, "Cannot open %s: %s (load ela_kmod first)\n",
			ELA_KMOD_DEVICE_PATH, strerror(errno));
	return fd;
}

static const char *nand_type_name(uint32_t type)
{
	if (type == ELA_MTD_NANDFLASH)
		return "slc";
	if (type == ELA_MTD_MLCNANDFLASH)
		return "mlc-or-tlc";
	return "unknown";
}

static int nand_collect(int fd, bool print,
			struct ela_nand_candidate **items_out,
			size_t *count_out)
{
	struct ela_nand_candidate *items = NULL;
	size_t count = 0;
	size_t capacity = 0;
	uint32_t ordinal;

	for (ordinal = 0; ; ordinal++) {
		struct ela_kmod_nand_mtd req;
		struct ela_nand_candidate *tmp;

		memset(&req, 0, sizeof(req));
		req.abi_version = ELA_KMOD_ABI_VERSION;
		req.ordinal = ordinal;
		if (ioctl(fd, ELA_IOC_NAND_MTD_GET, &req) != 0) {
			if (errno == ENOENT)
				break;
			fprintf(stderr, "ELA_IOC_NAND_MTD_GET failed: %s\n",
				strerror(errno));
			free(items);
			return -1;
		}
		if (print)
			printf("index=%u mtd%u type=%s name=%s size=%llu erase-size=%u page-size=%u oob-size=%u ecc-strength=%u\n",
			       ordinal, req.mtd_index, nand_type_name(req.type),
			       req.mtd_name[0] ? req.mtd_name : "-",
			       (unsigned long long)req.size, req.erasesize,
			       req.writesize, req.oobsize, req.ecc_strength);
		if (!items_out) {
			count++;
			continue;
		}
		if (count == capacity) {
			size_t new_capacity = capacity ? capacity * 2 : 8;

			tmp = realloc(items, new_capacity * sizeof(*items));
			if (!tmp) {
				fprintf(stderr, "Cannot allocate NAND device list\n");
				free(items);
				return -1;
			}
			items = tmp;
			capacity = new_capacity;
		}
		memset(&items[count], 0, sizeof(items[count]));
		snprintf(items[count].mtd_name, sizeof(items[count].mtd_name), "%s",
			 req.mtd_name);
		items[count].mtd_index = req.mtd_index;
		items[count].erasesize = req.erasesize;
		items[count].size = req.size;
		count++;
	}
	if (print && !count && !items_out)
		printf("No NAND MTD devices found.\n");
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

static int nand_dump(int kmod_fd, const char *output_path,
		     bool device_index_set, size_t device_index)
{
	struct ela_nand_candidate *items = NULL;
	unsigned char *buf = NULL;
	size_t count = 0;
	size_t selected;
	uint64_t offset = 0;
	bool saw_bad_block = false;
	char errbuf[256];
	int output_fd = -1;
	int ret = 1;

	if (nand_collect(kmod_fd, false, &items, &count) < 0)
		goto out;
	if (device_index_set) {
		selected = device_index;
		if (selected >= count) {
			fprintf(stderr,
				"NAND device index %zu is not available; run 'nand flash list' to inspect candidates\n",
				selected);
			goto out;
		}
		if (!items[selected].size) {
			fprintf(stderr, "NAND device index %zu has no readable size\n",
				selected);
			goto out;
		}
	} else if (ela_nand_select_dump_candidate(items, count, &selected,
						      errbuf, sizeof(errbuf)) < 0) {
		fprintf(stderr, "%s; run 'nand flash list' to inspect candidates\n",
			errbuf);
		goto out;
	}

	output_fd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (output_fd < 0) {
		fprintf(stderr, "Unable to open dump file %s: %s\n", output_path,
			strerror(errno));
		goto out;
	}
	buf = malloc(ELA_KMOD_NAND_MAX_READ);
	if (!buf) {
		fprintf(stderr, "Cannot allocate NAND dump buffer\n");
		goto out;
	}

	while (offset < items[selected].size) {
		struct ela_kmod_nand_mtd_read req;
		size_t chunk = ELA_KMOD_NAND_MAX_READ;

		if (items[selected].size - offset < chunk)
			chunk = (size_t)(items[selected].size - offset);
		memset(&req, 0, sizeof(req));
		req.abi_version = ELA_KMOD_ABI_VERSION;
		req.mtd_index = items[selected].mtd_index;
		req.offset = offset;
		req.length = chunk;
		req.buf = (uint64_t)(uintptr_t)buf;
		if (ioctl(kmod_fd, ELA_IOC_NAND_MTD_READ, &req) != 0) {
			fprintf(stderr, "ELA_IOC_NAND_MTD_READ failed at offset %llu: %s\n",
				(unsigned long long)offset, strerror(errno));
			goto out;
		}
		if (req.bad_blocks)
			saw_bad_block = true;
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
	printf("Dumped index %zu, mtd%u (%llu main-area bytes) to %s\n",
	       selected, items[selected].mtd_index,
	       (unsigned long long)items[selected].size, output_path);
	if (saw_bad_block)
		fprintf(stderr,
			"Warning: marked bad eraseblocks were padded with 0xff in the dump\n");
	ret = 0;
out:
	if (output_fd >= 0)
		close(output_fd);
	free(buf);
	free(items);
	return ret;
}

int nand_main(int argc, char **argv)
{
	char errbuf[128];
	size_t device_index = 0;
	bool device_index_set = false;
	int fd;
	int ret;

	if (argc < 2 || !strcmp(argv[1], "help") || !strcmp(argv[1], "-h") ||
	    !strcmp(argv[1], "--help")) {
		nand_usage(argv[0]);
		return argc < 2 ? 2 : 0;
	}
	if (strcmp(argv[1], "flash")) {
		fprintf(stderr, "Unknown nand subcommand: %s\n", argv[1]);
		nand_usage(argv[0]);
		return 2;
	}
	if (argc < 3 || !strcmp(argv[2], "help") || !strcmp(argv[2], "-h") ||
	    !strcmp(argv[2], "--help")) {
		nand_usage(argv[0]);
		return argc < 3 ? 2 : 0;
	}
	if (strcmp(argv[2], "list") && strcmp(argv[2], "dump")) {
		fprintf(stderr, "Unknown nand flash action: %s\n", argv[2]);
		nand_usage(argv[0]);
		return 2;
	}
	if (!strcmp(argv[2], "list") && argc != 3) {
		fprintf(stderr, "nand flash list does not accept additional arguments\n");
		nand_usage(argv[0]);
		return 2;
	}
	if (!strcmp(argv[2], "dump") && (argc < 4 || argc > 5)) {
		fprintf(stderr,
			"nand flash dump requires DUMP_FILE_PATH and an optional DEVICE_INDEX\n");
		nand_usage(argv[0]);
		return 2;
	}
	if (!strcmp(argv[2], "dump") && argc == 5) {
		if (ela_nand_parse_device_index(argv[4], &device_index,
						errbuf, sizeof(errbuf)) < 0) {
			fprintf(stderr, "%s\n", errbuf);
			return 2;
		}
		device_index_set = true;
	}

	fd = nand_open_kmod();
	if (fd < 0)
		return 1;
	if (!strcmp(argv[2], "list"))
		ret = nand_collect(fd, true, NULL, NULL);
	else
		ret = nand_dump(fd, argv[3], device_index_set, device_index);
	close(fd);
	return ret < 0 ? 1 : ret;
}
