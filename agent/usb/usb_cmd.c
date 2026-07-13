// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "usb_util.h"
#include "../../kmod/ela_ioctl.h"

#include <errno.h>
#include <fcntl.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

struct usb_port_candidate {
	uint32_t hub_busnum;
	uint32_t hub_devnum;
	uint32_t portnum;
};

static pcap_t *usb_capture_handle;

static void usb_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s list\n"
		"       %s reset <DEVICE_INDEX>\n"
		"       %s port list\n"
		"       %s port <reset|power-cycle> <PORT_INDEX>\n"
		"       %s descriptor dump <DUMP_FILE_PATH> [DEVICE_INDEX]\n"
		"       %s pcap <DUMP_FILE_PATH> [BUS_NUMBER]\n"
		"  Device and port indices come from their corresponding list\n"
		"  descriptor defaults only when one non-root device is present\n"
		"  pcap captures usbmon0 (all buses) or usbmonBUS_NUMBER until interrupted\n"
		"  Kernel operations require ela_kmod, /dev/ela_physmem, and CAP_SYS_RAWIO\n",
		prog, prog, prog, prog, prog, prog);
}

static int usb_open_kmod(void)
{
	int fd = open(ELA_KMOD_DEVICE_PATH, O_RDWR | O_CLOEXEC);

	if (fd < 0)
		fprintf(stderr, "Cannot open %s: %s (load ela_kmod first)\n",
			ELA_KMOD_DEVICE_PATH, strerror(errno));
	return fd;
}

static const char *usb_speed_name(uint32_t speed)
{
	switch (speed) {
	case 1: return "low";
	case 2: return "full";
	case 3: return "high";
	case 4: return "wireless";
	case 5: return "super";
	case 6: return "super-plus";
	default: return "unknown";
	}
}

static int usb_collect(int fd, bool print, struct ela_usb_candidate **items_out,
		       size_t *count_out)
{
	struct ela_usb_candidate *items = NULL;
	size_t count = 0;
	size_t capacity = 0;
	uint32_t ordinal;

	for (ordinal = 0; ; ordinal++) {
		struct ela_kmod_usb_device req;
		struct ela_usb_candidate *tmp;

		memset(&req, 0, sizeof(req));
		req.abi_version = ELA_KMOD_ABI_VERSION;
		req.ordinal = ordinal;
		if (ioctl(fd, ELA_IOC_USB_GET, &req) != 0) {
			if (errno == ENOENT)
				break;
			fprintf(stderr, "ELA_IOC_USB_GET failed: %s\n", strerror(errno));
			free(items);
			return -1;
		}
		if (print)
			printf("index=%u bus=%u device=%u parent=%u:%u port=%u speed=%s id=%04x:%04x class=%02x/%02x/%02x configs=%u ports=%u manufacturer=%s product=%s serial=%s\n",
			       ordinal, req.busnum, req.devnum, req.parent_busnum,
			       req.parent_devnum, req.portnum, usb_speed_name(req.speed),
			       req.vendor_id, req.product_id, req.device_class,
			       req.device_subclass, req.device_protocol,
			       req.num_configurations, req.maxchild,
			       req.manufacturer[0] ? req.manufacturer : "-",
			       req.product[0] ? req.product : "-",
			       req.serial[0] ? req.serial : "-");
		if (!items_out) {
			count++;
			continue;
		}
		if (count == capacity) {
			size_t new_capacity = capacity ? capacity * 2 : 16;

			tmp = realloc(items, new_capacity * sizeof(*items));
			if (!tmp) {
				free(items);
				return -1;
			}
			items = tmp;
			capacity = new_capacity;
		}
		items[count].busnum = req.busnum;
		items[count].devnum = req.devnum;
		items[count].parent_devnum = req.parent_devnum;
		count++;
	}
	if (print && !count && !items_out)
		printf("No USB devices found.\n");
	if (items_out)
		*items_out = items;
	if (count_out)
		*count_out = count;
	return 0;
}

static int usb_resolve_device(int fd, size_t index,
			      struct ela_usb_candidate *selected)
{
	struct ela_usb_candidate *items = NULL;
	size_t count = 0;
	int rc = -1;

	if (usb_collect(fd, false, &items, &count) < 0)
		goto out;
	if (index >= count) {
		fprintf(stderr, "USB device index %zu is unavailable; run 'usb list'\n",
			index);
		goto out;
	}
	*selected = items[index];
	rc = 0;
out:
	free(items);
	return rc;
}

static int usb_reset_index(int fd, size_t index)
{
	struct ela_usb_candidate selected;
	struct ela_kmod_usb_reset req;

	if (usb_resolve_device(fd, index, &selected) < 0)
		return 1;
	memset(&req, 0, sizeof(req));
	req.abi_version = ELA_KMOD_ABI_VERSION;
	req.busnum = selected.busnum;
	req.devnum = selected.devnum;
	if (ioctl(fd, ELA_IOC_USB_RESET, &req) != 0) {
		fprintf(stderr, "USB reset failed: %s\n", strerror(errno));
		return 1;
	}
	printf("Reset USB index %zu (%u:%u)\n", index, selected.busnum,
	       selected.devnum);
	return 0;
}

static int usb_port_collect(int fd, bool print,
			    struct usb_port_candidate **items_out,
			    size_t *count_out)
{
	struct usb_port_candidate *items = NULL;
	size_t count = 0;
	size_t capacity = 0;
	uint32_t ordinal;

	for (ordinal = 0; ; ordinal++) {
		struct ela_kmod_usb_port req;
		struct usb_port_candidate *tmp;

		memset(&req, 0, sizeof(req));
		req.abi_version = ELA_KMOD_ABI_VERSION;
		req.ordinal = ordinal;
		if (ioctl(fd, ELA_IOC_USB_PORT_GET, &req) != 0) {
			if (errno == ENOENT)
				break;
			fprintf(stderr, "ELA_IOC_USB_PORT_GET failed: %s\n",
				strerror(errno));
			free(items);
			return -1;
		}
		if (print)
			printf("index=%u hub=%u:%u port=%u status=0x%04x change=0x%04x connected=%s child=%u:%u powered=%s enabled=%s\n",
			       ordinal, req.hub_busnum, req.hub_devnum, req.portnum,
			       req.status, req.change,
			       (req.status & 0x0001U) ? "yes" : "no",
			       req.child_busnum, req.child_devnum,
			       (req.status & (req.hub_speed >= 5 ? 0x0200U : 0x0100U)) ?
				       "yes" : "no",
			       (req.status & 0x0002U) ? "yes" : "no");
		if (!items_out) {
			count++;
			continue;
		}
		if (count == capacity) {
			size_t new_capacity = capacity ? capacity * 2 : 16;

			tmp = realloc(items, new_capacity * sizeof(*items));
			if (!tmp) {
				free(items);
				return -1;
			}
			items = tmp;
			capacity = new_capacity;
		}
		items[count].hub_busnum = req.hub_busnum;
		items[count].hub_devnum = req.hub_devnum;
		items[count].portnum = req.portnum;
		count++;
	}
	if (print && !count && !items_out)
		printf("No USB hub ports found.\n");
	if (items_out)
		*items_out = items;
	if (count_out)
		*count_out = count;
	return 0;
}

static int usb_port_action(int fd, size_t index, uint32_t action)
{
	struct usb_port_candidate *items = NULL;
	struct ela_kmod_usb_port_action req;
	size_t count = 0;
	int ret = 1;

	if (usb_port_collect(fd, false, &items, &count) < 0)
		goto out;
	if (index >= count) {
		fprintf(stderr, "USB port index %zu is unavailable; run 'usb port list'\n",
			index);
		goto out;
	}
	memset(&req, 0, sizeof(req));
	req.abi_version = ELA_KMOD_ABI_VERSION;
	req.hub_busnum = items[index].hub_busnum;
	req.hub_devnum = items[index].hub_devnum;
	req.portnum = items[index].portnum;
	req.action = action;
	if (ioctl(fd, ELA_IOC_USB_PORT_ACTION, &req) != 0) {
		fprintf(stderr, "USB port action failed: %s\n", strerror(errno));
		goto out;
	}
	printf("USB port index %zu %s requested\n", index,
	       action == ELA_USB_PORT_ACTION_RESET ? "reset" : "power cycle");
	ret = 0;
out:
	free(items);
	return ret;
}

static int write_all(int fd, const unsigned char *data, size_t len)
{
	size_t offset = 0;

	while (offset < len) {
		ssize_t written = write(fd, data + offset, len - offset);

		if (written < 0 && errno == EINTR)
			continue;
		if (written <= 0)
			return -1;
		offset += (size_t)written;
	}
	return 0;
}

static int usb_descriptor_dump(int fd, const char *path, bool index_set,
			       size_t index)
{
	struct ela_usb_candidate *items = NULL;
	struct ela_kmod_usb_descriptors req;
	unsigned char *buf = NULL;
	size_t count = 0;
	size_t selected;
	char errbuf[160];
	int out_fd = -1;
	int ret = 1;

	if (usb_collect(fd, false, &items, &count) < 0)
		goto out;
	if (index_set) {
		selected = index;
		if (selected >= count) {
			fprintf(stderr, "USB device index %zu is unavailable; run 'usb list'\n",
				selected);
			goto out;
		}
	} else if (ela_usb_select_descriptor_candidate(items, count, &selected,
						   errbuf, sizeof(errbuf)) < 0) {
		fprintf(stderr, "%s; run 'usb list'\n", errbuf);
		goto out;
	}
	buf = malloc(ELA_KMOD_USB_DESC_MAX);
	if (!buf)
		goto out;
	memset(&req, 0, sizeof(req));
	req.abi_version = ELA_KMOD_ABI_VERSION;
	req.busnum = items[selected].busnum;
	req.devnum = items[selected].devnum;
	req.buf = (uint64_t)(uintptr_t)buf;
	req.length = ELA_KMOD_USB_DESC_MAX;
	if (ioctl(fd, ELA_IOC_USB_DESCRIPTORS, &req) != 0) {
		fprintf(stderr, "USB descriptor dump failed: %s\n", strerror(errno));
		goto out;
	}
	out_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (out_fd < 0 || write_all(out_fd, buf, (size_t)req.actual_length) < 0 ||
	    fsync(out_fd) < 0) {
		fprintf(stderr, "Writing USB descriptors to %s failed: %s\n", path,
			strerror(errno));
		goto out;
	}
	printf("Dumped USB descriptors for index %zu (%u:%u, %llu bytes) to %s\n",
	       selected, items[selected].busnum, items[selected].devnum,
	       (unsigned long long)req.actual_length, path);
	ret = 0;
out:
	if (out_fd >= 0)
		close(out_fd);
	free(buf);
	free(items);
	return ret;
}

static void usb_capture_signal(int signo)
{
	(void)signo;
	if (usb_capture_handle)
		pcap_breakloop(usb_capture_handle);
}

static int usb_pcap_capture(const char *path, uint32_t busnum)
{
	char source[32];
	char errbuf[PCAP_ERRBUF_SIZE];
	struct sigaction action;
	struct sigaction old_int;
	struct sigaction old_term;
	pcap_dumper_t *dumper = NULL;
	FILE *output = NULL;
	int output_fd = -1;
	int rc;
	int ret = 1;

	snprintf(source, sizeof(source), "usbmon%u", busnum);
	usb_capture_handle = pcap_create(source, errbuf);
	if (!usb_capture_handle) {
		fprintf(stderr, "usb pcap: cannot create capture on %s: %s\n",
			source, errbuf);
		goto out;
	}
	if (pcap_set_snaplen(usb_capture_handle, 65535) != 0 ||
	    pcap_set_timeout(usb_capture_handle, 250) != 0 ||
	    pcap_set_immediate_mode(usb_capture_handle, 1) != 0) {
		fprintf(stderr, "usb pcap: cannot configure %s: %s\n", source,
			pcap_geterr(usb_capture_handle));
		goto out;
	}
	rc = pcap_activate(usb_capture_handle);
	if (rc < 0) {
		fprintf(stderr, "usb pcap: cannot activate %s: %s\n", source,
			pcap_geterr(usb_capture_handle));
		goto out;
	}
	output_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (output_fd < 0 || !(output = fdopen(output_fd, "wb"))) {
		fprintf(stderr, "usb pcap: cannot open %s: %s\n", path,
			strerror(errno));
		goto out;
	}
	output_fd = -1;
	dumper = pcap_dump_fopen(usb_capture_handle, output);
	if (!dumper) {
		fprintf(stderr, "usb pcap: cannot initialize %s: %s\n", path,
			pcap_geterr(usb_capture_handle));
		fclose(output);
		output = NULL;
		goto out;
	}
	output = NULL;
	memset(&action, 0, sizeof(action));
	action.sa_handler = usb_capture_signal;
	sigemptyset(&action.sa_mask);
	sigaction(SIGINT, &action, &old_int);
	sigaction(SIGTERM, &action, &old_term);
	fprintf(stderr, "Capturing %s to %s; press Ctrl-C to stop\n", source, path);
	rc = pcap_loop(usb_capture_handle, -1, pcap_dump, (unsigned char *)dumper);
	pcap_dump_flush(dumper);
	sigaction(SIGINT, &old_int, NULL);
	sigaction(SIGTERM, &old_term, NULL);
	if (rc == PCAP_ERROR) {
		fprintf(stderr, "usb pcap: capture failed: %s\n",
			pcap_geterr(usb_capture_handle));
		goto out;
	}
	ret = 0;
out:
	if (dumper)
		pcap_dump_close(dumper);
	else if (output)
		fclose(output);
	if (output_fd >= 0)
		close(output_fd);
	if (usb_capture_handle)
		pcap_close(usb_capture_handle);
	usb_capture_handle = NULL;
	return ret;
}

int usb_main(int argc, char **argv)
{
	enum {
		USB_CMD_LIST,
		USB_CMD_RESET,
		USB_CMD_PORT_LIST,
		USB_CMD_PORT_RESET,
		USB_CMD_PORT_POWER_CYCLE,
		USB_CMD_DESCRIPTOR_DUMP,
	} command;
	char errbuf[128];
	uint32_t value;
	size_t index = 0;
	bool index_set = false;
	int fd;
	int ret;

	if (argc < 2 || !strcmp(argv[1], "help") || !strcmp(argv[1], "-h") ||
	    !strcmp(argv[1], "--help")) {
		usb_usage(argv[0]);
		return argc < 2 ? 2 : 0;
	}
	if (!strcmp(argv[1], "pcap")) {
		if (argc < 3 || argc > 4) {
			usb_usage(argv[0]);
			return 2;
		}
		value = 0;
		if (argc == 4 && ela_usb_parse_u32(argv[3], &value, "USB bus number",
						   errbuf, sizeof(errbuf)) < 0) {
			fprintf(stderr, "%s\n", errbuf);
			return 2;
		}
		return usb_pcap_capture(argv[2], value);
	}
	if (!strcmp(argv[1], "list") && argc == 2) {
		command = USB_CMD_LIST;
	} else if (!strcmp(argv[1], "reset") && argc == 3) {
		command = USB_CMD_RESET;
		if (ela_usb_parse_u32(argv[2], &value, "USB device index", errbuf,
				      sizeof(errbuf)) < 0)
			goto invalid_value;
		index = value;
	} else if (!strcmp(argv[1], "port") && argc == 3 &&
		   !strcmp(argv[2], "list")) {
		command = USB_CMD_PORT_LIST;
	} else if (!strcmp(argv[1], "port") && argc == 4 &&
		   (!strcmp(argv[2], "reset") || !strcmp(argv[2], "power-cycle"))) {
		command = !strcmp(argv[2], "reset") ? USB_CMD_PORT_RESET :
			USB_CMD_PORT_POWER_CYCLE;
		if (ela_usb_parse_u32(argv[3], &value, "USB port index", errbuf,
				      sizeof(errbuf)) < 0)
			goto invalid_value;
		index = value;
	} else if (!strcmp(argv[1], "descriptor") && argc >= 4 && argc <= 5 &&
		   !strcmp(argv[2], "dump")) {
		command = USB_CMD_DESCRIPTOR_DUMP;
		index_set = argc == 5;
		if (index_set) {
			if (ela_usb_parse_u32(argv[4], &value, "USB device index",
					      errbuf, sizeof(errbuf)) < 0)
				goto invalid_value;
			index = value;
		}
	} else {
		usb_usage(argv[0]);
		return 2;
	}
	fd = usb_open_kmod();
	if (fd < 0)
		return 1;
	switch (command) {
	case USB_CMD_LIST:
		ret = usb_collect(fd, true, NULL, NULL) < 0 ? 1 : 0;
		break;
	case USB_CMD_RESET:
		ret = usb_reset_index(fd, index);
		break;
	case USB_CMD_PORT_LIST:
		ret = usb_port_collect(fd, true, NULL, NULL) < 0 ? 1 : 0;
		break;
	case USB_CMD_PORT_RESET:
	case USB_CMD_PORT_POWER_CYCLE:
		ret = usb_port_action(fd, index,
			command == USB_CMD_PORT_RESET ? ELA_USB_PORT_ACTION_RESET :
			ELA_USB_PORT_ACTION_POWER_CYCLE);
		break;
	case USB_CMD_DESCRIPTOR_DUMP:
		ret = usb_descriptor_dump(fd, argv[3], index_set, index);
		break;
	}
	close(fd);
	return ret;

invalid_value:
	fprintf(stderr, "%s\n", errbuf);
	return 2;
}
