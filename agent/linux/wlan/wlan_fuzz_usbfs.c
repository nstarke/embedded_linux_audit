// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "wlan_fuzz_usbfs.h"

/* Live USB transport requires hardware and capture privileges, so only the
 * offline engine paths are exercised by tests. */
/* LCOV_EXCL_START */

/* First 18 bytes of the device node are the device descriptor. */
int usbfs_open(uint16_t vid, const uint16_t *pids, int npids,
	       uint16_t *found_pid)
{
	char busdir[300], path[600];
	unsigned char desc[18];
	struct dirent *be, *de;
	DIR *bus, *dev;
	int fd, i;

	bus = opendir("/dev/bus/usb");
	if (!bus)
		return -1;

	while ((be = readdir(bus))) {
		if (be->d_name[0] == '.')
			continue;
		snprintf(busdir, sizeof(busdir), "/dev/bus/usb/%s", be->d_name);
		dev = opendir(busdir);
		if (!dev)
			continue;
		while ((de = readdir(dev))) {
			if (de->d_name[0] == '.')
				continue;
			snprintf(path, sizeof(path), "%s/%s", busdir, de->d_name);
			fd = open(path, O_RDWR);
			if (fd < 0)
				continue;
			if (read(fd, desc, sizeof(desc)) == (int)sizeof(desc)) {
				uint16_t dvid = desc[8] | (desc[9] << 8);
				uint16_t dpid = desc[10] | (desc[11] << 8);

				if (dvid == vid) {
					for (i = 0; i < npids; i++) {
						if (pids[i] && dpid != pids[i])
							continue;
						if (found_pid)
							*found_pid = dpid;
						closedir(dev);
						closedir(bus);
						return fd;
					}
				}
			}
			close(fd);
		}
		closedir(dev);
	}
	closedir(bus);
	errno = ENODEV;
	return -1;
}

int usbfs_detach_kernel(int fd, int ifno)
{
	struct usbfs_ioctl cmd = {
		.ifno = ifno,
		.ioctl_code = USBFS_DISCONNECT,
		.data = NULL,
	};
	int r = ioctl(fd, USBFS_IOCTL, &cmd);

	if (r < 0 && errno == ENODATA)	/* no driver attached: fine */
		return 0;
	return r;
}

int usbfs_claim(int fd, int ifno)
{
	unsigned int i = ifno;

	return ioctl(fd, USBFS_CLAIMINTF, &i);
}

int usbfs_ctrl(int fd, uint8_t reqtype, uint8_t req, uint16_t val,
	       uint16_t idx, void *data, uint16_t len, int timeout_ms)
{
	struct usbfs_ctrltransfer ct = {
		.bRequestType = reqtype, .bRequest = req,
		.wValue = val, .wIndex = idx, .wLength = len,
		.timeout = (uint32_t)timeout_ms, .data = data,
	};

	return ioctl(fd, USBFS_CONTROL, &ct);
}

int usbfs_xfer(int fd, unsigned int ep, void *data, int len, int timeout_ms)
{
	struct usbfs_bulktransfer bt = {
		.ep = ep, .len = (unsigned int)len,
		.timeout = (unsigned int)timeout_ms, .data = data,
	};

	return ioctl(fd, USBFS_BULK, &bt);
}

/* LCOV_EXCL_STOP */
