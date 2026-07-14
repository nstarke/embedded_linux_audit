// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "wlan_fuzz.h"
#include "wlan_fuzz_kmod.h"
#include "../../../kmod/ela_ioctl.h"

/* The shim rides the ela_kmod device and needs the module loaded plus real
 * hardware, so these paths are exercised only in the field, not by tests. */
/* LCOV_EXCL_START */

int wlan_kmod_open(void)
{
	return open(ELA_KMOD_DEVICE_PATH, O_RDWR | O_CLOEXEC);
}

int wlan_kmod_attach(int fd, uint32_t driver)
{
	struct ela_kmod_wlan_attach req;

	memset(&req, 0, sizeof(req));
	req.abi_version = ELA_KMOD_ABI_VERSION;
	req.driver = driver;
	return ioctl(fd, ELA_IOC_WLAN_ATTACH, &req) < 0 ? -1 : 0;
}

void wlan_kmod_detach(int fd, uint32_t driver)
{
	struct ela_kmod_wlan_attach req;

	memset(&req, 0, sizeof(req));
	req.abi_version = ELA_KMOD_ABI_VERSION;
	req.driver = driver;
	(void)ioctl(fd, ELA_IOC_WLAN_DETACH, &req);
}

int wlan_kmod_status(int fd, uint64_t *restart_count, uint32_t *captured)
{
	struct ela_kmod_wlan_status req;

	memset(&req, 0, sizeof(req));
	req.abi_version = ELA_KMOD_ABI_VERSION;
	if (ioctl(fd, ELA_IOC_WLAN_STATUS, &req) < 0)
		return -1;
	if (restart_count)
		*restart_count = req.restart_count;
	if (captured)
		*captured = req.captured;
	return 0;
}

int wlan_kmod_wait_capture(int fd, int timeout_ms)
{
	int waited = 0;

	for (;;) {
		uint32_t captured = 0;

		if (wlan_kmod_status(fd, NULL, &captured) == 0 && captured)
			return 0;
		if (waited >= timeout_ms)
			return -1;
		msleep_ms(200);
		waited += 200;
	}
}

int wlan_kmod_inject(int fd, uint32_t cmd_id, const void *buf, int len,
		     int32_t *send_ret)
{
	struct ela_kmod_wlan_inject req;

	memset(&req, 0, sizeof(req));
	req.abi_version = ELA_KMOD_ABI_VERSION;
	req.cmd_id = cmd_id;
	req.len = (uint32_t)(len < 0 ? 0 : len);
	req.data = (uint64_t)(uintptr_t)buf;
	if (ioctl(fd, ELA_IOC_WLAN_INJECT, &req) < 0)
		return -1;
	if (send_ret)
		*send_ret = req.send_ret;
	return 0;
}

void wlan_kmod_close(int fd)
{
	if (fd >= 0)
		close(fd);
}

/* LCOV_EXCL_STOP */
