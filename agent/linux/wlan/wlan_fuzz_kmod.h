// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Userspace side of the ela_kmod WLAN firmware-command injection shim.
 * Thin wrappers over the ELA_IOC_WLAN_* ioctls on /dev/ela_physmem; used by
 * kmod-backed targets (PCIe/SDIO NICs) whose command ring is not reachable
 * from userspace usbfs.
 */
#ifndef WLAN_FUZZ_KMOD_H
#define WLAN_FUZZ_KMOD_H

#include <stdint.h>

/* Open the shim device (/dev/ela_physmem). Returns fd or -1. */
int wlan_kmod_open(void);

/* Arm the shim's kprobes for a driver (ELA_WLAN_DRV_*). 0 ok, -1 fail
 * (e.g. driver not loaded so its send symbol is absent). */
int wlan_kmod_attach(int fd, uint32_t driver);

void wlan_kmod_detach(int fd, uint32_t driver);

/* Poll until the shim captures the driver context (needs the driver to emit
 * firmware traffic). 0 captured, -1 timeout. */
int wlan_kmod_wait_capture(int fd, int timeout_ms);

/* Inject one firmware command. On success returns 0 and stores the driver
 * send function's return in *send_ret; returns -1 if the ioctl itself failed
 * (shim gone / not captured). */
int wlan_kmod_inject(int fd, uint32_t cmd_id, const void *buf, int len,
		     int32_t *send_ret);

/* Read the firmware-restart counter (crash oracle) and capture state. */
int wlan_kmod_status(int fd, uint64_t *restart_count, uint32_t *captured);

void wlan_kmod_close(int fd);

#endif
