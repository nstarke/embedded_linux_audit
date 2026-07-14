// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Minimal Linux usbfs wrapper -- no libusb, pure ioctl on /dev/bus/usb.
 *
 * The usbdevfs structs and ioctl numbers are a stable kernel ABI; they are
 * defined locally (rather than via <linux/usbdevice_fs.h>) so the tool
 * builds self-contained with any libc.
 */
#ifndef WLAN_FUZZ_USBFS_H
#define WLAN_FUZZ_USBFS_H

#include <stdint.h>

struct usbfs_ctrltransfer {
	uint8_t  bRequestType;
	uint8_t  bRequest;
	uint16_t wValue;
	uint16_t wIndex;
	uint16_t wLength;
	uint32_t timeout;	/* ms */
	void    *data;
};

struct usbfs_bulktransfer {
	unsigned int ep;
	unsigned int len;
	unsigned int timeout;	/* ms; works for interrupt endpoints too */
	void        *data;
};

struct usbfs_ioctl {
	int   ifno;
	int   ioctl_code;
	void *data;
};

/* Linux _IOC encoding, reimplemented so this header has no kernel deps */
#define LNX_IOC(dir, type, nr, size) \
	(((unsigned)(dir) << 30) | ((unsigned)(size) << 16) | \
	 ((unsigned)(type) << 8) | (unsigned)(nr))
#define LNX_IOC_NONE  0u
#define LNX_IOC_WRITE 1u
#define LNX_IOC_READ  2u

#define USBFS_CONTROL	LNX_IOC(LNX_IOC_READ | LNX_IOC_WRITE, 'U', 0, \
				sizeof(struct usbfs_ctrltransfer))
#define USBFS_BULK	LNX_IOC(LNX_IOC_READ | LNX_IOC_WRITE, 'U', 2, \
				sizeof(struct usbfs_bulktransfer))
#define USBFS_CLAIMINTF	LNX_IOC(LNX_IOC_READ, 'U', 15, sizeof(unsigned int))
#define USBFS_RELEASEINTF LNX_IOC(LNX_IOC_READ, 'U', 16, sizeof(unsigned int))
#define USBFS_IOCTL	LNX_IOC(LNX_IOC_READ | LNX_IOC_WRITE, 'U', 18, \
				sizeof(struct usbfs_ioctl))
#define USBFS_RESET	LNX_IOC(LNX_IOC_NONE, 'U', 20, 0)
#define USBFS_DISCONNECT LNX_IOC(LNX_IOC_NONE, 'U', 22, 0)

/* Scan /dev/bus/usb for vid + one of pids[]; returns open fd or -1. */
int usbfs_open(uint16_t vid, const uint16_t *pids, int npids,
	       uint16_t *found_pid);

/* Detach any kernel driver from interface (ignores "none attached"). */
int usbfs_detach_kernel(int fd, int ifno);

int usbfs_claim(int fd, int ifno);

/* Control transfer; returns bytes transferred or -1 (errno set). */
int usbfs_ctrl(int fd, uint8_t reqtype, uint8_t req, uint16_t val,
	       uint16_t idx, void *data, uint16_t len, int timeout_ms);

/* Bulk/interrupt transfer (direction from ep bit 7); bytes or -1. */
int usbfs_xfer(int fd, unsigned int ep, void *data, int len, int timeout_ms);

#endif
