// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Minimal Wireless Extensions (WEXT) ABI -- the SIOCSIWxxx ioctl numbers and
 * the iwreq/iw_point/iw_param/iw_freq structs, reimplemented locally (rather
 * than via <linux/wireless.h>) so the tool builds self-contained against any
 * libc, mirroring wlan_fuzz_usbfs.h. These are a stable kernel UAPI.
 *
 * Layout note: the structs use natural alignment (NOT packed) to match the
 * kernel exactly -- on LP64 iw_point is 16 bytes (ptr 8 + u16 + u16 + pad) and
 * iwreq is 32 (ifr_name[16] + union[16]); on ILP32 iw_point is 8 and the
 * sockaddr member still makes the union 16, so iwreq is 32 on both.
 */
#ifndef WLAN_FUZZ_WEXT_H
#define WLAN_FUZZ_WEXT_H

#include <stdint.h>

#define WEXT_IFNAMSIZ 16

/* Per-ioctl payload caps the WEXT core enforces (net/wireless/wext-core.c). */
#define IW_ESSID_MAX_SIZE      32
#define IW_ENCODING_TOKEN_MAX  64
#define IW_GENERIC_IE_MAX      1024

/* SET (write-to-driver) ioctls -- the fuzzed surface. */
#define SIOCSIWFREQ      0x8B04	/* iw_freq  */
#define SIOCSIWMODE      0x8B06	/* u32      */
#define SIOCSIWSENS      0x8B08	/* iw_param */
#define SIOCSIWAP        0x8B14	/* sockaddr */
#define SIOCSIWMLME      0x8B16	/* iw_point -> struct iw_mlme */
#define SIOCSIWSCAN      0x8B18	/* iw_point (len 0 = trigger) */
#define SIOCSIWESSID     0x8B1A	/* iw_point (<= 32)           */
#define SIOCSIWNICKN     0x8B1C	/* iw_point */
#define SIOCSIWRATE      0x8B20	/* iw_param */
#define SIOCSIWRTS       0x8B22	/* iw_param */
#define SIOCSIWFRAG      0x8B24	/* iw_param */
#define SIOCSIWTXPOW     0x8B26	/* iw_param */
#define SIOCSIWRETRY     0x8B28	/* iw_param */
#define SIOCSIWENCODE    0x8B2A	/* iw_point (<= 64)           */
#define SIOCSIWPOWER     0x8B2C	/* iw_param */
#define SIOCSIWGENIE     0x8B30	/* iw_point (<= 1024) IE blob */
#define SIOCSIWAUTH      0x8B32	/* iw_param (value + INDEX flags) */
#define SIOCSIWENCODEEXT 0x8B34	/* iw_point -> struct iw_encode_ext */

/* GET ioctl used as the benign liveness probe (no privilege needed). */
#define SIOCGIWNAME      0x8B01	/* iwreq.u.name[IFNAMSIZ] */

#define WEXT_ARPHRD_ETHER 1

struct iw_point {
	void    *pointer;
	uint16_t length;
	uint16_t flags;
};

struct iw_param {
	int32_t  value;
	uint8_t  fixed;
	uint8_t  disabled;
	uint16_t flags;
};

struct iw_freq {
	int32_t m;
	int16_t e;
	uint8_t i;
	uint8_t flags;
};

struct wext_sockaddr {
	uint16_t sa_family;
	char     sa_data[14];
};

union iwreq_data {
	char                 name[WEXT_IFNAMSIZ];
	struct iw_point      essid;
	struct iw_param      param;
	struct iw_freq       freq;
	uint32_t             mode;
	struct iw_point      encoding;
	struct wext_sockaddr ap_addr;
	struct iw_point      data;
};

struct iwreq {
	char             ifr_name[WEXT_IFNAMSIZ];
	union iwreq_data u;
};

#endif
