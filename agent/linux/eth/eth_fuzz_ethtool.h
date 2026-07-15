// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Minimal ethtool ioctl ABI for the blind ethtool-generic target: SIOCETHTOOL
 * plus the ETHTOOL_* command numbers we drive. Reimplemented locally (rather
 * than via <linux/ethtool.h>) so the tool builds self-contained against any
 * libc, mirroring wlan_fuzz_wext.h / wlan_fuzz_usbfs.h. `struct ifreq` itself
 * comes from <net/if.h> (portable across libcs); we only pass a command buffer
 * through ifr_data, so no ethtool struct layouts are needed here -- the grammar
 * renders them field by field.
 *
 * The command number is the first u32 of the buffer ifr_data points at; the
 * kernel dispatches on it. These are stable UAPI values from
 * include/uapi/linux/ethtool.h.
 */
#ifndef ETH_FUZZ_ETHTOOL_H
#define ETH_FUZZ_ETHTOOL_H

#ifndef SIOCETHTOOL
#define SIOCETHTOOL 0x8946
#endif

/* Read-path ops with a device offset/length the driver must bound-check. */
#define ETHTOOL_GREGS          0x00000004	/* cmd,version,len,data[]        */
#define ETHTOOL_GEEPROM        0x0000000b	/* cmd,magic,offset,len,data[]   */
#define ETHTOOL_GMODULEEEPROM  0x00000043	/* cmd,magic,offset,len,data[]   */

/* Non-persistent SET ops: the driver validates counts/params against its own
 * limits. (SEEPROM/SFLASH/SWOL are deliberately NOT here -- they write the
 * NIC's persistent EEPROM/flash and could brick it.) */
#define ETHTOOL_SMSGLVL        0x00000008	/* cmd,data (ethtool_value)      */
#define ETHTOOL_SRINGPARAM     0x00000011	/* cmd + 8 counts                */
#define ETHTOOL_SPAUSEPARAM    0x00000013	/* cmd,autoneg,rx_pause,tx_pause */
#define ETHTOOL_TEST           0x0000001a	/* cmd,flags,rsvd,len,data[]     */
#define ETHTOOL_PHYS_ID        0x0000001c	/* cmd,data (blink duration)     */
#define ETHTOOL_SCHANNELS      0x0000003d	/* cmd + 8 counts                */

/* Unprivileged liveness probe: report link state. Any live NIC answers it. */
#define ETHTOOL_GLINK          0x0000000a	/* cmd,data (ethtool_value)      */

#endif
