// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Minimal Bluetooth HCI socket ABI for the hci-generic target: AF_BLUETOOTH /
 * BTPROTO_HCI, the raw HCI User Channel, sockaddr_hci, and the HCI packet-type
 * indicators. Reimplemented locally (rather than via <bluetooth/hci.h>, which
 * needs libbluetooth, or the kernel's net/bluetooth headers) so the tool builds
 * self-contained against any libc -- mirroring wlan_fuzz_wext.h /
 * eth_fuzz_ethtool.h. These are stable kernel UAPI values.
 *
 * The User Channel (HCI_CHANNEL_USER) gives exclusive raw access to one
 * controller and forwards packets straight to it, bypassing the kernel's HCI
 * command bookkeeping -- so fuzzed commands reach the controller firmware. It
 * requires the controller to be DOWN (not held by BlueZ) and CAP_NET_ADMIN.
 */
#ifndef BT_FUZZ_HCI_H
#define BT_FUZZ_HCI_H

#include <stdint.h>

#ifndef AF_BLUETOOTH
#define AF_BLUETOOTH 31
#endif
#define BTPROTO_HCI 1

#define HCI_CHANNEL_RAW  0
#define HCI_CHANNEL_USER 1

/* HCI packet type indicators (first byte on the socket). */
#define HCI_COMMAND_PKT 0x01
#define HCI_EVENT_PKT   0x04

/* struct sockaddr_hci (6 bytes) -- family, device index, channel. */
struct bt_sockaddr_hci {
	uint16_t hci_family;
	uint16_t hci_dev;
	uint16_t hci_channel;
};

/* Compose a 16-bit HCI opcode from its OGF (opcode group, 6 bits) and OCF
 * (opcode command, 10 bits). */
#define HCI_OPCODE(ogf, ocf) ((uint16_t)(((ogf) << 10) | ((ocf) & 0x03FF)))

#endif
