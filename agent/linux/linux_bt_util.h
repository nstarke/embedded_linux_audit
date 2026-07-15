// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Pure helper for `linux bt`: parse a Bluetooth controller name ("hci0",
 * "hci12") into its device index for the HCI socket. Side-effect-free so it is
 * unit-testable without hardware.
 */
#ifndef LINUX_BT_UTIL_H
#define LINUX_BT_UTIL_H

/*
 * Parse "hci<N>" into *index (0..65535). Accepts exactly the "hci" prefix
 * followed by 1..5 decimal digits, nothing else. Returns 0 on success, -1 on a
 * malformed name or invalid argument.
 */
int bt_parse_hci_dev(const char *name, int *index);

#endif
