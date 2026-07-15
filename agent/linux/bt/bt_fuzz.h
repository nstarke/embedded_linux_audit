// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Bluetooth NIC fuzz target. Rides the shared class-directed fuzz engine
 * (grammar/mutation/loop/remote crash stream) declared in wlan_fuzz.h -- the
 * engine is NIC-agnostic despite the wlan_ prefix; only this target is
 * Bluetooth-specific.
 *
 * hci-generic fuzzes the host->controller HCI command interface over a raw HCI
 * User Channel socket, addressed by controller index (hci0, hci1, ...). Unlike
 * ethernet, there is no firmware-mailbox shim variant: HCI *is* the controller
 * firmware's command interface and is reachable directly from userspace.
 */
#ifndef BT_FUZZ_H
#define BT_FUZZ_H

#include "linux/wlan/wlan_fuzz.h"

/* Blind/class-directed HCI command fuzzer for controller `dev_index` (hciN). */
struct target *target_hci_generic(int dev_index);

#endif
