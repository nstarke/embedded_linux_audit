// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

/*
 * Shared --daemon helper for the fuzz commands (linux wlan/eth/bt/cpu fuzz).
 *
 * A fuzz run is long-lived, but the agent API's `.../ela/spawn` endpoint runs
 * an ela command in the foreground and waits for it to finish -- it assumes ela
 * commands daemonize themselves (as `linux gdbserver` does). Without that, a
 * spawned fuzz runs for its whole duration and the API call times out. `--daemon`
 * makes the fuzzer detach after setup so the spawn returns immediately while the
 * fuzz keeps running and streaming crashes to `--output-http`.
 */
#ifndef ELA_FUZZ_DAEMON_H
#define ELA_FUZZ_DAEMON_H

/*
 * Detach the current fuzz run into the background. Forks; the parent prints the
 * daemon PID (so an API-spawned `... fuzz --daemon` returns at once) and the
 * child setsid()s and redirects stdio to <out_dir>/<label>-daemon.log.
 *
 * Returns:
 *    1  caller is the PARENT -- it should `return 0` now (do NOT run the fuzz),
 *    0  caller is the detached CHILD -- it should run the fuzz,
 *   -1  fork failed -- caller should run the fuzz in the foreground.
 */
int ela_fuzz_daemonize(const char *label, const char *out_dir);

#endif /* ELA_FUZZ_DAEMON_H */
