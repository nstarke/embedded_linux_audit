Duplicate-code audit — 2026-09-17

Reviewed first-party agent and API code using repeated-block and function-body searches, then compared caller behavior before extracting shared implementations. Third-party library sources and historical database migrations were excluded from consolidation. The changes reduce production code by 776 lines, including the new shared modules and compatibility wrappers.

| Repeated behavior | Common location | Callers |
| --- | --- | --- |
| Growable-buffer printf formatting | `agent/util/output_buffer.h` | Eight Linux audit commands |
| Local printing and stdout mirroring | `agent/util/command_io_util.c` | dmesg and U-Boot environment, image, and security-audit commands |
| String-buffer allocation and append | `agent/util/str_util.c` | Text append and remote-output buffering |
| JSON string escaping | `agent/util/str_util.c` | Kernel module and buildinfo output |
| CSV field escaping | `agent/util/record_formatter.c`, using `csv_write_to_buf` | U-Boot environment and image records |
| Complete writes and symlink basenames | `agent/util/file_io_util.c` | SPI, NAND, eMMC, option ROM, USB, WLAN, Ethernet, and Bluetooth commands |
| HTTP-to-WebSocket stream URLs | `agent/net/ws_url_util.c` | Packet capture, CPU fuzzing, and NIC fuzzing |
| U-Boot output enum, format selection, and MIME types | `agent/uboot/uboot_output_format.h` | Image and security-audit output |
| FIT header validation | `agent/uboot/image/uboot_image_scan_util.c` | Image scanning and security auditing |
| U-Boot environment configuration discovery | `agent/uboot/env/uboot_env_cmd.c` | CRC and environment-writeability audit rules |
| Interactive environment listing | Existing formatter in `agent/shell/interactive_util.c` | `set` and supported-variable diagnostics |
| User and associated-device lookup | `api/lib/db/deviceRegistry.js` | Uploads, module builds, and Ghidra analysis jobs |
| Separator-insensitive MAC comparison | `api/lib/macAddress.js` | Client routes and device normalization |

Existing public helper names remain as thin delegates where needed. Callers retain their own endpoint names, output schemas, error policies, and upload timing. Device queries continue to restrict results to the authenticated user's associated devices; unknown users and unrelated MACs return no records. Interactive listings retain full long values and redact API keys. Production and unit build dependencies include the shared inline implementation headers.

Similar code with different contracts was retained: hardware-specific fuzz message definitions, command-specific request/operations structures, and transport-specific DNS fallback policies. These should not be combined solely because their control flow looks similar. This audit does not assert that every remaining repeated fragment should share an abstraction.

Validation completed:

- `make test-unit-agent-c`: 1,853 cases across 98 suites, zero failures.
- `npm run test:js`: 769 tests across 67 suites, all passed. The suite ran outside the sandbox because its local servers and child processes are blocked inside it.
- Full agent build passed with `make embedded_linux_audit CMAKE_CC_ARGS='-DCMAKE_C_COMPILER=cc -DCMAKE_POLICY_VERSION_MINIMUM=3.5'`. The compatibility flag was needed by the bundled libssh with the installed CMake; it is a validation command override, not a project build-setting change. The compiler still reports existing warnings in unrelated and unchanged code.
- Eight affected shell suites passed: Linux audits (40), hardware arguments (36), module arguments (24), module buildinfo including HTTP upload (12), U-Boot audits (56), U-Boot environments (28), U-Boot images (62), and HTTP output integration (5): 263 cases total.
- Added regression coverage for access control through all three database read paths, long and binary formatted output, stdout-only mirroring, complete file writes, symlink truncation, WebSocket endpoint/buffer boundaries, and long interactive values with API-key redaction.
- `git diff --check` passed.

Actual hardware dump operations and live CPU/NIC fuzzing were not exercised. File and symlink behavior was verified with temporary fixtures; hardware command argument/error paths were covered by the shell suites.
