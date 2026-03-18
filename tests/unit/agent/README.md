# Agent C Unit Tests

This directory holds fast host-native unit tests for low-dependency agent C code.

Strategy:
- Keep these tests focused on pure helpers and parsing/formatting logic.
- Avoid network, device, shell, and TLS side effects in this layer.
- Use shell/QEMU tests for end-to-end command behavior and platform coverage.
- Extract new pure helpers from command implementations as needed, then add unit coverage here.

Good candidates:
- `agent/util/*`
- URI/path parsing helpers
- output formatting helpers
- argument parsing helpers after they are separated from command execution

Keep out of this layer unless first refactored behind seams:
- direct `/dev` access
- network I/O
- TLS handshakes
- `popen()`/shell execution
- architecture-specific runtime probing
