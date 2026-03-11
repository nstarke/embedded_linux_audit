# Notes and Cautions

- Run as root (raw flash/block reads and device-node operations typically require it).
- Both tools report candidates and parsed results; always validate before destructive operations.
- Be careful with `fw_setenv` on production hardware.
