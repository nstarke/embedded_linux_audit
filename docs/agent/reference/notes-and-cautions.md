# Notes and Cautions

- Run as root (raw flash/block reads and device-node operations typically require it).
- Both tools report candidates and parsed results; always validate before destructive operations.
- Be careful with `fw_setenv` on production hardware.
- `spi`, `nand flash`, `emmc`, and top-level `orom` use `ela_kmod` and require
  `CAP_SYS_RAWIO`; treat the module device with the same access-control care as
  `/dev/mem`.
- `nand flash dump` excludes OOB bytes and fills marked bad eraseblocks with
  `0xff`; it is not a raw page-plus-OOB forensic image.
- `orom list` temporarily maps PCI expansion ROM resources. Some devices or
  active drivers may not tolerate ROM access, and devices without a
  kernel-mappable ROM remain unavailable.
