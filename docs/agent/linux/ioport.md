# `embedded_linux_audit linux ioport`

Perform a single x86 I/O-port read or write through the `ela_kmod` kernel
module.

## Usage

```text
embedded_linux_audit linux ioport read <PORT> <WIDTH>
embedded_linux_audit linux ioport write <PORT> <WIDTH> <VALUE>
```

`PORT` accepts decimal or `0x`-prefixed hexadecimal values from `0` through
`0xffff`. `WIDTH` is the access size in bytes and must be `1`, `2`, or `4`.
Write values must fit the selected width.

```sh
embedded_linux_audit linux ioport read 0x80 1
embedded_linux_audit linux ioport read 0xcf8 4
embedded_linux_audit linux ioport write 0x80 1 0xaa
```

The module emits exactly one width-specific x86 `IN` or `OUT` instruction.
This is legacy x86 I/O-port space, not memory-mapped I/O; use `linux mmio`
for physical MMIO registers. The ioctl returns `EOPNOTSUPP` on non-x86
kernels.

Build and load a module matching the running kernel before use. The command
opens `/dev/ela_physmem`, whose module open path requires `CAP_SYS_RAWIO`.
Both reads and writes may have hardware side effects. Writes can reconfigure,
interrupt, or disable active platform devices, and no port ownership or device
validation is performed.
