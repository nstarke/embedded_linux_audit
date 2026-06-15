# `embedded_linux_audit linux modules` Command

Lists, loads, unloads, and inspects Linux kernel modules without invoking module command-line utilities such as `lsmod`, `insmod`, `rmmod`, or `modprobe`.

## Subcommands

### `list`

Read `/proc/modules` directly and print loaded modules.

Output format is controlled by the top-level `--output-format <txt|csv|json>` option.

### `load [--force] <module.ko> [param=value ...]`

Open the module file and load it with the kernel module syscalls.

- `--force` sets the kernel `MODULE_INIT_IGNORE_VERMAGIC` flag when `finit_module` is available.
- Module parameters are passed to the kernel as a space-separated string.
- Dependency resolution is not performed; load dependencies explicitly when needed.

### `unload <module-name>`

Unload a module with the `delete_module` syscall.

### `vermagic <module.ko>`

Read the module file and emit the kernel `vermagic` string from its module metadata.

Output format is controlled by the top-level `--output-format <txt|csv|json>` option. The same payload is also sent to `--output-tcp` and `--output-http` destinations when configured.

## Examples

```bash
./embedded_linux_audit linux modules list
./embedded_linux_audit --output-format json linux modules list
./embedded_linux_audit linux modules load /tmp/demo.ko debug=1
./embedded_linux_audit linux modules load --force /tmp/demo.ko
./embedded_linux_audit linux modules unload demo
./embedded_linux_audit --output-format json linux modules vermagic /tmp/demo.ko
```
