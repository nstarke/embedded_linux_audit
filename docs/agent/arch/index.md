# `embedded_linux_audit arch` Command

Reports compile-time architecture properties of the agent binary.  All values
are derived from compiler predefined macros at build time and reflect the
**compilation target**, not the host system running the binary.  This makes
`arch` useful for confirming which cross-compiled binary is running on an
embedded device.

## Subcommands

### `arch bit`

Prints the pointer width of the compiled binary: `32` or `64`.

```
embedded_linux_audit arch bit
```

### `arch isa`

Prints the instruction set architecture family:

| Output       | Description                        |
|--------------|------------------------------------|
| `x86`        | 32-bit x86 (IA-32)                 |
| `x86_64`     | 64-bit x86 (AMD64 / Intel 64)      |
| `arm32`      | 32-bit ARM                         |
| `aarch64`    | 64-bit ARM (AArch64)               |
| `mips`       | 32-bit MIPS                        |
| `mips64`     | 64-bit MIPS                        |
| `powerpc`    | 32-bit PowerPC                     |
| `powerpc64`  | 64-bit PowerPC                     |
| `riscv32`    | 32-bit RISC-V                      |
| `riscv64`    | 64-bit RISC-V                      |

```
embedded_linux_audit arch isa
```

### `arch endianness`

Prints the byte order of the compiled binary: `big` or `little`.

```
embedded_linux_audit arch endianness
```

## Output formats

All three subcommands honor `--output-format`:

| Format | Example output |
|--------|----------------|
| `txt` (default) | `x86_64` |
| `csv` | `"x86_64"` |
| `json` | `{"record":"arch","subcommand":"isa","value":"x86_64"}` |

JSON output emits one object per invocation with the keys `record` (always
`"arch"`), `subcommand` (`"bit"`, `"isa"`, or `"endianness"`), and `value`
(the string result).

Remote output (`--output-tcp`, `--output-http`, `--output-https`) is also
supported; the formatted line is sent to the configured destination with the
appropriate `Content-Type` (`text/plain`, `text/csv`, or `application/json`).

## Examples

```bash
# Default (txt) output
./embedded_linux_audit arch bit
./embedded_linux_audit arch isa
./embedded_linux_audit arch endianness

# JSON output
./embedded_linux_audit --output-format json arch bit
./embedded_linux_audit --output-format json arch isa
./embedded_linux_audit --output-format json arch endianness

# CSV output
./embedded_linux_audit --output-format csv arch isa

# Send to a remote HTTP collector
./embedded_linux_audit --output-http http://192.168.1.50:5000/upload arch isa
./embedded_linux_audit --output-format json --output-http http://192.168.1.50:5000/upload arch isa

# Send over TCP
./embedded_linux_audit --output-tcp 192.168.1.50:5001 arch endianness
```

## Notes

- Values are baked in at compile time.  Running the binary under QEMU
  user-mode emulation or on a different-ISA host does not change the output.
- `arch isa` and `arch bit` are consistent with each other: ISAs whose name
  encodes a width (`x86_64`, `mips64`, `powerpc64`, `riscv64`, `riscv32`,
  `aarch64`) will always produce a matching `arch bit` value.
- Endianness is independently tracked from the ISA; `aarch64` can be either
  `big` or `little` depending on the build target.
