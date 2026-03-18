# Interactive Mode

`embedded_linux_audit` can be run in an interactive REPL where commands are entered one at a time at a prompt.

## Entering interactive mode

```bash
./embedded_linux_audit
./embedded_linux_audit --interactive
./embedded_linux_audit -i
```

Running with no arguments is equivalent to `--interactive`. The explicit flag is useful when other wrapper-level options are needed:

```bash
./embedded_linux_audit --output-format json --interactive
./embedded_linux_audit --output-http http://127.0.0.1:5000 -i
```

## Usage

Once in interactive mode, a prompt is displayed. Type any normal `embedded_linux_audit` subcommand (without the binary name) and press Enter:

```
> linux dmesg
> linux execute-command "uname -a"
> uboot env
> arch isa
```

Lines beginning with `#` are treated as comments and ignored.

Type `exit` or `quit` to leave interactive mode cleanly.

## Environment variable shortcuts

Several `set` commands are available to change options without restarting the process:

| Command | Effect |
|---------|--------|
| `set ELA_SCRIPT <path\|url>` | Set a default script source |
| `set ELA_OUTPUT_FORMAT <txt\|csv\|json>` | Change output format |
| `set ELA_OUTPUT_HTTP <url>` | Set HTTP output destination |
| `set ELA_OUTPUT_TCP <ip:port>` | Set TCP output destination |

## Behavior notes

- Wrapper-level options passed before `--interactive` (or `-i`) apply to every command entered at the prompt.
- `exit` terminates the process cleanly. If the agent is running under a `--remote` WebSocket session, a clean `exit` does **not** trigger a reconnect attempt.
- Interactive mode is the default when invoked with no arguments and no `--remote`, `--script`, or command group is provided.
