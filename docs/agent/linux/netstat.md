# `embedded_linux_audit linux netstat`

List TCP/UDP listening sockets and active connections with PID/program data.

```sh
embedded_linux_audit linux netstat
```

The command runs `netstat -tupan` when `netstat` is available and falls back
to `ss -tupan` on systems that ship `ss` instead. The `-p` flag requests the
process/program owner for listening ports and already-open outbound
connections. Some systems require root privileges to show all PID/program
entries.

Output is always `text/plain`. With `--output-http`, the agent uploads the
same text payload to `/:mac/upload/netstat`.
