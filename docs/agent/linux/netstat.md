# `embedded_linux_audit linux netstat`

List TCP/UDP listening sockets and active connections with PID/program data.

```sh
embedded_linux_audit linux netstat
```

The command reads socket rows from `/proc/net/tcp`, `/proc/net/tcp6`,
`/proc/net/udp`, and `/proc/net/udp6`. PID/program ownership is resolved by
matching socket inodes against `/proc/<pid>/fd` symlinks, so it does not rely
on the external `netstat` or `ss` utilities. Some systems require root
privileges to show all PID/program entries.

Output is always `text/plain`. With `--output-http`, the agent uploads the
same text payload to `/:mac/upload/netstat`.
