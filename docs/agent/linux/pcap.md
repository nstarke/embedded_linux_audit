# `embedded_linux_audit linux pcap`

Capture packets from a Linux network interface and emit classic pcap data.

```sh
embedded_linux_audit linux pcap --interface eth0
```

The command uses the bundled libpcap build and usually requires privileges that allow packet capture on the target interface, such as running as root or having the needed Linux capabilities. It runs until interrupted with `Ctrl-C` or terminated by a signal.

## Options

| Option | Description |
|---|---|
| `--interface <ifname>` | Required network interface to capture from, such as `eth0`, `wlan0`, or `br0` |
| `--stream-to-host` | Stream pcap data to the agent API over WebSocket instead of writing it to stdout |

Without `--stream-to-host`, pcap bytes are written to stdout:

```sh
embedded_linux_audit linux pcap --interface eth0 > capture.pcap
```

When global `--output-http` or HTTPS is configured, streaming to the host is enabled automatically. The agent derives a WebSocket URL from the HTTP(S) base URL by using the same authority and the `/pcap/<mac>` path:

```sh
embedded_linux_audit \
  --output-http http://workstation:5000/upload \
  linux pcap --interface eth0
```

The example above connects to `ws://workstation:5000/pcap/<mac>`. With `https://...`, the agent connects to `wss://.../pcap/<mac>`. Any path component in `--output-http`, such as `/upload`, is ignored for the pcap WebSocket endpoint.

`--stream-to-host` may also be supplied explicitly, but it still requires global `--output-http` or HTTPS so the agent knows where to connect:

```sh
embedded_linux_audit \
  --output-http https://workstation \
  --insecure \
  linux pcap --interface eth0 --stream-to-host
```

`--insecure` disables TLS certificate and hostname verification for `wss://` pcap streams.

## Agent API storage

The agent helper API accepts pcap streams at:

```text
ws://<host>/pcap/<mac>
wss://<host>/pcap/<mac>
```

Each binary WebSocket message is appended to one pcap artifact under:

```text
<data-dir>/<startup_timestamp>/<mac>/pcap/capture_<timestamp>_<source-ip>_<id>.pcap
```

The API also records an `uploads` row with upload type `pcap` after the WebSocket closes. The database row points at the saved artifact path; the pcap payload itself is stored on disk rather than in the database.

## Notes

- Output format flags do not apply; pcap output is binary.
- Packet capture may fail if the target kernel lacks packet capture support or if the process lacks capture privileges.
- Capturing busy interfaces can produce large files quickly. Use host storage with enough space when streaming to the agent API.
