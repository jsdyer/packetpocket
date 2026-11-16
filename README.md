# Packet Pocket

A static, local packet capture explorer. Open an uncompressed PCAP or PCAPNG, or try a synthetic exchange. Browse IP conversations, filter packet metadata by protocol, text and elapsed time, and export matching metadata as JSON. The chart shows the number of matching packets in each of 48 bins across the selected time window.

Selecting a TCP conversation shows the first observed initial SYN, corresponding SYN-ACK and final ACK when the capture contains them. Timing describes the recorded packets. Repeated initial SYNs can be caused by retries or by duplicated capture records.

The Web Worker reads up to 24 MiB or 50,000 packet records. It supports classic PCAP 2.4 in either byte order with microsecond or nanosecond timestamps, plus common PCAPNG Interface Description, Enhanced Packet, and Simple Packet blocks. Link formats include Ethernet with VLAN tags, raw IPv4 and IPv6, and Linux cooked headers. Unsupported or truncated frames show limited observations.

Plaintext DNS questions, HTTP/1 request methods, host fields and response status, and complete TLS Hello records can be recognized inside a single segment. The app does not parse every protocol or reassemble fragmented packets or TCP streams. Reported TLS names can be outer SNI when ECH is present. The tool does not decrypt anything. Port numbers are descriptive metadata. See the [IANA service registry](https://www.iana.org/assignments/service-names-port-numbers) and [PCAPNG format](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/).

Input bytes never leave the tab. Exports omit raw payloads, HTTP paths, cookie and credential fields. They retain IPs, names and timestamps, which can be sensitive. The bundled example uses reserved documentation addresses.

## Build and test

```sh
python3 scripts/build.py
node --test tests/*.test.mjs
python3 -m http.server --directory dist 8000
```

Deploy `dist/` to GitHub Pages. No dependency installation is required.
