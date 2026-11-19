# Packet Pocket

[Open Packet Pocket](https://coolcode.ca/packetpocket/) to inspect your own local PCAP or PCAPNG. Open one capture for its packet timeline and conversations. Drop a second into **Compare captures** for a before-and-after view. Files stay in the browser.

<!-- coolcode:guide -->
Compare two captures by protocol share and traffic rate, then select a conversation in the first capture to see its two directions. Export a filtered aggregate report to share counts and relative time bins without addresses or hostnames.
<!-- /coolcode:guide -->

## Start with a published capture

Download [Wireshark’s DNS capture](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dns.cap) and choose **Open capture**. Its 38 DNS records report 3,706 wire bytes across 278.879 seconds. Select a conversation to compare the volumes sent in the two directions. The [Wireshark sample capture catalogue](https://wiki.wireshark.org/samplecaptures) describes this recording. Packet Pocket links to Wireshark’s hosted original.

## Compare captures

The whole-file comparison shows packet records, reported wire bytes, captured bytes, snapshot-shortened records, missing timestamps, timestamp span, packets per second and wire bytes per second. For example, an increase from 10% to 25% DNS is a 15 percentage-point increase. Both packet counts appear beside their shares. Rates use only timestamped records divided by the time between each capture’s first and last timestamps. A missing or zero duration has no rate. A capture taken on another interface or with different recording filters can produce different totals.

## Follow a conversation

Browse IP conversations and select a pair for its directional packet and byte totals. Filter the packet list by protocol, text or elapsed time. The 48-bin timeline can show packet counts or reported wire bytes. A single timestamp appears as a single interval. A packet without a timestamp contributes to totals and appears in the full packet list, but has no place in a timed view.

Selecting a TCP conversation shows the first observed initial SYN, corresponding SYN-ACK and final ACK when the capture contains them. Timing describes the recorded packets. Repeated initial SYNs can be caused by retries or by duplicated capture records.

The Web Worker reads up to 24 MiB or 50,000 packet records. It supports classic PCAP 2.4 in either byte order with microsecond or nanosecond timestamps, plus common PCAPNG Interface Description, Enhanced Packet, and Simple Packet blocks. Link formats include Ethernet with VLAN tags, raw IPv4 and IPv6, and Linux cooked headers. Unsupported or truncated frames show limited observations.

Plaintext DNS questions, HTTP/1 request methods, host fields and response status, and complete TLS Hello records can be recognized inside a single segment. The app does not parse every protocol or reassemble fragmented packets or TCP streams. Reported TLS names can be outer SNI when ECH is present. The tool does not decrypt anything. Port numbers are descriptive metadata. See the [IANA service registry](https://www.iana.org/assignments/service-names-port-numbers) and [PCAPNG format](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/).

## Export reports

**Download aggregate summary** applies the first capture’s current filters. Its JSON includes protocol totals, snapshot and timestamp coverage, relative window bounds and bin totals. **Download aggregate comparison JSON** covers both complete parsed inputs, with protocol shares and changes. Both aggregate exports omit filenames, addresses, ports, hostnames, raw payloads, absolute timestamps and filter text. The first capture’s **Download packet metadata** includes addresses, observed hostnames and packet timestamps. Raw payloads, HTTP paths and credentials are excluded.

The parser identifies local capture files by their header bytes. A valid zero-packet capture can serve as a comparison baseline. Malformed files produce an error or a labelled partial report, depending on whether complete records were read.

## Build and test

```sh
python3 scripts/build.py
node --test tests/*.test.mjs
python3 -m http.server --directory dist 8000
```

Deploy `dist/` to GitHub Pages. No dependency installation is required.
