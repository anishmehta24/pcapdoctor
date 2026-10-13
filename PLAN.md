# pcapdoctor plan

## Goal

`pcapdoctor capture.pcap` says what went wrong on the network in plain English, and names the frames to look at in Wireshark.

```
$ pcapdoctor examples/demo.pcap
examples/demo.pcap: 314 packets over 8.19 s, from 2025-10-09 08:53:20.000 UTC

✗ DNS   api.internal: name does not exist (NXDOMAIN, asked 3 times)             frames 41-42, 134
✗ TLS   pay.example.com:443: client rejected the handshake: unknown_ca (the certificate's issuer is not trusted)  frame 84
        → usually a private CA, or a TLS-inspecting proxy whose CA the client does not have
⚠ SLOW  api.example.com:443: network RTT 40.0 ms, server took 2.10 s to answer  frames 114-166
        → the server is slow, not the network
⚠ LOSS  10.0.0.5 → cdn.example.com:443: 7.4% of segments retransmitted (4 of 54), mostly by the server  frames 206-261
        → the capture saw the first copies, so packets were lost between the capture point and the client
✓ 11 other connections look healthy
```

That is real output, from [`examples/demo.pcap`](examples/demo.pcap): a generated capture of a laptop browsing for ten seconds (see `examples/gen_demo.py`).

Who it's for: support engineers handed a customer's capture, backend developers chasing "it's slow" or "it fails sometimes", and CI pipelines that should fail on network errors. None of them should need to know Wireshark.

## Principles

- **Answers, not packets.** Each finding is one sentence plus evidence: frame numbers and measurements anyone can check.
- **Never crash on bad input.** Captures are untrusted, often cut off, often snaplen-truncated. Decode what is there, say what isn't.
- **Offline first.** Reading files needs no libpcap/Npcap and no admin rights. Live capture is an optional extra.
- **Wireshark is the answer key.** Every detector is checked against tshark on real captures; where we differ on purpose, the docs say why.
- **One binary per OS**, no runtime dependencies.

## CLI

| Command | What it does | Milestone |
|---|---|---|
| `pcapdoctor dump FILE [-c N]` | one line per packet, like tcpdump | M1 |
| `pcapdoctor dump FILE -f FILTER` | same, filtered | M7 |
| `pcapdoctor stats FILE [-n N]` | protocol mix, busiest hosts, conversations | M2 |
| `pcapdoctor FILE [--format text\|json\|html] [-o PATH] [--all]` | diagnosis report (default command) | M6 |
| `pcapdoctor check FILE --fail-on FILTER` | CI mode: exit 1 when something matches | M7 |
| `pcapdoctor live -i IFACE -d 30s` | capture, then diagnose | M8 |

Exit codes: 0 ok, 1 `check` found problems, 2 error.

## Architecture

```
capture/   pcap + pcapng readers, our own code (no libpcap)    -> Frame { number, ts, link_type, data }
decode/    link -> IPv4/IPv6/ARP -> TCP/UDP/ICMP                -> Packet { layers, error }
flow/      bidirectional 5-tuple table, TCP state per flow      (M2)
analyze/   TCP health, DNS, TLS, HTTP detectors                  (M3-M5)
diagnose/  rules over the analysis                               -> Finding { severity, category, text, frames, measurements, filter }  (M6)
report/    text / JSON / HTML                                    (M6)
filter/    tokenizer -> parser -> AST -> evaluator               (M7)
```

Decoding borrows the frame bytes (zero-copy). When a layer is malformed, the layers before it are kept, like Wireshark's "[Malformed Packet]".

## Milestones

### M0 Scaffold — done 2026-10-13
Cargo project, CLI skeleton, CI (fmt, clippy, tests on Linux, Windows and macOS), this plan, README.

### M1 Read and decode — done 2026-10-13
- pcap (both byte orders, µs and ns timestamps) and pcapng (multiple sections and interfaces, `if_tsresol`, `if_tsoffset`, enhanced/simple/obsolete packet blocks) readers
- Cut-off files: keep every complete packet and warn, instead of failing
- Link layers: Ethernet with VLAN/QinQ, Linux cooked v1/v2 (`tcpdump -i any`), BSD/Windows loopback, raw IP
- IPv4 (options, fragments, zero length from TCP segmentation offload), IPv6 (extension headers, fragments), ARP, TCP (MSS, window scale, SACK, timestamps), UDP, ICMP, ICMPv6
- Lengths come from the IP headers, not the captured bytes, so Ethernet padding is never treated as data and snaplen captures still give real segment sizes
- `dump` command
- **Done when:** every layer has tests, the no-panic tests pass, and `dump` agrees with tshark on the sample captures.
- **Status:** tests include mutation tests (50k packets, 20k files). Against tshark 4.6.9 on 22 captures, every TCP/UDP frame matches: addresses, ports, flags, raw and relative seq/ack, window, length (2,217 frames).

### M2 Flows and stats — done 2026-10-13
- Flow table keyed by normalized 5-tuple; per-direction packets, bytes, first and last seen
- TCP connection state: SYN, SYN-ACK, established, FIN, RST
- Relative sequence numbers in `dump`
- `stats`: protocol distribution (packets and bytes), top talkers, conversation table, packets per second
- **Done when:** the conversation table matches `tshark -z conv,tcp`.
- **Status:** all 47 conversations in the same captures match tshark: stream number, endpoints, packets, bytes in each direction.

### M3 TCP health — done 2026-10-13
- RTT from the handshake, split into client side and server side
- Retransmissions (including spurious ones), out-of-order segments, duplicate ACKs, fast retransmits. Track the next expected sequence number per direction, with 32-bit wraparound.
- Zero window, window full
- RST classified: refused (answer to a SYN), aborted mid-stream, after FIN
- SYN never answered (connection timeout)
- **Done when:** counts match tshark's `tcp.analysis.*` on samples and on captures made with `tc netem` loss, apart from documented differences.
- **Status:** the rules follow Wireshark's `tcp_analyze_sequence_number`, in the same order. Every flag matches tshark on 2,161 TCP frames (198 flagged) across 21 captures, including `tests/fixtures/tcp-zoo.pcap`, a generated capture with one connection per case so all 14 kinds of flag are covered. Initial RTT matches tshark on all 19 connections that have one. Still to do: a real capture with `tc netem` loss.

### M4 DNS — done 2026-10-13
- Wire format: header, questions, answers (A, AAAA, CNAME, ...), name compression with loop protection; over UDP and TCP
- Match responses to queries (ID + flow). Report rcode failures (NXDOMAIN, SERVFAIL, REFUSED), queries with no response, slow responses, and ICMP port unreachable from the DNS server.
- IP → hostname map built from answers, so reports say `api.example.com` instead of `93.184.216.34`
- **Status:** checked against tshark on 170 DNS messages: ID, query or response, name, type, response code, answer count and response time all match, apart from two intended differences.
  - A query repeated more than 5 s later is still a retry of the same lookup. Wireshark starts a new transaction, but the client was waiting all along, so the response time counts from the first query. This is how a 5-second DNS stall shows up.
  - A response must come from the server the query went to. Wireshark matches on the ID alone.
  `tests/fixtures/dns-zoo.pcap` has one connection per case (error codes, no response, ICMP unreachable, retries, truncation then TCP, IPv6, malformed names), and tshark's view of it is committed.
  Not covered: multicast DNS and LLMNR (other ports), and encrypted DNS (DoH, DoT).

### M5 TLS and HTTP — done 2026-10-13
- TLS records and handshake: ClientHello SNI, ALPN, offered versions; ServerHello chosen version; alerts (handshake_failure, unknown_ca, certificate_expired, protocol_version, ...)
- TLS 1.2 certificates: subject, issuer, expiry (TLS 1.3 encrypts them)
- HTTP/1.x: request line, status code, per-request timing (reassemble the start of each request and response)
- **Network or server?** Server time ≈ time to first response byte − RTT
- **TLS status:**
  - TLS is recognized by content, so any port works and plain HTTP on 443 is not mistaken for it.
  - Covers hellos (including HelloRetryRequest and pre-standard TLS 1.3 drafts), certificate chains up to TLS 1.2 (own DER reader: names, issuer, validity), plaintext and encrypted alerts, and handshake completion.
  - Problems found: rejected handshakes with the alert's meaning; no ServerHello (reset, closed or no answer); expired, not-yet-valid, wrong-name and self-signed certificates; outdated versions; and a slow ServerHello net of the network round trip.
  - Checked against tshark on 1,138 TLS events across all test captures. `tests/fixtures/tls-zoo.pcap` has 15 cases with real certificates from a test CA, and tshark's view of it is committed.
  - Differences, all expected:
    - tshark decrypts captures that embed their keys; we don't.
    - An SSLv2-format ClientHello isn't supported.
    - In TLS 1.3 a 19-byte encrypted record before the client's Finished is read as an alert. That's a heuristic; tshark can't tell without keys.
  - Not covered yet: client certificates (mutual TLS), QUIC.
- **HTTP status:**
  - HTTP/1.x is recognized by content on any port.
  - All the body rules are followed: length, chunked, until close, HEAD/1xx/204/304, pipelining, `100 Continue`, upgrades and CONNECT tunnels.
  - Each response is matched to its request, with its time to first byte and server time. Server time is the time to first byte minus the capture-to-server round trip.
  - TCP reassembly now holds segments that arrive ahead of a gap until it fills. That gives the same result as Wireshark with out-of-order reassembly on.
  - Checked against tshark on `tests/fixtures/http-zoo.pcap`: every request and response matches on method, URI, host, status, and which request a response answers.
- **Encrypted traffic:**
  - Each TCP connection gets a "wait": from the client's last data to the start of the server's largest burst in reply. It needs no decryption.
  - The largest burst skips the small things a server may send first (TLS 1.3 session tickets, HTTP/2 settings) or last (a close alert on an idle connection).
  - On a real HTTPS capture that tshark can decrypt with its embedded keys, the largest wait came out at 158.6 ms. tshark's per-request times are 156–164 ms.
  - Not covered: per-request timing inside HTTP/2 and HTTP/3, which need decryption.

### M6 Diagnosis and report — done 2026-10-14
- Finding: severity (error, warning, info), category, one sentence, evidence frames, measurements
- Rules turn M3–M5 data into findings; everything else rolls up into a health summary
- Output: colored text (default), JSON (versioned schema), HTML (one self-contained file)
- `pcapdoctor FILE` becomes the default command
- **Done when:** the example at the top of this file is real output from a capture committed to the repo.
- **Status:**
  - The example at the top is the report for `examples/demo.pcap`, and a test keeps it that way. tshark agrees on everything it points at: the NXDOMAIN responses, the unknown_ca alert, the 40 ms round trip, and the four fast retransmissions.
  - Every finding carries a Wireshark display filter. Across all 49 test captures, each filter parses in tshark 4.6 and matches the frames its finding names.
  - Findings are grouped: one per name, server or client-and-server pair, not one per packet. Errors come first, then warnings and notes, each in capture order.
  - Rules and their thresholds:
    - DNS: error codes by name; servers that never answer or can't be reached; lookups slower than 500 ms or sent again.
    - TCP: refused and unanswered connection attempts by server, after 3 s. One client trying 10 or more ports on a server is reported as a likely port scan, not as failures.
    - TCP: connections reset by the server while open; a connect that needed a second SYN (500 ms beyond the round trip).
    - Loss: at least 3 retransmissions and 2% of segments between a client and server; an error from 10 retransmissions and 10%. It says who resent, and whether the capture saw the first copies, which places the loss before or after the capture point.
    - Slow servers: HTTP responses whose server time is over 500 ms. For connections it can't read into (mostly encrypted ones), a wait over 1 s beyond the network's part. Interactive ports (SSH, telnet, RDP, VNC) are skipped. A round trip of 250 ms or more gets a note.
    - TLS: the problems from M5, with a certificate problem the client rejected written as cause and effect.
    - HTTP: 5xx as errors, 4xx as warnings, and requests with no response, with what happened to the connection.
    - Receivers out of buffer (zero window). A sender filling the window 5 or more times gets a note.
    - The capture itself: cut-off files, packets cut short by a snaplen, packets that couldn't be decoded, packets the capture missed, and connections captured in one direction only.
  - Heuristics that keep noise down:
    - A failed lookup of a name with a search domain added (`api.example.com.corp.local` next to `api.example.com`) is the resolver at work, and isn't reported.
    - A missing reverse name is a note; a missing service record (`_ldap._tcp...`) is a warning.
    - A client resetting connections is a note, since applications often close that way.
    - A reset already explained by a TLS or HTTP failure isn't reported again.
    - On connections captured in one direction only, missing answers aren't reported: they may have been sent.

### M7 Filter language and CI mode
- Wireshark-style syntax: `tcp.port == 443 && !(ip.src == 10.0.0.0/8)`, `dns.rcode != 0`, `tcp.flags.rst`, `tls.sni contains "api"`
- Tokenizer → recursive-descent parser → AST → evaluator; error messages point at the column
- `dump -f`, and `check --fail-on` for packets and findings (`finding.severity == error`)
- GitHub Action wrapper

### M8 Live capture
- `pcap` crate behind a `live` cargo feature (libpcap on Linux/macOS, Npcap on Windows)
- `live -i IFACE -d 30s [-w out.pcapng]`, plus a command to list interfaces
- Docs: Windows can capture with the built-in `pktmon`, no install needed

### M9 Release
- cargo-dist: binaries for Windows, Linux and macOS, `cargo install`, maybe Scoop and Homebrew
- README: before/after (Wireshark screenshot next to pcapdoctor output), sample captures, notes on where we differ from tshark
- Launch posts built around a real debugging story (r/networking, r/sysadmin, Show HN)

### Later, only if users ask
IP reassembly, QUIC (SNI from Initial packets), HTTP/2, port-scan and DNS-tunnel detection, process names for live capture, `--explain` through an LLM.

## Testing

- **Built captures:** unit tests per layer, plus integration tests that build packets and capture files in code (`tests/common`), so each edge case is a few lines with no binary fixtures.
- **No-panic tests:** random and mutated input through the readers and decoders. Later: `cargo fuzz`.
- **Wireshark as the answer key:** `tests/fixtures/tcp-zoo.pcap` is generated by `gen_tcp_zoo.py`, and `tcp-zoo.tshark.txt` is tshark's output for it. The tests compare against that file, so CI checks Wireshark's answers without tshark installed.
- **Making captures:**
  - Wireshark's sample captures
  - `tcpdump -w`
  - Windows: `pktmon start --capture --pkt-size 0`, then `pktmon stop` and `pktmon etl2pcap PktMon.etl --out capture.pcapng` (admin, nothing to install)
  - Packet loss on Linux/WSL: `tc qdisc add dev eth0 root netem loss 5%`
  - NXDOMAIN: `nslookup does-not-exist.example`
  - RST: `curl http://localhost:1`

## Decisions

- License: MIT or Apache-2.0 (decided 2026-10-13).
- Name: `pcapdoctor` was free on crates.io on 2026-10-13.
