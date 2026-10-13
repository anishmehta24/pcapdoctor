# pcapdoctor plan

## Goal

`pcapdoctor capture.pcap` says what went wrong on the network in plain English, and names the frames to look at in Wireshark.

```
$ pcapdoctor capture.pcap
✗ DNS   api.internal: NXDOMAIN (3 queries)                                frames 12, 40, 41
✗ TLS   pay.example.com: handshake failed, server sent unknown_ca         frame 88
⚠ SLOW  api.example.com:443: network RTT 40 ms, server took 2.1 s         frames 101-140
        → the server is slow, not the network
⚠ LOSS  10.0.0.5 → cdn.example.com:443: 6% of segments retransmitted      frames 210-480
✓ 214 other connections look healthy
```

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
| `pcapdoctor stats FILE` | protocol mix, top talkers, conversations | M2 |
| `pcapdoctor FILE [--format text\|json\|html]` | diagnosis report (default command) | M6 |
| `pcapdoctor check FILE --fail-on FILTER` | CI mode: exit 1 when something matches | M7 |
| `pcapdoctor live -i IFACE -d 30s` | capture, then diagnose | M8 |

Exit codes: 0 ok, 1 `check` found problems, 2 error.

## Architecture

```
capture/   pcap + pcapng readers, our own code (no libpcap)    -> Frame { number, ts, link_type, data }
decode/    link -> IPv4/IPv6/ARP -> TCP/UDP/ICMP                -> Packet { layers, error }
flow/      bidirectional 5-tuple table, TCP state per flow      (M2)
analyze/   TCP health, DNS, TLS, HTTP detectors                  -> Finding { severity, text, frames, metrics }  (M3-M5)
report/    text / JSON / HTML                                    (M6)
filter/    tokenizer -> parser -> AST -> evaluator               (M7)
```

Decoding borrows the frame bytes (zero-copy). When a layer is malformed, the layers before it are kept, like Wireshark's "[Malformed Packet]".

## Milestones

### M0 Scaffold — done 2026-10-13
Cargo project, CLI skeleton, CI (fmt, clippy, tests on Linux, Windows and macOS), this plan, README.

### M1 Read and decode — done 2026-10-13, except the tshark comparison
- pcap (both byte orders, µs and ns timestamps) and pcapng (multiple sections and interfaces, `if_tsresol`, `if_tsoffset`, enhanced/simple/obsolete packet blocks) readers
- Cut-off files: keep every complete packet and warn, instead of failing
- Link layers: Ethernet with VLAN/QinQ, Linux cooked v1/v2 (`tcpdump -i any`), BSD/Windows loopback, raw IP
- IPv4 (options, fragments, zero length from TCP segmentation offload), IPv6 (extension headers, fragments), ARP, TCP (MSS, window scale, SACK, timestamps), UDP, ICMP, ICMPv6
- Lengths come from the IP headers, not the captured bytes, so Ethernet padding is never treated as data and snaplen captures still give real segment sizes
- `dump` command
- **Done when:** every layer has tests, the no-panic tests pass, and `dump` agrees with tshark on the sample captures.
- **Status:** 37 tests pass, including mutation tests (50k packets, 20k files). On 9 Wireshark sample captures, all 191 TCP/UDP packets match an independent decoder (Python `dpkt`) field for field. Still to do: compare with tshark once Wireshark is installed.

### M2 Flows and stats
- Flow table keyed by normalized 5-tuple; per-direction packets, bytes, first and last seen
- TCP connection state: SYN, SYN-ACK, established, FIN, RST
- Relative sequence numbers in `dump`
- `stats`: protocol distribution (packets and bytes), top talkers, conversation table, packets per second
- **Done when:** the conversation table matches `tshark -z conv,tcp`.

### M3 TCP health
- RTT from the handshake, split into client side and server side
- Retransmissions (including spurious ones), out-of-order segments, duplicate ACKs, fast retransmits. Track the next expected sequence number per direction, with 32-bit wraparound.
- Zero window, window full
- RST classified: refused (answer to a SYN), aborted mid-stream, after FIN
- SYN never answered (connection timeout)
- **Done when:** counts match tshark's `tcp.analysis.*` on samples and on captures made with `tc netem` loss, apart from documented differences.

### M4 DNS
- Wire format: header, questions, answers (A, AAAA, CNAME, ...), name compression with loop protection; over UDP and TCP
- Match responses to queries (ID + flow). Report rcode failures (NXDOMAIN, SERVFAIL, REFUSED), queries with no response, slow responses, and ICMP port unreachable from the DNS server.
- IP → hostname map built from answers, so reports say `api.example.com` instead of `93.184.216.34`

### M5 TLS and HTTP
- TLS records and handshake: ClientHello SNI, ALPN, offered versions; ServerHello chosen version; alerts (handshake_failure, unknown_ca, certificate_expired, protocol_version, ...)
- TLS 1.2 certificates: subject, issuer, expiry (TLS 1.3 encrypts them)
- HTTP/1.x: request line, status code, per-request timing (reassemble the start of each request and response)
- **Network or server?** Server time ≈ time to first response byte − RTT

### M6 Diagnosis and report
- Finding: severity (error, warning, info), category, one sentence, evidence frames, measurements
- Rules turn M3–M5 data into findings; everything else rolls up into a health summary
- Output: colored text (default), JSON (versioned schema), HTML (one self-contained file)
- `pcapdoctor FILE` becomes the default command
- **Done when:** the example at the top of this file is real output from a capture committed to the repo.

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
- **Real captures** in `tests/fixtures/`, with expected numbers taken from tshark, e.g. `tshark -r f.pcap -Y tcp.analysis.retransmission | wc -l`.
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
