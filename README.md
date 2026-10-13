# pcapdoctor

Reads a packet capture and tells you what went wrong on the network, in plain English: failed DNS lookups, refused or reset connections, packet loss, TLS handshake failures, and whether a slow request was the network's fault or the server's.

**Status: early.** Packet listing, conversation summaries, TCP analysis (retransmissions, duplicate ACKs, zero windows, resets, round-trip times) DNS analysis (failed, missing, slow and retried lookups) TLS analysis (rejected handshakes, certificate problems, slow servers) and HTTP analysis (status codes, and how long the server took) work. The plain-English diagnosis report is next; see [PLAN.md](PLAN.md).

## Usage

`dump` prints one line per packet:

```
$ pcapdoctor dump capture.pcap
     1    0.000000  172.16.5.1:49178 → 172.16.5.10:8443 TCP [SYN] seq=0 win=29200 len=0 mss=1460 wscale=7 sack_perm
     2    0.000289  172.16.5.10:8443 → 172.16.5.1:49178 TCP [SYN, ACK] seq=0 ack=1 win=28960 len=0 mss=1460 wscale=7 sack_perm
     3    0.000322  172.16.5.1:49178 → 172.16.5.10:8443 TCP [ACK] seq=1 ack=1 win=229 len=0
   ...
    14   50.000000  192.168.1.10:40006 → 192.168.1.1:53 DNS query 0x0606 A slow.example
    15   51.000000  192.168.1.10:40006 → 192.168.1.1:53 DNS query 0x0606 A slow.example [retry of frame 14]
    16   51.200000  192.168.1.1:53 → 192.168.1.10:40006 DNS response 0x0606 A slow.example → A 198.51.100.6 (1.20 s)
    20   70.000000  192.168.1.10:40008 → 192.168.1.2:53 DNS query 0x0808 A down.example
    21   70.001000  192.168.1.2 → 192.168.1.10 ICMP destination unreachable (port unreachable) [about the DNS query in frame 20]
```

- TCP sequence numbers count from the start of each connection, as in Wireshark; `-S` shows the raw values.
- TCP problems get Wireshark's labels, e.g. `[TCP Retransmission]` or `[TCP Dup ACK 9#2]`, decided by the same rules.
- DNS responses show their response time, and ICMP errors point back to the query that caused them.
- TLS handshakes show the server name, versions and ALPN, the certificate (before TLS 1.3, which encrypts it) and alerts.
- HTTP requests and responses show which request each response answers and the time to its first byte.

`stats` summarizes the whole capture:

```
$ pcapdoctor stats capture.pcap
...
Problem lookups: 8
Name             Type  Server          Result                        Time  Sent  Frame
broken.example   A     192.168.1.1:53  server failure             20.0 ms     1     10
nope.example     A     192.168.1.1:53  no such name               20.0 ms     1      8
blocked.example  A     192.168.1.1:53  refused                    20.0 ms     1     12
loop.example     A     192.168.1.1:53  malformed response          9.0 ms     1     34
down.example     A     192.168.1.2:53  server unreachable (ICMP)        -     1     20
```

It shows:
- the protocol mix
- the busiest hosts, with the names they were looked up by in DNS
- each TCP and UDP conversation, with round-trip time, retransmissions and state
- a summary of TCP problems
- DNS results
- HTTP results: status codes, server times, and the requests that failed or were slow
- for every TCP connection, its "wait": how long the client waited for the server's answer. This works for HTTPS too, without decrypting.
- TLS results, with problem handshakes explained, e.g. `client rejected the handshake: unknown_ca (the certificate's issuer is not trusted)` or `certificate is for other.example, not wrong.example`

Stream numbers match Wireshark's `tcp.stream` and `udp.stream`, so `tcp.stream == 1` in Wireshark shows the same connection.

Every field, flag and timing above is checked against tshark on real and generated captures. The few places where pcapdoctor differs on purpose are noted in [PLAN.md](PLAN.md).

Reads pcap and pcapng files directly, with no libpcap or Npcap needed. Supported link layers: Ethernet (with VLAN tags), Linux cooked (`tcpdump -i any`), loopback, and raw IP. Cut-off captures are read up to the last complete packet.

## Getting a capture

- Linux/macOS: `sudo tcpdump -i any -w capture.pcap`
- Windows, with nothing to install (admin prompt):
  ```
  pktmon start --capture --pkt-size 0
  pktmon stop
  pktmon etl2pcap PktMon.etl --out capture.pcapng
  ```
- Wireshark: File → Save As → pcapng

## Building

```
cargo build --release
cargo test
```

## License

MIT or Apache-2.0, at your option.
