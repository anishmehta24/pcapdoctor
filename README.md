# pcapdoctor

Reads a packet capture and tells you what went wrong on the network, in plain English: failed DNS lookups, refused or reset connections, packet loss, TLS handshake failures, and whether a slow request was the network's fault or the server's.

**Status: early.** Reading captures, listing packets, summarizing conversations and TCP analysis (retransmissions, duplicate ACKs, zero windows, resets) work. The plain-English diagnosis report is next; see [PLAN.md](PLAN.md).

## Usage

```
$ pcapdoctor dump capture.pcap -c 3
     1    0.000000  172.16.5.1:49178 → 172.16.5.10:8443 TCP [SYN] seq=3485596975 win=29200 len=0 mss=1460 wscale=7 sack_perm
     2    0.000289  172.16.5.10:8443 → 172.16.5.1:49178 TCP [SYN, ACK] seq=3667251318 ack=3485596976 win=28960 len=0 mss=1460 wscale=7 sack_perm
     3    0.000322  172.16.5.1:49178 → 172.16.5.10:8443 TCP [ACK] seq=3485596976 ack=3667251319 win=229 len=0
```

TCP sequence numbers count from the start of each connection, like Wireshark; `-S` shows the raw values. Problems are flagged with Wireshark's labels, e.g. `[TCP Retransmission]` or `[TCP Dup ACK 9#2]`, using the same rules; on the test captures every flag matches tshark.

```
$ pcapdoctor stats capture.pcap
...
TCP conversations: 2
Stream  Client           Server         Packets  Client→Server  Server→Client  Duration  State
     0  127.0.0.1:38713  127.0.0.1:443       37         4.6 kB        11.9 kB   12.37 s  open
     1  127.0.0.1:38714  127.0.0.1:443       21         3.1 kB         4.4 kB    6.37 s  open
```

`stats` also shows the protocol mix, the busiest hosts, each connection's round-trip time and retransmissions, and a summary of TCP problems. Stream numbers match Wireshark's `tcp.stream` and `udp.stream`, so `tcp.stream == 1` in Wireshark shows the same connection.

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
