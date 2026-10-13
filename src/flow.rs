//! Groups packets into conversations (flows) and tracks TCP connection state.
//!
//! A flow is every TCP or UDP packet between two endpoints, in both
//! directions. Flows are numbered per protocol in order of first appearance,
//! which matches Wireshark's `tcp.stream` and `udp.stream`.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;

use crate::capture::{Frame, Timestamp};
use crate::decode::{IPPROTO_TCP, IPPROTO_UDP, Packet, Tcp, TcpFlags, Transport};
use crate::summary::SeqBase;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Side {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counter {
    pub packets: u64,
    /// Bytes on the wire, link-layer headers included (as Wireshark counts them).
    pub bytes: u64,
}

impl Counter {
    pub fn add(&mut self, bytes: u64) {
        self.packets += 1;
        self.bytes += bytes;
    }
}

#[derive(Debug, Clone)]
pub struct Flow {
    /// IP protocol: 6 for TCP, 17 for UDP.
    pub protocol: u8,
    /// Position among flows of the same protocol, like Wireshark's `tcp.stream`.
    pub stream: u32,
    pub client: SocketAddr,
    pub server: SocketAddr,
    pub from_client: Counter,
    pub from_server: Counter,
    pub first_frame: u64,
    pub last_frame: u64,
    pub first_ts: Timestamp,
    pub last_ts: Timestamp,
    /// Connection state; `None` for UDP.
    pub tcp: Option<TcpConn>,
}

impl Flow {
    pub fn packets(&self) -> u64 {
        self.from_client.packets + self.from_server.packets
    }

    pub fn bytes(&self) -> u64 {
        self.from_client.bytes + self.from_server.bytes
    }

    pub fn duration_secs(&self) -> f64 {
        self.last_ts.secs_since(self.first_ts)
    }

    /// A SYN on endpoints we've already seen starts a new connection (the
    /// client reused its port), unless it repeats the SYN that opened this one.
    fn is_new_connection(&self, tcp: &Tcp, src: SocketAddr) -> bool {
        let Some(conn) = &self.tcp else {
            return false;
        };
        if !tcp.flags.has(TcpFlags::SYN) || tcp.flags.has(TcpFlags::ACK) {
            return false;
        }
        let retransmitted =
            src == self.client && conn.syn.is_some() && conn.base_seq[0] == Some(tcp.seq);
        !retransmitted
    }
}

#[derive(Debug, Clone, Default)]
pub struct TcpConn {
    /// First SYN from the client: (frame number, time).
    pub syn: Option<(u64, Timestamp)>,
    /// First SYN-ACK from the server.
    pub syn_ack: Option<(u64, Timestamp)>,
    /// Set once anything other than SYN or RST is sent, which also covers
    /// connections that were already open when the capture started.
    pub established: bool,
    pub fin_from_client: bool,
    pub fin_from_server: bool,
    /// Who sent the first RST.
    pub reset_by: Option<Side>,
    /// Sequence number that counts as 0, for the client and server directions.
    base_seq: [Option<u32>; 2],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpStatus {
    /// Only SYNs were seen.
    NoAnswer,
    /// The server answered the SYN with RST: nothing listens on that port,
    /// or a firewall rejected it.
    Refused,
    /// The server sent SYN-ACK but the client never completed the handshake.
    HandshakeIncomplete,
    Open,
    /// One side has sent FIN.
    HalfClosed,
    Closed,
    Reset(Side),
}

impl fmt::Display for TcpStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TcpStatus::NoAnswer => "no answer",
            TcpStatus::Refused => "refused",
            TcpStatus::HandshakeIncomplete => "handshake incomplete",
            TcpStatus::Open => "open",
            TcpStatus::HalfClosed => "half-closed",
            TcpStatus::Closed => "closed",
            TcpStatus::Reset(Side::Client) => "reset by client",
            TcpStatus::Reset(Side::Server) => "reset by server",
        })
    }
}

impl TcpConn {
    pub fn status(&self) -> TcpStatus {
        // Both FINs means a clean close; an RST after that is a common way
        // to tear down the socket and not worth reporting.
        if self.fin_from_client && self.fin_from_server {
            return TcpStatus::Closed;
        }
        if let Some(side) = self.reset_by {
            let refused = side == Side::Server && !self.established && self.syn_ack.is_none();
            return if refused {
                TcpStatus::Refused
            } else {
                TcpStatus::Reset(side)
            };
        }
        if self.fin_from_client || self.fin_from_server {
            TcpStatus::HalfClosed
        } else if self.established {
            TcpStatus::Open
        } else if self.syn_ack.is_some() {
            TcpStatus::HandshakeIncomplete
        } else {
            TcpStatus::NoAnswer
        }
    }

    /// The capture began after this connection was opened.
    pub fn started_before_capture(&self) -> bool {
        self.syn.is_none() && self.syn_ack.is_none()
    }

    /// What to subtract from a segment sent by `side` to show relative numbers.
    pub fn seq_base(&self, side: Side) -> SeqBase {
        let (own, other) = indexes(side);
        SeqBase {
            seq: self.base_seq[own].unwrap_or(0),
            ack: self.base_seq[other].unwrap_or(0),
        }
    }

    fn update(&mut self, side: Side, tcp: &Tcp, frame: &Frame) {
        let flags = tcp.flags;
        let (own, other) = indexes(side);
        if flags.has(TcpFlags::SYN) {
            if self.base_seq[own].is_none() {
                self.base_seq[own] = Some(tcp.seq);
            }
            let seen = Some((frame.number, frame.ts));
            match (side, flags.has(TcpFlags::ACK)) {
                (Side::Client, false) if self.syn.is_none() => self.syn = seen,
                (Side::Server, true) if self.syn_ack.is_none() => self.syn_ack = seen,
                _ => {}
            }
        } else {
            // Without the SYN, count from the first segment seen, which then
            // shows as 1. Wireshark does the same.
            if self.base_seq[own].is_none() {
                self.base_seq[own] = Some(tcp.seq.wrapping_sub(1));
            }
            if !flags.has(TcpFlags::RST) {
                self.established = true;
            }
        }
        if flags.has(TcpFlags::ACK) && self.base_seq[other].is_none() {
            self.base_seq[other] = Some(tcp.ack.wrapping_sub(1));
        }
        if flags.has(TcpFlags::FIN) {
            match side {
                Side::Client => self.fin_from_client = true,
                Side::Server => self.fin_from_server = true,
            }
        }
        if flags.has(TcpFlags::RST) && self.reset_by.is_none() {
            self.reset_by = Some(side);
        }
    }
}

fn indexes(side: Side) -> (usize, usize) {
    match side {
        Side::Client => (0, 1),
        Side::Server => (1, 0),
    }
}

/// The flow a packet belongs to, and which side sent it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowRef {
    pub index: usize,
    pub from: Side,
}

/// Endpoints in a fixed order, so both directions map to the same key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    protocol: u8,
    low: SocketAddr,
    high: SocketAddr,
}

impl FlowKey {
    fn new(protocol: u8, x: SocketAddr, y: SocketAddr) -> Self {
        let (low, high) = if x <= y { (x, y) } else { (y, x) };
        FlowKey {
            protocol,
            low,
            high,
        }
    }
}

#[derive(Debug, Default)]
pub struct FlowTable {
    flows: Vec<Flow>,
    /// The current flow for each pair of endpoints. When a port is reused the
    /// entry moves to the new flow; the old one stays in `flows`.
    current: HashMap<FlowKey, usize>,
    tcp_streams: u32,
    udp_streams: u32,
}

impl FlowTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a TCP or UDP packet to its flow, starting a new flow if needed.
    /// Returns `None` for other packets, and for fragments that don't carry
    /// the transport header.
    pub fn observe(&mut self, frame: &Frame, pkt: &Packet<'_>) -> Option<FlowRef> {
        let (src_ip, dst_ip) = pkt.network.as_ref()?.ip_addrs()?;
        let (protocol, src_port, dst_port, tcp) = match pkt.transport.as_ref()? {
            Transport::Tcp(t) => (IPPROTO_TCP, t.src_port, t.dst_port, Some(t)),
            Transport::Udp(u) => (IPPROTO_UDP, u.src_port, u.dst_port, None),
            _ => return None,
        };
        let src = SocketAddr::new(src_ip, src_port);
        let dst = SocketAddr::new(dst_ip, dst_port);
        let key = FlowKey::new(protocol, src, dst);
        let index = match self.current.get(&key).copied() {
            Some(i) if !tcp.is_some_and(|t| self.flows[i].is_new_connection(t, src)) => i,
            _ => {
                let i = self.start_flow(protocol, src, dst, tcp, frame);
                self.current.insert(key, i);
                i
            }
        };

        let flow = &mut self.flows[index];
        let from = if src == flow.client {
            Side::Client
        } else {
            Side::Server
        };
        let bytes = u64::from(frame.orig_len);
        match from {
            Side::Client => flow.from_client.add(bytes),
            Side::Server => flow.from_server.add(bytes),
        }
        flow.last_frame = frame.number;
        flow.first_ts = flow.first_ts.min(frame.ts);
        flow.last_ts = flow.last_ts.max(frame.ts);
        if let (Some(conn), Some(tcp)) = (flow.tcp.as_mut(), tcp) {
            conn.update(from, tcp, frame);
        }
        Some(FlowRef { index, from })
    }

    pub fn flows(&self) -> &[Flow] {
        &self.flows
    }

    pub fn get(&self, r: FlowRef) -> &Flow {
        &self.flows[r.index]
    }

    /// Relative-numbering base for a TCP segment; `None` for UDP.
    pub fn seq_base(&self, r: FlowRef) -> Option<SeqBase> {
        self.get(r).tcp.as_ref().map(|conn| conn.seq_base(r.from))
    }

    fn start_flow(
        &mut self,
        protocol: u8,
        src: SocketAddr,
        dst: SocketAddr,
        tcp: Option<&Tcp>,
        frame: &Frame,
    ) -> usize {
        let (client, server) = client_and_server(src, dst, tcp);
        let counter = if protocol == IPPROTO_TCP {
            &mut self.tcp_streams
        } else {
            &mut self.udp_streams
        };
        let stream = *counter;
        *counter += 1;
        self.flows.push(Flow {
            protocol,
            stream,
            client,
            server,
            from_client: Counter::default(),
            from_server: Counter::default(),
            first_frame: frame.number,
            last_frame: frame.number,
            first_ts: frame.ts,
            last_ts: frame.ts,
            tcp: tcp.map(|_| TcpConn::default()),
        });
        self.flows.len() - 1
    }
}

/// Decides which end of a new flow is the client, from its first packet.
fn client_and_server(
    src: SocketAddr,
    dst: SocketAddr,
    tcp: Option<&Tcp>,
) -> (SocketAddr, SocketAddr) {
    if let Some(tcp) = tcp
        && tcp.flags.has(TcpFlags::SYN)
    {
        // The client sends SYN; the server answers with SYN-ACK.
        return if tcp.flags.has(TcpFlags::ACK) {
            (dst, src)
        } else {
            (src, dst)
        };
    }
    // Otherwise go by the ports: servers listen on well-known or registered
    // ports, clients send from high ephemeral ones.
    let rank = |port: u16| match port {
        0..1024 => 0,
        1024..32768 => 1,
        _ => 2,
    };
    match rank(src.port()).cmp(&rank(dst.port())) {
        Ordering::Less => (dst, src),
        // Same kind of port on both ends: whoever spoke first is the client.
        Ordering::Greater | Ordering::Equal => (src, dst),
    }
}
