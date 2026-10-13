//! Puts one direction of a TCP connection back in order, for protocols whose
//! messages span segments: DNS over TCP, TLS, HTTP.
//!
//! Only in-order data is used. A gap (a segment the capture missed) loses
//! the message boundaries, so the direction is given up from there on.

use std::collections::VecDeque;

use crate::capture::Timestamp;
use crate::decode::{Tcp, TcpFlags};

/// When a byte of the stream arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arrival {
    pub frame: u64,
    pub ts: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum State {
    #[default]
    Following,
    /// Data went missing: a gap, or a segment the capture cut short.
    Lost,
    /// The protocol parser needs nothing more.
    Stopped,
}

#[derive(Debug, Default)]
pub struct Reassembler {
    next_seq: Option<u32>,
    buf: Vec<u8>,
    /// Stream offset of `buf[0]`; the first byte of the stream is offset 0.
    start: u64,
    /// For each buffered segment: the stream offset just past it, and when
    /// it arrived. Oldest first.
    arrivals: VecDeque<(u64, Arrival)>,
    state: State,
}

impl Reassembler {
    /// Adds a segment's payload and returns how many new bytes it added.
    /// More than `limit` unconsumed bytes counts as losing the stream, so a
    /// parser that never finds a message boundary can't hold unlimited memory.
    pub fn push(&mut self, tcp: &Tcp, payload: &[u8], at: Arrival, limit: usize) -> usize {
        let mut seq = tcp.seq;
        if tcp.flags.has(TcpFlags::SYN) {
            // The SYN takes one sequence number; data on it (TCP Fast Open)
            // starts right after.
            seq = seq.wrapping_add(1);
            *self = Reassembler {
                next_seq: Some(seq),
                ..Reassembler::default()
            };
        }
        if self.state != State::Following || tcp.payload_len == 0 {
            return 0;
        }
        if payload.len() < tcp.payload_len as usize {
            self.lose();
            return 0;
        }
        // Joined mid-connection: start wherever this segment starts.
        let next = *self.next_seq.get_or_insert(seq);
        let overlap = next.wrapping_sub(seq) as i32;
        if overlap < 0 {
            self.lose();
            return 0;
        }
        let Some(new) = payload.get(overlap as usize..).filter(|d| !d.is_empty()) else {
            return 0; // a retransmission of data we already have
        };
        if self.buf.len() + new.len() > limit {
            self.lose();
            return 0;
        }
        self.buf.extend_from_slice(new);
        self.next_seq = Some(next.wrapping_add(new.len() as u32));
        self.arrivals
            .push_back((self.start + self.buf.len() as u64, at));
        new.len()
    }

    /// Bytes received in order and not yet consumed.
    pub fn data(&self) -> &[u8] {
        &self.buf
    }

    /// Stream offset of the first byte of `data()`.
    pub fn offset(&self) -> u64 {
        self.start
    }

    /// When the byte at stream `offset` arrived, if it is still buffered.
    pub fn arrival(&self, offset: u64) -> Option<Arrival> {
        if offset < self.start {
            return None;
        }
        self.arrivals
            .iter()
            .find(|(end, _)| offset < *end)
            .map(|(_, at)| *at)
    }

    /// Drops the first `n` bytes of `data()` once they have been parsed.
    pub fn consume(&mut self, n: usize) {
        let n = n.min(self.buf.len());
        self.buf.drain(..n);
        self.start += n as u64;
        while self
            .arrivals
            .front()
            .is_some_and(|(end, _)| *end <= self.start)
        {
            self.arrivals.pop_front();
        }
    }

    /// Stops following this direction and frees the buffer.
    pub fn stop(&mut self) {
        self.state = State::Stopped;
        self.release();
    }

    pub fn is_following(&self) -> bool {
        self.state == State::Following
    }

    /// Data went missing, so whatever came after is unreadable.
    pub fn lost_data(&self) -> bool {
        self.state == State::Lost
    }

    fn lose(&mut self) {
        self.state = State::Lost;
        self.release();
    }

    fn release(&mut self) {
        self.buf = Vec::new();
        self.arrivals.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::TcpOptions;

    fn segment(seq: u32, flags: u16, payload_len: u32) -> Tcp {
        Tcp {
            src_port: 50000,
            dst_port: 443,
            seq,
            ack: 0,
            flags: TcpFlags(flags),
            window: 64240,
            header_len: 20,
            options: TcpOptions::default(),
            payload_len,
        }
    }

    fn at(frame: u64) -> Arrival {
        Arrival {
            frame,
            ts: Timestamp(frame * 1000),
        }
    }

    #[test]
    fn in_order_overlap_and_arrivals() {
        let mut r = Reassembler::default();
        r.push(&segment(99, TcpFlags::SYN, 0), &[], at(1), 100);
        assert_eq!(
            r.push(&segment(100, TcpFlags::ACK, 3), b"abc", at(2), 100),
            3
        );
        // Retransmission, then a segment overlapping what we have.
        assert_eq!(
            r.push(&segment(100, TcpFlags::ACK, 3), b"abc", at(3), 100),
            0
        );
        assert_eq!(
            r.push(&segment(102, TcpFlags::ACK, 3), b"cde", at(4), 100),
            2
        );
        assert_eq!(r.data(), b"abcde");
        assert_eq!(r.arrival(1), Some(at(2)));
        assert_eq!(r.arrival(4), Some(at(4)));
        r.consume(3);
        assert_eq!((r.data(), r.offset()), (&b"de"[..], 3));
        assert_eq!(r.arrival(1), None);
        assert_eq!(r.arrival(3), Some(at(4)));
    }

    #[test]
    fn data_on_the_syn() {
        let mut r = Reassembler::default();
        assert_eq!(r.push(&segment(10, TcpFlags::SYN, 2), b"hi", at(1), 100), 2);
        assert_eq!(r.push(&segment(13, TcpFlags::ACK, 1), b"!", at(2), 100), 1);
        assert_eq!(r.data(), b"hi!");
    }

    #[test]
    fn gaps_cuts_and_limits_lose_the_stream() {
        let mut gap = Reassembler::default();
        gap.push(&segment(0, TcpFlags::ACK, 2), b"ab", at(1), 100);
        gap.push(&segment(10, TcpFlags::ACK, 2), b"cd", at(2), 100);
        assert!(gap.lost_data());
        assert_eq!(
            gap.push(&segment(2, TcpFlags::ACK, 2), b"ef", at(3), 100),
            0
        );

        let mut cut = Reassembler::default();
        cut.push(
            &segment(0, TcpFlags::ACK, 1000),
            b"only the start",
            at(1),
            2000,
        );
        assert!(cut.lost_data());

        let mut full = Reassembler::default();
        full.push(&segment(0, TcpFlags::ACK, 6), b"abcdef", at(1), 5);
        assert!(full.lost_data());
    }
}
