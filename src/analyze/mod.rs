//! Detectors that look at decoded packets and conversations for problems.

pub mod dns;
pub mod tcp;

use crate::capture::Frame;
use crate::decode::Packet;
use crate::flow::{FlowTable, Observed};

use self::dns::{DnsLog, DnsPacket};

/// Everything the analysis keeps from packet to packet.
#[derive(Debug, Default)]
pub struct Analyzer {
    pub flows: FlowTable,
    pub dns: DnsLog,
}

/// What the analysis found in one packet.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PacketFindings {
    pub flow: Option<Observed>,
    pub dns: DnsPacket,
}

impl Analyzer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&mut self, frame: &Frame, pkt: &Packet<'_>) -> PacketFindings {
        let flow = self.flows.observe(frame, pkt);
        let dns = self.dns.observe(frame, pkt, flow.as_ref());
        PacketFindings { flow, dns }
    }
}
