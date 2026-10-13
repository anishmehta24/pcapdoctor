//! Detectors that look at decoded packets and conversations for problems.

pub mod dns;
pub mod stream;
pub mod tcp;
pub mod tls;

use std::collections::HashMap;
use std::net::IpAddr;

use crate::capture::Frame;
use crate::decode::{Packet, Transport};
use crate::flow::{FlowTable, Observed};

use self::dns::{DnsLog, DnsPacket};
use self::tls::{TlsEvent, TlsLog};

/// Everything the analysis keeps from packet to packet.
#[derive(Debug, Default)]
pub struct Analyzer {
    pub flows: FlowTable,
    pub dns: DnsLog,
    pub tls: TlsLog,
    /// Server names from TLS ClientHellos, by server address.
    tls_names: HashMap<IpAddr, String>,
}

/// What the analysis found in one packet.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PacketFindings {
    pub flow: Option<Observed>,
    pub dns: DnsPacket,
    pub tls: Vec<TlsEvent>,
}

impl Analyzer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&mut self, frame: &Frame, pkt: &Packet<'_>) -> PacketFindings {
        let flow = self.flows.observe(frame, pkt);
        let dns = self.dns.observe(frame, pkt, flow.as_ref());
        let mut tls = Vec::new();
        if let (Some(Transport::Tcp(tcp)), Some(observed)) = (&pkt.transport, &flow) {
            tls = self.tls.observe(frame, tcp, pkt.payload, observed);
            for event in &tls {
                if let TlsEvent::ClientHello(hello) = event
                    && let Some(name) = &hello.server_name
                {
                    let server = self.flows.get(observed.flow).server.ip();
                    self.tls_names.entry(server).or_insert_with(|| name.clone());
                }
            }
        }
        PacketFindings { flow, dns, tls }
    }

    /// The name an address is known by: what DNS looked it up as, or else
    /// the server name a TLS client asked it for.
    pub fn name_of(&self, ip: IpAddr) -> Option<&str> {
        self.dns
            .name_of(ip)
            .or_else(|| self.tls_names.get(&ip).map(String::as_str))
    }

    /// The name of a connection's server: the name its TLS client asked
    /// for, which can differ between connections to the same address, or
    /// else the address's name.
    pub fn server_name(&self, flow: usize) -> Option<&str> {
        self.tls
            .for_flow(flow)
            .and_then(|h| h.server_name())
            .or_else(|| self.name_of(self.flows.flows()[flow].server.ip()))
    }
}
