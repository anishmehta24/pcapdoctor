//! Capture-wide numbers for `pcapdoctor stats`: protocol mix, busiest hosts
//! and conversations.

use std::collections::HashMap;
use std::fmt::Write;
use std::net::IpAddr;

use crate::capture::{Frame, Timestamp};
use crate::decode::{Link, Network, Packet, Transport};
use crate::flow::{Counter, Flow, FlowTable};
use crate::names;
use crate::units::{self, Align, Table};

#[derive(Debug, Default)]
pub struct Stats {
    pub total: Counter,
    pub first_ts: Option<Timestamp>,
    pub last_ts: Option<Timestamp>,
    /// Protocol hierarchy; the root itself is unnamed.
    pub protocols: ProtocolNode,
    pub hosts: HashMap<IpAddr, Host>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Host {
    pub sent: Counter,
    pub received: Counter,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProtocolNode {
    pub name: String,
    pub count: Counter,
    pub children: Vec<ProtocolNode>,
}

impl ProtocolNode {
    fn add(&mut self, path: &[String], bytes: u64) {
        let Some((first, rest)) = path.split_first() else {
            return;
        };
        let i = match self.children.iter().position(|c| &c.name == first) {
            Some(i) => i,
            None => {
                self.children.push(ProtocolNode {
                    name: first.clone(),
                    ..Default::default()
                });
                self.children.len() - 1
            }
        };
        self.children[i].count.add(bytes);
        self.children[i].add(rest, bytes);
    }

    /// Children with the most bytes first.
    pub fn sorted_children(&self) -> Vec<&ProtocolNode> {
        let mut children: Vec<&ProtocolNode> = self.children.iter().collect();
        children.sort_by(|a, b| {
            b.count
                .bytes
                .cmp(&a.count.bytes)
                .then_with(|| a.name.cmp(&b.name))
        });
        children
    }
}

impl Stats {
    pub fn add(&mut self, frame: &Frame, pkt: &Packet<'_>) {
        let bytes = u64::from(frame.orig_len);
        self.total.add(bytes);
        self.first_ts = Some(self.first_ts.map_or(frame.ts, |t| t.min(frame.ts)));
        self.last_ts = Some(self.last_ts.map_or(frame.ts, |t| t.max(frame.ts)));
        self.protocols.add(&protocol_path(pkt), bytes);
        if let Some((src, dst)) = pkt.network.as_ref().and_then(Network::ip_addrs) {
            self.hosts.entry(src).or_default().sent.add(bytes);
            self.hosts.entry(dst).or_default().received.add(bytes);
        }
    }

    pub fn duration_secs(&self) -> f64 {
        match (self.first_ts, self.last_ts) {
            (Some(first), Some(last)) => last.secs_since(first),
            _ => 0.0,
        }
    }

    /// Hosts by bytes sent plus received, largest first.
    pub fn busiest_hosts(&self) -> Vec<(IpAddr, Host)> {
        let mut hosts: Vec<(IpAddr, Host)> = self.hosts.iter().map(|(ip, h)| (*ip, *h)).collect();
        hosts.sort_by(|(a_ip, a), (b_ip, b)| {
            let total = |h: &Host| h.sent.bytes + h.received.bytes;
            total(b).cmp(&total(a)).then_with(|| a_ip.cmp(b_ip))
        });
        hosts
    }
}

/// Where a packet sits in the protocol tree, e.g. ["IPv4", "TCP"].
fn protocol_path(pkt: &Packet<'_>) -> Vec<String> {
    let mut path = Vec::new();
    match &pkt.network {
        Some(Network::Ipv4(h)) => {
            path.push("IPv4".to_string());
            if h.fragment_offset > 0 {
                path.push("fragments".to_string());
            }
        }
        Some(Network::Ipv6(h)) => {
            path.push("IPv6".to_string());
            if h.fragment.is_some_and(|f| f.offset > 0) {
                path.push("fragments".to_string());
            }
        }
        Some(Network::Arp(_)) => path.push("ARP".to_string()),
        Some(Network::Other { ethertype }) => path.push(names::ethertype(*ethertype)),
        // Decoding stopped at the link layer.
        None => match &pkt.link {
            Link::Ethernet { ethertype, .. } => path.push(names::ethertype(*ethertype)),
            Link::Unsupported(lt) => path.push(format!("link type {lt}")),
            Link::LinuxCooked | Link::Loopback | Link::RawIp => {}
        },
    }
    match &pkt.transport {
        Some(Transport::Tcp(_)) => path.push("TCP".to_string()),
        Some(Transport::Udp(_)) => path.push("UDP".to_string()),
        Some(Transport::Icmp(i)) => path.push(if i.v6 { "ICMPv6" } else { "ICMP" }.to_string()),
        Some(Transport::Other { protocol }) => path.push(names::ip_protocol(*protocol)),
        None => {}
    }
    if pkt.error.is_some() {
        path.push("malformed".to_string());
    }
    path
}

/// Text report for `pcapdoctor stats`; tables show at most `top` rows.
pub fn render(stats: &Stats, flows: &FlowTable, top: usize) -> String {
    let mut out = String::new();
    let duration = stats.duration_secs();
    let _ = writeln!(out, "Packets   {}", units::count(stats.total.packets));
    let _ = writeln!(out, "Bytes     {}", units::bytes(stats.total.bytes));
    if let Some(first) = stats.first_ts {
        let _ = writeln!(out, "Start     {}", units::utc(first));
        let _ = writeln!(out, "Duration  {}", units::duration(duration));
    }
    if duration > 0.0 {
        let _ = writeln!(
            out,
            "Rate      {:.1} packets/s, {}",
            stats.total.packets as f64 / duration,
            units::bitrate(stats.total.bytes as f64 * 8.0 / duration)
        );
    }

    let mut table = Table::new(&[
        ("Protocol", Align::Left),
        ("Packets", Align::Right),
        ("%", Align::Right),
        ("Bytes", Align::Right),
        ("%", Align::Right),
    ]);
    add_protocol_rows(&mut table, &stats.protocols, &stats.total, 0);
    let _ = write!(out, "\n{}", table.render());

    let hosts = stats.busiest_hosts();
    if !hosts.is_empty() {
        let mut table = Table::new(&[
            ("Host", Align::Left),
            ("Packets sent", Align::Right),
            ("Bytes sent", Align::Right),
            ("Packets received", Align::Right),
            ("Bytes received", Align::Right),
        ]);
        for (ip, host) in hosts.iter().take(top) {
            table.row(vec![
                ip.to_string(),
                units::count(host.sent.packets),
                units::bytes(host.sent.bytes),
                units::count(host.received.packets),
                units::bytes(host.received.bytes),
            ]);
        }
        let _ = write!(
            out,
            "\n{}{}",
            heading("Hosts", hosts.len(), top, "by bytes"),
            table.render()
        );
    }

    for (name, tcp) in [("TCP", true), ("UDP", false)] {
        let mut list: Vec<&Flow> = flows
            .flows()
            .iter()
            .filter(|f| f.tcp.is_some() == tcp)
            .collect();
        if list.is_empty() {
            continue;
        }
        list.sort_by(|a, b| {
            b.bytes()
                .cmp(&a.bytes())
                .then_with(|| a.stream.cmp(&b.stream))
        });
        let mut columns = vec![
            ("Stream", Align::Right),
            ("Client", Align::Left),
            ("Server", Align::Left),
            ("Packets", Align::Right),
            ("Client→Server", Align::Right),
            ("Server→Client", Align::Right),
            ("Duration", Align::Right),
        ];
        if tcp {
            columns.push(("State", Align::Left));
        }
        let mut table = Table::new(&columns);
        let mut joined_late = false;
        for flow in list.iter().take(top) {
            let mut row = vec![
                flow.stream.to_string(),
                flow.client.to_string(),
                flow.server.to_string(),
                units::count(flow.packets()),
                units::bytes(flow.from_client.bytes),
                units::bytes(flow.from_server.bytes),
                units::duration(flow.duration_secs()),
            ];
            if let Some(conn) = &flow.tcp {
                let mut state = conn.status().to_string();
                if conn.started_before_capture() {
                    state.push('*');
                    joined_late = true;
                }
                row.push(state);
            }
            table.row(row);
        }
        let title = format!("{name} conversations");
        let _ = write!(
            out,
            "\n{}{}",
            heading(&title, list.len(), top, "by bytes"),
            table.render()
        );
        if joined_late {
            let _ = writeln!(out, "* already open when the capture started");
        }
    }
    out
}

fn add_protocol_rows(table: &mut Table, node: &ProtocolNode, total: &Counter, depth: usize) {
    for child in node.sorted_children() {
        table.row(vec![
            format!("{}{}", "  ".repeat(depth), child.name),
            units::count(child.count.packets),
            units::percent(child.count.packets, total.packets),
            units::bytes(child.count.bytes),
            units::percent(child.count.bytes, total.bytes),
        ]);
        add_protocol_rows(table, child, total, depth + 1);
    }
}

fn heading(title: &str, len: usize, top: usize, order: &str) -> String {
    if len > top {
        format!("{title}: {len}, showing top {top} {order}\n")
    } else {
        format!("{title}: {len}\n")
    }
}
