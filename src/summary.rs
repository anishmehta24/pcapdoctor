//! One-line packet descriptions for `pcapdoctor dump`, in the spirit of
//! tcpdump and Wireshark's Info column.

use std::fmt::Write;
use std::net::SocketAddr;

use crate::decode::{Arp, Icmp, Link, Network, Packet, Tcp, TcpFlags, Transport};

pub fn describe(pkt: &Packet<'_>) -> String {
    let mut line = match (&pkt.network, &pkt.transport) {
        (Some(net), Some(transport)) => describe_transport(net, transport),
        (Some(net), None) => describe_network(&pkt.link, net),
        (None, _) => describe_link(&pkt.link, pkt.error.is_some()),
    };
    if let Some(err) = &pkt.error {
        if !line.is_empty() {
            line.push(' ');
        }
        let _ = write!(line, "[{err}]");
    }
    line
}

fn describe_transport(net: &Network, transport: &Transport) -> String {
    let Some((src, dst)) = net.ip_addrs() else {
        return String::new();
    };
    match transport {
        Transport::Tcp(tcp) => format!(
            "{} → {} TCP {}",
            SocketAddr::new(src, tcp.src_port),
            SocketAddr::new(dst, tcp.dst_port),
            tcp_info(tcp)
        ),
        Transport::Udp(udp) => format!(
            "{} → {} UDP len={}",
            SocketAddr::new(src, udp.src_port),
            SocketAddr::new(dst, udp.dst_port),
            udp.payload_len
        ),
        Transport::Icmp(icmp) => {
            let name = if icmp.v6 { "ICMPv6" } else { "ICMP" };
            format!("{src} → {dst} {name} {}", icmp_info(icmp))
        }
        Transport::Other { protocol } => format!("{src} → {dst} {}", ip_protocol_name(*protocol)),
    }
}

fn tcp_info(tcp: &Tcp) -> String {
    let mut s = format!("[{}] seq={}", tcp.flags, tcp.seq);
    if tcp.flags.has(TcpFlags::ACK) {
        let _ = write!(s, " ack={}", tcp.ack);
    }
    let _ = write!(s, " win={} len={}", tcp.window, tcp.payload_len);
    let opts = &tcp.options;
    if let Some(mss) = opts.mss {
        let _ = write!(s, " mss={mss}");
    }
    if let Some(ws) = opts.window_scale {
        let _ = write!(s, " wscale={ws}");
    }
    if opts.sack_permitted {
        s.push_str(" sack_perm");
    }
    for (left, right) in &opts.sack {
        let _ = write!(s, " sack={left}-{right}");
    }
    s
}

fn describe_network(link: &Link, net: &Network) -> String {
    match net {
        Network::Ipv4(h) if h.fragment_offset > 0 => format!(
            "{} → {} IPv4 fragment offset={} ({})",
            h.src,
            h.dst,
            h.fragment_offset,
            ip_protocol_name(h.protocol)
        ),
        Network::Ipv4(h) => format!("{} → {} {}", h.src, h.dst, ip_protocol_name(h.protocol)),
        Network::Ipv6(h) => match h.fragment {
            Some(frag) if frag.offset > 0 => format!(
                "{} → {} IPv6 fragment offset={} ({})",
                h.src,
                h.dst,
                frag.offset,
                ip_protocol_name(h.protocol)
            ),
            _ => format!("{} → {} {}", h.src, h.dst, ip_protocol_name(h.protocol)),
        },
        Network::Arp(arp) => arp_info(arp),
        Network::Other { ethertype } => match link {
            Link::Ethernet { src, dst, .. } => {
                format!("{src} → {dst} {}", ethertype_name(*ethertype))
            }
            _ => ethertype_name(*ethertype),
        },
    }
}

/// Used when decoding stopped at the link layer.
fn describe_link(link: &Link, has_error: bool) -> String {
    match link {
        Link::Ethernet {
            src,
            dst,
            ethertype,
            ..
        } if *ethertype < 0x0600 => {
            format!("{src} → {dst} 802.3 LLC")
        }
        Link::Ethernet {
            src,
            dst,
            ethertype,
            ..
        } => {
            format!("{src} → {dst} {}", ethertype_name(*ethertype))
        }
        Link::Unsupported(lt) if !has_error => format!("link type {lt} (not decoded)"),
        _ => String::new(),
    }
}

fn arp_info(arp: &Arp) -> String {
    match (arp.operation, arp.sender_ip, arp.target_ip, arp.sender_mac) {
        (1, Some(sender), Some(target), _) if sender.is_unspecified() => {
            format!("ARP probe for {target}")
        }
        (1, Some(sender), Some(target), _) if sender == target => {
            format!("ARP announcement for {target}")
        }
        (1, Some(sender), Some(target), _) => format!("ARP who has {target}? tell {sender}"),
        (2, Some(sender), _, Some(mac)) => format!("ARP {sender} is at {mac}"),
        (op, ..) => format!("ARP operation {op}"),
    }
}

fn icmp_info(icmp: &Icmp) -> String {
    let text = if icmp.v6 {
        match (icmp.icmp_type, icmp.code) {
            (1, 1) => "destination unreachable (administratively prohibited)",
            (1, 3) => "destination unreachable (address unreachable)",
            (1, 4) => "destination unreachable (port unreachable)",
            (1, _) => "destination unreachable",
            (2, _) => "packet too big",
            (3, _) => "hop limit exceeded",
            (128, _) => "echo request",
            (129, _) => "echo reply",
            (133, _) => "router solicitation",
            (134, _) => "router advertisement",
            (135, _) => "neighbor solicitation",
            (136, _) => "neighbor advertisement",
            (137, _) => "redirect",
            (143, _) => "multicast listener report v2",
            (t, c) => return format!("type {t} code {c}"),
        }
    } else {
        match (icmp.icmp_type, icmp.code) {
            (0, _) => "echo reply",
            (3, 0) => "destination unreachable (network unreachable)",
            (3, 1) => "destination unreachable (host unreachable)",
            (3, 3) => "destination unreachable (port unreachable)",
            (3, 4) => "destination unreachable (fragmentation needed)",
            (3, 9 | 10 | 13) => "destination unreachable (administratively prohibited)",
            (3, _) => "destination unreachable",
            (5, _) => "redirect",
            (8, _) => "echo request",
            (11, 0) => "time exceeded (TTL expired in transit)",
            (11, _) => "time exceeded (fragment reassembly)",
            (t, c) => return format!("type {t} code {c}"),
        }
    };
    text.to_string()
}

fn ip_protocol_name(protocol: u8) -> String {
    let name = match protocol {
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        89 => "OSPF",
        103 => "PIM",
        112 => "VRRP",
        132 => "SCTP",
        p => return format!("IP protocol {p}"),
    };
    name.to_string()
}

fn ethertype_name(ethertype: u16) -> String {
    let name = match ethertype {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x86dd => "IPv6",
        0x8035 => "RARP",
        0x8847 | 0x8848 => "MPLS",
        0x8863 => "PPPoE discovery",
        0x8864 => "PPPoE session",
        0x888e => "EAPOL (802.1X)",
        0x88cc => "LLDP",
        0x88e5 => "MACsec",
        t => return format!("EtherType {t:#06x}"),
    };
    name.to_string()
}
