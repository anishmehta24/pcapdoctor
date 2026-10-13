//! Human-readable names for protocol numbers.

pub fn ip_protocol(protocol: u8) -> String {
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

pub fn ethertype(ethertype: u16) -> String {
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
        t if t < 0x0600 => "802.3 LLC",
        t => return format!("EtherType {t:#06x}"),
    };
    name.to_string()
}
