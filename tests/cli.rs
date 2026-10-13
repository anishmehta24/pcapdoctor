mod common;

use std::path::PathBuf;
use std::process::{Command, Output};

use common::*;

/// Writes `bytes` to a temp file named after the test and runs the binary on it.
fn run(name: &str, bytes: &[u8], args: &[&str]) -> Output {
    let path: PathBuf =
        std::env::temp_dir().join(format!("pcapdoctor-{}-{name}.pcap", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pcapdoctor"))
        .args(args)
        .arg(&path)
        .output()
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    output
}

fn handshake() -> Pcap {
    let (client, server) = ([10, 0, 0, 1], [10, 0, 0, 2]);
    let mut pcap = Pcap::new(LINKTYPE_ETHERNET);
    pcap.packet(
        0,
        &ethernet(
            0x0800,
            &ipv4(client, server, 6, &tcp(50000, 80, 100, 0, SYN, &[])),
        ),
    )
    .packet(
        1_500,
        &ethernet(
            0x0800,
            &ipv4(server, client, 6, &tcp(80, 50000, 900, 101, SYN | ACK, &[])),
        ),
    )
    .packet(
        1_900,
        &ethernet(
            0x0800,
            &ipv4(client, server, 6, &tcp(50000, 80, 101, 901, ACK, &[])),
        ),
    );
    pcap
}

#[test]
fn dump_prints_one_line_per_packet() {
    let out = run("dump", &handshake().bytes(), &["dump"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(
        lines[1],
        "     2    0.001500  10.0.0.2:80 → 10.0.0.1:50000 TCP [SYN, ACK] seq=900 ack=101 win=64240 len=0"
    );
}

#[test]
fn dump_count_limits_output() {
    let out = run("count", &handshake().bytes(), &["dump", "-c", "2"]);
    assert_eq!(String::from_utf8(out.stdout).unwrap().lines().count(), 2);
}

#[test]
fn cut_off_capture_warns_and_succeeds() {
    let bytes = handshake().bytes();
    let out = run("cutoff", &bytes[..bytes.len() - 10], &["dump"]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap().lines().count(), 2);
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("ends in the middle of packet 3"),
        "{stderr}"
    );
}

#[test]
fn non_capture_file_exits_with_2() {
    let out = run("garbage", b"definitely not a capture", &["dump"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("not a pcap or pcapng file"), "{stderr}");
}
