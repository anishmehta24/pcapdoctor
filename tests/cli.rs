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
        "     2    0.001500  10.0.0.2:80 → 10.0.0.1:50000 TCP [SYN, ACK] seq=0 ack=1 win=64240 len=0"
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

#[test]
fn absolute_flag_shows_raw_sequence_numbers() {
    let out = run("absolute", &handshake().bytes(), &["dump", "-S"]);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("[SYN, ACK] seq=900 ack=101 "), "{stdout}");
}

#[test]
fn report_is_the_default_command() {
    let out = run("report", &handshake().bytes(), &["--color", "always"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        lines[0].contains(": 3 packets over 1.9 ms, from 1970-01-01"),
        "{stdout}"
    );
    assert_eq!(
        lines[2],
        "\u{1b}[32m✓\u{1b}[0m No problems found in 1 connection"
    );
}

#[test]
fn report_formats_and_output_file() {
    let json = run("json", &handshake().bytes(), &["--format", "json"]);
    let stdout = String::from_utf8(json.stdout).unwrap();
    assert!(stdout.starts_with("{\n  \"schema\": 1,"), "{stdout}");
    assert!(!stdout.contains('\u{1b}'));

    let path = std::env::temp_dir().join(format!("pcapdoctor-{}-report.html", std::process::id()));
    let html = run(
        "html",
        &handshake().bytes(),
        &["--format", "html", "-o", path.to_str().unwrap()],
    );
    assert!(html.status.success());
    assert!(html.stdout.is_empty());
    let written = std::fs::read_to_string(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(written.starts_with("<!doctype html>"), "{written}");
}

#[test]
fn report_of_a_cut_off_capture() {
    let bytes = handshake().bytes();
    let out = run(
        "report-cutoff",
        &bytes[..bytes.len() - 10],
        &["--color", "never"],
    );
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains(
            "⚠ FILE  the file ends in the middle of packet 3; it was probably cut off while capturing"
        ),
        "{stdout}"
    );
}

#[test]
fn one_direction_only() {
    // The client's side of a connection, without the server's.
    let (client, server) = ([10, 0, 0, 1], [10, 0, 0, 2]);
    let mut pcap = Pcap::new(LINKTYPE_ETHERNET);
    for (i, (flags, payload)) in [(ACK, &b""[..]), (PSH | ACK, &b"GET / HTTP/1.1\r\n\r\n"[..])]
        .into_iter()
        .enumerate()
    {
        // An empty ACK doesn't use up a sequence number.
        pcap.packet(
            i as u64 * 1000,
            &ethernet(
                0x0800,
                &ipv4(client, server, 6, &tcp(50000, 80, 101, 901, flags, payload)),
            ),
        );
    }
    let out = run("one-sided", &pcap.bytes(), &["--color", "never"]);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("⚠ FILE  only one direction of 1 connection was captured"),
        "{stdout}"
    );
    assert!(!stdout.contains("no response"), "{stdout}");
}

#[test]
fn no_file_is_a_usage_error() {
    let out = Command::new(env!("CARGO_BIN_EXE_pcapdoctor"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn stats_lists_conversations() {
    let out = run("stats", &handshake().bytes(), &["stats"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("TCP conversations: 1\n"), "{stdout}");
    let row = stdout
        .lines()
        .find(|l| l.contains("10.0.0.1:50000"))
        .unwrap();
    assert!(
        row.contains("10.0.0.2:80") && row.ends_with("open"),
        "{row}"
    );
}
