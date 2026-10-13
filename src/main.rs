use std::io::{self, BufWriter, Write};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use pcapdoctor::capture::{Capture, CaptureError, Frame};
use pcapdoctor::flow::FlowTable;
use pcapdoctor::stats::{self, Stats};
use pcapdoctor::{decode, summary};

#[derive(Parser)]
#[command(
    version,
    about = "Reads a packet capture and tells you what went wrong"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print one line per packet, like tcpdump
    Dump {
        /// Capture file (.pcap or .pcapng)
        file: PathBuf,
        /// Stop after this many packets
        #[arg(short = 'c', long)]
        count: Option<u64>,
        /// Show raw TCP sequence numbers instead of counting from the start
        /// of each connection
        #[arg(short = 'S', long)]
        absolute: bool,
    },
    /// Summarize the capture: protocols, busiest hosts, conversations
    Stats {
        /// Capture file (.pcap or .pcapng)
        file: PathBuf,
        /// Rows to show in the host and conversation tables
        #[arg(short = 'n', long, default_value_t = 10)]
        top: usize,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Dump {
            file,
            count,
            absolute,
        } => dump(&file, count, absolute),
        Command::Stats { file, top } => stats(&file, top),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn dump(path: &Path, count: Option<u64>, absolute: bool) -> Result<()> {
    let mut out = BufWriter::new(io::stdout().lock());
    let mut flows = FlowTable::new();
    let mut first_ts = None;
    let end = read_frames(path, |frame| {
        if count.is_some_and(|c| frame.number > c) {
            return Ok(ControlFlow::Break(()));
        }
        let start = *first_ts.get_or_insert(frame.ts);
        let pkt = decode::decode(&frame);
        let observed = flows.observe(&frame, &pkt);
        let seq_base = match &observed {
            Some(o) if !absolute => flows.seq_base(o.flow),
            _ => None,
        };
        let mut text = summary::describe(&pkt, seq_base);
        for event in observed.iter().flat_map(|o| &o.tcp_events) {
            text.push_str(&format!(" [{event}]"));
        }
        let line = writeln!(
            out,
            "{:>6} {:>11.6}  {}",
            frame.number,
            frame.ts.secs_since(start),
            text
        );
        if is_broken_pipe(&line) {
            return Ok(ControlFlow::Break(()));
        }
        line?;
        Ok(ControlFlow::Continue(()))
    })?;
    ignore_broken_pipe(out.flush())?;
    end.warn(path);
    Ok(())
}

fn stats(path: &Path, top: usize) -> Result<()> {
    let mut stats = Stats::default();
    let mut flows = FlowTable::new();
    let end = read_frames(path, |frame| {
        let pkt = decode::decode(&frame);
        flows.observe(&frame, &pkt);
        stats.add(&frame, &pkt);
        Ok(ControlFlow::Continue(()))
    })?;
    let report = stats::render(&stats, &flows, top);
    ignore_broken_pipe(io::stdout().lock().write_all(report.as_bytes()))?;
    end.warn(path);
    Ok(())
}

/// How reading a capture ended.
enum End {
    Complete,
    /// The file stops partway through a packet; `frames` were read before that.
    CutOff {
        frames: u64,
    },
}

impl End {
    fn warn(&self, path: &Path) {
        if let End::CutOff { frames } = self {
            eprintln!(
                "warning: {} ends in the middle of packet {}; it was probably cut off while capturing",
                path.display(),
                frames + 1
            );
        }
    }
}

/// Calls `each` for every packet in the file until it returns `Break`. A file
/// that was cut off mid-packet is not an error: everything before the cut is
/// still worth reading.
fn read_frames(path: &Path, mut each: impl FnMut(Frame) -> Result<ControlFlow<()>>) -> Result<End> {
    let mut capture =
        Capture::open(path).with_context(|| format!("cannot read {}", path.display()))?;
    loop {
        match capture.next_frame() {
            Ok(Some(frame)) => {
                if each(frame)?.is_break() {
                    return Ok(End::Complete);
                }
            }
            Ok(None) => return Ok(End::Complete),
            Err(CaptureError::Truncated) => {
                return Ok(End::CutOff {
                    frames: capture.frames_read(),
                });
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "{} is unreadable after packet {}",
                        path.display(),
                        capture.frames_read()
                    )
                });
            }
        }
    }
}

/// `pcapdoctor dump big.pcap | head` closes stdout early; that's not an error.
fn is_broken_pipe(result: &io::Result<()>) -> bool {
    matches!(result, Err(e) if e.kind() == io::ErrorKind::BrokenPipe)
}

fn ignore_broken_pipe(result: io::Result<()>) -> Result<()> {
    if is_broken_pipe(&result) {
        return Ok(());
    }
    Ok(result?)
}
