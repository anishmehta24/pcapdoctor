use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use pcapdoctor::capture::{Capture, CaptureError};
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
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Dump { file, count } => dump(&file, count),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn dump(path: &Path, count: Option<u64>) -> Result<()> {
    let mut capture =
        Capture::open(path).with_context(|| format!("cannot read {}", path.display()))?;
    let mut out = BufWriter::new(io::stdout().lock());
    let mut first_ts = None;
    loop {
        if count.is_some_and(|c| capture.frames_read() >= c) {
            break;
        }
        let frame = match capture.next_frame() {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(CaptureError::Truncated) => {
                ignore_broken_pipe(out.flush())?;
                eprintln!(
                    "warning: {} ends in the middle of packet {}; it was probably cut off while capturing",
                    path.display(),
                    capture.frames_read() + 1
                );
                return Ok(());
            }
            Err(e) => {
                ignore_broken_pipe(out.flush())?;
                return Err(e).with_context(|| format!("after packet {}", capture.frames_read()));
            }
        };
        let start = *first_ts.get_or_insert(frame.ts);
        let pkt = decode::decode(&frame);
        let line = writeln!(
            out,
            "{:>6} {:>11.6}  {}",
            frame.number,
            frame.ts.secs_since(start),
            summary::describe(&pkt)
        );
        if is_broken_pipe(&line) {
            return Ok(());
        }
        line?;
    }
    ignore_broken_pipe(out.flush())
}

/// `pcapdoctor dump big.pcap | head` closes our stdout early; that's not an error.
fn is_broken_pipe(result: &io::Result<()>) -> bool {
    matches!(result, Err(e) if e.kind() == io::ErrorKind::BrokenPipe)
}

fn ignore_broken_pipe(result: io::Result<()>) -> Result<()> {
    if is_broken_pipe(&result) {
        return Ok(());
    }
    Ok(result?)
}
