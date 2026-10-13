use std::io::{self, BufWriter, Write};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};

use pcapdoctor::analyze::Analyzer;
use pcapdoctor::capture::{Capture, CaptureError, Frame};
use pcapdoctor::report::{html, json, text};
use pcapdoctor::stats::{self, Stats};
use pcapdoctor::{decode, diagnose, summary};

/// Findings shown in text output unless `--all` is given.
const TEXT_FINDINGS: usize = 30;

#[derive(Parser)]
#[command(
    version,
    about = "Reads a packet capture and tells you what went wrong",
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    report: ReportArgs,
}

/// `pcapdoctor FILE`: the diagnosis report.
#[derive(Args)]
struct ReportArgs {
    /// Capture file (.pcap or .pcapng)
    #[arg(required = true)]
    file: Option<PathBuf>,
    /// Output format
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
    /// Write the report to this file instead of the terminal
    #[arg(short, long, value_name = "PATH")]
    output: Option<PathBuf>,
    /// Show every finding; text output stops after 30 otherwise
    #[arg(short, long)]
    all: bool,
    /// When to color text output
    #[arg(long, value_enum, default_value_t = ColorWhen::Auto)]
    color: ColorWhen,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    Text,
    Json,
    Html,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ColorWhen {
    /// When writing to a terminal, unless NO_COLOR is set
    Auto,
    Always,
    Never,
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
    /// Summarize the capture: protocols, hosts, conversations, TCP and DNS problems
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
        Some(Command::Dump {
            file,
            count,
            absolute,
        }) => dump(&file, count, absolute),
        Some(Command::Stats { file, top }) => stats(&file, top),
        None => report(cli.report),
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
    let mut analyzer = Analyzer::new();
    let mut first_ts = None;
    let end = read_frames(path, |frame| {
        if count.is_some_and(|c| frame.number > c) {
            return Ok(ControlFlow::Break(()));
        }
        let start = *first_ts.get_or_insert(frame.ts);
        let pkt = decode::decode(&frame);
        let found = analyzer.observe(&frame, &pkt);
        let seq_base = match &found.flow {
            Some(o) if !absolute => analyzer.flows.seq_base(o.flow),
            _ => None,
        };
        let text = summary::describe_with(&pkt, &found, seq_base);
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
    let mut analyzer = Analyzer::new();
    let end = read_frames(path, |frame| {
        let pkt = decode::decode(&frame);
        analyzer.observe(&frame, &pkt);
        stats.add(&frame, &pkt);
        Ok(ControlFlow::Continue(()))
    })?;
    let report = stats::render(&stats, &analyzer, top);
    ignore_broken_pipe(io::stdout().lock().write_all(report.as_bytes()))?;
    end.warn(path);
    Ok(())
}

fn report(args: ReportArgs) -> Result<()> {
    let path = args.file.expect("clap requires a file");
    let mut stats = Stats::default();
    let mut analyzer = Analyzer::new();
    let end = read_frames(&path, |frame| {
        let pkt = decode::decode(&frame);
        analyzer.observe(&frame, &pkt);
        stats.add(&frame, &pkt);
        Ok(ControlFlow::Continue(()))
    })?;
    let cut_off = match end {
        End::CutOff { frames } => Some(frames),
        End::Complete => None,
    };
    let diagnosis = diagnose::diagnose(&stats, &analyzer, cut_off);
    let name = path.display().to_string();
    let body = match args.format {
        Format::Text => text::render(&name, &diagnosis, (!args.all).then_some(TEXT_FINDINGS)),
        Format::Json => json::render(&name, &diagnosis),
        Format::Html => html::render(&name, &diagnosis),
    };
    if let Some(output) = &args.output {
        let body = match args.format {
            Format::Text => anstream::adapter::strip_str(&body).to_string(),
            Format::Json | Format::Html => body,
        };
        return std::fs::write(output, body)
            .with_context(|| format!("cannot write {}", output.display()));
    }
    let choice = match (args.format, args.color) {
        (Format::Text, ColorWhen::Auto) => anstream::ColorChoice::Auto,
        (Format::Text, ColorWhen::Always) => anstream::ColorChoice::Always,
        _ => anstream::ColorChoice::Never,
    };
    let mut out = anstream::AutoStream::new(io::stdout().lock(), choice);
    ignore_broken_pipe(out.write_all(body.as_bytes()).and_then(|()| out.flush()))
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
