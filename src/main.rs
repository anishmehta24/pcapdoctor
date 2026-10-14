use std::fs::File;
use std::io::{self, BufWriter, IsTerminal, Write};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};

use pcapdoctor::analyze::{Analyzer, PacketFindings};
use pcapdoctor::capture::{Capture, CaptureError, Frame, InterfaceInfo, PcapNgWriter, Timestamp};
use pcapdoctor::decode::Packet;
use pcapdoctor::diagnose::{CaptureInfo, Diagnosis, Finding, Severity};
use pcapdoctor::filter::{self, Filter, PacketView, Target, Tracker, Whole};
use pcapdoctor::live::{self, Live};
use pcapdoctor::report::{html, json, text};
use pcapdoctor::stats::{self, Stats};
use pcapdoctor::{decode, diagnose, summary, units};

/// Findings shown in text output unless `--all` is given.
const TEXT_FINDINGS: usize = 30;
/// Matching packets `check` prints per filter.
const CHECK_PACKETS: usize = 10;
/// What `check` fails on when no `--fail-on` is given.
const DEFAULT_FAIL_ON: &str = "finding.severity == error";
/// Bytes kept from each packet in a live capture: all of it, as tcpdump does.
const SNAPLEN: u32 = 262_144;

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
    #[command(flatten)]
    output: OutputArgs,
}

/// How to show a report.
#[derive(Args)]
struct OutputArgs {
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

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CheckFormat {
    Text,
    /// Text, plus annotations for GitHub Actions
    Github,
}

#[derive(Subcommand)]
enum Command {
    /// Print one line per packet, like tcpdump
    Dump {
        /// Capture file (.pcap or .pcapng)
        file: PathBuf,
        /// Only packets that match this filter, in Wireshark's syntax:
        /// "tcp.port == 443 && !tcp.analysis.flags"
        #[arg(short = 'f', long, value_name = "FILTER")]
        filter: Option<String>,
        /// Stop after printing this many packets
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
    /// For CI: exit with status 1 when a capture has problems
    Check {
        /// Capture files (.pcap or .pcapng)
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Fail when a finding or packet matches this filter; give it more
        /// than once to check several things [default: "finding.severity ==
        /// error"]
        #[arg(long, value_name = "FILTER")]
        fail_on: Vec<String>,
        /// Output format
        #[arg(long, value_enum, default_value_t = CheckFormat::Text)]
        format: CheckFormat,
        /// When to color text output
        #[arg(long, value_enum, default_value_t = ColorWhen::Auto)]
        color: ColorWhen,
    },
    /// List the fields filters can use
    Fields,
    /// Capture from a network interface, then diagnose what was captured
    Live(LiveArgs),
    /// List the interfaces live can capture on
    Interfaces,
}

#[derive(Args)]
struct LiveArgs {
    /// Interface: its name, its number in `pcapdoctor interfaces`, one of its
    /// addresses, or its description [default: the one with the route to
    /// the internet]
    #[arg(short, long, value_name = "IFACE")]
    interface: Option<String>,
    /// Stop after this long, such as 30s, 5m or 1h [default: at Ctrl-C]
    #[arg(short, long, value_name = "TIME", value_parser = duration_arg)]
    duration: Option<Duration>,
    /// Stop after this many packets
    #[arg(short = 'c', long)]
    count: Option<u64>,
    /// Also save the packets to this file (pcapng), to open in Wireshark
    #[arg(short, long, value_name = "PATH")]
    write: Option<PathBuf>,
    /// Capture only packets that match this filter, in tcpdump's syntax:
    /// "port 443", "host 10.0.0.5"
    #[arg(long, value_name = "BPF")]
    capture_filter: Option<String>,
    /// Also capture traffic between other machines, where the network
    /// shows it
    #[arg(long)]
    promisc: bool,
    #[command(flatten)]
    output: OutputArgs,
}

fn duration_arg(s: &str) -> Result<Duration, String> {
    units::parse_duration(s).ok_or_else(|| "expected a time such as 30s, 5m or 1h".to_string())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Some(Command::Dump {
            file,
            filter,
            count,
            absolute,
        }) => dump(&file, filter.as_deref(), count, absolute).map(|()| true),
        Some(Command::Stats { file, top }) => stats(&file, top).map(|()| true),
        Some(Command::Check {
            files,
            fail_on,
            format,
            color,
        }) => check(&files, &fail_on, format, color),
        Some(Command::Fields) => fields().map(|()| true),
        Some(Command::Live(args)) => live(args).map(|()| true),
        Some(Command::Interfaces) => interfaces().map(|()| true),
        None => report(cli.report).map(|()| true),
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

/// The error shows the filter with a mark under the problem.
fn parse_filter(text: &str) -> Result<Filter> {
    Ok(Filter::parse(text)?)
}

fn dump(path: &Path, filter: Option<&str>, count: Option<u64>, absolute: bool) -> Result<()> {
    let filter = filter.map(parse_filter).transpose()?;
    if filter
        .as_ref()
        .is_some_and(|f| f.target() == Target::Findings)
    {
        bail!("dump -f takes a packet filter; finding.* fields are for check --fail-on");
    }
    let whole = match &filter {
        Some(f) if f.needs_whole_capture() => Some(first_pass(path)?),
        _ => None,
    };
    let mut out = BufWriter::new(io::stdout().lock());
    let mut analyzer = Analyzer::new();
    let mut tracker = Tracker::new(whole);
    let mut first_ts = None;
    let mut printed = 0;
    let end = read_frames(path, |frame| {
        if count.is_some_and(|c| printed >= c) {
            return Ok(ControlFlow::Break(()));
        }
        let start = *first_ts.get_or_insert(frame.ts);
        let pkt = decode::decode(&frame);
        let found = analyzer.observe(&frame, &pkt);
        tracker.observe(&frame, &found);
        if let Some(filter) = &filter
            && !filter.matches(&PacketView::new(&frame, &pkt, &found, &analyzer, &tracker))
        {
            return Ok(ControlFlow::Continue(()));
        }
        let line = writeln!(
            out,
            "{}",
            dump_line(&frame, &pkt, &found, &analyzer, start, absolute)
        );
        if is_broken_pipe(&line) {
            return Ok(ControlFlow::Break(()));
        }
        line?;
        printed += 1;
        Ok(ControlFlow::Continue(()))
    })?;
    ignore_broken_pipe(out.flush())?;
    end.warn(path);
    Ok(())
}

fn dump_line(
    frame: &Frame,
    pkt: &Packet<'_>,
    found: &PacketFindings,
    analyzer: &Analyzer,
    start: Timestamp,
    absolute: bool,
) -> String {
    let seq_base = match &found.flow {
        Some(o) if !absolute => analyzer.flows.seq_base(o.flow),
        _ => None,
    };
    format!(
        "{:>6} {:>11.6}  {}",
        frame.number,
        frame.ts.secs_since(start),
        summary::describe_with(pkt, found, seq_base)
    )
}

/// Reads the whole capture once, for filters that need to know what comes
/// later in it.
fn first_pass(path: &Path) -> Result<Whole> {
    let mut analyzer = Analyzer::new();
    let mut whole = Whole::default();
    read_frames(path, |frame| {
        let pkt = decode::decode(&frame);
        let found = analyzer.observe(&frame, &pkt);
        whole.observe(&frame, &pkt, &found);
        Ok(ControlFlow::Continue(()))
    })?;
    whole.finish(&analyzer);
    Ok(whole)
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

/// Reads a capture and diagnoses it.
fn diagnose_file(path: &Path) -> Result<Diagnosis> {
    let mut stats = Stats::default();
    let mut analyzer = Analyzer::new();
    let end = read_frames(path, |frame| {
        let pkt = decode::decode(&frame);
        analyzer.observe(&frame, &pkt);
        stats.add(&frame, &pkt);
        Ok(ControlFlow::Continue(()))
    })?;
    let cut_off_after = match end {
        End::CutOff { frames } => Some(frames),
        End::Complete => None,
    };
    let info = CaptureInfo {
        cut_off_after,
        dropped: None,
    };
    Ok(diagnose::diagnose(&stats, &analyzer, info))
}

fn report(args: ReportArgs) -> Result<()> {
    let path = args.file.expect("clap requires a file");
    let diagnosis = diagnose_file(&path)?;
    show_report(&path.display().to_string(), &diagnosis, &args.output)
}

fn show_report(name: &str, diagnosis: &Diagnosis, args: &OutputArgs) -> Result<()> {
    let body = match args.format {
        Format::Text => text::render(name, diagnosis, (!args.all).then_some(TEXT_FINDINGS)),
        Format::Json => json::render(name, diagnosis),
        Format::Html => html::render(name, diagnosis),
    };
    if let Some(output) = &args.output {
        let body = match args.format {
            Format::Text => anstream::adapter::strip_str(&body).to_string(),
            Format::Json | Format::Html => body,
        };
        return std::fs::write(output, body)
            .with_context(|| format!("cannot write {}", output.display()));
    }
    let color = match args.format {
        Format::Text => args.color,
        Format::Json | Format::Html => ColorWhen::Never,
    };
    write_out(&body, color)
}

fn write_out(body: &str, color: ColorWhen) -> Result<()> {
    let choice = match color {
        ColorWhen::Auto => anstream::ColorChoice::Auto,
        ColorWhen::Always => anstream::ColorChoice::Always,
        ColorWhen::Never => anstream::ColorChoice::Never,
    };
    let mut out = anstream::AutoStream::new(io::stdout().lock(), choice);
    ignore_broken_pipe(out.write_all(body.as_bytes()).and_then(|()| out.flush()))
}

/// What one `--fail-on` filter matched in one capture.
enum Matched<'a> {
    Findings(Vec<&'a Finding>),
    Packets { count: u64, lines: Vec<String> },
}

impl Matched<'_> {
    fn count(&self) -> u64 {
        match self {
            Matched::Findings(f) => f.len() as u64,
            Matched::Packets { count, .. } => *count,
        }
    }
}

/// Returns whether every capture passed.
fn check(
    files: &[PathBuf],
    fail_on: &[String],
    format: CheckFormat,
    color: ColorWhen,
) -> Result<bool> {
    let texts = if fail_on.is_empty() {
        vec![DEFAULT_FAIL_ON.to_string()]
    } else {
        fail_on.to_vec()
    };
    let filters: Vec<Filter> = texts
        .iter()
        .map(|t| parse_filter(t))
        .collect::<Result<_>>()?;
    let mut out = String::new();
    let mut annotations = String::new();
    let mut passed = true;
    let findings_wanted = filters.iter().any(|f| f.target() == Target::Findings);
    for path in files {
        let diagnosis = findings_wanted.then(|| diagnose_file(path)).transpose()?;
        let packets = match_packets(path, &filters)?;
        let name = path.display().to_string();
        for (filter, packets) in filters.iter().zip(packets) {
            let matched = match (packets, &diagnosis) {
                (Some(packets), _) => packets,
                (None, Some(diagnosis)) => Matched::Findings(
                    diagnosis
                        .findings
                        .iter()
                        .filter(|f| filter.matches(*f))
                        .collect(),
                ),
                (None, None) => unreachable!("finding filters come with a diagnosis"),
            };
            if matched.count() > 0 {
                passed = false;
            }
            check_text(&mut out, &name, filter, &matched);
            if format == CheckFormat::Github {
                github_annotations(&mut annotations, &name, filter, &matched);
            }
        }
    }
    out.push_str(&annotations);
    write_out(&out, color)?;
    Ok(passed)
}

/// Runs the packet filters over a capture. Returns what each matched, or
/// `None` for the finding filters.
fn match_packets(path: &Path, filters: &[Filter]) -> Result<Vec<Option<Matched<'static>>>> {
    let mut matched: Vec<Option<Matched>> = filters
        .iter()
        .map(|f| {
            (f.target() == Target::Packets).then(|| Matched::Packets {
                count: 0,
                lines: Vec::new(),
            })
        })
        .collect();
    if matched.iter().all(Option::is_none) {
        return Ok(matched);
    }
    let whole = match filters.iter().any(Filter::needs_whole_capture) {
        true => Some(first_pass(path)?),
        false => None,
    };
    let mut analyzer = Analyzer::new();
    let mut tracker = Tracker::new(whole);
    let mut first_ts = None;
    read_frames(path, |frame| {
        let start = *first_ts.get_or_insert(frame.ts);
        let pkt = decode::decode(&frame);
        let found = analyzer.observe(&frame, &pkt);
        tracker.observe(&frame, &found);
        let view = PacketView::new(&frame, &pkt, &found, &analyzer, &tracker);
        for (filter, matched) in filters.iter().zip(&mut matched) {
            if let Some(Matched::Packets { count, lines }) = matched
                && filter.matches(&view)
            {
                *count += 1;
                if lines.len() < CHECK_PACKETS {
                    lines.push(dump_line(&frame, &pkt, &found, &analyzer, start, false));
                }
            }
        }
        Ok(ControlFlow::Continue(()))
    })?;
    Ok(matched)
}

fn check_text(out: &mut String, file: &str, filter: &Filter, matched: &Matched<'_>) {
    use std::fmt::Write as _;
    let n = matched.count();
    if n == 0 {
        let _ = writeln!(out, "{file}: nothing matches {filter}");
        return;
    }
    let what = match matched {
        Matched::Findings(_) => text::plural(n, "finding", "findings"),
        Matched::Packets { .. } => text::plural(n, "packet", "packets"),
    };
    let verb = if n == 1 { "matches" } else { "match" };
    let _ = writeln!(out, "{file}: {what} {verb} {filter}");
    match matched {
        Matched::Findings(findings) => out.push_str(&text::findings(findings.iter().copied())),
        Matched::Packets { lines, .. } => {
            for line in lines {
                let _ = writeln!(out, "{line}");
            }
            let more = n - lines.len() as u64;
            if more > 0 {
                let _ = writeln!(
                    out,
                    "… {more} more; pcapdoctor dump {file} -f '{filter}' shows them"
                );
            }
        }
    }
}

/// Workflow commands that make GitHub show each match as an annotation.
fn github_annotations(out: &mut String, file: &str, filter: &Filter, matched: &Matched<'_>) {
    use std::fmt::Write as _;
    match matched {
        Matched::Findings(findings) => {
            for f in findings {
                let level = match f.severity {
                    Severity::Error => "error",
                    Severity::Warning => "warning",
                    Severity::Info => "notice",
                };
                let mut message = f.text.clone();
                if !f.frames.is_empty() {
                    message = format!("{message} ({})", f.frames_text(4));
                }
                if let Some(hint) = &f.hint {
                    message = format!("{message}\n{hint}");
                }
                let title = match f.subject.as_str() {
                    "" => format!("{} in {file}", f.category.name()),
                    subject => format!("{} {subject}", f.category.name()),
                };
                let _ = writeln!(
                    out,
                    "::{level} file={},title={}::{}",
                    escape_property(file),
                    escape_property(&title),
                    escape_data(&message)
                );
            }
        }
        Matched::Packets { count: 0, .. } => {}
        Matched::Packets { count, lines } => {
            let first = lines.first().map(|l| l.trim_start()).unwrap_or_default();
            let message = format!(
                "{} {} {filter}, first: {first}",
                text::plural(*count, "packet", "packets"),
                if *count == 1 { "matches" } else { "match" },
            );
            let _ = writeln!(
                out,
                "::error file={},title=pcapdoctor check::{}",
                escape_property(file),
                escape_data(&message)
            );
        }
    }
}

fn escape_data(s: &str) -> String {
    s.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

fn escape_property(s: &str) -> String {
    escape_data(s).replace(':', "%3A").replace(',', "%2C")
}

fn fields() -> Result<()> {
    use std::fmt::Write as _;
    let mut out = String::from(
        "Fields for dump -f and check --fail-on. They have Wireshark's names and\n\
         meanings, so a filter works the same in both.\n\n",
    );
    let rows: Vec<_> = filter::all_fields().collect();
    let width = rows.iter().map(|(name, ..)| name.len()).max().unwrap_or(0);
    for (name, kind, help) in rows {
        if name == "finding.severity" {
            out.push_str("\nFields of findings, for check --fail-on:\n");
        }
        let _ = writeln!(out, "{name:<width$}  {:<15}  {help}", kind.describe());
    }
    ignore_broken_pipe(io::stdout().lock().write_all(out.as_bytes()))
}

/// Captures until the time or count runs out or Ctrl-C, analyzing as the
/// packets come, then prints the report.
fn live(args: LiveArgs) -> Result<()> {
    let list = live::interfaces()?;
    let chosen = match &args.interface {
        Some(wanted) => live::find(&list, wanted),
        None => Some(live::default_interface(&list).context(
            "no interface is up with an address; pcapdoctor interfaces lists them, and -i picks one",
        )?),
    };
    // A name libpcap knows but doesn't list, such as a VLAN device, is
    // still worth trying.
    let (device, label, description) = match chosen {
        Some(i) => (
            list[i].name.as_str(),
            list[i].label(),
            list[i].description.as_deref(),
        ),
        None => {
            let wanted = args
                .interface
                .as_deref()
                .expect("only a named interface is missing");
            (wanted, wanted, None)
        }
    };
    let options = live::Options {
        snaplen: SNAPLEN,
        promisc: args.promisc,
        filter: args.capture_filter.as_deref(),
    };
    let (mut capture, warning) = Live::open(device, &options)?;
    if let Some(warning) = warning {
        eprintln!("warning: {warning}");
    }
    let mut file = match &args.write {
        Some(path) => {
            let out =
                File::create(path).with_context(|| format!("cannot create {}", path.display()))?;
            let interface = InterfaceInfo {
                link_type: capture.link_type(),
                snaplen: SNAPLEN,
                name: device,
                description,
            };
            Some(PcapNgWriter::new(BufWriter::new(out), &interface)?)
        }
        None => None,
    };

    // The first Ctrl-C (or kill) ends the capture and shows the report; a
    // second one gives up on it. A signal sent to sudo and to us both
    // arrives twice at once, so the second must come a moment later.
    let stop = Arc::new(AtomicBool::new(false));
    let handler_stop = Arc::clone(&stop);
    let mut stopped_at = None;
    ctrlc::set_handler(move || match stopped_at {
        None => {
            stopped_at = Some(Instant::now());
            handler_stop.store(true, Ordering::SeqCst);
        }
        Some(at) if at.elapsed() > Duration::from_millis(500) => std::process::exit(130),
        Some(_) => {}
    })
    .context("cannot catch Ctrl-C")?;

    let started = Instant::now();
    let deadline = args.duration.map(|d| started + d);
    match args.duration {
        Some(d) => eprintln!(
            "Capturing on {label} for {}; Ctrl-C stops it sooner",
            plain_duration(d)
        ),
        None => eprintln!("Capturing on {label}; Ctrl-C stops it"),
    }
    let progress = io::stderr().is_terminal();
    let mut shown = started;
    let mut stats = Stats::default();
    let mut analyzer = Analyzer::new();
    let mut packets = 0u64;
    while !stop.load(Ordering::SeqCst)
        && deadline.is_none_or(|d| Instant::now() < d)
        && args.count.is_none_or(|c| packets < c)
    {
        if let Some(frame) = capture.next_frame()? {
            if let Some(file) = &mut file {
                file.write(&frame).context("cannot save the capture")?;
            }
            let pkt = decode::decode(&frame);
            analyzer.observe(&frame, &pkt);
            stats.add(&frame, &pkt);
            packets += 1;
        }
        if progress && shown.elapsed() >= Duration::from_secs(1) {
            eprint!("\r{} so far ", text::plural(packets, "packet", "packets"));
            shown = Instant::now();
        }
    }
    if progress {
        eprint!("\r{:30}\r", "");
    }
    let dropped = capture.dropped();
    drop(capture);
    if let Some(file) = &mut file {
        file.flush().context("cannot save the capture")?;
    }

    let info = CaptureInfo {
        cut_off_after: None,
        dropped,
    };
    let diagnosis = diagnose::diagnose(&stats, &analyzer, info);
    let name = match &args.write {
        Some(path) => path.display().to_string(),
        None => format!("{label} (live)"),
    };
    show_report(&name, &diagnosis, &args.output)?;
    if args.write.is_none() && !diagnosis.findings.is_empty() {
        eprintln!(
            "note: -w FILE saves the packets, so the frames above can be opened in Wireshark"
        );
    }
    Ok(())
}

/// "30 s" for whole seconds, as people type them.
fn plain_duration(d: Duration) -> String {
    match d.subsec_nanos() {
        0 => format!("{} s", d.as_secs()),
        _ => units::duration(d.as_secs_f64()),
    }
}

fn interfaces() -> Result<()> {
    use std::fmt::Write as _;
    let list = live::interfaces()?;
    let default = live::default_interface(&list);
    let mut out = format!("{}\n\n", live::library_version()?);
    for (i, iface) in list.iter().enumerate() {
        let _ = write!(out, "{:>2}. {}", i + 1, iface.name);
        if let Some(description) = &iface.description {
            let _ = write!(out, "  {description}");
        }
        if default == Some(i) {
            out.push_str("  (default)");
        }
        out.push('\n');
        let state = [
            (iface.loopback, "loopback"),
            (iface.wireless, "wireless"),
            (!iface.up, "down"),
            (iface.up && !iface.running, "not running"),
            (iface.disconnected, "disconnected"),
        ];
        let mut notes: Vec<String> = state
            .iter()
            .filter(|(on, _)| *on)
            .map(|(_, word)| word.to_string())
            .collect();
        let addresses: Vec<String> = iface.addresses.iter().map(|a| a.to_string()).collect();
        if !addresses.is_empty() {
            notes.push(addresses.join(", "));
        }
        if !notes.is_empty() {
            let _ = writeln!(out, "    {}", notes.join("; "));
        }
    }
    if list.is_empty() {
        out.push_str("No interfaces found. Listing them may need root, or administrator rights on Windows.\n");
    } else {
        out.push_str("\npcapdoctor live -i NAME or -i NUMBER captures on one; without -i it uses the default.\n");
    }
    ignore_broken_pipe(io::stdout().lock().write_all(out.as_bytes()))
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
