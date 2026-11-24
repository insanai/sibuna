//! The access log: a bounded queue and the one thread that writes (SID 0020).
//!
//! ```text
//!  request paths --offer (try_send)--> [ bounded queue ] --> writer thread --> file
//!        |                                                      |
//!        +-- full: drop, count                                  +-- reopen on SIGHUP
//! ```
//!
//! A request path never waits here. The queue holds entries, so that formatting runs on
//! the writer thread.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sibuna_lb::{AccessLogOptions, LogOutput};

use super::Entry;

/// How long the writer waits for an entry before it flushes and looks at its flags.
const IDLE: Duration = Duration::from_millis(200);
/// The longest time written lines stay in the buffer.
const FLUSH_EVERY: Duration = Duration::from_secs(1);

enum Message {
    Entry(Entry),
    /// Write what is queued and end.
    Close,
}

#[derive(Default)]
struct Counters {
    written: AtomicU64,
    dropped: AtomicU64,
    errors: AtomicU64,
    /// Reopen the file before the next line.
    reopen: AtomicBool,
}

/// The sending side of the access log. Dropping it writes what is queued.
pub(crate) struct AccessLog {
    sender: SyncSender<Message>,
    counters: Arc<Counters>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl AccessLog {
    /// Opens the destination and starts the writer thread.
    ///
    /// # Errors
    ///
    /// The error of opening the file, with its path, or of starting the thread.
    pub(crate) fn start(options: &AccessLogOptions) -> io::Result<Self> {
        let target = Target::open(&options.output)?;
        let (sender, receiver) = mpsc::sync_channel(options.queue);
        let counters = Arc::new(Counters::default());
        let writer = Writer {
            out: BufWriter::with_capacity(64 * 1024, target),
            output: options.output.clone(),
            counters: counters.clone(),
            line: Vec::with_capacity(512),
            flushed: Instant::now(),
            reported: None,
        };
        let thread = std::thread::Builder::new()
            .name("edge-access-log".into())
            .spawn(move || writer.run(&receiver))?;
        Ok(Self { sender, counters, thread: Mutex::new(Some(thread)) })
    }

    /// Offers one entry. A full queue drops it and counts the drop. Never waits.
    pub(crate) fn offer(&self, entry: Entry) {
        match self.sender.try_send(Message::Entry(entry)) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.counters.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Asks the writer to reopen a file destination before its next line.
    pub(crate) fn reopen(&self) {
        self.counters.reopen.store(true, Ordering::Release);
    }

    /// Lines written, entries dropped and write errors.
    pub(crate) fn counts(&self) -> (u64, u64, u64) {
        let counters = &self.counters;
        (
            counters.written.load(Ordering::Relaxed),
            counters.dropped.load(Ordering::Relaxed),
            counters.errors.load(Ordering::Relaxed),
        )
    }

    /// Writes what is queued and ends the writer. Later entries are dropped.
    pub(crate) fn close(&self) {
        let thread = self.thread.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let Some(thread) = thread {
            // This waits for room in the queue. Only a shutdown calls it.
            let _ = self.sender.send(Message::Close);
            let _ = thread.join();
        }
    }
}

impl Drop for AccessLog {
    fn drop(&mut self) {
        self.close();
    }
}

/// Where lines go.
enum Target {
    Stdout,
    Stderr,
    File(File),
}

impl Target {
    fn open(output: &LogOutput) -> io::Result<Self> {
        match output {
            LogOutput::Stdout => Ok(Self::Stdout),
            LogOutput::Stderr => Ok(Self::Stderr),
            LogOutput::File(path) => {
                let mut options = OpenOptions::new();
                options.append(true).create(true);
                #[cfg(unix)]
                std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o640);
                options.open(path).map(Self::File).map_err(|error| {
                    io::Error::new(error.kind(), format!("access log {path}: {error}"))
                })
            }
        }
    }
}

impl Write for Target {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Stdout => io::stdout().write(bytes),
            Self::Stderr => io::stderr().write(bytes),
            Self::File(file) => file.write(bytes),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Stdout => io::stdout().flush(),
            Self::Stderr => io::stderr().flush(),
            Self::File(file) => file.flush(),
        }
    }
}

struct Writer {
    out: BufWriter<Target>,
    output: LogOutput,
    counters: Arc<Counters>,
    /// The line being formatted, reused.
    line: Vec<u8>,
    flushed: Instant,
    /// When a write error was last reported.
    reported: Option<Instant>,
}

impl Writer {
    fn run(mut self, receiver: &Receiver<Message>) {
        loop {
            match receiver.recv_timeout(IDLE) {
                Ok(Message::Entry(entry)) => {
                    self.reopen_if_asked();
                    self.write(&entry);
                    if self.flushed.elapsed() >= FLUSH_EVERY {
                        self.flush();
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.flush();
                    self.reopen_if_asked();
                }
                Ok(Message::Close) | Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        self.flush();
    }

    fn write(&mut self, entry: &Entry) {
        self.line.clear();
        format_json(entry, &mut self.line);
        match self.out.write_all(&self.line) {
            Ok(()) => {
                self.counters.written.fetch_add(1, Ordering::Relaxed);
            }
            Err(error) => self.failed(&error),
        }
    }

    fn flush(&mut self) {
        self.flushed = Instant::now();
        if let Err(error) = self.out.flush() {
            self.failed(&error);
        }
    }

    /// Counts a write error and reports the first of each minute.
    fn failed(&mut self, error: &io::Error) {
        self.counters.errors.fetch_add(1, Ordering::Relaxed);
        let due = self.reported.is_none_or(|at| at.elapsed() >= Duration::from_secs(60));
        if due && !matches!(self.output, LogOutput::Stderr) {
            self.reported = Some(Instant::now());
            eprintln!("EDGE010: access log: {error}\nHint: check the disk and the log path.");
        }
    }

    /// Reopens a file destination between two lines, for log rotation.
    fn reopen_if_asked(&mut self) {
        if !self.counters.reopen.swap(false, Ordering::AcqRel) {
            return;
        }
        if !matches!(self.output, LogOutput::File(_)) {
            return;
        }
        self.flush();
        match Target::open(&self.output) {
            Ok(target) => self.out = BufWriter::with_capacity(64 * 1024, target),
            // The old file stays in use, so no line is lost.
            Err(error) => self.failed(&error),
        }
    }
}

/// Writes `entry` as one JSON object and a line feed. The field set and its order are
/// fixed (SID 0020).
pub(crate) fn format_json(entry: &Entry, out: &mut Vec<u8>) {
    out.extend_from_slice(b"{\"time\":\"");
    write_time(entry.time_ms, out);
    out.extend_from_slice(b"\",\"client\":");
    write_string(entry.client(), out);
    out.extend_from_slice(b",\"frontend\":");
    write_string(entry.frontend.as_ref().map_or("-", |front| &front.name).as_bytes(), out);
    out.extend_from_slice(b",\"protocol\":");
    write_string(entry.protocol.as_bytes(), out);
    out.extend_from_slice(b",\"method\":");
    write_string(entry.method(), out);
    out.extend_from_slice(b",\"host\":");
    write_string(entry.host(), out);
    out.extend_from_slice(b",\"path\":");
    write_string(entry.path(), out);
    let _ = write!(
        out,
        ",\"status\":{},\"bytes_in\":{},\"bytes_out\":{},\"duration_ms\":",
        entry.status, entry.bytes_in, entry.bytes_out
    );
    write_millis(entry.elapsed, out);
    out.extend_from_slice(b",\"ttfb_ms\":");
    match entry.first_byte {
        Some(wait) => write_millis(wait, out),
        None => out.extend_from_slice(b"null"),
    }
    let (backend, server) =
        entry.server.as_ref().map_or(("-", "-"), |server| (&*server.backend, &*server.server));
    out.extend_from_slice(b",\"backend\":");
    write_string(backend.as_bytes(), out);
    out.extend_from_slice(b",\"server\":");
    write_string(server.as_bytes(), out);
    out.extend_from_slice(b",\"verdict\":");
    write_string(entry.verdict.as_bytes(), out);
    out.extend_from_slice(b"}\n");
}

/// Writes a duration as milliseconds with three decimals.
fn write_millis(duration: Duration, out: &mut Vec<u8>) {
    let micros = duration.as_micros();
    let _ = write!(out, "{}.{:03}", micros / 1000, micros % 1000);
}

/// Writes `bytes` as a JSON string in printable ASCII: every other byte is `\u00XX`.
fn write_string(bytes: &[u8], out: &mut Vec<u8>) {
    out.push(b'"');
    for &byte in bytes {
        match byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x20..=0x7e => out.push(byte),
            _ => {
                let _ = write!(out, "\\u{byte:04x}");
            }
        }
    }
    out.push(b'"');
}

/// Writes Unix milliseconds as UTC in RFC 3339: `2026-11-24T10:15:02.418Z`.
fn write_time(unix_ms: u64, out: &mut Vec<u8>) {
    let (seconds, millis) = (unix_ms / 1000, unix_ms % 1000);
    let (days, second_of_day) = (seconds / 86_400, seconds % 86_400);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) =
        (second_of_day / 3600, second_of_day / 60 % 60, second_of_day % 60);
    let _ = write!(
        out,
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z"
    );
}

/// The proleptic Gregorian date of a day count since 1970-01-01 (Howard Hinnant's
/// `civil_from_days`, for days at or after the epoch).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 { month_index + 3 } else { month_index - 9 };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &[u8]) -> Entry {
        let mut entry = Entry::unparsed(b"203.0.113.7", None, "http/1.1");
        entry.set_text(b"203.0.113.7", b"www.example.com", b"GET", path);
        entry.time_ms = 1_795_515_302_418;
        entry.status = 200;
        entry.bytes_in = 112;
        entry.bytes_out = 5310;
        entry.elapsed = Duration::from_micros(3184);
        entry.verdict = "pass";
        entry
    }

    /// The line is JSON for the project's own parser, when the build has it.
    fn assert_parses(line: &str) {
        #[cfg(feature = "console")]
        assert!(sibuna_json::parse(line.trim_end().as_bytes()).is_ok(), "{line}");
        #[cfg(not(feature = "console"))]
        let _ = line;
    }

    fn line(entry: &Entry) -> String {
        let mut out = Vec::new();
        format_json(entry, &mut out);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn a_line_has_the_fixed_fields_in_order() {
        let mut entry = entry(b"/index.html");
        assert_eq!(
            line(&entry),
            "{\"time\":\"2026-11-24T10:15:02.418Z\",\"client\":\"203.0.113.7\",\
             \"frontend\":\"-\",\"protocol\":\"http/1.1\",\"method\":\"GET\",\
             \"host\":\"www.example.com\",\"path\":\"/index.html\",\"status\":200,\
             \"bytes_in\":112,\"bytes_out\":5310,\"duration_ms\":3.184,\"ttfb_ms\":null,\
             \"backend\":\"-\",\"server\":\"-\",\"verdict\":\"pass\"}\n"
        );
        entry.first_byte = Some(Duration::from_micros(2907));
        assert!(line(&entry).contains("\"ttfb_ms\":2.907,"));
        assert_eq!(line(&entry).matches("\":").count(), 15, "fifteen fields");
        assert_parses(&line(&entry));
    }

    #[test]
    fn a_request_cannot_forge_a_second_line() {
        let text = line(&entry(b"/a\"}\n{\"time\":\"x\"\\\x00\xff\x7f"));
        assert_eq!(text.matches('\n').count(), 1, "{text}");
        assert!(text.is_ascii());
        assert!(
            text.contains(r#""path":"/a\"}\u000a{\"time\":\"x\"\\\u0000\u00ff\u007f""#),
            "{text}"
        );
        assert_parses(&text);
    }

    #[test]
    fn dates_follow_the_gregorian_calendar() {
        let time = |ms| {
            let mut out = Vec::new();
            write_time(ms, &mut out);
            String::from_utf8(out).unwrap()
        };
        assert_eq!(time(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(time(951_782_400_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(time(1_709_251_199_999), "2024-02-29T23:59:59.999Z");
        assert_eq!(time(4_102_444_800_000), "2100-01-01T00:00:00.000Z");
    }

    fn options(path: &std::path::Path, queue: usize) -> AccessLogOptions {
        AccessLogOptions { output: LogOutput::File(path.to_string_lossy().into_owned()), queue }
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let directory =
            std::env::temp_dir().join(format!("sibuna-log-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn every_offered_entry_is_written_or_counted_as_dropped() {
        let directory = scratch("count");
        let path = directory.join("access.log");
        let log = AccessLog::start(&options(&path, 64)).unwrap();
        // Far more than the queue holds, as fast as one thread can offer.
        for _ in 0..20_000 {
            log.offer(entry(b"/"));
        }
        log.close();
        let (written, dropped, errors) = log.counts();
        assert_eq!(written + dropped, 20_000);
        assert_eq!(errors, 0);
        assert!(written >= 64, "the queue itself is written: {written}");
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count() as u64, written);
        // After the close an offer is a counted drop, not a wait.
        log.offer(entry(b"/"));
        assert_eq!(log.counts().1, dropped + 1);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn a_reopen_follows_a_rotated_file_and_splits_no_line() {
        let directory = scratch("rotate");
        let path = directory.join("access.log");
        let log = AccessLog::start(&options(&path, 1024)).unwrap();
        log.offer(entry(b"/before"));
        let wait = |written: u64| {
            let deadline = Instant::now() + Duration::from_secs(10);
            while log.counts().0 < written && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        wait(1);
        let rotated = directory.join("access.log.1");
        std::fs::rename(&path, &rotated).unwrap();
        log.reopen();
        // The writer looks at the flag at least every 200 ms.
        std::thread::sleep(Duration::from_millis(500));
        log.offer(entry(b"/after"));
        log.close();
        let before = std::fs::read_to_string(&rotated).unwrap();
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(before.contains("/before") && !before.contains("/after"), "{before}");
        assert!(after.contains("/after") && after.ends_with("}\n"), "{after}");
        assert_eq!(before.lines().count() + after.lines().count(), 2);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn a_missing_directory_fails_the_start_with_the_path() {
        let path = std::path::Path::new("/nonexistent-sibuna/access.log");
        let error = AccessLog::start(&options(path, 64)).err().unwrap();
        assert!(error.to_string().contains("/nonexistent-sibuna/access.log"), "{error}");
    }
}
