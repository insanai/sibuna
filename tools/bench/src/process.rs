//! Child processes pinned to CPU sets, and what `/proc` tells us about them.
//!
//! Every process the benchmark starts is held by a [`Process`], which stops it by PID when it
//! is dropped, so an early return or a panic does not leave daemons running. Pinning uses
//! `taskset -c`, which sets the affinity and then executes the program in place: the PID we
//! hold is the program's own, and every thread it creates inherits the CPU set.

use std::fs::{self, File};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

/// A set of logical CPUs, as written for `taskset -c` (`0-3,8`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpuSet {
    /// The CPUs in ascending order, without duplicates.
    pub cpus: Vec<u32>,
}

impl CpuSet {
    /// Parses a list such as `0-3,8,10-11`.
    ///
    /// # Errors
    ///
    /// Fails on an empty list, a malformed item, a reversed range or more than 1,024 CPUs.
    pub fn parse(text: &str) -> Result<CpuSet> {
        let invalid = || {
            Error::new("INVALID CPU LIST", format!("`{text}` is not a CPU list."))
                .hint("Write CPUs as `taskset -c` does, for example `0-3` or `0,2,4-7`.")
        };
        let mut cpus = Vec::new();
        for item in text.split(',') {
            let (first, last) = match item.split_once('-') {
                Some((a, b)) => (a.trim().parse(), b.trim().parse()),
                None => (item.trim().parse(), item.trim().parse()),
            };
            let (Ok(first), Ok(last)): (std::result::Result<u32, _>, std::result::Result<u32, _>) =
                (first, last)
            else {
                return Err(invalid());
            };
            if first > last || last >= 1024 {
                return Err(invalid());
            }
            cpus.extend(first..=last);
        }
        cpus.sort_unstable();
        cpus.dedup();
        Ok(CpuSet { cpus })
    }

    /// Returns the number of CPUs in the set.
    pub fn count(&self) -> usize {
        self.cpus.len()
    }

    /// Returns the set as a comma-separated list that `taskset -c` accepts.
    pub fn to_list(&self) -> String {
        let items: Vec<String> = self.cpus.iter().map(u32::to_string).collect();
        items.join(",")
    }
}

/// A running child process that is stopped by PID when dropped.
#[derive(Debug)]
pub struct Process {
    child: Child,
    name: String,
}

impl Process {
    /// Starts `program` with `args`, pinned to `cpus` when given, with its standard output and
    /// error appended to `log` (or discarded).
    ///
    /// # Errors
    ///
    /// Fails when the program (or `taskset`) cannot be started.
    pub fn spawn(
        name: &str,
        program: &Path,
        args: &[String],
        cpus: Option<&CpuSet>,
        log: Option<&Path>,
    ) -> Result<Process> {
        Process::spawn_with_env(name, program, args, &[], cpus, log)
    }

    /// Starts `program` like [`Process::spawn`], with the variables `env` added to the
    /// environment it inherits (Anubis reads `GOMAXPROCS` from there).
    ///
    /// # Errors
    ///
    /// Fails when the program (or `taskset`) cannot be started.
    pub fn spawn_with_env(
        name: &str,
        program: &Path,
        args: &[String],
        env: &[(&str, String)],
        cpus: Option<&CpuSet>,
        log: Option<&Path>,
    ) -> Result<Process> {
        let mut command = match cpus {
            Some(set) => {
                let mut command = Command::new("taskset");
                command.arg("-c").arg(set.to_list()).arg(program);
                command
            }
            None => Command::new(program),
        };
        command.args(args).stdin(Stdio::null());
        for (key, value) in env {
            command.env(key, value);
        }
        match log {
            Some(path) => {
                let file = File::create(path).map_err(|e| Error::io(path.display(), e))?;
                let copy = file.try_clone().map_err(|e| Error::io(path.display(), e))?;
                command.stdout(file).stderr(copy);
            }
            None => {
                command.stdout(Stdio::null()).stderr(Stdio::null());
            }
        }
        let child = command.spawn().map_err(|e| {
            Error::new(
                "START FAILED",
                format!("Cannot start {name} ({}): {e}.", program.display()),
            )
            .hint("Check that the binary exists and that `taskset` is installed.")
        })?;
        Ok(Process { child, name: name.to_owned() })
    }

    /// Returns the process id.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Returns true while the process has not exited.
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Sends SIGTERM by PID, waits up to five seconds, then kills the process.
    pub fn stop(&mut self) {
        if !self.is_running() {
            return;
        }
        let pid = self.pid().to_string();
        let _ = Command::new("kill")
            .args(["-TERM", &pid])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.is_running() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        if self.is_running() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }

    /// Returns the name given at start, for messages.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Returns a TCP port on 127.0.0.1 that was free a moment ago.
///
/// # Errors
///
/// Fails when no port can be bound.
pub fn free_port() -> Result<u16> {
    let listener =
        TcpListener::bind("127.0.0.1:0").map_err(|e| Error::io("binding a free port", e))?;
    listener.local_addr().map(|a| a.port()).map_err(|e| Error::io("reading a bound port", e))
}

/// Returns the user and system CPU time of process `pid` so far, in seconds, from
/// `/proc/<pid>/stat`. The kernel counts the time of exited threads too.
///
/// # Errors
///
/// Fails when the file cannot be read or parsed (the process exited).
pub fn cpu_seconds(pid: u32) -> Result<f64> {
    let path = format!("/proc/{pid}/stat");
    let text = fs::read_to_string(&path).map_err(|e| Error::io(&path, e))?;
    let ticks = stat_cpu_ticks(&text)
        .ok_or_else(|| Error::new("PROC PARSE", format!("{path} has no CPU times.")))?;
    Ok(ticks as f64 / clock_ticks_per_second() as f64)
}

/// Returns utime + stime from the text of `/proc/<pid>/stat`. Fields are counted after the
/// last `)`, because the command name may itself hold spaces and parentheses.
fn stat_cpu_ticks(text: &str) -> Option<u64> {
    let rest = &text[text.rfind(')')? + 1..];
    let mut fields = rest.split_whitespace();
    // After the name: state is field 3 of stat(5); utime and stime are fields 14 and 15.
    let utime: u64 = fields.nth(11)?.parse().ok()?;
    let stime: u64 = fields.next()?.parse().ok()?;
    Some(utime + stime)
}

/// Returns the kernel's clock ticks per second (`getconf CLK_TCK`, normally 100).
fn clock_ticks_per_second() -> u64 {
    static TICKS: OnceLock<u64> = OnceLock::new();
    *TICKS.get_or_init(|| {
        Command::new("getconf")
            .arg("CLK_TCK")
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .and_then(|text| text.trim().parse().ok())
            .filter(|&ticks| ticks > 0)
            .unwrap_or(100)
    })
}

/// Returns field `name` (`VmHWM`, `VmRSS`) of `/proc/<pid>/status` in KiB.
///
/// # Errors
///
/// Fails when the file cannot be read or has no such field.
pub fn status_kib(pid: u32, name: &str) -> Result<u64> {
    let path = format!("/proc/{pid}/status");
    let text = fs::read_to_string(&path).map_err(|e| Error::io(&path, e))?;
    status_field_kib(&text, name)
        .ok_or_else(|| Error::new("PROC PARSE", format!("{path} has no field {name}.")))
}

fn status_field_kib(text: &str, name: &str) -> Option<u64> {
    let line = text.lines().find(|line| line.split(':').next() == Some(name))?;
    line.split(':').nth(1)?.split_whitespace().next()?.parse().ok()
}

/// Resets the peak resident set (`VmHWM`) of `pid` to its current resident set by writing
/// `5` to `/proc/<pid>/clear_refs`. Returns false when the kernel refused.
pub fn reset_peak_rss(pid: u32) -> bool {
    fs::write(format!("/proc/{pid}/clear_refs"), b"5").is_ok()
}

/// The TCP state number of `TIME_WAIT` in `/proc/net/tcp` (`include/net/tcp_states.h`).
const TIME_WAIT_STATE: &str = "06";

/// Returns the number of IPv4 and IPv6 sockets of this network namespace in `TIME_WAIT`,
/// from `/proc/net/tcp` and `/proc/net/tcp6`. A file that cannot be read counts as empty.
pub fn time_wait_count() -> usize {
    ["/proc/net/tcp", "/proc/net/tcp6"]
        .iter()
        .map(|path| fs::read_to_string(path).map_or(0, |text| count_time_wait(&text)))
        .sum()
}

/// Counts the rows of a `/proc/net/tcp` table whose state (the fourth column) is
/// `TIME_WAIT`. The first line is the header.
fn count_time_wait(text: &str) -> usize {
    text.lines()
        .skip(1)
        .filter(|line| line.split_whitespace().nth(3) == Some(TIME_WAIT_STATE))
        .count()
}

/// Waits, for at most `timeout`, until fewer than `limit` sockets are in `TIME_WAIT`.
///
/// A product that opens an origin connection per request leaves one socket in `TIME_WAIT`
/// per request for a minute; a run that starts while tens of thousands remain can exhaust
/// the ephemeral ports. `tools.py` waited the same way before every run (limit 3,000, 90
/// seconds). Returns the count when the wait ended.
pub fn drain_time_wait(limit: usize, timeout: Duration) -> usize {
    let deadline = Instant::now() + timeout;
    loop {
        let count = time_wait_count();
        if count < limit || Instant::now() >= deadline {
            return count;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// A private temporary directory, removed when dropped.
#[derive(Debug)]
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Creates `<temp>/sibuna-bench-<pid>-<label>`.
    ///
    /// # Errors
    ///
    /// Fails when the directory cannot be created.
    pub fn new(label: &str) -> Result<TempDir> {
        let path =
            std::env::temp_dir().join(format!("sibuna-bench-{}-{label}", std::process::id()));
        fs::create_dir_all(&path).map_err(|e| Error::io(path.display(), e))?;
        Ok(TempDir { path })
    }

    /// Returns the directory.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Returns the last `max` bytes of the file at `path`, for error messages.
pub fn tail(path: &Path, max: usize) -> String {
    let text = fs::read(path).unwrap_or_default();
    let start = text.len().saturating_sub(max);
    String::from_utf8_lossy(&text[start..]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cpu_lists() {
        assert_eq!(CpuSet::parse("0-3").unwrap().cpus, vec![0, 1, 2, 3]);
        assert_eq!(CpuSet::parse("8,0-1,1").unwrap().to_list(), "0,1,8");
        assert_eq!(CpuSet::parse("5").unwrap().count(), 1);
        for bad in ["", "3-1", "a", "0-", "0-5000"] {
            assert!(CpuSet::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn reads_cpu_ticks_after_a_name_with_spaces() {
        let text = "1234 (a b) c) S 1 2 3 4 5 6 7 8 9 10 250 50 0 0 20 0";
        assert_eq!(stat_cpu_ticks(text), Some(300));
        assert_eq!(stat_cpu_ticks("1 (x) S"), None);
    }

    #[test]
    fn counts_time_wait_rows() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue\n\
            0: 0100007F:1F90 00000000:0000 0A 00000000:00000000\n\
            1: 0100007F:9C40 0100007F:1F90 06 00000000:00000000\n\
            2: 0100007F:9C41 0100007F:1F90 06 00000000:00000000\n\
            3: 0100007F:9C42 0100007F:1F90 01 00000000:00000000\n";
        assert_eq!(count_time_wait(text), 2);
        assert_eq!(count_time_wait(""), 0);
        assert!(drain_time_wait(usize::MAX, Duration::ZERO) < usize::MAX);
    }

    #[test]
    fn reads_status_fields_and_own_process() {
        let text = "Name:\tx\nVmHWM:\t   27136 kB\nVmRSS:\t    9952 kB\n";
        assert_eq!(status_field_kib(text, "VmHWM"), Some(27136));
        assert_eq!(status_field_kib(text, "VmRSS"), Some(9952));
        assert_eq!(status_field_kib(text, "VmSwap"), None);
        let me = std::process::id();
        assert!(status_kib(me, "VmRSS").unwrap() > 0);
        assert!(cpu_seconds(me).unwrap() >= 0.0);
    }
}
