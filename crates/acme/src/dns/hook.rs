//! The hook program: an executable of the operator that writes and removes the record.
//!
//! ```text
//! HOOK present RECORD VALUE        RECORD has a final dot: _acme-challenge.example.org.
//! HOOK cleanup RECORD VALUE        VALUE is the text of the TXT record
//! ```
//!
//! We run the program directly, with no shell. Exit status 0 means done. The program
//! is the first process of a new process group. When it runs too long, the whole group
//! is killed: the program and what it started, unless that left the group.

use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::Error;
use crate::error::printable;

/// The bytes kept from the end of each of the two outputs of the program.
pub const MAX_OUTPUT: usize = 1024;
/// How often we look whether the program has ended.
const POLL: Duration = Duration::from_millis(20);
/// How long we wait for the output after the program has ended. A child of the program
/// may keep the pipe open; we do not wait for it.
const OUTPUT_WAIT: Duration = Duration::from_secs(1);

/// One run of the hook.
#[derive(Clone, Copy, Debug)]
pub struct Run<'a> {
    /// The path of the program.
    pub program: &'a Path,
    /// `present` or `cleanup`.
    pub action: &'a str,
    /// The owner of the record, without a final dot. The program receives one.
    pub owner: &'a str,
    /// The text of the TXT record.
    pub value: &'a str,
    /// The `auto` name of the certificate.
    pub name: &'a str,
    /// The owner that the authority asks: `_acme-challenge.NAME`, without a final dot.
    /// It differs from `owner` when a CNAME record delegates the challenge.
    pub challenge: &'a str,
    /// How long the program may run before it is killed.
    pub timeout: Duration,
}

/// Reads a pipe to its end and sends the last [`MAX_OUTPUT`] bytes.
fn collect(mut pipe: impl Read + Send + 'static, sender: mpsc::Sender<(u8, Vec<u8>)>, order: u8) {
    std::thread::spawn(move || {
        let mut tail = Vec::new();
        let mut buffer = [0; 1024];
        while let Ok(count @ 1..) = pipe.read(&mut buffer) {
            tail.extend_from_slice(&buffer[..count]);
            if tail.len() > MAX_OUTPUT {
                tail.drain(..tail.len() - MAX_OUTPUT);
            }
        }
        let _ = sender.send((order, tail));
    });
}

/// Waits for the program to end. At `deadline` it kills the process group of the
/// program, then the program itself, and returns `None`.
fn wait(child: &mut Child, deadline: Instant) -> Option<std::process::ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL),
            _ => {
                // The program has not been waited for, so its number still names it
                // and its group. Where groups do not exist, the program alone ends.
                let _ = super::group::kill_group(child.id());
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// Runs the hook and waits for it. Fails with `ACME009` when the program cannot be
/// started, runs longer than the timeout, or ends with a status other than 0. The
/// message has the end of what the program wrote, made printable.
pub fn run(run: Run<'_>) -> Result<(), Error> {
    let record = format!("{}.", run.owner.trim_end_matches('.'));
    let shown = format!("`{} {} {record} {}`", run.program.display(), run.action, run.value);
    let mut command = Command::new(run.program);
    command.args([run.action, record.as_str(), run.value]);
    command.env("SIBUNA_ACME_ACTION", run.action);
    command.env("SIBUNA_ACME_RECORD", &record);
    command.env("SIBUNA_ACME_VALUE", run.value);
    command.env("SIBUNA_ACME_NAME", run.name);
    command.env("SIBUNA_ACME_CHALLENGE", format!("{}.", run.challenge.trim_end_matches('.')));
    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|error| Error::provider(format!("{shown} could not be started: {error}.")))?;
    let (sender, receiver) = mpsc::channel();
    let mut pipes = 0;
    if let Some(pipe) = child.stdout.take() {
        collect(pipe, sender.clone(), 0);
        pipes += 1;
    }
    if let Some(pipe) = child.stderr.take() {
        collect(pipe, sender, 1);
        pipes += 1;
    }
    let status = wait(&mut child, Instant::now() + run.timeout);
    if status.is_some_and(|status| status.success()) {
        return Ok(());
    }
    // Standard output first, then standard error, whichever ended first.
    let mut tails = Vec::new();
    let output_deadline = Instant::now() + OUTPUT_WAIT;
    for _ in 0..pipes {
        let left = output_deadline.saturating_duration_since(Instant::now());
        tails.extend(receiver.recv_timeout(left));
    }
    tails.sort_by_key(|(order, _)| *order);
    let output: Vec<u8> = tails.into_iter().flat_map(|(_, tail)| tail).collect();
    let output = printable(String::from_utf8_lossy(&output).trim(), 2 * MAX_OUTPUT);
    let ended = match status {
        None => format!("ran longer than {} seconds and was stopped", run.timeout.as_secs()),
        Some(status) => match status.code() {
            Some(code) => format!("ended with the status {code}"),
            None => "was ended by a signal".to_owned(),
        },
    };
    let said = match output.as_str() {
        "" => "It wrote nothing.".to_owned(),
        text if text.ends_with('.') => format!("It wrote: {text}"),
        text => format!("It wrote: {text}."),
    };
    Err(Error::provider(format!("{shown} {ended}. {said}")))
}
