//! RSA keys from the `openssl` program (SID 0021).
//!
//! `ring` signs with an RSA key and cannot make one. We run the installed program:
//!
//! ```text
//! openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:N -outform PEM
//! ```
//!
//! The program runs directly, with no shell and with standard input closed. The key
//! comes out of its standard output, so it is in no file before the store writes it.
//! What we read is bounded, the run has a time limit, and the program is killed at
//! that limit.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::Error;
use crate::error::printable;

/// The program that makes RSA keys. It is found through the `PATH` of the process.
pub const TOOL: &str = "openssl";
/// The most bytes read from the standard output of the program. A key of 4096 bits
/// takes about 3.3 KiB of PEM.
const MAX_OUTPUT: u64 = 16 * 1024;
/// The bytes kept from the standard error of the program, for the diagnostic.
const MAX_COMPLAINT: u64 = 1024;
/// How long the making of one key may take.
const KEY_TIMEOUT: Duration = Duration::from_secs(120);
/// How long `openssl version` may take.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// How often we look whether the program has ended.
const POLL: Duration = Duration::from_millis(10);
/// How long we wait for the output after the program has ended.
const OUTPUT_WAIT: Duration = Duration::from_secs(1);

/// Reads at most `limit` bytes of a pipe on a thread of its own and sends them. The
/// thread ends when the program closes the pipe, which a killed program does.
fn collect(pipe: impl Read + Send + 'static, limit: u64) -> mpsc::Receiver<Vec<u8>> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = pipe.take(limit).read_to_end(&mut bytes);
        let _ = sender.send(bytes);
    });
    receiver
}

/// Waits for the program to end. At `deadline` it kills the program and returns `None`.
fn wait(child: &mut Child, deadline: Instant) -> Option<std::process::ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// Runs `program` with `arguments` and returns what it wrote to its standard output, at
/// most [`MAX_OUTPUT`] bytes. Fails with `ACME015` when the program cannot be started,
/// runs longer than `timeout`, or ends with a failure.
fn run(program: &str, arguments: &[&str], timeout: Duration) -> Result<Vec<u8>, Error> {
    let shown = format!("`{program} {}`", arguments.join(" "));
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| Error::key_tool(format!("{shown} could not be started: {error}.")))?;
    let output = child.stdout.take().map(|pipe| collect(pipe, MAX_OUTPUT));
    let complaint = child.stderr.take().map(|pipe| collect(pipe, MAX_COMPLAINT));
    let status = wait(&mut child, Instant::now() + timeout);
    let read = |pipe: Option<mpsc::Receiver<Vec<u8>>>| {
        pipe.and_then(|pipe| pipe.recv_timeout(OUTPUT_WAIT).ok()).unwrap_or_default()
    };
    let (output, complaint) = (read(output), read(complaint));
    let ended = match status {
        Some(status) if status.success() => return Ok(output),
        None => format!("ran longer than {} seconds and was stopped", timeout.as_secs()),
        Some(status) => match status.code() {
            Some(code) => format!("ended with the status {code}"),
            None => "was ended by a signal".to_owned(),
        },
    };
    let said = printable(String::from_utf8_lossy(&complaint).trim(), MAX_COMPLAINT as usize);
    let said = match said.as_str() {
        "" => String::new(),
        text => format!(" It wrote: {}.", text.trim_end_matches('.')),
    };
    Err(Error::key_tool(format!("{shown} {ended}.{said}")))
}

/// Checks that the program which makes RSA keys can be run, with `openssl version`.
/// A configuration with an RSA key calls this when it is checked, so that a missing
/// program is found then and not when a certificate is due. Fails with `ACME015`.
pub fn probe() -> Result<(), Error> {
    probe_with(TOOL)
}

/// As [`probe`], for the program `program`.
fn probe_with(program: &str) -> Result<(), Error> {
    run(program, &["version"], PROBE_TIMEOUT).map(|_| ())
}

/// Makes an RSA key of `bits` bits and returns it as the PEM text of a PKCS#8 private
/// key. The caller checks that the text is a key of that size. Fails with `ACME015`.
pub(crate) fn rsa_pem(bits: u32) -> Result<String, Error> {
    rsa_pem_with(TOOL, bits)
}

/// As [`rsa_pem`], with the program `program`.
fn rsa_pem_with(program: &str, bits: u32) -> Result<String, Error> {
    let size = format!("rsa_keygen_bits:{bits}");
    let arguments = ["genpkey", "-algorithm", "RSA", "-pkeyopt", size.as_str(), "-outform", "PEM"];
    let output = run(program, &arguments, KEY_TIMEOUT)?;
    String::from_utf8(output).map_err(|_| Error::key_tool("The program wrote no PEM text."))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn a_missing_program_is_reported_with_its_code_and_a_hint() {
        let error = probe_with("/nonexistent/sibuna-test/openssl").unwrap_err();
        assert_eq!((error.code, error.title), ("ACME015", "KEY TOOL FAILED"));
        assert!(error.message.contains("could not be started"), "{}", error.message);
        assert!(error.hint.contains("p256") && error.hint.contains("PATH"), "{}", error.hint);
        assert!(rsa_pem_with("/nonexistent/sibuna-test/openssl", 2048).is_err());
    }

    #[test]
    fn a_program_that_fails_is_reported_with_its_status_and_its_words() {
        let _spawn = crate::SPAWN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // `sh` stands in for a program that fails. The words go to standard error.
        let error = run("sh", &["-c", "echo no entropy >&2; exit 3"], PROBE_TIMEOUT).unwrap_err();
        assert!(error.message.contains("ended with the status 3"), "{}", error.message);
        assert!(error.message.contains("It wrote: no entropy."), "{}", error.message);
    }

    #[test]
    fn a_program_that_runs_too_long_is_killed_and_its_output_is_bounded() {
        let _spawn = crate::SPAWN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let started = Instant::now();
        let error = run("sleep", &["30"], Duration::from_millis(200)).unwrap_err();
        assert!(error.message.contains("was stopped"), "{}", error.message);
        assert!(started.elapsed() < Duration::from_secs(10));
        // More output than the bound is read up to the bound and no further.
        let flood = run("sh", &["-c", "head -c 20000 /dev/zero"], PROBE_TIMEOUT).unwrap();
        assert_eq!(flood.len() as u64, MAX_OUTPUT);
    }
}
