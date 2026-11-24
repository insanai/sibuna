//! `sibuna ctl SOCKET COMMAND...`: the client of the admin socket (SID 0018). It sends one
//! line, prints the result to standard output, and prints a failure as a diagnostic.

use std::process::ExitCode;

use sibuna_core::diagnostic;

use super::control::{self, Answer, MAX_LINE};

/// The most bytes read from an answer. `show servers` of 128 full pools stays below it.
#[cfg(unix)]
const MAX_ANSWER: u64 = 4 << 20;

/// Prints a diagnostic to standard error and returns the failure status.
fn fail(title: &str, message: &str, hint: &str) -> ExitCode {
    let mut text = String::new();
    let _ = diagnostic::render(&mut text, title, message, hint);
    eprint!("{text}");
    ExitCode::FAILURE
}

/// Runs the client with the arguments after `ctl`.
pub(super) fn run(args: &[String]) -> ExitCode {
    let [socket, words @ ..] = args else {
        return usage("`sibuna ctl` needs the path of the admin socket and a command.");
    };
    if socket == "--help" || words.is_empty() {
        return usage("`sibuna ctl` needs the path of the admin socket and a command.");
    }
    let line = words.join(" ");
    if line.len() > MAX_LINE {
        return fail(
            "command too long",
            &format!("The command has {} bytes. The limit is {MAX_LINE}.", line.len()),
            "Send one command at a time.",
        );
    }
    match exchange(socket, &line) {
        Ok(text) => report(&text),
        Err(error) => fail(
            "no admin socket",
            &format!("Cannot reach the daemon at `{socket}`: {error}."),
            "Start the daemon with `global.admin_socket` in its file, or with \
             `sibuna lb --admin PATH`, and run `sibuna ctl` as the same user.",
        ),
    }
}

fn usage(message: &str) -> ExitCode {
    let commands = control::USAGE.replace('\n', "\n  ");
    let hint =
        format!("sibuna ctl SOCKET COMMAND, where COMMAND is one of\n  {}", commands.trim_end());
    fail("missing command", message, &hint)
}

/// Prints the answer. Returns success after `ok`.
fn report(text: &str) -> ExitCode {
    match control::decode(text) {
        Some(Answer::Done(body)) => {
            use std::io::Write as _;
            let _ = std::io::stdout().lock().write_all(body.as_bytes());
            ExitCode::SUCCESS
        }
        Some(Answer::Failed { code, title, message, hint }) => {
            fail(&format!("{title} ({code})"), message, hint)
        }
        None => fail(
            "unexpected answer",
            "The socket did not answer as a Sibuna admin socket does.",
            "Check that the path is the `global.admin_socket` of a running daemon.",
        ),
    }
}

/// Sends the line and reads the whole answer.
#[cfg(unix)]
fn exchange(socket: &str, line: &str) -> std::io::Result<String> {
    use std::io::{Read as _, Write as _};
    use std::time::Duration;

    let mut stream = std::os::unix::net::UnixStream::connect(socket)?;
    // A reload compiles the file and waits for the worker, so we wait longer than both.
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(line.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut text = String::new();
    stream.take(MAX_ANSWER).read_to_string(&mut text)?;
    Ok(text)
}

#[cfg(not(unix))]
fn exchange(_socket: &str, _line: &str) -> std::io::Result<String> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "the admin socket needs a Unix system",
    ))
}
