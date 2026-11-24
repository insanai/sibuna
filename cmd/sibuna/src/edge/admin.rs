//! The admin socket of SID 0018: a Unix stream socket with mode 0600 that carries one
//! command per connection. One thread serves it. The edge worker applies the commands.

use std::io;
use std::sync::Arc;
use std::sync::mpsc::{Sender, SyncSender};

use sibuna_lb::RuntimeError;

use super::Revision;
use super::control::Command;
use super::watch::Source;

/// One command on its way to the edge worker.
pub(super) struct Job {
    /// The line as the client sent it, for the log.
    pub line: String,
    pub command: Command,
    /// The checked file, for `reload`.
    pub revision: Option<Revision>,
    /// Where the worker puts the answer.
    pub reply: SyncSender<Result<String, RuntimeError>>,
}

/// The listening socket. Dropping it removes the socket file.
pub(super) struct Admin {
    #[cfg(unix)]
    path: std::path::PathBuf,
}

#[cfg(not(unix))]
impl Admin {
    /// Refuses: the admin socket is a Unix socket.
    pub fn start(_path: &str, _source: Arc<Source>, _jobs: Sender<Job>) -> io::Result<Self> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "global.admin_socket needs a Unix system"))
    }
}

#[cfg(unix)]
impl Drop for Admin {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
impl Admin {
    /// Binds the socket at `path` and starts the thread that serves it. Fails when the
    /// path is taken by a live daemon or by a file that is no socket, or when the
    /// directory cannot be written.
    pub fn start(path: &str, source: Arc<Source>, jobs: Sender<Job>) -> io::Result<Self> {
        let path = std::path::PathBuf::from(path);
        let listener = unix::listen(&path).map_err(|error| {
            io::Error::new(error.kind(), format!("admin socket {}: {error}", path.display()))
        })?;
        std::thread::Builder::new()
            .name("edge-admin".into())
            .spawn(move || unix::serve(&listener, &source, &jobs))?;
        Ok(Self { path })
    }
}

#[cfg(unix)]
mod unix {
    use std::fs;
    use std::io::{self, Read, Write};
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;
    use std::sync::mpsc::{self, Sender};
    use std::time::{Duration, Instant};

    use sibuna_lb::RuntimeError;

    use super::super::control::{self, Bucket, Command, MAX_LINE};
    use super::super::watch::Source;
    use super::Job;

    /// How long a client may take to send its line, and to read the answer.
    const CLIENT_TIMEOUT: Duration = Duration::from_secs(2);
    /// The longest socket path. A Unix socket address holds 104 bytes on the smallest
    /// system we support, and the private directory adds up to 18.
    const MAX_PATH: usize = 86;
    /// How long the admin thread waits for the edge worker.
    const WORKER_TIMEOUT: Duration = Duration::from_secs(5);

    /// Binds the socket so that it is never reachable with a mode wider than 0600: in a
    /// private directory first, then renamed to `path`. A stale socket file is replaced.
    pub(super) fn listen(path: &Path) -> io::Result<UnixListener> {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(found) if !found.file_type().is_socket() => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "the path holds a file that is not a socket",
                ));
            }
            Ok(_) if UnixStream::connect(path).is_ok() => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "another daemon answers on this socket",
                ));
            }
            // A socket that nobody answers was left by a daemon that died.
            Ok(_) => {}
        }
        if path.as_os_str().len() > MAX_PATH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "the path is longer than {MAX_PATH} bytes, the most a Unix socket takes here"
                ),
            ));
        }
        let parent = path.parent().filter(|parent| !parent.as_os_str().is_empty());
        let private =
            parent.unwrap_or(Path::new(".")).join(format!(".sibuna-{}", std::process::id()));
        // A directory of this name can only be the remains of an earlier process.
        let _ = fs::remove_file(private.join("s"));
        let _ = fs::remove_dir(&private);
        fs::DirBuilder::new().mode(0o700).create(&private)?;
        let bound = private.join("s");
        let result = UnixListener::bind(&bound).and_then(|listener| {
            fs::set_permissions(&bound, fs::Permissions::from_mode(0o600))?;
            fs::rename(&bound, path)?;
            Ok(listener)
        });
        let _ = fs::remove_file(&bound);
        let _ = fs::remove_dir(&private);
        result
    }

    /// Serves one connection after another until the process ends.
    pub(super) fn serve(listener: &UnixListener, source: &Source, jobs: &Sender<Job>) {
        let mut bucket = Bucket::new(Instant::now());
        for stream in listener.incoming() {
            // A failed accept belongs to one client. The socket stays in service, and
            // a short pause keeps a persistent failure from spinning.
            let Ok(mut stream) = stream else {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            };
            let answer = read_line(&mut stream).and_then(|line| {
                if bucket.take(Instant::now()) {
                    return run(&line, source, jobs);
                }
                Err(control::failure(
                    "ADM009",
                    "TOO MANY COMMANDS",
                    "The socket accepts a burst of 20 commands and 10 per second after it.",
                    "Wait a moment and send the command again.",
                ))
            });
            let _ = stream.set_write_timeout(Some(CLIENT_TIMEOUT));
            let _ = stream.write_all(control::encode(&answer).as_bytes());
            finish(&mut stream);
        }
    }

    /// Ends the answer and takes what the client still sends, for a moment. Closing a
    /// Unix socket with unread input would reset the client before it read the answer.
    fn finish(stream: &mut UnixStream) {
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
        let mut rest = [0u8; 1024];
        for _ in 0..4 {
            if !matches!(stream.read(&mut rest), Ok(count) if count > 0) {
                break;
            }
        }
    }

    /// Reads one line of at most [`MAX_LINE`] bytes within [`CLIENT_TIMEOUT`]. The end
    /// of the stream also ends the line.
    fn read_line(stream: &mut UnixStream) -> Result<String, RuntimeError> {
        let deadline = Instant::now() + CLIENT_TIMEOUT;
        let mut buffer = [0u8; MAX_LINE + 1];
        let mut filled = 0;
        loop {
            if let Some(end) = buffer[..filled].iter().position(|byte| *byte == b'\n') {
                return control::line(&buffer[..end]).map(str::to_owned);
            }
            if filled == buffer.len() {
                return Err(control::malformed("The command is longer than the limit."));
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || stream.set_read_timeout(Some(left)).is_err() {
                return Err(control::malformed("The command did not arrive in two seconds."));
            }
            match stream.read(&mut buffer[filled..]) {
                Ok(0) => return control::line(&buffer[..filled]).map(str::to_owned),
                Ok(count) => filled += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => {
                    return Err(control::malformed("The command did not arrive in two seconds."));
                }
            }
        }
    }

    /// Parses the line, loads the file for `reload`, and asks the worker.
    fn run(line: &str, source: &Source, jobs: &Sender<Job>) -> Result<String, RuntimeError> {
        let command = control::parse(line)?;
        if command == Command::Help {
            return Ok(control::USAGE.to_owned());
        }
        // The file is compiled and checked here, off the worker, as for SIGHUP.
        let revision = match command {
            Command::Reload if source.path().is_none() => {
                return Err(super::super::nothing_to_reload());
            }
            Command::Reload => Some(source.load().map_err(super::super::reload_rejected)?),
            _ => None,
        };
        let (reply, answer) = mpsc::sync_channel(1);
        let job = Job { line: line.to_owned(), command, revision, reply };
        let no_answer = || {
            control::failure(
                "ADM010",
                "NO ANSWER",
                "The edge worker did not answer in five seconds.",
                "The daemon may be stopping. Run `show info` to see whether it serves.",
            )
        };
        jobs.send(job).map_err(|_| no_answer())?;
        answer.recv_timeout(WORKER_TIMEOUT).map_err(|_| no_answer())?
    }
}
