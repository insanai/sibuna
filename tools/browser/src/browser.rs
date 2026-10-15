//! Starting and stopping headless Chromium.

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::cdp::{Params, string_at};
use crate::connection::Connection;
use crate::error::Error;
use crate::page::Page;

/// How a browser is launched.
///
/// ```no_run
/// use sibuna_browser::{Browser, Options};
///
/// let options = Options { extra_flags: vec!["--lang=en-US".into()], ..Default::default() };
/// let mut browser = Browser::launch(options)?;
/// let mut page = browser.new_page()?;
/// page.navigate("http://127.0.0.1:8080/")?;
/// page.screenshot(std::path::Path::new("page.png"))?;
/// # Ok::<(), sibuna_browser::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct Options {
    /// The Chromium executable. Default: `chromium`, found on PATH.
    pub executable: PathBuf,
    /// Flags added after the fixed ones, such as `--lang=en-US`. To remove WebAssembly,
    /// use [`Page::disable_webassembly`](crate::Page::disable_webassembly): Chromium 155
    /// ignores `--js-flags=--noexpose_wasm`.
    pub extra_flags: Vec<String>,
    /// How long Chromium may take to announce its DevTools port. Default: 20 s.
    pub launch_timeout: Duration,
    /// How long one DevTools command may take. Default: 30 s.
    pub command_timeout: Duration,
    /// The largest DevTools message accepted, in bytes. Screenshots arrive as one base64
    /// message, so this bounds their size. Default: 64 MiB.
    pub max_message_bytes: usize,
    /// A file that receives every DevTools message sent (`>`) and received (`<`), each
    /// cut to 400 bytes, with milliseconds since launch. For diagnosing hangs. Default:
    /// none.
    pub protocol_log: Option<PathBuf>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            executable: PathBuf::from("chromium"),
            extra_flags: Vec::new(),
            launch_timeout: Duration::from_secs(20),
            command_timeout: Duration::from_secs(30),
            max_message_bytes: 64 << 20,
            protocol_log: None,
        }
    }
}

/// The flags every launch uses. `--remote-debugging-port=0` lets Chromium choose a free
/// port, which it writes to `DevToolsActivePort` in the profile.
const FIXED_FLAGS: [&str; 10] = [
    "--headless=new",
    "--no-sandbox",
    "--disable-gpu",
    "--remote-debugging-port=0",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    "--disable-background-networking",
    "--hide-scrollbars",
    "--mute-audio",
];

/// A running headless Chromium with a private temporary profile.
///
/// Dropping it closes the browser (killing it if it does not exit within two seconds) and
/// removes the profile.
#[derive(Debug)]
pub struct Browser {
    // Fields drop in order: the socket closes before the process is killed.
    pub(crate) connection: Connection,
    process: Process,
    pub(crate) options: Options,
}

impl Browser {
    /// Starts Chromium with `options` and connects to its browser endpoint.
    ///
    /// # Errors
    ///
    /// [`Error::Launch`] when the process cannot start, exits, or does not announce its
    /// port in time; [`Error::Io`] and [`Error::Handshake`] when connecting fails.
    pub fn launch(options: Options) -> Result<Browser, Error> {
        let mut process = Process::start(&options)?;
        let (port, path) = process.wait_for_port(options.launch_timeout)?;
        let mut connection =
            Connection::open(port, &path, options.max_message_bytes, options.command_timeout)?;
        if let Some(log) = &options.protocol_log {
            let file = File::create(log).map_err(|error| {
                Error::io(format!("creating the protocol log {}", log.display()), error)
            })?;
            connection.set_protocol_log(file);
        }
        Ok(Browser { connection, process, options })
    }

    /// The browser's product and version, such as `Chrome/155.0.8059.39`.
    ///
    /// # Errors
    ///
    /// The errors of a DevTools command.
    pub fn version(&mut self) -> Result<String, Error> {
        let reply = self.call("Browser.getVersion", &Params::new())?;
        Ok(string_at(&reply.body()?, &["result", "product"]).to_owned())
    }

    /// Opens a new tab and attaches to it. The page borrows the browser, so one page is
    /// driven at a time.
    ///
    /// # Errors
    ///
    /// The errors of the DevTools commands that create, attach and enable the page.
    pub fn new_page(&mut self) -> Result<Page<'_>, Error> {
        Page::open(self)
    }

    /// The directory of the temporary profile.
    pub fn profile_dir(&self) -> &Path {
        &self.process.profile
    }

    /// Sends a browser-level command and waits for its response.
    pub(crate) fn call(
        &mut self,
        method: &str,
        params: &Params,
    ) -> Result<crate::cdp::Message, Error> {
        let deadline = Instant::now() + self.options.command_timeout;
        self.connection.call(None, method, params, deadline)
    }
}

impl Drop for Browser {
    fn drop(&mut self) {
        // Ask politely; Process::drop kills whatever is still running.
        if self.connection.send(None, "Browser.close", &Params::new()).is_ok() {
            self.process.wait_for_exit(Duration::from_secs(2));
        }
        self.connection.close();
    }
}

/// The Chromium process and its profile directory, cleaned up on drop even when a launch
/// fails half way.
#[derive(Debug)]
struct Process {
    child: Child,
    profile: PathBuf,
}

/// The name of Chromium's standard error file inside the profile.
const STDERR_FILE: &str = "chromium-stderr.log";

impl Process {
    fn start(options: &Options) -> Result<Process, Error> {
        let profile = create_profile_dir()?;
        let stderr = match File::create(profile.join(STDERR_FILE)) {
            Ok(file) => file,
            Err(error) => {
                let _ = fs::remove_dir_all(&profile);
                return Err(Error::io("creating Chromium's log file", error));
            }
        };
        let spawned = Command::new(&options.executable)
            .args(FIXED_FLAGS)
            .arg(format!("--user-data-dir={}", profile.display()))
            .args(&options.extra_flags)
            .arg("about:blank")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr)
            .spawn();
        match spawned {
            Ok(child) => Ok(Process { child, profile }),
            Err(error) => {
                let _ = fs::remove_dir_all(&profile);
                let message = format!("cannot run {}: {error}", options.executable.display());
                Err(Error::Launch { message, log_tail: String::new() })
            }
        }
    }

    /// Waits for `DevToolsActivePort`: the port on its first line, the browser endpoint's
    /// path on its second.
    fn wait_for_port(&mut self, timeout: Duration) -> Result<(u16, String), Error> {
        let deadline = Instant::now() + timeout;
        let file = self.profile.join("DevToolsActivePort");
        loop {
            // Chromium writes the file in one go, but we may read it half written; a
            // malformed read is retried until the deadline.
            if let Ok(text) = fs::read_to_string(&file)
                && let Some(found) = parse_active_port(&text)
            {
                return Ok(found);
            }
            if let Ok(Some(status)) = self.child.try_wait() {
                let message = format!("Chromium exited with {status} before DevTools started");
                return Err(Error::Launch { message, log_tail: self.log_tail() });
            }
            if Instant::now() >= deadline {
                let message = format!("no DevTools port after {} s", timeout.as_secs());
                return Err(Error::Launch { message, log_tail: self.log_tail() });
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The last two kilobytes of Chromium's standard error.
    fn log_tail(&self) -> String {
        let Ok(mut file) = File::open(self.profile.join(STDERR_FILE)) else {
            return String::new();
        };
        let length = file.metadata().map_or(0, |metadata| metadata.len());
        let _ = file.seek(SeekFrom::Start(length.saturating_sub(2048)));
        let mut tail = Vec::new();
        let _ = file.read_to_end(&mut tail);
        String::from_utf8_lossy(&tail).trim().to_owned()
    }

    /// Polls for the process to exit, for at most `timeout`.
    fn wait_for_exit(&mut self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if !matches!(self.child.try_wait(), Ok(None)) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        // Chromium's helper processes may still be writing for a moment after the main
        // process exits; a second attempt catches files they created.
        if fs::remove_dir_all(&self.profile).is_err() {
            std::thread::sleep(Duration::from_millis(200));
            let _ = fs::remove_dir_all(&self.profile);
        }
    }
}

/// Parses `DevToolsActivePort`: a port line and a `/devtools/browser/<id>` line.
pub(crate) fn parse_active_port(text: &str) -> Option<(u16, String)> {
    let mut lines = text.lines();
    let port = lines.next()?.trim().parse::<u16>().ok().filter(|&port| port != 0)?;
    let path = lines.next()?.trim();
    path.starts_with("/devtools/browser/").then(|| (port, path.to_owned()))
}

/// Creates a fresh, uniquely named directory under the system temporary directory.
fn create_profile_dir() -> Result<PathBuf, Error> {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |time| time.subsec_nanos());
    let base = std::env::temp_dir();
    for _ in 0..16 {
        // Relaxed: the counter only needs distinct values, not ordering with other memory.
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!("sibuna-browser-{}-{nanos}-{count}", std::process::id());
        let path = base.join(name);
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(Error::io("creating the Chromium profile directory", error)),
        }
    }
    Err(Error::Launch {
        message: "no free profile directory name".into(),
        log_tail: String::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_active_port_file() {
        let text = "41235\n/devtools/browser/0c1b2a3d-aaaa\n";
        assert_eq!(
            parse_active_port(text),
            Some((41235, "/devtools/browser/0c1b2a3d-aaaa".into()))
        );
        assert_eq!(parse_active_port("41235\n"), None);
        assert_eq!(parse_active_port("0\n/devtools/browser/x"), None);
        assert_eq!(parse_active_port("x\n/devtools/browser/x"), None);
        assert_eq!(parse_active_port("1\n/other"), None);
    }

    #[test]
    fn profile_directories_are_distinct() {
        let first = create_profile_dir().unwrap();
        let second = create_profile_dir().unwrap();
        assert_ne!(first, second);
        fs::remove_dir(&first).unwrap();
        fs::remove_dir(&second).unwrap();
    }

    #[test]
    fn a_missing_executable_is_a_launch_error() {
        let options =
            Options { executable: PathBuf::from("/nonexistent/chromium"), ..Default::default() };
        assert!(matches!(Browser::launch(options), Err(Error::Launch { .. })));
    }
}
