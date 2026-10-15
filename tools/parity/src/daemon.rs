//! Starting and stopping the daemons under test. Each runs as a child process that is
//! killed by its process id when its [`Daemon`] is dropped, also when the run fails.

use std::fs::File;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::socket::connect_from;

/// The source address of the startup probe.
const PROBE_SOURCE: Ipv4Addr = Ipv4Addr::new(127, 255, 254, 2);

/// How long a daemon may take to accept its first connection.
const STARTUP: Duration = Duration::from_secs(20);

/// A running daemon.
#[derive(Debug)]
pub struct Daemon {
    child: Child,
    /// The loopback address it listens on.
    pub address: SocketAddrV4,
}

/// Returns a loopback port that was free a moment ago.
///
/// # Errors
///
/// Returns the error of binding a probe listener.
pub fn free_port() -> io::Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

/// Start-ups are serialised: a port is picked and bound before another start-up picks
/// one, so two daemons of concurrent configurations never draw the same free port.
static STARTING: Mutex<()> = Mutex::new(());

impl Daemon {
    /// Starts `binary` on a free loopback port with the arguments `args` builds for that
    /// port, its output going to `log`, and waits until it accepts connections.
    ///
    /// # Errors
    ///
    /// Fails when the process cannot start, exits during startup, or does not listen
    /// within 20 seconds; the message points at the log.
    pub fn start(
        binary: &Path,
        args: impl Fn(u16) -> Vec<String>,
        log: &Path,
    ) -> io::Result<Daemon> {
        let _starting = STARTING.lock().unwrap_or_else(|poison| poison.into_inner());
        let port = free_port()?;
        let output = File::create(log)?;
        let child = Command::new(binary)
            .args(args(port))
            .stdin(Stdio::null())
            .stdout(output.try_clone()?)
            .stderr(output)
            .spawn()
            .map_err(|error| {
                io::Error::new(error.kind(), format!("cannot start {}: {error}", binary.display()))
            })?;
        let address = SocketAddrV4::new([127, 0, 0, 1].into(), port);
        let mut daemon = Daemon { child, address };
        let failure = |what: &str| {
            io::Error::other(format!("{} {what}; see {}", binary.display(), log.display()))
        };
        let deadline = Instant::now() + STARTUP;
        // The probe comes from an address of its own: a probe from 127.0.0.1 to a port
        // nobody listens on yet can connect to itself (TCP simultaneous open) and pass.
        while connect_from(PROBE_SOURCE, address).is_err() {
            if let Some(status) = daemon.exited() {
                return Err(failure(&format!("exited during startup ({status})")));
            }
            if Instant::now() > deadline {
                return Err(failure(&format!("did not listen on {address}")));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        // A daemon that failed to bind may still be on its way out.
        std::thread::sleep(Duration::from_millis(50));
        if let Some(status) = daemon.exited() {
            return Err(failure(&format!("exited during startup ({status})")));
        }
        Ok(daemon)
    }

    /// The child's process id.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Returns the exit status when the daemon has stopped on its own.
    pub fn exited(&mut self) -> Option<String> {
        match self.child.try_wait() {
            Ok(Some(status)) => Some(status.to_string()),
            Ok(None) | Err(_) => None,
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // `Child::kill` sends SIGKILL to this child's process id; `wait` reaps it.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_binary_that_does_not_listen_is_reported() {
        let dir =
            std::env::temp_dir().join(format!("sibuna-parity-daemon-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("log.txt");
        let error = Daemon::start(Path::new("/bin/true"), |_| Vec::new(), &log).unwrap_err();
        assert!(error.to_string().contains("exited during startup"), "{error}");
        let missing =
            Daemon::start(Path::new("/nonexistent/sibuna"), |_| Vec::new(), &log).unwrap_err();
        assert!(missing.to_string().contains("cannot start"), "{missing}");
        let _ = std::fs::remove_dir_all(dir);
    }
}
