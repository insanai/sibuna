//! A server under test started with an explicit command line and environment: Anubis in
//! every run that compares with it, and Sibuna in the admission runs, whose flags differ from
//! those of the product runs. The server is ready when a probe request answers with the
//! status we expect, as `tools.py` and `compare.py` waited.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::daemon::browser_headers;
use crate::error::{Error, Result};
use crate::http;
use crate::process::{self, CpuSet, Process};

/// How to start a server and how to tell that it is ready.
#[derive(Debug)]
pub struct Launch<'a> {
    /// The name of the process and its log file.
    pub label: &'a str,
    /// The program to run.
    pub binary: &'a Path,
    /// Its arguments.
    pub args: Vec<String>,
    /// Variables added to the inherited environment.
    pub env: Vec<(&'static str, String)>,
    /// The CPUs every thread of the server is pinned to.
    pub cpus: &'a CpuSet,
    /// The port the arguments make it listen on, on 127.0.0.1.
    pub port: u16,
    /// The directory of its log file.
    pub log_dir: &'a Path,
    /// The target of the readiness probe, sent with the browser headers.
    pub probe: &'a str,
    /// The status the probe answers with once the server is ready.
    pub ready_status: u16,
}

/// A running server, stopped when dropped.
#[derive(Debug)]
pub struct Server {
    /// The process.
    pub process: Process,
    /// The port it listens on.
    pub port: u16,
    /// Its log file.
    pub log: PathBuf,
}

impl Server {
    /// Starts the server `launch` describes and waits until its probe answers with the
    /// expected status.
    ///
    /// # Errors
    ///
    /// Fails when the server cannot start, exits, or is not ready within 30 seconds; the
    /// message carries the end of its log.
    pub fn start(launch: Launch<'_>) -> Result<Server> {
        let log = launch.log_dir.join(format!("{}.log", launch.label));
        let process = Process::spawn_with_env(
            launch.label,
            launch.binary,
            &launch.args,
            &launch.env,
            Some(launch.cpus),
            Some(&log),
        )?;
        let mut server = Server { process, port: launch.port, log };
        server.wait_ready(launch.probe, launch.ready_status)?;
        Ok(server)
    }

    /// Returns the server's process id.
    pub fn pid(&self) -> u32 {
        self.process.pid()
    }

    fn wait_ready(&mut self, probe: &str, status: u16) -> Result<()> {
        let headers = browser_headers();
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut last = String::from("no answer");
        while Instant::now() < deadline {
            if !self.process.is_running() {
                return Err(self.failure("exited during startup"));
            }
            match http::request(self.port, "GET", probe, &headers, b"") {
                Ok(response) if response.status == status => return Ok(()),
                Ok(response) => last = format!("status {}", response.status),
                Err(error) => last = error.message,
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let what = format!("did not answer {probe} with {status} within 30 seconds ({last})");
        Err(self.failure(&what))
    }

    fn failure(&self, what: &str) -> Error {
        let name = self.process.name();
        Error::new(
            "SERVER FAILED",
            format!("{name} {what}. Its log ends:\n{}", process::tail(&self.log, 2000)),
        )
        .hint("Run the server by hand with the same flags to see the problem.")
    }
}
