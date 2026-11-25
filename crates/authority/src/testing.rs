//! Test support: a PostgreSQL server of our own in a temporary directory, on loopback,
//! with password authentication. It uses the `initdb` and `pg_ctl` installed on this
//! machine and never touches a database service that already runs. Without those
//! programs [`Postgres::start`] returns `None` and says so, and the test is skipped.

// Test support: a failure to set up the server is reported by panicking.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::print_stderr)]

use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

/// The superuser of the test server.
pub const ROLE: &str = "sibuna";
/// The password of [`ROLE`].
pub const PASSWORD: &str = "edge-test-password";

/// A PostgreSQL server in a directory of its own. Dropping it stops the server and
/// removes the directory.
pub struct Postgres {
    bin: PathBuf,
    home: PathBuf,
    port: u16,
    running: bool,
}

/// The directory that holds `initdb` and `pg_ctl`, if PostgreSQL is installed.
fn bin_directory() -> Option<PathBuf> {
    let has_tools = |dir: &Path| dir.join("initdb").is_file() && dir.join("pg_ctl").is_file();
    let path = std::env::var_os("PATH").unwrap_or_default();
    if let Some(dir) = std::env::split_paths(&path).find(|dir| has_tools(dir)) {
        return Some(dir);
    }
    // Debian and Fedora keep the server programs outside the search path.
    let mut found: Vec<PathBuf> = ["/usr/lib/postgresql", "/usr/pgsql", "/usr/local/pgsql"]
        .iter()
        .filter_map(|root| fs::read_dir(root).ok())
        .flatten()
        .filter_map(|entry| Some(entry.ok()?.path().join("bin")))
        .chain([PathBuf::from("/usr/local/pgsql/bin"), PathBuf::from("/opt/homebrew/bin")])
        .filter(|dir| has_tools(dir))
        .collect();
    found.sort();
    found.pop()
}

fn quiet(command: &mut Command) -> bool {
    command
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

impl Postgres {
    /// Creates a database cluster in a new temporary directory and starts its server on
    /// a free loopback port. Returns `None`, with a line on standard error, when
    /// PostgreSQL is not installed. Panics when an installed PostgreSQL does not start.
    pub fn start(name: &str) -> Option<Postgres> {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let Some(bin) = bin_directory() else {
            eprintln!("skipped: no initdb and pg_ctl on this machine, PostgreSQL is not tested");
            return None;
        };
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let home =
            std::env::temp_dir().join(format!("sibuna-pg-{}-{serial}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&home).expect("a directory for the test server");
        fs::write(home.join("password"), PASSWORD).expect("the password file");
        let mut initdb = Command::new(bin.join("initdb"));
        initdb.arg("-D").arg(home.join("data")).args(["-U", ROLE, "--auth=scram-sha-256"]);
        initdb.arg(format!("--pwfile={}", home.join("password").display()));
        initdb.args(["--no-sync", "-E", "UTF8", "--locale=C"]);
        assert!(quiet(&mut initdb), "initdb failed in {}", home.display());
        let mut server = Postgres { bin, home, port: 0, running: false };
        // A port that was free a moment ago may be taken by a test beside this one.
        for _ in 0..5 {
            let free = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
            server.port = free.local_addr().expect("its address").port();
            drop(free);
            if server.resume() {
                return Some(server);
            }
        }
        panic!("the PostgreSQL test server did not start; see {}", server.home.display());
    }

    /// Starts the server again after [`Postgres::stop`], on the same port. Returns
    /// whether it accepts connections.
    pub fn resume(&mut self) -> bool {
        let options = format!(
            "-p {} -c listen_addresses=127.0.0.1 -c unix_socket_directories={} -c fsync=off \
             -c max_connections=60",
            self.port,
            self.home.display()
        );
        let mut start = Command::new(self.bin.join("pg_ctl"));
        start.arg("-D").arg(self.home.join("data")).arg("-l").arg(self.home.join("log"));
        start.args(["-w", "-t", "30", "-o", &options, "start"]);
        self.running = quiet(&mut start);
        self.running
    }

    /// Stops the server at once, as a crash or a lost host does. Its data stays.
    pub fn stop(&mut self) {
        let mut stop = Command::new(self.bin.join("pg_ctl"));
        stop.arg("-D").arg(self.home.join("data")).args(["-m", "immediate", "-w", "stop"]);
        quiet(&mut stop);
        self.running = false;
    }

    /// The address of the server.
    pub fn address(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }

    /// The directory of the server, for the files of a test.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// The URL of `database` for `role` with `password`.
    pub fn url(&self, role: &str, password: &str, database: &str) -> String {
        format!("postgres://{role}:{password}@127.0.0.1:{}/{database}", self.port)
    }

    /// Writes the URL of `database` for `role` into a file named `name` in the
    /// directory of the server, readable by its owner alone, and returns its path.
    pub fn url_file(&self, name: &str, role: &str, password: &str, database: &str) -> PathBuf {
        let path = self.home.join(name);
        fs::write(&path, self.url(role, password, database)).expect("the URL file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode 0600");
        }
        path
    }

    /// Runs a script of SQL statements in `database` as the superuser. Panics when the
    /// server refuses it.
    pub fn execute(&self, database: &str, script: &str) {
        let target = sibuna_storage::Target::Postgres(self.url(ROLE, PASSWORD, database));
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build();
        runtime.expect("a runtime").block_on(async {
            let db = sibuna_storage::Database::open(&target).await.expect("the test server");
            db.execute_script(script).await.expect(script);
            db.close().await;
        });
    }
}

impl Drop for Postgres {
    fn drop(&mut self) {
        if self.running {
            self.stop();
        }
        let _ = fs::remove_dir_all(&self.home);
    }
}
