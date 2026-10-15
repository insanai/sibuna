//! The binary itself: `--help`, `--version`, the `INVALID COMMAND LINE` report, policy-file
//! diagnostics, secrets, the banner and the stop on SIGTERM.
//!
//! With `SIBUNA_ZIG_BINARY` naming a Zig build of the daemon, the shared outputs are also
//! compared with it byte for byte.

#![allow(clippy::unwrap_used)]

use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const SIBUNA: &str = env!("CARGO_BIN_EXE_sibuna");

fn run(binary: &str, args: &[&str]) -> Output {
    Command::new(binary).args(args).env_remove("SIBUNA_SECRET").output().unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn zig() -> Option<String> {
    std::env::var("SIBUNA_ZIG_BINARY").ok().filter(|path| !path.is_empty())
}

/// A fresh directory under the system temporary directory.
fn scratch_dir() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let name =
        format!("sibuna-cli-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed));
    let dir = std::env::temp_dir().join(name);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn version_prints_the_package_version() {
    let output = run(SIBUNA, &["--version"]);
    assert!(output.status.success());
    assert_eq!(stderr(&output), "sibuna 0.2.0\n");
    assert!(output.stdout.is_empty());
    if let Some(zig) = zig() {
        assert_eq!(stderr(&run(&zig, &["--version"])), stderr(&output));
    }
    // `--version` wins wherever it appears, before any other option is checked.
    assert!(run(SIBUNA, &["--bogus", "--version"]).status.success());
}

#[test]
fn help_lists_every_option() {
    let output = run(SIBUNA, &["-p", "1", "--help"]);
    assert!(output.status.success());
    let text = stderr(&output);
    // With the console, its options are listed first, as Zig listed them.
    #[cfg(feature = "console")]
    let text = text.strip_prefix(sibuna::console::HELP).unwrap().to_owned();
    assert_eq!(text, sibuna_core::config::HELP);
    for option in ["--max-connections", "--policy-file", "--database-url", "--storage-poll-ms"] {
        assert!(text.contains(option), "{option}");
    }
    if let Some(zig) = zig() {
        // The network, proof and surface sections are the Zig daemon's, line for line.
        let zig_help = stderr(&run(&zig, &["--help"]));
        let section = |text: &str| {
            let start = text.find("Usage: sibuna [options]").unwrap();
            let end = text.find("  --policy-file").unwrap();
            text[start..end].replace(
                "  --no-trust-forwarded         Never honour them, even in forward_auth mode\n",
                "",
            )
        };
        assert_eq!(section(&text), section(&zig_help));
    }
}

/// Command lines both daemons refuse, with the report the Rust daemon prints.
const REFUSED: [(&[&str], &str); 6] = [
    (&["--bogus"], "Option:   --bogus\nError:    UnknownOption\n"),
    (&["--port", "99999"], "Option:   --port\nValue:    99999\nExpected: a port 1-65535\n"),
    (&["--port"], "Option:   --port\nError:    MissingValue\n"),
    (&["--mode", "sideways"], "Option:   --mode\nValue:    sideways\n"),
    (&["-m", "proxy", "--mode", "auth"], "Option:   --mode\nError:    DuplicateMode\n"),
    (&["--difficulty", "lots"], "Option:   --difficulty\nValue:    lots\n"),
];

#[test]
fn invalid_command_lines_stop_with_the_diagnostic() {
    for (args, expected) in REFUSED {
        let output = run(SIBUNA, args);
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        let text = stderr(&output);
        assert!(text.starts_with("-- INVALID COMMAND LINE ----"), "{text}");
        assert!(text.contains("The daemon cannot start with this command line.\n\n"));
        assert!(text.contains(expected), "{args:?}: {text}");
        assert!(text.contains("\n\nHint: "));
        assert!(text.ends_with(".\n\n"), "{text:?}");
        if let Some(zig) = zig() {
            assert_eq!(text, stderr(&run(&zig, args)), "{args:?}");
        }
    }
    let exact = stderr(&run(SIBUNA, &["--port"]));
    assert_eq!(
        exact,
        "-- INVALID COMMAND LINE ----------------------------------------------------\n\n\
         The daemon cannot start with this command line.\n\nOption:   --port\n\
         Error:    MissingValue\n\n\nHint: Supply a value after the option.\n\n"
    );
}

#[test]
fn removed_cluster_options_name_the_storage_record() {
    let output = run(SIBUNA, &["--cluster-peer", "1@127.0.0.1:9901"]);
    assert_eq!(output.status.code(), Some(1));
    let text = stderr(&output);
    assert!(text.contains("Option:   --cluster-peer"));
    assert!(text.contains("SID 0011"));
}

/// Policy files both daemons reject, by what they contain.
const POLICIES: [&str; 5] = [
    r#"{"rules":[{"name":"r","path":"/x","action":"DENNY"}]}"#,
    r#"{"rules":[{"name":"r","path":"/x","action":"DENY","colour":"red"}]}"#,
    r#"{"rules":[{"name":"r","path":"/x""#,
    r#"{"default_action":"WEIGH"}"#,
    r#"{"rules":[{"name":"r","path":"/x","action":"WEIGH"}]}"#,
];

#[test]
fn rejected_policy_files_stop_startup_with_an_elm_style_diagnostic() {
    let dir = scratch_dir();
    for (index, policy) in POLICIES.iter().enumerate() {
        let path = dir.join(format!("policy-{index}.json"));
        std::fs::write(&path, policy).unwrap();
        let path = path.to_str().unwrap();
        let args = ["--port", "1", "--policy-file", path];
        let output = run(SIBUNA, &args);
        assert_eq!(output.status.code(), Some(1), "{policy}");
        let text = stderr(&output);
        assert!(text.starts_with("-- "), "{text}");
        assert!(text.contains(&format!("File:   {path}\nError:  ")), "{text}");
        assert!(text.contains("\n\nHint: "), "{text}");
        if let Some(zig) = zig() {
            assert_eq!(text, stderr(&run(&zig, &args)), "{policy}");
        }
    }
    let text = stderr(&run(SIBUNA, &["--policy-file", "/nonexistent/policy.json"]));
    assert_eq!(
        text,
        "POLICYFILE: unable to open policy file /nonexistent/policy.json: FileNotFound. Hint: \
         check the path and permissions, or omit --policy-file.\n"
    );
    let first =
        stderr(&run(SIBUNA, &["--policy-file", dir.join("policy-0.json").to_str().unwrap()]));
    assert!(first.starts_with("-- INVALID POLICY ACTION"), "{first}");
    assert!(first.contains("Rule:   r\nField:  action\nValue:  DENNY\n"), "{first}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn unusable_secrets_stop_startup() {
    let text = stderr(&run(SIBUNA, &["--secret-file", "/nonexistent/seed"]));
    assert_eq!(text, "Cannot open secret file /nonexistent/seed: FileNotFound\n");
    let dir = scratch_dir();
    let path = dir.join("seed");
    std::fs::write(&path, "too short").unwrap();
    let path = path.to_str().unwrap();
    let text = stderr(&run(SIBUNA, &["--secret-file", path]));
    assert_eq!(text, format!("Secret file {path} must hold 64 hex characters or 32 raw bytes\n"));
    let output = Command::new(SIBUNA).env("SIBUNA_SECRET", "nothex").output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stderr(&output), "SIBUNA_SECRET must hold 64 hex characters\n");
    // A secret that is not UTF-8 is refused, not taken for an unset variable.
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let mut invalid = vec![b'a'; 63];
        invalid.push(0xff);
        let invalid = std::ffi::OsStr::from_bytes(&invalid);
        let output = Command::new(SIBUNA).env("SIBUNA_SECRET", invalid).output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(stderr(&output), "SIBUNA_SECRET must hold 64 hex characters\n");
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(not(feature = "console"))]
#[test]
fn the_console_subcommand_needs_the_console_feature() {
    let output = run(SIBUNA, &["console", "users"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).starts_with("CONSOLEBUILD: console support is not compiled."));
}

/// A daemon process whose standard error is read line by line.
struct Daemon {
    child: Child,
    lines: Vec<String>,
}

impl Daemon {
    fn spawn(binary: &str, args: &[&str]) -> Daemon {
        let child = Command::new(binary)
            .args(args)
            .env_remove("SIBUNA_SECRET")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        Daemon { child, lines: Vec::new() }
    }

    /// Reads standard error until the banner's closing rule.
    fn read_banner(&mut self) -> String {
        let stderr = self.child.stderr.as_mut().unwrap();
        let mut reader = BufReader::new(stderr);
        let mut rules = 0;
        while rules < 3 {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 {
                break;
            }
            if line.starts_with("-----") {
                rules += 1;
            }
            self.lines.push(line);
        }
        self.lines.concat()
    }

    fn terminate(&mut self) -> Option<i32> {
        let pid = self.child.id().to_string();
        Command::new("kill").args(["-TERM", &pid]).status().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status.code();
            }
            assert!(Instant::now() < deadline, "the daemon ignored SIGTERM");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[test]
fn the_banner_describes_the_configuration_and_sigterm_stops_the_daemon() {
    let port = free_port().to_string();
    let args = ["--host", "127.0.0.1", "--port", &port, "--gate", "-a", "hashcash", "-d", "12"];
    let mut daemon = Daemon::spawn(SIBUNA, &args);
    let banner = daemon.read_banner();
    assert!(banner.contains(&format!("Listening:   127.0.0.1:{port}\n")), "{banner}");
    assert!(banner.contains("Proof:       hashcash at 12 work bits (mac tokens)\n"));
    assert!(banner.contains("Surface:     gate (challenge only)\n"));
    assert!(banner.contains("Storage:     in-memory only\n"));
    assert!(banner.contains("Secret:      random (set --secret-file)\n"));
    // A connection held open does not keep the daemon from stopping.
    let mut held =
        std::net::TcpStream::connect(("127.0.0.1", port.parse::<u16>().unwrap())).unwrap();
    assert_eq!(daemon.terminate(), Some(0));
    let mut rest = Vec::new();
    let _ = held.read_to_end(&mut rest);
    if let Some(zig) = zig() {
        let port = free_port().to_string();
        let args =
            ["--host", "127.0.0.1", "--port", &port, "--gate", "-a", "hashcash", "-d", "12"];
        let mut theirs = Daemon::spawn(&zig, &args);
        let expected = theirs.read_banner();
        theirs.terminate();
        let mut ours = Daemon::spawn(SIBUNA, &args);
        assert_eq!(ours.read_banner(), expected);
        assert_eq!(ours.terminate(), Some(0));
    }
}

#[test]
fn a_listener_that_cannot_bind_is_reported() {
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port().to_string();
    let output = run(SIBUNA, &["--host", "127.0.0.1", "--port", &port]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains(&format!("Failed to bind socket on port {port}: AddressInUse"))
    );
    let output = run(SIBUNA, &["--host", "localhost"]);
    assert!(stderr(&output).contains("Failed to parse listen address localhost:8080"));
}

#[cfg(not(feature = "storage"))]
#[test]
fn storage_options_need_a_storage_build() {
    let output = run(SIBUNA, &["--data-dir", "/tmp"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("Failed to start persistent storage: StorageDisabled"));
}
