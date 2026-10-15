//! The console's command line (milestone A of the console port): the `CONSOLE001` and
//! `CONSOLE002` diagnostics, the offline `init-admin` bootstrap and its `CONSOLEBOOT`
//! refusal, the help text, and `sibuna console ...` handed to the console's commands.
#![cfg(feature = "console")]
#![allow(clippy::unwrap_used)]

use std::process::{Command, Output};

const SIBUNA: &str = env!("CARGO_BIN_EXE_sibuna");

fn run(args: &[&str]) -> Output {
    Command::new(SIBUNA).args(args).output().unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_console_without_storage_is_refused_with_console001() {
    let output = run(&["--console", "127.0.0.1:9443"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        stderr(&output),
        "CONSOLE001: console configuration rejected (StorageRequired). Hint: configure \
         storage and a trusted HTTPS ingress for remote access.\n"
    );
    let off_loopback = run(&["--console", "0.0.0.0:9443", "--data-dir", "/nonexistent"]);
    assert!(stderr(&off_loopback).contains("(TrustedProxyRequired)"), "{off_loopback:?}");
}

#[test]
fn invalid_console_options_are_refused_with_console002() {
    let output = run(&["--console", "127.0.0.1:9443", "--console-query-steps", "4M"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        stderr(&output),
        "CONSOLE002: invalid console options (InvalidQuerySteps). Hint: check --console \
         host:port, proxy settings, and query steps (100000-50000000, supplied once).\n"
    );
    let unknown = run(&["--console-mistake", "1"]);
    assert!(stderr(&unknown).contains("(UnknownConsoleOption)"));
}

#[test]
fn init_admin_creates_one_administrator_offline() {
    let dir = std::env::temp_dir().join(format!("sibuna-console-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.to_str().unwrap();
    let output = run(&["init-admin", "admin", "--data-dir", path]);
    let text = stderr(&output);
    assert!(output.status.success(), "{text}");
    assert!(text.starts_with("Console administrator created: admin\n"), "{text}");
    assert!(text.contains("Temporary console password (expires in one hour): "), "{text}");
    let again = run(&["console", "init-admin", "admin", "--data-dir", path]);
    assert_eq!(again.status.code(), Some(1));
    assert!(
        stderr(&again).starts_with(
            "CONSOLEBOOT: local initialization failed (AlreadyInitialized). Hint: use \
             --data-dir with a stopped, uninitialized Sibuna instance."
        ),
        "{again:?}"
    );
    let memory = run(&["init-admin", "admin"]);
    assert!(stderr(&memory).contains("(StorageRequired)"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn help_lists_the_console_options_and_commands_reach_the_console() {
    let help = stderr(&run(&["--help"]));
    assert!(help.starts_with("Local bootstrap: sibuna init-admin"), "{help}");
    assert!(help.contains("--console-peer-ca-file"));
    // A console command is never parsed as daemon options.
    let output = run(&["console", "users"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(!stderr(&output).contains("INVALID COMMAND LINE"), "{output:?}");
}
