//! The daemon with its console (milestone A of the console port): the offline bootstrap,
//! the start order (storage with the console's hooks, the console server, the data plane),
//! rule-hit counters published with the stored policy, the drain flag in the accept loop,
//! and a clean stop.
#![cfg(feature = "console")]
#![allow(clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

use sibuna::console::init::{self, InitError};
use sibuna::{Daemon, DaemonOptions, Hooks, Recipe, StartError};
use sibuna_challenge::Seed;
use sibuna_core::Config;

/// A fresh data directory under the system's temporary directory.
fn data_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sibuna-console-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn config(dir: &std::path::Path) -> Config {
    Config {
        data_dir: Some(dir.to_str().unwrap().to_owned()),
        upstream_port: 9,
        workers: 1,
        ..Config::default()
    }
}

fn start(config: &Config) -> Result<Daemon, StartError> {
    let console = sibuna_console::Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        ..sibuna_console::Config::default()
    };
    start_with(config, console)
}

fn start_with(config: &Config, console: sibuna_console::Config) -> Result<Daemon, StartError> {
    let options = DaemonOptions {
        config: config.clone(),
        recipe: Recipe::new(config, None),
        seed: Seed::new([7; 32]),
        hooks: Hooks::default(),
    };
    Daemon::start_with_console(options, console, TcpListener::bind("127.0.0.1:0").unwrap())
}

/// Sends `GET path` with `Connection: close` and returns the whole response as text.
fn get(address: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(address).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response).into_owned()
}

#[test]
fn the_daemon_runs_its_console_beside_the_data_plane() {
    let dir = data_dir("daemon");
    let config = config(&dir);
    let password = init::run(&config, "admin").unwrap();
    assert_eq!(password.len(), 48);
    assert!(matches!(init::run(&config, "admin"), Err(InitError::AlreadyInitialized)));
    let daemon = start(&config).unwrap();
    let console = daemon.console().unwrap();
    let setup = get(console.address(), "/console/api/setup");
    assert!(setup.starts_with("HTTP/1.1 200"), "{setup}");
    assert!(setup.ends_with("{\"setup_required\":false}"), "{setup}");
    assert!(console.reserved_bytes() > 0);
    // The stored policy was published with rule-hit counters.
    let hits = daemon.server().unwrap().slot().load_hits().unwrap();
    assert!(hits.generation().number >= 1);
    // The accept loop answers 503 while the node drains.
    let address = daemon.address().unwrap();
    daemon.server().unwrap().set_draining(true);
    let drained = get(address, "/__sibuna/health");
    assert!(drained.starts_with("HTTP/1.1 503"), "{drained}");
    assert!(drained.contains("node is draining"), "{drained}");
    daemon.server().unwrap().set_draining(false);
    assert!(get(address, "/__sibuna/health").starts_with("HTTP/1.1 200"));
    assert!(daemon.stop());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_console_needs_storage() {
    let error = start(&Config::default()).unwrap_err();
    assert!(matches!(error, StartError::StorageDisabled));
}

#[test]
fn a_console_that_cannot_start_releases_storage() {
    let dir = data_dir("refused");
    let config = config(&dir);
    // Behind a proxy the console needs a key file to seal second factors.
    let refused = sibuna_console::Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        behind_proxy: true,
        ..sibuna_console::Config::default()
    };
    let error = start_with(&config, refused).unwrap_err();
    assert!(error.to_string().contains("ConsoleKeyRequired"), "{error}");
    // Storage was stopped: the same database starts again at once.
    let daemon = start(&config).unwrap();
    assert!(daemon.stop());
    std::fs::remove_dir_all(&dir).unwrap();
}
