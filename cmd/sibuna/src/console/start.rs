//! Composition of the console in the daemon (Zig's `console_start.zig` `Runtime`): the
//! shared values the request path and the storage thread feed, the storage hooks, the
//! console keys, and the start of the console server with its banner.
//!
//! ```text
//! Seams::new                      telemetry, incident feed, GeoIP slot, clock, boot id
//!   -> Seams::extend_storage      console migrations, sidecars, committed feed, page reads
//!   -> Publisher::observed        rule-hit counters with every published engine
//!   -> Hooks::telemetry           the request path's seams
//!   -> start                      keys, Node, assets -> sibuna_console::Console::start
//! ```

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sibuna_console::config::Config as ConsoleConfig;
use sibuna_console::{
    AssetBytes, Console, GeoSlot, Inputs, KeyError, Keys, SystemClock, committed_hook, load_key,
    snapshot_hook,
};
use sibuna_console_protocol::ProxyMode;
use sibuna_console_protocol::challenges::{Algorithm, Defaults};
use sibuna_console_storage::accounts::is_setup_required;
use sibuna_console_storage::sidecars::incident_hook;
use sibuna_core::{Config, Mode};
use sibuna_crypto::ct;
use sibuna_storage::{Hooks, Storage};
use sibuna_store::incidents::ConsoleIncidents;
use sibuna_store::telemetry::ConsoleTelemetry;

use super::hits::Generations;
use super::node::DaemonNode;
use crate::server::{Server, VERSION};

/// The interface's files, embedded at build time (`build.rs` builds the module).
const ASSETS: AssetBytes = AssetBytes {
    wasm: include_bytes!(concat!(env!("OUT_DIR"), "/console.wasm")),
    glue: include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../console-ui/web/glue.js")),
    css: include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../console-ui/web/assets/console.css"
    )),
    shell: include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../console-ui/web/shell.html")),
    world: include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../console-ui/web/assets/world-110m.bin"
    )),
};

/// Why the console did not start.
#[derive(Debug)]
pub enum ConsoleError {
    /// No random bytes for the boot id could be read.
    Random,
    /// A console behind a proxy needs `--console-key-file` (it seals second factors).
    ConsoleKeyRequired,
    /// The peer key file is another secret's file, or holds the console key's bytes.
    PeerKeyReused,
    /// A key file was refused.
    Key(PathBuf, KeyError),
    /// The console server did not start.
    Start(sibuna_console::StartError),
}

impl ConsoleError {
    /// Returns a sentence that tells the operator how to fix the problem.
    pub fn hint(&self) -> &'static str {
        match self {
            ConsoleError::Random => "Check that /dev/urandom is readable.",
            ConsoleError::ConsoleKeyRequired => {
                "Give `--console-key-file` with `--console-behind-proxy`."
            }
            ConsoleError::PeerKeyReused => {
                "Give the management peers a key of their own, in a file of its own."
            }
            ConsoleError::Key(_, error) => error.hint(),
            ConsoleError::Start(_) => "Check the console options and the database.",
        }
    }
}

impl fmt::Display for ConsoleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConsoleError::Random => f.write_str("cannot read random bytes for the boot id"),
            ConsoleError::ConsoleKeyRequired => f.write_str("ConsoleKeyRequired"),
            ConsoleError::PeerKeyReused => f.write_str("PeerKeyReused"),
            ConsoleError::Key(path, error) => write!(f, "{}: {error}", path.display()),
            ConsoleError::Start(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ConsoleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConsoleError::Key(_, error) => Some(error),
            ConsoleError::Start(error) => Some(error),
            _ => None,
        }
    }
}

/// The values the console shares with the request path and the storage thread, built
/// before either starts.
#[derive(Debug)]
pub struct Seams {
    /// Outcome counters, request samples and challenge events from the request path.
    pub telemetry: Arc<ConsoleTelemetry>,
    /// Committed incidents from the storage thread.
    pub incidents: Arc<ConsoleIncidents>,
    /// The active GeoIP generation, shared with the incident sidecar hook.
    pub geo: Arc<GeoSlot>,
    /// The console's clocks, also stamping rule-hit generations.
    pub clock: Arc<SystemClock>,
    /// This process's boot id; never all zeros.
    pub boot: [u8; 16],
}

impl Seams {
    /// Allocates the telemetry rings and the incident feed and draws the boot id.
    ///
    /// Fails with [`ConsoleError::Random`] when no random bytes can be read.
    pub fn new() -> Result<Seams, ConsoleError> {
        let mut boot = [0u8; 16];
        while boot == [0; 16] {
            boot = sibuna_console::random::array().map_err(|_| ConsoleError::Random)?;
        }
        Ok(Seams {
            telemetry: Arc::new(ConsoleTelemetry::new()),
            incidents: Arc::new(ConsoleIncidents::new()),
            geo: Arc::new(GeoSlot::new()),
            clock: Arc::new(SystemClock::new()),
            boot,
        })
    }

    /// Adds the console to the storage thread's hooks: its migrations, the incident
    /// sidecars (with the country from the GeoIP slot), the committed-incident feed and the
    /// page templates of each snapshot.
    pub fn extend_storage(&self, hooks: &mut Hooks) {
        hooks.migrations.push(sibuna_console_storage::CONSOLE);
        hooks.on_incidents = Some(incident_hook(Some(self.geo.country_lookup())));
        hooks.on_committed = Some(committed_hook(Arc::clone(&self.incidents)));
        hooks.on_snapshot = Some(snapshot_hook());
    }

    /// Returns the numbering of node `node`'s rule-hit generations in this boot.
    pub fn generations(&self, node: u32) -> Generations {
        Generations::new(
            node,
            self.boot,
            Arc::clone(&self.clock) as Arc<dyn sibuna_console::Clock>,
        )
    }
}

/// Starts the console of `server` with `config`, over `storage`, fed by `seams`. `core` is
/// the daemon's configuration (node id, mode, secret files).
///
/// Fails with a [`ConsoleError`]; nothing keeps running after a failure.
pub fn start(
    config: ConsoleConfig,
    core: &Config,
    seams: &Seams,
    storage: Arc<Storage>,
    server: &Arc<Server>,
) -> Result<Console, ConsoleError> {
    if config.behind_proxy && config.key_file.is_none() {
        return Err(ConsoleError::ConsoleKeyRequired);
    }
    let keys = load_keys(&config, core)?;
    let inputs = Inputs {
        telemetry: Arc::clone(&seams.telemetry),
        incidents: Arc::clone(&seams.incidents),
        metrics: Arc::clone(&server.metrics),
        geo: Arc::clone(&seams.geo),
        node_id: core.node_id(),
        version: VERSION.to_owned(),
        proxy_mode: match core.mode {
            Mode::ReverseProxy => ProxyMode::ReverseProxy,
            Mode::ForwardAuth => ProxyMode::ForwardAuth,
        },
        challenge_defaults: challenge_defaults(server),
        keys,
        assets: ASSETS,
        clock: Arc::clone(&seams.clock) as Arc<dyn sibuna_console::Clock>,
        ..Inputs::new(storage, Arc::new(DaemonNode::new(Arc::clone(server))), seams.boot)
    };
    Console::start(config, inputs).map_err(ConsoleError::Start)
}

/// The challenge parameters the node issues by default, as the console shows them.
fn challenge_defaults(server: &Server) -> Defaults {
    let spec = server.coordinator().default_spec();
    match spec.algorithm {
        sibuna_challenge::Algorithm::Hashcash => Defaults {
            algorithm: Algorithm::Hashcash,
            difficulty: spec.difficulty,
            parameter: spec.hashcash_bits(),
            openings: 0,
        },
        sibuna_challenge::Algorithm::Posw => Defaults {
            algorithm: Algorithm::Posw,
            difficulty: spec.difficulty,
            parameter: spec.posw_depth(),
            openings: spec.posw_challenges,
        },
    }
}

/// Reads the console keys. The peer key must be a file of its own (not the console key's,
/// the master secret's or the database URL's) and hold other bytes than the console key.
fn load_keys(config: &ConsoleConfig, core: &Config) -> Result<Keys, ConsoleError> {
    let read = |path: &Path| load_key(path).map_err(|error| ConsoleError::Key(path.into(), error));
    let totp = config.key_file.as_deref().map(read).transpose()?;
    let peer = match (&config.peers.key_file, config.peers.targets.is_empty()) {
        (Some(path), false) => {
            let secrets = [
                config.key_file.as_deref(),
                core.secret_file.as_deref().map(Path::new),
                core.database_url_file.as_deref().map(Path::new),
            ];
            if secrets.iter().flatten().any(|other| *other == path.as_path()) {
                return Err(ConsoleError::PeerKeyReused);
            }
            let key = read(path)?;
            if totp.as_ref().is_some_and(|totp| ct::eq(totp.bytes(), key.bytes())) {
                return Err(ConsoleError::PeerKeyReused);
            }
            Some(key)
        }
        _ => None,
    };
    Ok(Keys { totp, peer })
}

/// Returns whether the console has no account yet, or `None` when storage cannot say.
pub fn is_uninitialized(storage: &Storage) -> Option<bool> {
    let required = storage.with_database(|db| async move {
        let mut tx = db.begin().await?;
        Ok(is_setup_required(&mut tx).await.ok())
    });
    required.ok().flatten()
}

/// The startup lines about the console, as Zig printed them: a reminder to bootstrap an
/// uninitialized console, its address, and the memory it may reserve (SID 0007, Invariant
/// I4).
pub fn banner(console: &Console, uninitialized: bool) -> String {
    let mut text = String::new();
    if uninitialized {
        text.push_str("Console is uninitialized. Stop Sibuna and run init-admin locally.\n");
    }
    text.push_str(&format!("Console: {}/console/\n", console.origin()));
    text.push_str(&format!(
        "Console capacity envelope: {} MiB; database/cache and allocator overhead are \
         separate.\n",
        console.reserved_bytes() / (1024 * 1024)
    ));
    text
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use sibuna_console::config::{PeerTarget, Peers};

    use super::*;

    fn key_file(dir: &Path, name: &str, byte: u8) -> PathBuf {
        use std::os::unix::fs::OpenOptionsExt;
        let path = dir.join(name);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        writeln!(file, "{}", format!("{byte:02x}").repeat(32)).unwrap();
        path
    }

    fn with_peer(key: &Path, peer_key: &Path) -> ConsoleConfig {
        ConsoleConfig {
            key_file: Some(key.into()),
            peers: Peers {
                targets: vec![PeerTarget { node: 2, origin: "https://peer.test".into() }],
                key_file: Some(peer_key.into()),
                ca_file: None,
            },
            ..ConsoleConfig::default()
        }
    }

    // console_start.zig `peerKey`: a peer key must not alias another key domain.
    #[test]
    fn a_peer_key_must_not_alias_another_secret() {
        let dir = std::env::temp_dir().join(format!("sibuna-keys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let console = key_file(&dir, "console.key", 0x11);
        let peer = key_file(&dir, "peer.key", 0x22);
        let same = key_file(&dir, "same.key", 0x11);
        let core = Config { secret_file: Some(peer.display().to_string()), ..Config::default() };
        let keys = load_keys(&with_peer(&console, &peer), &Config::default()).unwrap();
        assert!(keys.totp.is_some() && keys.peer.is_some());
        let aliases = [
            load_keys(&with_peer(&console, &console), &Config::default()),
            load_keys(&with_peer(&console, &peer), &core),
            load_keys(&with_peer(&console, &same), &Config::default()),
        ];
        for result in aliases {
            assert!(matches!(result, Err(ConsoleError::PeerKeyReused)), "{result:?}");
        }
        // Without peers the peer key is not read.
        let lone = ConsoleConfig { peers: Peers::default(), ..with_peer(&console, &console) };
        assert!(load_keys(&lone, &Config::default()).unwrap().peer.is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
