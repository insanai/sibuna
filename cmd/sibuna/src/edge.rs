//! Edge-mode startup, reload at batch boundaries and bounded shutdown. The quick start,
//! the admin socket and the file watcher of SID 0018 live in the submodules.

mod admin;
mod control;
mod ctl;
mod failure;
mod http;
#[cfg(feature = "https")]
mod inline;
mod quick;
mod watch;
mod workers;

use std::fs::File;
use std::io::{self, Read};
use std::process::ExitCode;
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::time::{Duration, Instant};

use sibuna_lb::{Config, Edge, RuntimeError};

use crate::signals::{self, Shutdown};
use control::Command;
use watch::{Source, Watcher};

pub(crate) fn command(args: &[String], secret: Option<&str>) -> Option<ExitCode> {
    let path = match args {
        [word, rest @ ..] if word == "lb" => return Some(quick::run(rest, secret)),
        [word, rest @ ..] if word == "ctl" => return Some(ctl::run(rest)),
        [option, path] if option == "--config-file" => path,
        [check, option, path] if check == "check" && option == "-f" => path,
        _ => return None,
    };
    let result = if args[0] == "check" {
        // Build the origin adapters too, so a bad CA file fails the check.
        load(path).and_then(|mut revision| adapt(&mut Adapters::default(), &mut revision.config))
    } else {
        // The source records the stamp of the file that the daemon starts with.
        let source = Source::file(path);
        source.load().and_then(|revision| serve(source, revision, secret))
    };
    Some(match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            failure::report(Some(path), &error);
            ExitCode::FAILURE
        }
    })
}

struct Revision {
    config: Config,
    http: Option<http::Prepared>,
}

fn load(path: &str) -> io::Result<Revision> {
    let config = topology(path)?;
    let http = http::Prepared::load(&config)?;
    Ok(Revision { config, http })
}
fn topology(path: &str) -> io::Result<Config> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(Config::DOCUMENT_LIMITS.max_input_bytes as u64 + 1)
        .read_to_end(&mut bytes)?;
    if std::path::Path::new(path).extension().is_some_and(|ext| ext == "jlv") {
        #[cfg(feature = "jlv")]
        return sibuna_jlv::parse(path, &bytes);
        #[cfg(not(feature = "jlv"))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this build needs the jlv feature for .jlv files",
        ));
    }
    Config::parse(&bytes)
}

/// The slot where the signal thread and the watcher leave a checked revision.
type Pending = Arc<Mutex<Option<Revision>>>;

/// Loads the source and leaves the revision for the worker, or logs why it was rejected.
fn offer(source: &Source, pending: &Pending) {
    match source.load() {
        Ok(next) => *pending.lock().unwrap_or_else(PoisonError::into_inner) = Some(next),
        Err(error) => eprintln!("EDGE002: keeping current routes: {error}"),
    }
}

/// The `ADM008` failure of a reload that kept the serving revision.
fn reload_rejected(error: io::Error) -> RuntimeError {
    control::failure(
        "ADM008",
        "RELOAD REJECTED",
        format!("The serving routes are unchanged: {error}."),
        "Check the file with `sibuna check -f FILE`, correct it and run `reload` again.",
    )
}

/// The `ADM008` failure of a reload in a daemon that `sibuna lb` started.
fn nothing_to_reload() -> RuntimeError {
    control::failure(
        "ADM008",
        "RELOAD REJECTED",
        "The daemon was started by `sibuna lb` and has no file to reload.",
        "Print the topology with `sibuna lb ... --print-config`, save it, and start the \
         daemon with `--config-file`.",
    )
}

/// What the edge worker owns while it serves.
struct Serving {
    edge: Edge,
    http: Option<http::Http>,
    adapters: Adapters,
    source: Arc<Source>,
    pending: Pending,
    watcher: Watcher,
    /// The path of the admin socket. A reload cannot change it.
    admin_socket: Option<String>,
    /// How long a shutdown waits for established flows (`global.shutdown_timeout`).
    shutdown_timeout: Duration,
    started: Instant,
    reloads: u64,
}

impl Serving {
    /// Applies a checked revision and returns the log line. A drain stays while the
    /// file still describes its server. Every other run-time change gives way.
    fn reload(&mut self, revision: Revision) -> io::Result<String> {
        if revision.config.admin_socket() != self.admin_socket.as_deref() {
            return Err(io::Error::other("changing global.admin_socket requires a restart"));
        }
        let watch = revision.config.watch();
        let shutdown_timeout = revision.config.shutdown_timeout();
        let before = self.edge.change_count();
        reload(&mut self.edge, self.http.as_mut(), &mut self.adapters, revision)?;
        self.reloads += 1;
        self.shutdown_timeout = shutdown_timeout;
        self.watch(watch)?;
        let kept = self.edge.change_count();
        let mut line = "Sibuna edge routes reloaded".to_owned();
        if before > 0 {
            let replaced = before.saturating_sub(kept);
            let plural = |count: usize| if count == 1 { "" } else { "s" };
            line.push_str(&format!(
                ": {kept} drain{} kept, {replaced} run-time change{} replaced by the file",
                plural(kept),
                plural(replaced)
            ));
        }
        Ok(line)
    }

    /// Turns the file watcher on or off, or changes its interval.
    fn watch(&self, interval: Option<Duration>) -> io::Result<()> {
        let pending = Arc::clone(&self.pending);
        self.watcher.set(interval, &self.source, move |source| offer(source, &pending))
    }

    /// Applies the revision that the signal thread or the watcher left, if any.
    fn take_pending(&mut self) {
        let next = self.pending.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let Some(next) = next {
            match self.reload(next) {
                Ok(line) => eprintln!("{line}"),
                Err(error) => eprintln!("EDGE002: keeping current routes: {error}"),
            }
        }
    }

    /// Runs one admin command and answers it. A command that changed state is logged.
    fn answer(&mut self, job: admin::Job) {
        let admin::Job { line, command, revision, reply } = job;
        let changes = command.changes();
        let answer = self.run(command, revision);
        if changes && answer.is_ok() {
            eprintln!("EDGE010: admin: {line}");
        }
        // The client may have given up. Its answer is then dropped.
        let _ = reply.try_send(answer);
    }

    fn run(
        &mut self,
        command: Command,
        revision: Option<Revision>,
    ) -> Result<String, RuntimeError> {
        let edge = &mut self.edge;
        let done = |()| String::new();
        match command {
            Command::ShowServers => Ok(control::render_servers(&edge.servers())),
            Command::ShowInfo => Ok(self.info()),
            Command::Help => Ok(control::USAGE.to_owned()),
            Command::State { pool, name, state } => {
                edge.set_server_state(&pool, &name, state).map(done)
            }
            Command::Weight { pool, name, weight } => {
                edge.set_server_weight(&pool, &name, weight).map(done)
            }
            Command::Add { pool, name, addr, weight } => {
                edge.add_server(&pool, &name, addr, weight).map(done)
            }
            Command::Del { pool, name } => edge.remove_server(&pool, &name).map(done),
            Command::Reload => {
                let revision = revision
                    .ok_or_else(|| reload_rejected(io::Error::other("the file was not loaded")))?;
                let line = self.reload(revision).map_err(reload_rejected)?;
                eprintln!("{line}");
                Ok(format!("{line}\n"))
            }
        }
    }

    /// The answer to `show info`: one `key: value` per line.
    fn info(&self) -> String {
        let servers = self.edge.servers();
        let drained =
            servers.iter().filter(|server| server.state == sibuna_lb::ServerState::Drain).count();
        let watch = match self.watcher.interval() {
            Some(interval) => format!("{}s", interval.as_secs()),
            None => "off".to_owned(),
        };
        let mut text = format!(
            "version: {}\npid: {}\nsource: {}\nuptime_seconds: {}\nreloads: {}\nwatch: {watch}\n\
             flows: {}\ndrops: {}\nservers: {}\ndrained: {drained}\nruntime_changes: {}\n",
            crate::server::VERSION,
            std::process::id(),
            self.source.path().unwrap_or("quick start, no file"),
            self.started.elapsed().as_secs(),
            self.reloads,
            self.edge.active(),
            self.edge.dropped(),
            servers.len(),
            self.edge.change_count(),
        );
        for removed in self.edge.removed_servers() {
            text.push_str(&format!("removed: {removed}\n"));
        }
        text
    }
}

/// The most admin commands applied between two readiness batches.
const COMMANDS_PER_STEP: usize = 16;

fn serve(source: Source, revision: Revision, secret: Option<&str>) -> io::Result<()> {
    let shutdown = Shutdown::new();
    let source = Arc::new(source);
    let pending = Pending::default();
    let (hup_source, slot) = (Arc::clone(&source), Arc::clone(&pending));
    signals::install_edge(Arc::clone(&shutdown), move || offer(&hup_source, &slot))
        .map_err(io::Error::other)?;
    let Revision { mut config, http } = revision;
    let mut adapters = Adapters::default();
    adapt(&mut adapters, &mut config)?;
    let mesh = config.mesh().map(start_mesh).transpose()?;
    let admin_socket = config.admin_socket().map(str::to_owned);
    let takeover = config.reuse_port();
    let watch = config.watch();
    let shutdown_timeout = config.shutdown_timeout();
    let mut current = sibuna_lb::Regime::Standalone;
    let edge = Edge::bind(config)?;
    let http = http.map(|p| http::Http::start(p, &edge, secret)).transpose()?;
    attach(http.as_ref(), &adapters);
    let (jobs, inbox) = mpsc::channel();
    let _admin = match &admin_socket {
        Some(path) => Some(admin::Admin::start(path, takeover, Arc::clone(&source), jobs)?),
        None => None,
    };
    let watcher = Watcher::new();
    let started = Instant::now();
    let mut serving = Serving {
        edge,
        http,
        adapters,
        source,
        pending,
        watcher,
        admin_socket,
        shutdown_timeout,
        started,
        reloads: 0,
    };
    serving.watch(watch)?;
    eprintln!("Sibuna edge listeners ready");
    while !shutdown.is_requested() {
        serving.take_pending();
        for job in inbox.try_iter().take(COMMANDS_PER_STEP) {
            serving.answer(job);
        }
        if let Some(mesh) = &mesh {
            let regime = mesh.regime();
            if current != regime {
                serving.edge.set_regime(regime);
                eprintln!("Sibuna edge routing regime: {regime:?}");
                current = regime;
            }
        }
        step(&mut serving.edge, serving.http.as_ref())?;
    }
    drop(mesh);
    let Serving { mut edge, http, shutdown_timeout, .. } = serving;
    edge.drain();
    if let Some(http) = &http {
        http.drain();
    }
    let deadline = Instant::now() + shutdown_timeout;
    while edge.active() > 0 && Instant::now() < deadline {
        step(&mut edge, http.as_ref())?;
    }
    eprintln!("Sibuna edge stopped: {} forced closes, {} drops", edge.active(), edge.dropped());
    Ok(())
}

fn step(edge: &mut Edge, http: Option<&http::Http>) -> io::Result<()> {
    edge.step()?;
    if let Some(http) = http {
        for (bind, stream, permit) in edge.accepted_http() {
            http.accept(bind, stream, permit);
        }
    }
    Ok(())
}

fn reload(
    edge: &mut Edge,
    http: Option<&mut http::Http>,
    adapters: &mut Adapters,
    mut revision: Revision,
) -> io::Result<()> {
    match (http, revision.http) {
        (None, None) => edge.reload(revision.config),
        (Some(http), Some(prepared)) if http.compatible(&prepared) => {
            adapt(adapters, &mut revision.config)?;
            edge.reload(revision.config)?;
            // The engine follows the routes at once. A request decided under the old
            // engine in between is routed by the old revision (SID 0018). The adapters
            // of that revision close last.
            http.reload(prepared);
            commit(adapters);
            // A reload may have started the first adapters.
            attach(Some(http), adapters);
            Ok(())
        }
        _ => Err(io::Error::other(
            "changing HTTP firewall settings or TLS listeners requires a restart",
        )),
    }
}

/// The protocol adapters towards TLS, HTTP/2 and HTTP/3 origins, started on first use.
#[cfg(feature = "https")]
type Adapters = Option<sibuna_ingress::Egress>;
#[cfg(not(feature = "https"))]
type Adapters = Option<std::convert::Infallible>;

/// Routes each pool with `http_version` or `tls` through its adapters.
fn adapt(adapters: &mut Adapters, config: &mut Config) -> io::Result<()> {
    if adapters.is_none() && config.origins().is_empty() {
        return Ok(());
    }
    #[cfg(feature = "https")]
    {
        let egress = match adapters {
            Some(egress) => egress,
            None => adapters.insert(sibuna_ingress::Egress::new()?),
        };
        egress.configure(config).map_err(io::Error::other)
    }
    #[cfg(not(feature = "https"))]
    Err(io::Error::other("TLS, HTTP/2 and HTTP/3 origins require the https feature"))
}

/// Lets requests of HTTP/2 and HTTP/3 clients reach the HTTP/2 and HTTP/3 servers of
/// the adapters without an HTTP/1.1 hop (SID 0017).
fn attach(http: Option<&http::Http>, adapters: &Adapters) {
    #[cfg(feature = "https")]
    if let (Some(http), Some(egress)) = (http, adapters) {
        http.attach(egress.directory());
    }
    #[cfg(not(feature = "https"))]
    let _ = (http, adapters);
}

/// Closes the adapters that the reloaded topology no longer uses.
fn commit(adapters: &mut Adapters) {
    #[cfg(feature = "https")]
    if let Some(egress) = adapters {
        egress.commit();
    }
    #[cfg(not(feature = "https"))]
    let _ = adapters;
}

fn start_mesh(spec: &sibuna_lb::MeshConfig) -> io::Result<sibuna_lb::Mesh> {
    let mut key = [0; 32];
    let mut file = File::open(&spec.key_file)?;
    file.read_exact(&mut key)?;
    if file.read(&mut [0])? != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "mesh key must be 32 bytes"));
    }
    let mut boot = [0; 16];
    crate::random::fill(&mut boot)?;
    sibuna_lb::Mesh::start(spec, &key, boot)
}
