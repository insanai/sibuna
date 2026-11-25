//! Edge-mode startup, reload at batch boundaries and bounded shutdown. The quick start,
//! the admin socket and the file watcher of SID 0018 live in the submodules.

mod admin;
mod authority;
#[cfg(feature = "https")]
mod automatic;
mod cluster;
mod control;
mod ctl;
mod failure;
mod fdlimit;
mod http;
#[cfg(feature = "https")]
mod inline;
mod observed;
mod probe;
mod quick;
mod watch;
mod workers;

use std::fs::File;
use std::io::{self, Read};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::time::{Duration, Instant};

use sibuna_lb::{Change, Config, Edge, MeshCommand, RuntimeError, ServerState};

use crate::signals::{self, Shutdown};
use control::Command;
use watch::{Source, Watcher};

pub(crate) fn command(args: &[String], secret: Option<&str>) -> Option<ExitCode> {
    let path = match args {
        [word, rest @ ..] if word == "lb" => return Some(quick::run(rest, secret)),
        [word, rest @ ..] if word == "ctl" => return Some(ctl::run(rest)),
        [word, rest @ ..] if word == "authority" => return Some(authority::run(rest)),
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
    /// The revision of the database that the topology came from (SID 0028). The worker
    /// settles it. `None` for a topology that a file holds whole.
    published: Option<authority::Stamp>,
}

/// Loads the file at `path` for a check: a whole topology, or the file of a node in
/// persistent mode, which is composed with the head of its database.
fn load(path: &str) -> io::Result<Revision> {
    load_into(path, &authority::Slot::default())
}

/// Loads the file at `path` for the source that owns `slot`. The first load fixes
/// whether the daemon serves its file or follows a database.
fn load_into(path: &str, slot: &authority::Slot) -> io::Result<Revision> {
    let document = document(path)?;
    if authority::is_node_file(&document) {
        return authority::load(&document, slot, &revision);
    }
    slot.serve_file()?;
    revision(&document)
}

/// Checks the JSON document of a whole topology and prepares its HTTP side.
fn revision(document: &[u8]) -> io::Result<Revision> {
    let config = Config::parse(document)?;
    let http = http::Prepared::load(&config)?;
    Ok(Revision { config, http, published: None })
}

/// Reads the file at `path` within the limit of an edge file and returns its JSON
/// document. A `.jlv` file is evaluated.
fn document(path: &str) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(Config::DOCUMENT_LIMITS.max_input_bytes as u64 + 1)
        .read_to_end(&mut bytes)?;
    evaluate(path, bytes)
}

/// The JSON document of the source `bytes` that was read from `path`.
fn evaluate(path: &str, bytes: Vec<u8>) -> io::Result<Vec<u8>> {
    if std::path::Path::new(path).extension().is_some_and(|ext| ext == "jlv") {
        #[cfg(feature = "jlv")]
        return sibuna_jlv::evaluate(path, &bytes).map(String::into_bytes);
        #[cfg(not(feature = "jlv"))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this build needs the jlv feature for .jlv files",
        ));
    }
    Ok(bytes)
}

/// The slot where the signal thread and the watcher leave a checked revision.
type Pending = Arc<Mutex<Option<Revision>>>;

/// Loads the source and leaves the revision for the worker, or logs why it was rejected.
fn offer(source: &Source, pending: &Pending) {
    match source.load() {
        Ok(next) => *pending.lock().unwrap_or_else(PoisonError::into_inner) = Some(next),
        Err(error) => note(format_args!("EDGE002: keeping current routes: {error}")),
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
    /// How long a shutdown serves on while readiness answers 503 (`global.drain_delay`).
    drain_delay: Duration,
    started: Instant,
    reloads: u64,
    /// The counters, the access log and the separate listener of SID 0020.
    observed: observed::Observed,
    /// The drain commands shared with the peers of the mesh (SID 0022).
    drains: Drains,
}

/// The run-time commands on their way to the peers and from them.
#[derive(Default)]
struct Drains {
    /// Where a command of this node's operator goes. `None` without a mesh.
    feed: Option<sibuna_lb::CommandFeed>,
    /// The commands of the operators of other nodes, from the mesh thread.
    remote: Option<mpsc::Receiver<MeshCommand>>,
}

/// The commands of peers applied in one turn of the edge worker.
const REMOTE_DRAINS_PER_STEP: usize = 64;

impl Serving {
    /// Applies a checked revision and returns the log line. A drain stays while the
    /// file still describes its server. Every other run-time change gives way.
    fn reload(&mut self, mut revision: Revision) -> io::Result<String> {
        // The follower of a database learns whether its revision is served (SID 0028).
        let published = revision.published.take();
        let outcome = self.replace(revision);
        if let Some(published) = published {
            published.settle(outcome.as_ref().err());
        }
        outcome
    }

    /// Puts a checked revision in the place of the serving one.
    fn replace(&mut self, revision: Revision) -> io::Result<String> {
        if revision.config.admin_socket() != self.admin_socket.as_deref() {
            return Err(io::Error::other("changing global.admin_socket requires a restart"));
        }
        let watch = revision.config.watch();
        let shutdown_timeout = revision.config.shutdown_timeout();
        let drain_delay = revision.config.drain_delay();
        let before = self.edge.change_count();
        let observed = &mut self.observed;
        reload(&mut self.edge, self.http.as_mut(), &mut self.adapters, observed, revision)?;
        self.reloads += 1;
        self.shutdown_timeout = shutdown_timeout;
        self.drain_delay = drain_delay;
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

    /// Follows the mesh: applies the drain commands of the peers and the routing regime.
    fn follow(&mut self, mesh: Option<&sibuna_lb::Mesh>, current: &mut sibuna_lb::Regime) {
        let commands = self.drains.remote.iter().flat_map(mpsc::Receiver::try_iter);
        let commands: Vec<MeshCommand> = commands.take(REMOTE_DRAINS_PER_STEP).collect();
        for command in commands {
            // A command that this node cannot apply is another node's concern: a
            // server it does not have, or one that its file fixes.
            if self.apply(&command).is_ok() {
                note(format_args!("EDGE010: mesh: {}", control::render_command(&command)));
            }
        }
        let Some(regime) = mesh.map(sibuna_lb::Mesh::regime) else { return };
        if *current != regime {
            self.edge.set_regime(regime);
            note(format_args!("Sibuna edge routing regime: {regime:?}"));
            *current = regime;
        }
    }

    /// Applies the revision that the signal thread or the watcher left, if any.
    fn take_pending(&mut self) {
        let next = self.pending.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let Some(next) = next {
            match self.reload(next) {
                Ok(line) => note(format_args!("{line}")),
                Err(error) => note(format_args!("EDGE002: keeping current routes: {error}")),
            }
        }
    }

    /// Runs one admin command and answers it. A command that changed state is logged.
    fn answer(&mut self, job: admin::Job) {
        let admin::Job { line, command, revision, reply } = job;
        let changes = command.changes();
        let answer = self.run(command, revision);
        if changes && answer.is_ok() {
            note(format_args!("EDGE010: admin: {line}"));
        }
        // The client may have given up. Its answer is then dropped.
        let _ = reply.try_send(answer);
    }

    fn run(
        &mut self,
        command: Command,
        revision: Option<Revision>,
    ) -> Result<String, RuntimeError> {
        match command {
            Command::ShowServers => Ok(control::render_servers(&self.edge.servers())),
            Command::ShowInfo => Ok(self.info()),
            Command::ShowStats => Ok(self.stats()),
            Command::ShowCerts => Ok(self.certs()),
            Command::ShowCa => Ok(self.ca()),
            // The admin thread answers these. They never reach the worker.
            Command::Help | Command::ShowCluster | Command::ShowAuthority => {
                Ok(control::USAGE.to_owned())
            }
            Command::ReopenLog => {
                self.observed.shared().reopen_log();
                Ok(String::new())
            }
            Command::Local(command) => self.change(&command, false),
            Command::State { .. }
            | Command::Weight { .. }
            | Command::Add { .. }
            | Command::Del { .. }
            | Command::DelBan { .. } => self.change(&command, true),
            Command::Reload | Command::ReloadCluster => {
                let revision = revision
                    .ok_or_else(|| reload_rejected(io::Error::other("the file was not loaded")))?;
                let line = self.reload(revision).map_err(reload_rejected)?;
                note(format_args!("{line}"));
                Ok(format!("{line}\n"))
            }
        }
    }

    /// Applies a change to a server and, when `share` is set and the edge has a mesh,
    /// hands it to the peers.
    fn change(&mut self, command: &Command, share: bool) -> Result<String, RuntimeError> {
        if let Command::DelBan { client } = command {
            let Some(http) = &self.http else {
                return Err(RuntimeError::invalid(
                    "This edge has no HTTP frontend, and so no bans.".to_owned(),
                    "Bans belong to the firewall of an HTTP frontend.",
                ));
            };
            http.lift_ban(*client, share);
            return Ok(String::new());
        }
        let Some(change) = control::mesh_command(command, &self.edge.servers()) else {
            // Only the removal of a server that is not there has no change to share.
            // The edge names the fault.
            let Command::Del { pool, name } = command else { return Ok(String::new()) };
            return self.edge.remove_server(pool, name).map(|()| String::new());
        };
        self.apply(&change)?;
        if let (true, Some(feed)) = (share, &self.drains.feed) {
            feed.publish(&change);
        }
        Ok(String::new())
    }

    /// Applies one change to a server, from this node's operator or from a peer.
    fn apply(&mut self, command: &MeshCommand) -> Result<(), RuntimeError> {
        let (edge, pool, name) = (&mut self.edge, &command.pool, &command.name);
        match command.change {
            Change::State { drained } => {
                let state = if drained { ServerState::Drain } else { ServerState::Ready };
                edge.set_server_state(pool, name, state)
            }
            Change::Weight(weight) => edge.set_server_weight(pool, name, weight),
            Change::Member { addr, weight, present: true } => {
                edge.add_server(pool, name, addr, weight)
            }
            Change::Member { present: false, .. } => edge.remove_server(pool, name),
        }
    }

    /// Says that the listeners serve. Automatic HTTPS places its orders from now on.
    fn announce(&self) {
        note(format_args!("Sibuna edge listeners ready"));
        #[cfg(feature = "https")]
        if let Some(http) = &self.http {
            http.listening();
        }
    }

    /// The answer to `show stats`: the counters of SID 0020 and of automatic HTTPS.
    fn stats(&self) -> String {
        #[cfg_attr(not(feature = "https"), allow(unused_mut))]
        let mut text = crate::access::metrics_text(None, self.observed.shared());
        #[cfg(feature = "https")]
        if let Some(automatic) = self.http.as_ref().and_then(http::Http::automatic) {
            crate::acme::write_metrics(automatic, crate::acme::unix_now(), &mut text);
        }
        text
    }

    /// The answer to `show certs`: the certificates of automatic HTTPS (SID 0021).
    /// Without automatic HTTPS the table has its header only.
    fn certs(&self) -> String {
        #[cfg(feature = "https")]
        {
            let automatic = self.http.as_ref().and_then(http::Http::automatic);
            crate::acme::render_certs(&automatic.map(|a| a.status()).unwrap_or_default())
        }
        #[cfg(not(feature = "https"))]
        "name via issuer expires renews state error\n".to_owned()
    }

    /// The answer to `show ca`: where the root of the local authority is, and its PEM
    /// text, for the operator who installs it in clients (SID 0021).
    fn ca(&self) -> String {
        #[cfg(feature = "https")]
        {
            let automatic = self.http.as_ref().and_then(http::Http::automatic);
            crate::acme::render_ca(automatic.map(|automatic| automatic.local_root()))
        }
        #[cfg(not(feature = "https"))]
        "# no local authority: this build has no TLS\n".to_owned()
    }

    /// The answer to `show info`: one `key: value` per line.
    fn info(&self) -> String {
        let servers = self.edge.servers();
        let drained = servers.iter().filter(|server| server.state == ServerState::Drain).count();
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

/// Checks the descriptor limit and installs the signal handlers of an edge. SIGHUP
/// offers the source again. It also sets the returned flag, which asks for the access
/// log to be reopened, whether or not the new topology loads (SID 0020).
fn prepare(
    shutdown: &Arc<Shutdown>,
    source: &Arc<Source>,
    pending: &Pending,
    config: &Config,
) -> io::Result<Arc<AtomicBool>> {
    let described = source.path().unwrap_or("quick start");
    fdlimit::check(described, fdlimit::Demand::of(config));
    let rotate = Arc::new(AtomicBool::new(false));
    let rotated = Arc::clone(&rotate);
    let (hup_source, slot) = (Arc::clone(source), Arc::clone(pending));
    signals::install_edge(Arc::clone(shutdown), move || {
        rotated.store(true, Ordering::Release);
        offer(&hup_source, &slot);
    })
    .map_err(io::Error::other)?;
    Ok(rotate)
}

/// The most admin commands applied between two readiness batches.
const COMMANDS_PER_STEP: usize = 16;

fn serve(source: Source, revision: Revision, secret: Option<&str>) -> io::Result<()> {
    let shutdown = Shutdown::new();
    let source = Arc::new(source);
    let pending = Pending::default();
    let rotate = prepare(&shutdown, &source, &pending, &revision.config)?;
    let Revision { mut config, http, published } = revision;
    let observe_options = config.observe().clone();
    let mut adapters = Adapters::default();
    adapt(&mut adapters, &mut config)?;
    let mesh = config.mesh().map(|spec| start_mesh(spec, &source, &pending)).transpose()?;
    let admin_socket = config.admin_socket().map(str::to_owned);
    let takeover = config.reuse_port();
    let watch = config.watch();
    let (shutdown_timeout, drain_delay) = (config.shutdown_timeout(), config.drain_delay());
    let mut current = sibuna_lb::Regime::Standalone;
    let edge = Edge::bind(config)?;
    let http = http.map(|p| http::Http::start(p, &edge, secret)).transpose()?;
    let drains = join(http.as_ref(), &adapters, mesh.as_ref());
    let observed = observed::Observed::start(http.as_ref(), &observe_options, &edge)?;
    let (jobs, inbox) = mpsc::channel();
    let _admin = match &admin_socket {
        Some(path) => Some(admin::Admin::start(path, takeover, Arc::clone(&source), jobs)?),
        None => None,
    };
    let mut serving = Serving {
        edge,
        http,
        adapters,
        source,
        pending,
        watcher: Watcher::new(),
        admin_socket,
        shutdown_timeout,
        drain_delay,
        started: Instant::now(),
        reloads: 0,
        observed,
        drains,
    };
    serving.watch(watch)?;
    serving.announce();
    // The follower of a database starts with the revision that the worker serves.
    if let Some(published) = published {
        published.settle(None);
    }
    authority::follow(&serving.source, &serving.pending)?;
    while !shutdown.is_requested() {
        serving.observed.reopen_log_when(&rotate);
        serving.take_pending();
        for job in inbox.try_iter().take(COMMANDS_PER_STEP) {
            serving.answer(job);
        }
        serving.follow(mesh.as_ref(), &mut current);
        serving.step()?;
    }
    serving.observed.drain();
    serving.linger()?;
    drop(mesh);
    serving.stop()
}

impl Serving {
    /// Serves on for `global.drain_delay` after readiness turned to 503, so that a
    /// balancer in front stops sending before the listeners close (SID 0020).
    fn linger(&mut self) -> io::Result<()> {
        if self.drain_delay.is_zero() {
            return Ok(());
        }
        let delay = self.drain_delay;
        note(format_args!("Sibuna edge draining: not ready, serving for {delay:?}"));
        let until = Instant::now() + self.drain_delay;
        while Instant::now() < until {
            self.step()?;
        }
        Ok(())
    }

    /// One turn of the edge worker: the load balancer, the accepted HTTP connections
    /// and the log lines of the flows that ended.
    fn step(&mut self) -> io::Result<()> {
        step(&mut self.edge, self.http.as_ref())?;
        self.observed.pass_flows(&mut self.edge);
        Ok(())
    }

    /// Stops the listeners and waits for the established flows, at most
    /// `global.shutdown_timeout`.
    fn stop(self) -> io::Result<()> {
        let Serving { mut edge, http, shutdown_timeout, observed, .. } = self;
        edge.drain();
        if let Some(http) = &http {
            http.drain();
        }
        let deadline = Instant::now() + shutdown_timeout;
        while edge.active() > 0 && Instant::now() < deadline {
            step(&mut edge, http.as_ref())?;
            observed.pass_flows(&mut edge);
        }
        let (forced, drops) = (edge.active(), edge.dropped());
        note(format_args!("Sibuna edge stopped: {forced} forced closes, {drops} drops"));
        // The flows that are still open end here, and their lines say `shutdown`.
        edge.close_flows();
        observed.pass_flows(&mut edge);
        // The HTTP server ends its request paths before the log writes its last lines.
        drop(http);
        observed.close_log();
        Ok(())
    }
}

fn step(edge: &mut Edge, http: Option<&http::Http>) -> io::Result<()> {
    edge.step()?;
    if let Some(http) = http {
        for accepted in edge.accepted() {
            http.accept(accepted);
        }
    }
    Ok(())
}

fn reload(
    edge: &mut Edge,
    http: Option<&mut http::Http>,
    adapters: &mut Adapters,
    observed: &mut observed::Observed,
    mut revision: Revision,
) -> io::Result<()> {
    let observe = revision.config.observe().clone();
    match (http, revision.http) {
        (None, None) => {
            let plan = observed.plan(&observe)?;
            edge.reload(revision.config)?;
            observed.apply(observe, plan, edge);
            Ok(())
        }
        (Some(http), Some(prepared)) if http.compatible(&prepared) => {
            // The new log file and the new listener open first. A failure refuses the
            // reload, and the old ones serve on (SID 0020).
            let plan = observed.plan(&observe)?;
            adapt(adapters, &mut revision.config)?;
            edge.reload(revision.config)?;
            // The engine follows the routes at once. A request decided under the old
            // engine in between is routed by the old revision (SID 0018). The adapters
            // of that revision close last.
            http.reload(prepared);
            observed.apply(observe, plan, edge);
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

/// Joins the started parts of the edge: the HTTP runtime learns the multiplexed
/// servers of the adapters, and the daemon shares bans and drain commands with the mesh
/// (SID 0022).
fn join(http: Option<&http::Http>, adapters: &Adapters, mesh: Option<&sibuna_lb::Mesh>) -> Drains {
    attach(http, adapters);
    let Some(mesh) = mesh else { return Drains::default() };
    if let Some(http) = http {
        http.share_bans(mesh);
    }
    let (commands, remote) = mpsc::sync_channel(1024);
    // The mesh thread never waits for the edge worker. A full queue drops the command.
    let sink = move |command: MeshCommand| {
        let _ = commands.try_send(command);
    };
    Drains { feed: mesh.share_commands(Box::new(sink)), remote: Some(remote) }
}

/// Writes one line to standard error. A daemon whose standard error was closed, by a
/// supervisor that went away or a pipe that nobody reads, keeps serving: the line is
/// lost and nothing else happens. `eprintln!` would end the process there.
pub(crate) fn note(line: std::fmt::Arguments<'_>) {
    use std::io::Write as _;
    let _ = writeln!(io::stderr().lock(), "{line}");
}

/// Starts the mesh thread. The admin socket learns where `reload cluster` sends the
/// file, and with `mesh.accept_config` this node takes the file of a peer (SID 0023).
fn start_mesh(
    spec: &sibuna_lb::MeshConfig,
    source: &Arc<Source>,
    pending: &Pending,
) -> io::Result<sibuna_lb::Mesh> {
    let mut key = [0; 32];
    let mut file = File::open(&spec.key_file)?;
    file.read_exact(&mut key)?;
    if file.read(&mut [0])? != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "mesh key must be 32 bytes"));
    }
    let mut boot = [0; 16];
    crate::random::fill(&mut boot)?;
    let peers = Arc::new(cluster::Peers::new(spec, &key));
    source.set_cluster(Arc::clone(&peers));
    let serving = peers.accept(Arc::clone(source), Arc::clone(pending), spec.accept_config);
    if let Err(error) = serving {
        // A node that takes files must be reachable. One that only answers
        // `show cluster` serves without that answer.
        if spec.accept_config {
            return Err(error);
        }
        note(format_args!("EDGE012: the mesh address cannot serve `show cluster`: {error}"));
    }
    sibuna_lb::Mesh::start(spec, &key, boot)
}
