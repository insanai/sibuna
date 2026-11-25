//! The node side of persistent mode (SID 0028): the first load, the thread that follows
//! the store, and what the worker tells it.

use std::io;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sibuna_authority::{
    Access, Error, Following, Head, NodeReport, Published, Settings, SqlStore, Store, Waker,
    compose, read_cache, render_nodes, short, write_cache,
};

use super::super::watch::Source;
use super::super::{Pending, Revision, note};

pub(in super::super) use sibuna_authority::is_node_file;

/// How long the admin thread waits for the list of nodes.
const ASK_TIMEOUT: Duration = Duration::from_secs(4);

/// A question of the admin thread for the thread that owns the store.
enum Request {
    /// The head and the reports of all nodes.
    Nodes(mpsc::SyncSender<Result<(Head, Vec<NodeReport>), Error>>),
}

/// Where the topology of this daemon comes from. The first load decides, and a later
/// load must agree: changing the mode needs a restart.
#[derive(Default)]
enum Mode {
    #[default]
    Unset,
    File,
    Database(Arc<Authority>),
}

/// The mode of one source, and in persistent mode its follower.
#[derive(Default)]
pub(in super::super) struct Slot(Mutex<Mode>);

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())
}

/// A failure of the authority as the error of a load. The cause keeps its code and
/// its hint for the diagnostic.
fn fault(error: Error) -> io::Error {
    io::Error::other(error)
}

/// The title and the hint of `error` when the authority caused it.
pub(in super::super) fn failure(error: &io::Error) -> Option<(&'static str, &'static str)> {
    let cause = error.get_ref()?.downcast_ref::<Error>()?;
    Some((cause.title(), cause.hint()))
}

impl Slot {
    /// Records that the source is a file with a whole topology. Fails when the daemon
    /// follows a database.
    pub fn serve_file(&self) -> io::Result<()> {
        let mut mode = locked(&self.0);
        if matches!(*mode, Mode::Database(_)) {
            return Err(io::Error::other("removing `authority` from the file requires a restart"));
        }
        *mode = Mode::File;
        Ok(())
    }

    /// The follower of this source, started at the first call. Fails when the daemon
    /// serves a file, when `settings` are not those of the start, or when the first
    /// revision cannot be had.
    fn database(&self, settings: Settings) -> io::Result<Arc<Authority>> {
        let mut mode = locked(&self.0);
        match &*mode {
            Mode::File => {
                Err(io::Error::other("adding `authority` to the file requires a restart"))
            }
            Mode::Database(authority) if authority.settings == settings => {
                Ok(Arc::clone(authority))
            }
            Mode::Database(_) => {
                Err(io::Error::other("changing `authority` requires a restart, except its binds"))
            }
            Mode::Unset => {
                let authority = Authority::start(settings)?;
                *mode = Mode::Database(Arc::clone(&authority));
                Ok(authority)
            }
        }
    }

    /// The follower, when the daemon is in persistent mode.
    fn get(&self) -> Option<Arc<Authority>> {
        match &*locked(&self.0) {
            Mode::Database(authority) => Some(Arc::clone(authority)),
            _ => None,
        }
    }
}

/// What was said once, so that it is not said at every poll.
#[derive(Default)]
struct Said {
    /// The revision whose unused binds were logged.
    binds: u64,
    /// The revision in the cache file.
    cached: u64,
    /// The revision that was read from the cache at the start.
    restored: u64,
    cache_failed: bool,
    report_failed: bool,
}

/// The follower of one daemon.
pub(in super::super) struct Authority {
    settings: Settings,
    state: Mutex<Following>,
    /// The store, until the thread that follows takes it.
    store: Mutex<Option<SqlStore>>,
    waker: Waker,
    requests: Mutex<Option<mpsc::Sender<Request>>>,
    said: Mutex<Said>,
}

/// The revision that a checked topology came from. The worker settles it.
pub(in super::super) struct Stamp {
    authority: Arc<Authority>,
    published: Arc<Published>,
}

impl Stamp {
    /// Tells the follower what the worker did with the revision: it serves it, or it
    /// refused it with `refusal` and serves what it served.
    pub fn settle(self, refusal: Option<&io::Error>) {
        let Stamp { authority, published } = self;
        match refusal {
            None => {
                if locked(&authority.state).applied(&published) {
                    let digest = short(&published.digest);
                    note(format_args!(
                        "DBA010: revision {} applied ({digest})",
                        published.revision
                    ));
                }
            }
            Some(refusal) => authority.refuse(published.revision, &refusal.to_string()),
        }
        authority.waker.wake();
    }
}

impl Authority {
    /// Opens the store and reads the head. When the database does not answer, or the
    /// node has a cache, the cached revision is a second choice. Fails when there is
    /// nothing to serve.
    fn start(settings: Settings) -> io::Result<Arc<Authority>> {
        settings.check_node().map_err(fault)?;
        let mut store = SqlStore::new(&settings, Access::Node).map_err(fault)?;
        let authority = Arc::new(Authority {
            state: Mutex::new(Following::new(&settings.node)),
            waker: store.waker(),
            settings,
            store: Mutex::new(None),
            requests: Mutex::new(None),
            said: Mutex::new(Said::default()),
        });
        let (candidate, failure) = authority.look(&mut store);
        *locked(&authority.store) = Some(store);
        authority.restore(candidate.as_deref());
        if locked(&authority.state).choices().is_empty() {
            return Err(fault(failure.unwrap_or(Error::Empty)));
        }
        Ok(authority)
    }

    /// Takes the revision of the cache file as what the node last served, unless it is
    /// the candidate.
    fn restore(&self, candidate: Option<&Published>) {
        let Some(path) = &self.settings.cache else { return };
        match read_cache(path) {
            Ok(cached) if candidate.is_some_and(|c| c.digest == cached.digest) => {
                locked(&self.said).cached = cached.revision;
            }
            Ok(cached) => {
                locked(&self.said).restored = cached.revision;
                locked(&self.said).cached = cached.revision;
                locked(&self.state).applied(&Arc::new(cached));
            }
            // A node that never served has no cache yet.
            Err(error) if error.is_unavailable() => {}
            Err(error) => note(format_args!("DBA016: the cache is ignored: {error}")),
        }
    }

    /// Looks at the head. Returns a revision that is new to this node, and the failure
    /// when the store did not answer. Nothing that is served changes here.
    fn look(&self, store: &mut SqlStore) -> (Option<Arc<Published>>, Option<Error>) {
        let head = match store.head() {
            Ok(head) => head,
            Err(error) => return (None, Some(self.lost(error))),
        };
        let was_down = locked(&self.state).is_down();
        let wanted = locked(&self.state).saw_head(&head, unix_now());
        if was_down {
            let number = head.revision;
            note(format_args!("DBA013: the database answers again, head is revision {number}"));
        }
        let Some(number) = wanted else { return (None, None) };
        match store.revision(number) {
            Ok(revision) => {
                let published = Published {
                    revision: number,
                    digest: revision.entry.digest,
                    document: revision.document,
                };
                (Some(locked(&self.state).read(published)), None)
            }
            Err(error) if error.is_unavailable() => (None, Some(self.lost(error))),
            Err(error) => {
                self.refuse(number, &error.to_string());
                (None, Some(error))
            }
        }
    }

    /// Records that the store did not answer and logs the first time.
    fn lost(&self, error: Error) -> Error {
        let mut state = locked(&self.state);
        if state.lost_database(&error.to_string(), unix_now()) {
            let serving = state.serving().map_or(0, |serving| serving.revision);
            note(format_args!("DBA012: {error}; keeping revision {serving}"));
        }
        error
    }

    /// Records that this node refused `revision` and logs it.
    fn refuse(&self, revision: u64, reason: &str) {
        let mut state = locked(&self.state);
        let serving = state.serving().map_or(0, |serving| serving.revision);
        if serving == revision {
            return;
        }
        state.refuse(revision, reason);
        note(format_args!(
            "DBA011: revision {revision} refused, keeping revision {serving}: {reason}"
        ));
    }

    /// Composes the file with one revision and checks the result.
    fn try_choice(
        self: &Arc<Self>,
        node_file: &[u8],
        choice: &Arc<Published>,
        check: &dyn Fn(&[u8]) -> io::Result<Revision>,
    ) -> io::Result<Revision> {
        let composition = compose(node_file, &choice.document).map_err(fault)?;
        let mut revision = check(composition.document.as_bytes())?;
        let mut said = locked(&self.said);
        if !composition.unused_binds.is_empty() && said.binds != choice.revision {
            said.binds = choice.revision;
            let names = composition.unused_binds.join(", ");
            note(format_args!(
                "DBA015: authority.binds names no published frontend: {names} (revision {})",
                choice.revision
            ));
        }
        let stamp = Stamp { authority: Arc::clone(self), published: Arc::clone(choice) };
        revision.published = Some(stamp);
        Ok(revision)
    }

    /// Composes the file with the candidate. When that is refused, composes it with the
    /// revision that the node serves, so that a change to the file still applies.
    fn compose_checked(
        self: &Arc<Self>,
        node_file: &[u8],
        check: &dyn Fn(&[u8]) -> io::Result<Revision>,
    ) -> io::Result<Revision> {
        let choices = locked(&self.state).choices();
        let mut first = None;
        for choice in &choices {
            match self.try_choice(node_file, choice, check) {
                Ok(revision) => {
                    self.say_restored(choice.revision, first.as_ref());
                    return Ok(revision);
                }
                Err(error) => {
                    self.refuse(choice.revision, &error.to_string());
                    first.get_or_insert(error);
                }
            }
        }
        Err(first.unwrap_or_else(|| fault(Error::Empty)))
    }

    /// Logs once that the node serves the revision of its cache, and why.
    fn say_restored(&self, chosen: u64, refusal: Option<&io::Error>) {
        let mut said = locked(&self.said);
        if said.restored != chosen {
            return;
        }
        said.restored = 0;
        let why = match refusal {
            Some(refusal) => format!("the head was refused: {refusal}"),
            None => "the database does not answer".to_owned(),
        };
        note(format_args!("DBA014: started from the cache at revision {chosen}: {why}"));
    }

    /// Makes the thread look now. A head that was refused before it could be read is
    /// read again.
    fn look_again(&self) {
        let mut state = locked(&self.state);
        let unread = state.refused().is_some_and(|(revision, _)| {
            !state.choices().iter().any(|choice| choice.revision == revision)
        });
        if unread {
            state.retry();
        }
        drop(state);
        self.waker.wake();
    }

    /// Follows the store until the process ends.
    fn run(
        self: Arc<Self>,
        mut store: SqlStore,
        source: &Source,
        pending: &Pending,
        requests: &mpsc::Receiver<Request>,
    ) {
        loop {
            store.wait(self.settings.poll);
            for Request::Nodes(reply) in requests.try_iter() {
                let listing = store.head().and_then(|head| Ok((head, store.nodes()?)));
                // The admin client may have given up.
                let _ = reply.try_send(listing);
            }
            if let (Some(candidate), _) = self.look(&mut store) {
                self.offer(source, pending, &candidate);
            }
            self.keep(&mut store);
        }
    }

    /// Checks a new revision against the file and leaves it for the worker. A revision
    /// that does not check is refused here, and the worker hears nothing.
    fn offer(self: &Arc<Self>, source: &Source, pending: &Pending, candidate: &Arc<Published>) {
        let Some(path) = source.path() else { return };
        let checked = super::super::document(path)
            .and_then(|file| self.try_choice(&file, candidate, &super::super::revision));
        match checked {
            Ok(revision) => *locked(pending) = Some(revision),
            Err(error) => self.refuse(candidate.revision, &error.to_string()),
        }
    }

    /// Writes the cache when the served revision is new, and reports to the store.
    fn keep(&self, store: &mut SqlStore) {
        let (report, serving, down) = {
            let state = locked(&self.state);
            (state.report(unix_now()), state.serving().cloned(), state.is_down())
        };
        let mut said = locked(&self.said);
        if let (Some(path), Some(serving)) = (&self.settings.cache, &serving)
            && said.cached != serving.revision
        {
            match write_cache(path, serving) {
                Ok(()) => (said.cached, said.cache_failed) = (serving.revision, false),
                Err(error) if !said.cache_failed => {
                    said.cache_failed = true;
                    note(format_args!(
                        "DBA016: cannot write the cache {}: {error}",
                        path.display()
                    ));
                }
                Err(_) => {}
            }
        }
        if down || report.applied == 0 {
            return;
        }
        match store.report(&report) {
            Ok(()) => said.report_failed = false,
            Err(error) if !said.report_failed => {
                said.report_failed = true;
                note(format_args!("DBA016: cannot report to the database: {error}"));
            }
            Err(_) => {}
        }
    }

    /// Asks the thread that owns the store for the head and the reports of all nodes.
    fn ask_nodes(&self) -> Result<(Head, Vec<NodeReport>), String> {
        let sender = locked(&self.requests).clone().ok_or("the follower does not run")?;
        let (reply, answer) = mpsc::sync_channel(1);
        sender.send(Request::Nodes(reply)).map_err(|_| "the follower stopped")?;
        self.waker.wake();
        let listing = answer.recv_timeout(ASK_TIMEOUT);
        listing
            .map_err(|_| "the database did not answer in time".to_owned())?
            .map_err(|error| error.to_string())
    }

    /// The answer to `show cluster`: every node with the revision it serves. The line
    /// of this node comes from memory, so it is right when the database is not.
    fn cluster(&self) -> String {
        let (own, known) = {
            let state = locked(&self.state);
            let served = state.serving().filter(|serving| serving.revision == state.head());
            let digest = served.map_or(String::new(), |serving| serving.digest.clone());
            (state.report(unix_now()), Head { revision: state.head(), digest })
        };
        let this = Some(self.settings.node.as_str());
        match self.ask_nodes() {
            Ok((head, mut nodes)) => {
                nodes.retain(|report| report.node != own.node);
                nodes.push(own);
                nodes.sort_by(|left, right| left.node.cmp(&right.node));
                render_nodes(&head, &nodes, this, unix_now())
            }
            Err(reason) => {
                let table = render_nodes(&known, &[own], this, unix_now());
                format!("{table}database unavailable: {reason}\n")
            }
        }
    }

    /// The answer to `show authority`: the view of this node, one key on each line.
    fn describe(&self) -> String {
        let cache = match &self.settings.cache {
            Some(path) => path.display().to_string(),
            None => "none".to_owned(),
        };
        format!(
            "store: {}\nnode: {}\npoll: {}ms\n{}cache: {cache}\n",
            self.settings.describe(),
            self.settings.node,
            self.settings.poll.as_millis(),
            locked(&self.state).describe(unix_now()),
        )
    }
}

/// Loads the evaluated node file `node_file`: finds or starts the follower of `slot`,
/// composes the file with the best revision that passes `check`, and stamps the result
/// with that revision. Fails when the `authority` section is wrong or changed, when no
/// revision can be had, or with the failure of the check.
pub(in super::super) fn load(
    node_file: &[u8],
    slot: &Slot,
    check: &dyn Fn(&[u8]) -> io::Result<Revision>,
) -> io::Result<Revision> {
    let settings = Settings::parse(node_file).map_err(fault)?;
    let authority = slot.database(settings)?;
    let revision = authority.compose_checked(node_file, check);
    authority.look_again();
    revision
}

/// Starts the thread that follows the store, when `source` is in persistent mode. It
/// leaves checked revisions in `pending`. Fails when the thread cannot start.
pub(in super::super) fn follow(source: &Arc<Source>, pending: &Pending) -> io::Result<()> {
    let Some(authority) = source.authority().get() else { return Ok(()) };
    let Some(store) = locked(&authority.store).take() else { return Ok(()) };
    let (sender, requests) = mpsc::channel();
    *locked(&authority.requests) = Some(sender);
    let (source, pending) = (Arc::clone(source), Arc::clone(pending));
    std::thread::Builder::new()
        .name("edge-authority".into())
        .spawn(move || authority.run(store, &source, &pending, &requests))
        .map(drop)
}

/// The answer to `show cluster` in persistent mode, or `None` on an edge that serves a
/// file.
pub(in super::super) fn cluster(source: &Source) -> Option<String> {
    source.authority().get().map(|authority| authority.cluster())
}

/// The answer to `show authority`, or `None` on an edge that serves a file.
pub(in super::super) fn describe(source: &Source) -> Option<String> {
    source.authority().get().map(|authority| authority.describe())
}
