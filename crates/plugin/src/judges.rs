//! Judges: threads that decide parked connections (SID 0030, "Parking a connection").
//!
//! ```text
//!  caller thread                     judges (options.threads)
//!  [Judges::submit(case, deliver)] -> bounded queue -> [Local::run] -> deliver(answer)
//!        |                            (options.queue)   blocking agent calls
//!        +-- queue full: the caller runs the chain itself with [Local::run_shedding]
//! ```
//!
//! A thread that may not wait for an agent, such as the edge worker, parks a connection
//! whose chain names an agent ([`Local::parks`]). It gives a [`Case`], an owned copy of
//! the view, to the judges. A judge owns a [`Local`] of its own and runs the whole chain
//! with the blocking calls of the agent tier. The answer goes back through the closure
//! of the caller, which runs on the judge's thread and must not wait.

use std::io;
use std::ops::Range;
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use crate::set::{Local, Slot};
use crate::spec::JudgeOptions;
use crate::verdict::{Stage, Verdict};
use crate::view::{Field, Protocol, View};

/// An owned copy of a [`View`], for a decision on another thread.
#[derive(Clone, Debug)]
pub struct Case {
    stage: Stage,
    protocol: Protocol,
    secure: bool,
    client: std::net::SocketAddr,
    local: std::net::SocketAddr,
    status: u16,
    duration_us: u32,
    /// Every text of the view, one after the other.
    text: Vec<u8>,
    /// The frontend, the server name, the JA4, the method, the host, the path and the
    /// query as ranges of `text`.
    parts: [Range<usize>; 7],
    /// The name and the value of each field as ranges of `text`.
    fields: Vec<(Range<usize>, Range<usize>)>,
}

impl Case {
    /// Copies `view`.
    pub fn of(view: &View<'_>) -> Case {
        let mut text = Vec::new();
        let mut keep = |bytes: &[u8]| {
            let start = text.len();
            text.extend_from_slice(bytes);
            start..text.len()
        };
        let parts = [
            keep(view.frontend.as_bytes()),
            keep(view.server_name),
            keep(view.ja4),
            keep(view.method),
            keep(view.host),
            keep(view.path),
            keep(view.query),
        ];
        let fields = view.fields.iter().map(|field| (keep(field.name), keep(field.value)));
        let fields = fields.collect();
        Case {
            stage: view.stage,
            protocol: view.protocol,
            secure: view.secure,
            client: view.client,
            local: view.local,
            status: view.status,
            duration_us: view.duration_us,
            text,
            parts,
            fields,
        }
    }

    fn part(&self, range: &Range<usize>) -> &[u8] {
        self.text.get(range.clone()).unwrap_or_default()
    }

    /// Calls `run` with the view that this case copied.
    pub fn with_view<R>(&self, run: impl FnOnce(&View<'_>) -> R) -> R {
        let field = |(name, value): &(Range<usize>, Range<usize>)| Field {
            name: self.part(name),
            value: self.part(value),
        };
        let fields: Vec<Field<'_>> = self.fields.iter().map(field).collect();
        let [frontend, server_name, ja4, method, host, path, query] = &self.parts;
        run(&View {
            stage: self.stage,
            protocol: self.protocol,
            secure: self.secure,
            client: self.client,
            local: self.local,
            // The frontend was a `str` when it was copied.
            frontend: std::str::from_utf8(self.part(frontend)).unwrap_or_default(),
            server_name: self.part(server_name),
            ja4: self.part(ja4),
            method: self.part(method),
            host: self.part(host),
            path: self.part(path),
            query: self.part(query),
            fields: &fields,
            status: self.status,
            duration_us: self.duration_us,
        })
    }
}

/// What the judges decided about a case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    /// The verdict of the chain.
    pub verdict: Verdict,
    /// The plugin that refused; empty for an admission.
    pub hook: Box<str>,
}

/// Receives the answer to one case. It runs on a judge's thread and must not wait.
pub type Deliver = Box<dyn FnOnce(Answer) + Send>;

struct Job {
    case: Case,
    deliver: Deliver,
    queued: Instant,
}

/// The judges of one caller. Dropping the value ends the threads after their case.
pub struct Judges {
    queue: SyncSender<Job>,
}

impl std::fmt::Debug for Judges {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Judges").finish_non_exhaustive()
    }
}

impl Judges {
    /// Starts `options.threads` judges that follow the plans of `slot` and share a
    /// queue of `options.queue` cases.
    ///
    /// # Errors
    ///
    /// The error of starting a thread. Judges that started end again.
    pub fn start(slot: &Arc<Slot>, options: JudgeOptions) -> io::Result<Judges> {
        let (queue, jobs) = mpsc::sync_channel::<Job>(options.queue.max(1) as usize);
        let jobs = Arc::new(Mutex::new(jobs));
        for _ in 0..options.threads.max(1) {
            let (jobs, slot) = (Arc::clone(&jobs), Arc::clone(slot));
            std::thread::Builder::new()
                .name("sibuna-hook-judge".to_owned())
                .spawn(move || judge(&jobs, &slot))?;
        }
        Ok(Judges { queue })
    }

    /// Gives `case` to the judges. `deliver` receives the answer on a judge's thread.
    ///
    /// # Errors
    ///
    /// The closure comes back when the queue is full or no judge lives. The caller
    /// then decides the case itself with [`Local::run_shedding`].
    pub fn submit(&self, case: Case, deliver: Deliver) -> Result<(), Deliver> {
        let job = Job { case, deliver, queued: Instant::now() };
        match self.queue.try_send(job) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(job) | TrySendError::Disconnected(job)) => Err(job.deliver),
        }
    }
}

/// The loop of one judge. Only the wait for a case holds the lock of the queue.
fn judge(jobs: &Mutex<Receiver<Job>>, slot: &Slot) {
    let mut local = Local::new();
    loop {
        let next = jobs.lock().unwrap_or_else(PoisonError::into_inner).recv();
        let Ok(job) = next else { return };
        // A case that waited longer than an agent may take is not worth a call.
        let late = job.queued.elapsed() > local.patience(slot);
        let answer = job.case.with_view(|view| {
            let decision =
                if late { local.run_shedding(slot, view) } else { local.run(slot, view) };
            Answer { verdict: decision.verdict, hook: decision.hook.into() }
        });
        (job.deliver)(answer);
    }
}
