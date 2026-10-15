//! The hub's feeder thread (Zig's `subscription_job.zig`).
//!
//! Every 100 ms the feeder polls its storage tickets and submits the reads its subscribers
//! need: one incident feed per cluster member (for `events`), the membership (for `nodes`,
//! and to learn the members whose incidents `events` covers), the committed policy revision
//! (for `policy`) and the audit feed (for `audit`). A source is read again a second after
//! its last answer, at once while a feed pages through a backlog. On the first tick of each
//! UTC second it publishes the local views (statistics and the dashboard, the challenge
//! funnel) and fans out.
//!
//! Storage is reached only through background tickets, never waited for: a job unanswered
//! after ten seconds is abandoned (its ticket dropped) and tried again a second later. The
//! feeder holds at most [`FEEDER_JOBS`] jobs at a time, half of the console's background
//! allowance, so the collector's journals always find room.

use sibuna_console_protocol::codec::to_json;
use sibuna_console_protocol::nodes::{self, MAX_MEMBERS, Page as MembersPage, Storage};
use sibuna_console_protocol::subscription_feed::{Kind, Page, Request};
use sibuna_console_protocol::subscriptions::TOPIC_COUNT;
use sibuna_console_protocol::{Text, Topic};
use sibuna_console_storage::feed;
use sibuna_console_storage::nodes::{Membership, load_members};
use sibuna_storage::Dialect;

use std::time::Duration;

use super::views::{NodesView, PolicyView};
use crate::shared::Shared;
use crate::storage::{BackgroundTicket, StorageFailure};

/// The feeder's period.
pub const PERIOD: Duration = Duration::from_millis(100);
/// The most background storage jobs the feeder holds at once.
pub const FEEDER_JOBS: usize = 2;
/// How long a job may stay unanswered before the feeder abandons it, in milliseconds.
const ABANDON_MS: u64 = 10_000;
/// The pause before a source is read again, in milliseconds.
const RETRY_MS: u64 = 1_000;

/// A storage read in flight.
enum Job {
    /// A page of an incident or audit feed.
    Feed(BackgroundTicket<Page>),
    /// The membership, and whether the database is SQLite.
    Members(BackgroundTicket<(Membership, bool)>),
    /// The committed policy revision.
    Policy(BackgroundTicket<u64>),
}

/// What a finished job produced.
enum Done {
    Feed(Page),
    Members(Membership, bool),
    Policy(u64),
}

impl Job {
    /// Returns the job's result once it has finished, without waiting.
    fn try_take(&mut self) -> Option<Result<Done, StorageFailure>> {
        match self {
            Job::Feed(ticket) => ticket.try_take().map(|result| result.map(Done::Feed)),
            Job::Members(ticket) => ticket
                .try_take()
                .map(|result| result.map(|(members, single)| Done::Members(members, single))),
            Job::Policy(ticket) => ticket.try_take().map(|result| result.map(Done::Policy)),
        }
    }
}

/// What a source reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    /// The incident feed of one member.
    Events,
    Members,
    Policy,
    Audit,
}

/// One storage source and its cursor.
struct Slot {
    source: Source,
    job: Option<Job>,
    started_ms: u64,
    next_ms: u64,
    cursor: Request,
}

impl Slot {
    fn new(source: Source, cursor: Request) -> Slot {
        Slot { source, job: None, started_ms: 0, next_ms: 0, cursor }
    }
}

/// The feeder's state, owned by its thread.
struct Feeder {
    /// The membership, policy and audit sources, then one incident feed per known member,
    /// this node's first.
    slots: Vec<Slot>,
    /// The second of the last fan-out.
    last_second: Option<u64>,
    observations: Vec<crate::peer::Observation>,
}

/// The feeder thread's body: returns when the console stops.
pub fn run(shared: &Shared) {
    let mut feeder = Feeder::new(shared.live.node());
    while !shared.is_stopping() {
        feeder.tick(shared);
        if !shared.sleep(PERIOD) {
            break;
        }
    }
}

impl Feeder {
    fn new(node: u32) -> Feeder {
        let events = Request { kind: Kind::Events, node, ..Request::default() };
        let audit = Request { kind: Kind::Audit, ..Request::default() };
        Feeder {
            slots: vec![
                Slot::new(Source::Members, Request::default()),
                Slot::new(Source::Policy, Request::default()),
                Slot::new(Source::Audit, audit),
                Slot::new(Source::Events, events),
            ],
            last_second: None,
            observations: Vec::new(),
        }
    }

    /// One period: poll and submit storage reads, then fan out once per second.
    fn tick(&mut self, shared: &Shared) {
        let ms = shared.monotonic_ms();
        let wanted = shared.hub.wanted();
        for index in 0..self.slots.len() {
            self.poll(shared, index, ms);
        }
        for index in 0..self.slots.len() {
            self.submit(shared, index, ms, &wanted);
        }
        let second = shared.now();
        if self.last_second == Some(second) {
            return;
        }
        self.last_second = Some(second);
        // A local view that cannot be published keeps the topic's previous state; its
        // subscribers see it age.
        let _ = self.local(shared, &wanted);
        shared.hub.fanout();
    }

    /// Completes, or abandons after ten seconds, the job of slot `index`.
    fn poll(&mut self, shared: &Shared, index: usize, ms: u64) {
        let Some(slot) = self.slots.get_mut(index) else { return };
        let Some(job) = slot.job.as_mut() else { return };
        match job.try_take() {
            Some(result) => {
                slot.job = None;
                slot.next_ms = ms.saturating_add(RETRY_MS);
                if let Ok(done) = result {
                    // A refused page or an inconsistent source is read again later.
                    let _ = self.complete(shared, index, done, ms);
                }
            }
            None if ms.saturating_sub(slot.started_ms) >= ABANDON_MS => {
                slot.job = None;
                slot.next_ms = ms.saturating_add(RETRY_MS);
            }
            None => {}
        }
    }

    /// Submits the read of slot `index` when it is due, wanted and the allowance permits.
    fn submit(&mut self, shared: &Shared, index: usize, ms: u64, wanted: &[bool; TOPIC_COUNT]) {
        let held = self.slots.iter().filter(|slot| slot.job.is_some()).count();
        let Some(slot) = self.slots.get_mut(index) else { return };
        let needed = match slot.source {
            Source::Events => wanted[Topic::Events.index()],
            Source::Members => wanted[Topic::Nodes.index()] || wanted[Topic::Events.index()],
            Source::Policy => wanted[Topic::Policy.index()],
            Source::Audit => wanted[Topic::Audit.index()],
        };
        if slot.job.is_some() || ms < slot.next_ms || !needed || held >= FEEDER_JOBS {
            return;
        }
        let now = shared.now();
        let storage = &shared.storage;
        let cursor = slot.cursor;
        let job = match slot.source {
            Source::Events | Source::Audit => storage
                .submit_background(move |tx| {
                    Box::pin(async move { feed::read_page(tx, &cursor, now).await })
                })
                .map(Job::Feed),
            Source::Members => storage
                .submit_background(|tx| {
                    Box::pin(async move {
                        let single = tx.dialect() == Dialect::Sqlite;
                        Ok((load_members(tx).await?, single))
                    })
                })
                .map(Job::Members),
            Source::Policy => storage
                .submit_background(|tx| Box::pin(feed::committed_revision(tx)))
                .map(Job::Policy),
        };
        match job {
            Ok(job) => {
                slot.job = Some(job);
                slot.started_ms = ms;
            }
            Err(_) => slot.next_ms = ms.saturating_add(RETRY_MS),
        }
    }

    /// Publishes what the job of slot `index` read.
    fn complete(
        &mut self,
        shared: &Shared,
        index: usize,
        done: Done,
        ms: u64,
    ) -> Result<(), super::TopicError> {
        match done {
            Done::Feed(page) => self.feed_page(shared, index, page, ms),
            Done::Members(membership, single) => {
                self.add_members(shared, &membership)?;
                shared.hub.publish_nodes(nodes_view(shared, membership, single))
            }
            Done::Policy(committed) => {
                let view = PolicyView {
                    node: shared.live.node(),
                    committed,
                    applied: shared.node.applied_revision(),
                    observed_at: shared.now(),
                };
                shared.hub.publish_state(Topic::Policy, &to_json(&view))
            }
        }
    }

    /// Journals a feed page and moves the slot's cursor; a page with more rows behind it is
    /// followed at once.
    fn feed_page(
        &mut self,
        shared: &Shared,
        index: usize,
        mut page: Page,
        ms: u64,
    ) -> Result<(), super::TopicError> {
        let topic = if page.kind == Kind::Events { Topic::Events } else { Topic::Audit };
        if page.kind == Kind::Events && page.node == shared.live.node() {
            page.producer_dropped = Some(shared.metrics.incidents_dropped.value());
        }
        page.producer_boot = Text::new(shared.hub.boot()).unwrap_or_default();
        shared.hub.publish_page(topic, &page)?;
        if let Some(slot) = self.slots.get_mut(index) {
            slot.cursor.after = Some(page.next);
            slot.cursor.through = page.more.then_some(page.through);
            if page.more {
                slot.next_ms = ms;
            }
        }
        Ok(())
    }

    /// Adds an incident feed for every member not yet read.
    fn add_members(
        &mut self,
        shared: &Shared,
        membership: &Membership,
    ) -> Result<(), super::TopicError> {
        for member in &membership.members {
            let node = member.node;
            if node == 0 || node >= 1 << 23 {
                return Err(super::TopicError::TooManySources);
            }
            let events = || self.slots.iter().filter(|slot| slot.source == Source::Events);
            if events().any(|slot| slot.cursor.node == node) {
                continue;
            }
            let count = events().count();
            if count == MAX_MEMBERS {
                return Err(super::TopicError::TooManySources);
            }
            let cursor = Request { kind: Kind::Events, node, ..Request::default() };
            self.slots.push(Slot::new(Source::Events, cursor));
            // At most MAX_MEMBERS (9) sources.
            shared.hub.expect_sources((count + 1) as u8);
        }
        Ok(())
    }

    /// Publishes the local statistics, the dashboard and the challenge funnel, as wanted.
    fn local(
        &mut self,
        shared: &Shared,
        wanted: &[bool; TOPIC_COUNT],
    ) -> Result<(), super::TopicError> {
        if wanted[Topic::Challenges.index()]
            && let Ok(snapshot) = shared.live.challenges(shared)
        {
            shared.hub.publish_state(Topic::Challenges, &to_json(&snapshot))?;
        }
        if wanted[Topic::Stats.index()] {
            let local = shared.live.stats(shared);
            shared.hub.publish_state(Topic::Stats, &to_json(&local))?;
            shared.peers.snapshots(&mut self.observations);
            shared.hub.collect_dashboard(&local, &self.observations, shared.now())?;
        }
        Ok(())
    }
}

/// Builds the `nodes` view from the stored membership, this console's probes and its
/// peers' reports. Without a consensus log, SQLite reports itself as the single leader and
/// PostgreSQL as unknown, and quorum means the database answered (SID 0007).
fn nodes_view(shared: &Shared, membership: Membership, single: bool) -> NodesView {
    let node = shared.live.node();
    let now = shared.now();
    let storage = Storage {
        role: if single { nodes::Role::Single } else { nodes::Role::Unknown },
        leader: single.then_some(node),
        quorum: true,
        observed_at: now,
        ..Storage::default()
    };
    let page = MembersPage {
        self_node: node,
        committed: membership.committed,
        storage,
        members: membership.members,
    };
    let mut probes = Vec::new();
    shared.probes.snapshot(&mut probes);
    let mut peers = Vec::new();
    shared.peers.reports(now, &mut peers);
    NodesView { page, probes, peers, observed_at: now }
}
