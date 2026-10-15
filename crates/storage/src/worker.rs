//! The storage thread's state and its tick: persist queued incidents (announcing each batch
//! once it is confirmed committed), then rebuild the policy snapshot, with its page
//! templates, when the revision changed or a ban expired.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use sibuna_core::{Incident, Metrics};
use sibuna_store::ring::BoundedQueue;

use crate::campaigns::CampaignWindow;
use crate::database::Database;
#[cfg(test)]
use crate::database::Target;
use crate::error::StorageError;
use crate::incidents::{
    BatchContext, INCIDENT_BATCH, INCIDENT_QUEUE, IncidentRecord, PreparedBatch,
    load_next_sequence, prepare, view, write_batch,
};
use crate::schema::{CORE, MigrationSet, migrate};
use crate::storage::{Committed, Hooks};

/// The state request threads share with the storage thread.
pub(crate) struct Shared {
    /// Incidents waiting for the storage thread.
    pub(crate) queue: BoundedQueue<IncidentRecord, INCIDENT_QUEUE>,
    /// The daemon's counters.
    pub(crate) metrics: Arc<Metrics>,
    /// Wakes the storage thread: shutdown, a command, or a policy notification.
    pub(crate) wake: tokio::sync::Notify,
    /// Set once by `shutdown`. Release on store and Acquire on load, so the storage thread
    /// sees every incident pushed before the flag when it drains for the last time.
    pub(crate) stopping: AtomicBool,
    /// Set by the PostgreSQL listener when another node changed the policy. Relaxed is
    /// enough: it only makes the next tick earlier, and `wake` orders the hand-over.
    pub(crate) policy_notified: AtomicBool,
}

impl Shared {
    pub(crate) fn new(metrics: Arc<Metrics>) -> Shared {
        Shared {
            queue: BoundedQueue::new(),
            metrics,
            wake: tokio::sync::Notify::new(),
            stopping: AtomicBool::new(false),
            policy_notified: AtomicBool::new(false),
        }
    }

    /// Copies `incident` into the ring; a full ring drops it and counts the drop.
    pub(crate) fn record(&self, incident: &Incident<'_>) {
        if self.queue.push(IncidentRecord::from_incident(incident)).is_err() {
            self.metrics.incidents_dropped.bump();
        }
    }
}

/// Settings the worker takes from the daemon's configuration.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Settings {
    /// This node's id, 1 when none was configured (as in Zig).
    pub(crate) node: u32,
    /// How long a honeypot ban lasts.
    pub(crate) ban_seconds: u64,
}

/// Returns the current Unix time in seconds.
pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The storage thread's state. Tests drive [`Worker::tick`] directly, as the Zig tests
/// drove `Persistent.tick`.
pub(crate) struct Worker {
    pub(crate) db: Database,
    pub(crate) shared: Arc<Shared>,
    pub(crate) hooks: Hooks,
    /// The core schema followed by the hooks' components.
    migrations: Vec<MigrationSet>,
    pub(crate) settings: Settings,
    /// The sequence number the next batch starts at.
    pub(crate) next_sequence: u64,
    /// Records taken from the ring and not yet confirmed written.
    pub(crate) pending: Vec<IncidentRecord>,
    /// The prepared form of `pending`, kept so a retry writes the identical batch.
    pub(crate) prepared: Option<PreparedBatch>,
    /// The revision of the last published snapshot.
    pub(crate) applied_revision: Option<u64>,
    /// When the earliest loaded ban expires.
    pub(crate) reputation_expires: Option<u64>,
    pub(crate) campaigns: CampaignWindow,
    /// The wall clock in Unix seconds; tests replace it.
    pub(crate) clock: fn() -> u64,
}

impl Worker {
    /// Returns a worker over `db` that has not loaded anything yet.
    pub(crate) fn new(
        db: Database,
        settings: Settings,
        mut hooks: Hooks,
        shared: Arc<Shared>,
    ) -> Worker {
        let mut migrations = vec![CORE];
        migrations.append(&mut hooks.migrations);
        Worker {
            db,
            shared,
            hooks,
            migrations,
            settings,
            next_sequence: 1,
            pending: Vec::with_capacity(INCIDENT_BATCH),
            prepared: None,
            applied_revision: None,
            reputation_expires: None,
            campaigns: CampaignWindow::new(),
            clock: unix_now,
        }
    }

    /// Connects to `target` and initialises a worker; tests use it in place of the thread.
    #[cfg(test)]
    pub(crate) async fn open(
        target: &Target,
        settings: Settings,
        hooks: Hooks,
        shared: Arc<Shared>,
    ) -> Result<Worker, StorageError> {
        let db = Database::open(target).await?;
        let mut worker = Worker::new(db, settings, hooks, shared);
        worker.initialize().await?;
        Ok(worker)
    }

    /// Migrates, loads the incident receipt and the campaign window, and publishes the
    /// first snapshot. It may be retried after a failure.
    pub(crate) async fn initialize(&mut self) -> Result<(), StorageError> {
        migrate(&self.db, &self.migrations, unix_now()).await?;
        self.load_next_sequence().await?;
        self.campaigns = CampaignWindow::new();
        self.campaigns.load(&self.db).await?;
        self.rebuild().await
    }

    pub(crate) async fn load_next_sequence(&mut self) -> Result<(), StorageError> {
        self.next_sequence = load_next_sequence(&self.db, self.settings.node).await?;
        Ok(())
    }

    /// One maintenance round. A failed incident write is counted and kept for the next
    /// round; it does not stop the policy check, so a stalled write cannot starve policy
    /// and reputation updates. Fails when the policy check or rebuild fails.
    pub(crate) async fn tick(&mut self) -> Result<(), StorageError> {
        if let Err(error) = self.campaigns.refresh(&self.db).await {
            self.report(&error);
        }
        if let Err(error) = self.drain().await {
            self.shared.metrics.incident_write_failures.bump();
            self.report(&error);
        }
        let revision = self.db.policy_revision().await?;
        let expired = self.reputation_expires.is_some_and(|at| (self.clock)() >= at);
        if self.applied_revision != Some(revision) || expired {
            self.rebuild().await?;
        }
        if let Some(on_tick) = self.hooks.on_tick.as_mut() {
            on_tick(self.db.clone()).await;
        }
        Ok(())
    }

    pub(crate) fn report(&mut self, error: &StorageError) {
        if let Some(on_error) = self.hooks.on_error.as_mut() {
            on_error(error);
        }
    }

    /// Takes up to a batch of records from the ring when nothing is pending.
    fn fill_pending(&mut self) {
        if !self.pending.is_empty() {
            return;
        }
        // Only the storage thread consumes; `consumer` fails only if another consumer is
        // alive, which would be a bug in this module.
        let Some(mut consumer) = self.shared.queue.consumer() else { return };
        while self.pending.len() < INCIDENT_BATCH {
            let Some(record) = consumer.pop() else { break };
            self.pending.push(record);
        }
    }

    /// Writes the pending batch, taking a new one from the ring first when none is pending.
    /// Returns the number of incidents written (0 when the ring was empty).
    pub(crate) async fn drain(&mut self) -> Result<usize, StorageError> {
        self.fill_pending();
        if self.pending.is_empty() {
            return Ok(0);
        }
        if self.prepared.is_none() {
            let context = BatchContext {
                node: self.settings.node,
                first_sequence: self.next_sequence,
                ban_seconds: self.settings.ban_seconds,
                embed: self.hooks.embed.as_ref(),
                window: &self.campaigns,
            };
            self.prepared = Some(prepare(&self.pending, &context)?);
        }
        let Some(batch) = self.prepared.take() else { return Ok(0) };
        let hook = self.hooks.on_incidents.as_mut();
        if let Err(error) = write_batch(&self.db, self.settings.node, &batch, hook).await {
            self.prepared = Some(batch);
            return Err(error);
        }
        self.announce(&batch);
        let written = batch.incidents.len();
        let metrics = &self.shared.metrics;
        metrics.incidents_persisted.add(u64::try_from(written).unwrap_or(u64::MAX));
        metrics.incident_batches.bump();
        // A refresh may already have read this batch back after an unacknowledged commit.
        let node = self.settings.node;
        if self.campaigns.cursor(node) < batch.end {
            for incident in &batch.incidents {
                self.campaigns.push(incident.unit, incident.campaign);
            }
            self.campaigns.advance(node, batch.end);
        }
        self.next_sequence = batch.end;
        self.pending.clear();
        Ok(written)
    }

    /// Tells the committed hook about `batch`, whose write was just confirmed. A batch is
    /// confirmed once: `drain` clears it from `pending` right after, and a batch whose
    /// commit was not acknowledged stays pending until a retry confirms it.
    fn announce(&mut self, batch: &PreparedBatch) {
        let Some(on_committed) = self.hooks.on_committed.as_mut() else { return };
        let committed: Vec<Committed<'_>> = batch
            .incidents
            .iter()
            .map(|incident| {
                let incident = view(incident);
                Committed {
                    id: incident.id,
                    client_ip: incident.client_ip,
                    recorded_at: incident.recorded_at,
                }
            })
            .collect();
        on_committed(&committed);
    }

    /// Loads a snapshot and its page templates, checks that no writer committed meanwhile,
    /// and hands it to the publish hook. On any failure (the page hook's included) the
    /// applied revision and the expiry stay as they were, so the next tick tries again and
    /// the old engine stays live.
    pub(crate) async fn rebuild(&mut self) -> Result<(), StorageError> {
        let revision = self.db.policy_revision().await?;
        let mut snapshot = self.db.load_policy_snapshot(revision, (self.clock)()).await?;
        if let Some(on_snapshot) = self.hooks.on_snapshot.as_mut() {
            let mut tx = self.db.begin().await?;
            snapshot.pages = on_snapshot(&mut tx).await?;
            tx.commit().await?;
        }
        // A page change advances the revision too, so this check also covers the templates.
        if self.db.policy_revision().await? != revision {
            return Err(StorageError::PolicyRevisionChanged);
        }
        let expires = snapshot.next_expiry;
        if !(self.hooks.publish)(snapshot) {
            return Err(StorageError::PublishRejected);
        }
        self.applied_revision = Some(revision);
        self.reputation_expires = expires;
        Ok(())
    }

    /// Flushes every queued incident. Returns true when all of them were confirmed written;
    /// false after the first failure. The caller bounds the time it may take.
    pub(crate) async fn flush(&mut self) -> bool {
        loop {
            match self.drain().await {
                Ok(0) => return true,
                Ok(_) => {}
                Err(error) => {
                    self.shared.metrics.incident_write_failures.bump();
                    self.report(&error);
                    return false;
                }
            }
        }
    }

    /// Returns true once `shutdown` has been requested.
    pub(crate) fn is_stopping(&self) -> bool {
        self.shared.stopping.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests;
