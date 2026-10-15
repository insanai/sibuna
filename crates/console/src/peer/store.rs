//! The peer store (Zig's `peer_store.zig`): the latest observation of each configured peer,
//! the inbound admission of peer streams, and each peer's query queue. One mutex in
//! [`super::Peers`] guards it; every method here runs under that lock and does bounded
//! work.
//!
//! An outbound connection is a [`Handle`]: the peer's index, a connection generation and
//! the boot the peer proved. A snapshot is accepted only from the current generation, only
//! when it names the peer's node and boot, and only when its sequence, watermark and uptime
//! all move forward; a new boot counts a reset. A connection that ends leaves the last
//! observation stale, never zero.

use std::collections::VecDeque;
use std::fmt;

use sibuna_console_protocol::nodes::{Peer, PeerStatus};
use sibuna_console_protocol::{CountryCount, StatsSnapshot, Text};
use sibuna_geoip::Country;

use super::Observation;
use super::auth::{AuthError, ReplayCache, Transcript};
use super::query::{Cursor, Kind, MAX_OUTSTANDING, Outcome, Queued, Status, Ticket};

/// A peer whose last snapshot is this old (seconds) is reported stale.
pub const STALE_SECONDS: u64 = 10;

/// Why the store refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StoreError {
    /// The peer proof was refused.
    Auth(AuthError),
    /// The node is not a configured peer, or this console has no peer key.
    UnknownPeer,
    /// The node already has an inbound stream.
    DuplicateConnection,
    /// The console is stopping.
    Stopping,
    /// The connection generation cannot advance.
    GenerationExhausted,
    /// The snapshot names another node, boot or format, or has invalid geography.
    InvalidObservation,
    /// The peer is not current, or its query queue is full.
    PeerUnavailable,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Auth(error) => error.fmt(f),
            StoreError::UnknownPeer => f.write_str("unknown management peer"),
            StoreError::DuplicateConnection => f.write_str("the peer is already connected"),
            StoreError::Stopping => f.write_str("the console is stopping"),
            StoreError::GenerationExhausted => f.write_str("peer generations exhausted"),
            StoreError::InvalidObservation => f.write_str("invalid peer snapshot"),
            StoreError::PeerUnavailable => f.write_str("the peer is unavailable"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<AuthError> for StoreError {
    fn from(error: AuthError) -> StoreError {
        StoreError::Auth(error)
    }
}

/// One authenticated outbound connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Handle {
    /// The peer's position in the configuration.
    pub index: usize,
    /// The connection generation.
    pub generation: u64,
    /// The boot the peer proved.
    pub boot: [u8; 16],
}

/// A snapshot a peer sent, with its subscription position.
#[derive(Clone, Copy, Debug)]
pub struct Update<'a> {
    /// The peer's statistics; copied when accepted.
    pub value: &'a StatsSnapshot,
    /// The view's watermark.
    pub watermark: u64,
    /// The view's sequence.
    pub sequence: u64,
    /// When it arrived, in Unix seconds.
    pub received_at: u64,
}

/// One configured peer.
#[derive(Debug)]
struct Slot {
    incoming: bool,
    generation: u64,
    published_generation: u64,
    boot: [u8; 16],
    observation: Observation,
    queries: VecDeque<Queued>,
    /// Queries queued or on the wire.
    outstanding: usize,
}

/// The observations, admissions and query queues of the configured peers.
#[derive(Debug)]
pub struct Store {
    self_node: u32,
    slots: Vec<Slot>,
    replay: ReplayCache,
    stopping: bool,
}

impl Store {
    /// Returns a store for this console's node `self_node` and the peers `nodes`, in
    /// configuration order.
    pub fn new(self_node: u32, nodes: &[u32]) -> Store {
        let slots = nodes
            .iter()
            .map(|&node| Slot {
                incoming: false,
                generation: 0,
                published_generation: 0,
                boot: [0; 16],
                observation: Observation::unobserved(node),
                queries: VecDeque::new(),
                outstanding: 0,
            })
            .collect();
        Store { self_node, slots, replay: ReplayCache::default(), stopping: false }
    }

    /// Returns the configuration index of `node`.
    pub fn find(&self, node: u32) -> Option<usize> {
        self.slots.iter().position(|slot| slot.observation.node == node)
    }

    /// Refuses everything from now on and fails every queued query as cancelled.
    pub fn stop(&mut self) {
        self.stopping = true;
        for slot in &mut self.slots {
            for queued in slot.queries.drain(..) {
                queued.answer(Outcome::Failed(Status::Cancelled));
                slot.outstanding = slot.outstanding.saturating_sub(1);
            }
        }
    }

    /// Admits an inbound stream with `transcript` and `proof` at `now`, proved under `key`,
    /// and returns the peer's index; at most one inbound stream per peer.
    ///
    /// Fails with [`StoreError::Stopping`], [`StoreError::UnknownPeer`] (no key, or the
    /// sender is not configured), [`StoreError::Auth`] with
    /// [`AuthError::InvalidIdentity`] when the transcript is not addressed to this node,
    /// [`StoreError::DuplicateConnection`], or the replay cache's errors.
    pub fn admit(
        &mut self,
        key: Option<&[u8; 32]>,
        transcript: &Transcript,
        proof: &[u8; 32],
        now: u64,
    ) -> Result<usize, StoreError> {
        if self.stopping {
            return Err(StoreError::Stopping);
        }
        let key = key.ok_or(StoreError::UnknownPeer)?;
        if transcript.to != self.self_node {
            return Err(AuthError::InvalidIdentity.into());
        }
        let index = self.find(transcript.from).ok_or(StoreError::UnknownPeer)?;
        if self.slots.get(index).is_some_and(|slot| slot.incoming) {
            return Err(StoreError::DuplicateConnection);
        }
        self.replay.accept(key, transcript, proof, now)?;
        if let Some(slot) = self.slots.get_mut(index) {
            slot.incoming = true;
        }
        Ok(index)
    }

    /// Ends the inbound stream of peer `index`.
    pub fn release(&mut self, index: usize) {
        if let Some(slot) = self.slots.get_mut(index) {
            slot.incoming = false;
        }
    }

    /// Starts a new connection generation for peer `index`, which proved `boot`. A retained
    /// observation turns stale until the new connection delivers a snapshot.
    ///
    /// Fails with [`StoreError::Stopping`], [`StoreError::InvalidObservation`] for an
    /// all-zero boot or an unknown index, or [`StoreError::GenerationExhausted`].
    pub fn activate(&mut self, index: usize, boot: [u8; 16]) -> Result<Handle, StoreError> {
        if self.stopping {
            return Err(StoreError::Stopping);
        }
        if boot == [0; 16] {
            return Err(StoreError::InvalidObservation);
        }
        let slot = self.slots.get_mut(index).ok_or(StoreError::InvalidObservation)?;
        slot.generation = slot.generation.checked_add(1).ok_or(StoreError::GenerationExhausted)?;
        slot.boot = boot;
        let observation = &mut slot.observation;
        observation.status =
            if observation.value.is_some() { PeerStatus::Stale } else { PeerStatus::Connecting };
        Ok(Handle { index, generation: slot.generation, boot })
    }

    /// Publishes a snapshot of connection `handle`. Returns true when it was accepted, false
    /// when it is from an old connection, or does not advance the sequence (within this
    /// connection), the watermark or the uptime of the same boot.
    ///
    /// Fails with [`StoreError::InvalidObservation`] when the snapshot names another node
    /// or boot, an outcome format other than 1, a sampling probability other than 1/64, an
    /// invalid location, or invalid or repeated countries.
    pub fn publish(&mut self, handle: &Handle, update: &Update<'_>) -> Result<bool, StoreError> {
        let Some(slot) = self.slots.get_mut(handle.index) else { return Ok(false) };
        if self.stopping || slot.generation != handle.generation {
            return Ok(false);
        }
        let value = update.value;
        let malformed = value.node != slot.observation.node
            || value.outcomes_version != 1
            || value.boot != handle.boot
            || value.sample_probability != "1/64"
            || value.server_location.is_some_and(|location| !location.is_valid());
        if malformed {
            return Err(StoreError::InvalidObservation);
        }
        validate_countries(&value.countries)?;
        if let Some(incidents) = &value.incident_geo {
            if incidents.version != 1 {
                return Err(StoreError::InvalidObservation);
            }
            validate_countries(&incidents.countries)?;
        }
        let observation = &mut slot.observation;
        if let Some(previous) = &observation.value {
            if previous.boot == value.boot {
                let repeated = slot.published_generation == handle.generation
                    && update.sequence <= observation.sequence;
                if repeated
                    || update.watermark <= observation.watermark
                    || value.uptime_ms <= previous.uptime_ms
                {
                    return Ok(false);
                }
            } else {
                observation.resets = observation.resets.saturating_add(1);
            }
        }
        observation.value = Some(value.clone());
        observation.watermark = update.watermark;
        observation.sequence = update.sequence;
        observation.received_at = update.received_at;
        observation.status = PeerStatus::Current;
        slot.published_generation = handle.generation;
        Ok(true)
    }

    /// Records that the connection to peer `index` ended: rejected (refused proof or
    /// certificate) or stale. Returns true when the peer was not rejected before, so the
    /// caller audits a refusal once, not on every retry.
    pub fn failed(&mut self, index: usize, rejected: bool) -> bool {
        let Some(slot) = self.slots.get_mut(index) else { return false };
        let before = slot.observation.status;
        slot.observation.status = if rejected { PeerStatus::Rejected } else { PeerStatus::Stale };
        rejected && before != PeerStatus::Rejected
    }

    /// Replaces `out` with every peer's latest observation, in configuration order.
    pub fn snapshots(&self, out: &mut Vec<Observation>) {
        out.clear();
        out.extend(self.slots.iter().map(|slot| slot.observation.clone()));
    }

    /// Replaces `out` with every peer's report at `now`; a missing sample stays absent, and
    /// wall-clock skew is reported apart from the receipt age.
    pub fn reports(&self, now: u64, out: &mut Vec<Peer>) {
        out.clear();
        out.extend(self.slots.iter().map(|slot| report(&slot.observation, now)));
    }

    /// Queues a query of `kind` with `cursor` to peer `node` as query `id`, at `now`.
    ///
    /// Fails with [`StoreError::Stopping`], [`StoreError::UnknownPeer`], or
    /// [`StoreError::PeerUnavailable`] when the peer is not current, its last snapshot is
    /// ten seconds old, or [`MAX_OUTSTANDING`] queries are outstanding.
    pub fn submit(
        &mut self,
        id: u64,
        node: u32,
        kind: Kind,
        cursor: Cursor,
        now: u64,
    ) -> Result<Ticket, StoreError> {
        if self.stopping {
            return Err(StoreError::Stopping);
        }
        let index = self.find(node).ok_or(StoreError::UnknownPeer)?;
        let slot = self.slots.get_mut(index).ok_or(StoreError::UnknownPeer)?;
        let observation = &slot.observation;
        let current = observation.status == PeerStatus::Current
            && now.saturating_sub(observation.received_at) < STALE_SECONDS;
        if !current || slot.outstanding >= MAX_OUTSTANDING {
            return Err(StoreError::PeerUnavailable);
        }
        let handle = Handle { index, generation: slot.generation, boot: slot.boot };
        let (queued, ticket) = Queued::new(id, &handle, kind, cursor);
        slot.queries.push_back(queued);
        slot.outstanding += 1;
        Ok(ticket)
    }

    /// Takes the oldest queued query of peer `index`; it stays outstanding until
    /// [`Store::finish`].
    pub fn take(&mut self, index: usize) -> Option<Queued> {
        self.slots.get_mut(index).and_then(|slot| slot.queries.pop_front())
    }

    /// Answers `queued`, taken from peer `index`, with `outcome`.
    pub fn finish(&mut self, index: usize, queued: &Queued, outcome: Outcome) {
        queued.answer(outcome);
        if let Some(slot) = self.slots.get_mut(index) {
            slot.outstanding = slot.outstanding.saturating_sub(1);
        }
    }
}

/// The report of one observation at `now`.
fn report(observation: &Observation, now: u64) -> Peer {
    let mut report =
        Peer { node: observation.node, status: observation.status, ..Peer::default() };
    let Some(value) = &observation.value else { return report };
    let age = now.saturating_sub(observation.received_at);
    if age >= STALE_SECONDS && report.status == PeerStatus::Current {
        report.status = PeerStatus::Stale;
    }
    report.boot = Text::new(&sibuna_encoding::hex::encode(&value.boot)).ok();
    report.age_seconds = Some(age);
    report.clock_skew_seconds = Some(value.timestamp.abs_diff(observation.received_at));
    report.sequence = observation.sequence;
    report.watermark = observation.watermark;
    report.resets = observation.resets;
    report.requests = Some(value.requests);
    report.sample_loss = Some(value.sample_loss);
    report.geoip_available = value.geoip_available;
    report.rss_kib = value.rss_kib;
    report.cpu_permille = value.cpu_permille;
    report
}

/// Checks a peer's country rows: wire codes pack two ASCII letters (unlike the collector's
/// dense 26 x 26 index); an empty row has no samples; Unknown has its own counter, never a
/// row; no code repeats.
fn validate_countries(rows: &[CountryCount]) -> Result<(), StoreError> {
    for (index, row) in rows.iter().enumerate() {
        if row.code == 0 {
            if row.samples != 0 {
                return Err(StoreError::InvalidObservation);
            }
            continue;
        }
        let country = Country::from_bytes(row.code.to_be_bytes());
        if country.is_none_or(Country::is_unknown)
            || rows.iter().take(index).any(|prior| prior.code == row.code)
        {
            return Err(StoreError::InvalidObservation);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
