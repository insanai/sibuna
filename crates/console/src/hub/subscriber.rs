//! One subscriber's state machine (Zig's `subscriber.zig`).
//!
//! Each topic of a subscriber is in one phase:
//!
//! ```text
//! off --sub/filter--> waiting --snapshot--> streaming --snapshot_end--> live
//!  ^                     ^                                               |
//!  +------unsub----------+---------- sub/filter (new epoch) -------------+
//!                        |                                               v
//!                        +---------- sub/filter (new epoch) --------- paused
//!                                                     (a ring or outbox gap)
//! ```
//!
//! A snapshot is `snapshot_begin`, numbered `snapshot_chunk` fragments of the view and
//! `snapshot_end`, all with the ring watermark the view was taken at; deltas follow from the
//! record after that watermark. A topic whose view is computed per subscriber (the browser's
//! dashboard, and `nodes` filtered to one node) is refreshed whenever its journal moves: the
//! view is computed again and the delta from the subscriber's previous view is sent as a
//! fragmented `delta`. A gap pauses the topic until the client subscribes again.
//!
//! The fan-out calls [`Subscriber::pump`] once a second; it sends at most
//! [`MESSAGES_PER_SECOND`] messages and scans at most that many per topic, which bounds the
//! filtering work as well as the traffic.

use std::fmt::{self, Write};

use sibuna_console_protocol::Topic;
use sibuna_console_protocol::codec::{WireEnum, counter_field, field, to_json};
use sibuna_console_protocol::json_delta;
use sibuna_console_protocol::subscriptions::{
    Args, Command, MESSAGES_PER_SECOND, Op, RECORD_BYTES, SNAPSHOT_BYTES, TOPIC_COUNT,
    fragment_length,
};
use sibuna_json::Writer;

use super::Frame;
use super::outbox::Outbox;
use super::ring::Read;
use super::topic::{Bounded, Kind, Store, TopicError, fragments};
use super::views::NodesView;
use crate::collector::dashboard;

/// The largest view kept per subscriber for a filtered topic (Zig's 16 KiB buffers).
pub const VIEW_BYTES: usize = 16_384;

/// What the fan-out reads while it pumps subscribers.
#[derive(Clone, Copy, Debug)]
pub struct Sources<'a> {
    /// This console's boot as hex, the first half of every epoch.
    pub boot: &'a str,
    /// The topic stores; for browsers with a dashboard, the stats entry is the dashboard's
    /// journal.
    pub stores: [&'a Store; TOPIC_COUNT],
    /// The dashboard, for browsers once it has been collected.
    pub dashboard: Option<&'a dashboard::Frame>,
    /// The structured `nodes` view, once published.
    pub nodes: Option<&'a NodesView>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Phase {
    #[default]
    Off,
    Waiting,
    Streaming,
    Live,
    Paused,
}

#[derive(Clone, Debug)]
struct State {
    phase: Phase,
    args: Args,
    epoch: u64,
    /// The next message's sequence number.
    sequence: u64,
    /// The next ring record to read.
    cursor: u64,
}

impl Default for State {
    fn default() -> State {
        State { phase: Phase::Off, args: Args::default(), epoch: 0, sequence: 0, cursor: 1 }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Begin,
    Chunks,
    End,
}

/// A message being sent in fragments: a snapshot, or the delta of a filtered view.
#[derive(Clone, Copy, Debug)]
struct Pending {
    topic: Topic,
    snapshot: bool,
    step: Step,
    watermark: u64,
    /// The bytes of the payload already sent.
    offset: usize,
    part: u16,
    parts: u16,
}

/// Which per-subscriber view a filtered topic keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum View {
    Stats,
    Nodes,
}

/// What a server message is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Message {
    Begin,
    Chunk,
    End,
    Delta,
}

/// One server message before it is written.
struct Envelope<'a> {
    message: Message,
    topic: Topic,
    epoch: &'a str,
    seq: u64,
    watermark: u64,
    part: u16,
    parts: u16,
    update: u64,
    row: bool,
    data: &'a str,
}

impl Envelope<'_> {
    /// Writes the message with the members its operation has, in the order of SID 0007's
    /// example exchange.
    fn write<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        let (op, snapshot) = match self.message {
            Message::Begin => ("snapshot_begin", true),
            Message::Chunk => ("snapshot_chunk", true),
            Message::End => ("snapshot_end", true),
            Message::Delta => ("delta", false),
        };
        json.begin_object()?;
        field(json, "op", op)?;
        field(json, "topic", &self.topic)?;
        field(json, "epoch", self.epoch)?;
        counter_field(json, "seq", self.seq)?;
        field(json, "snapshot", &snapshot)?;
        counter_field(json, "watermark", self.watermark)?;
        match self.message {
            Message::Begin => field(json, "parts", &self.parts)?,
            Message::Chunk => {
                field(json, "part", &self.part)?;
                field(json, "parts", &self.parts)?;
                field(json, "data", self.data)?;
            }
            Message::End => {}
            Message::Delta => {
                field(json, "part", &self.part)?;
                field(json, "parts", &self.parts)?;
                counter_field(json, "update", self.update)?;
                field(json, "kind", if self.row { "row" } else { "patch" })?;
                field(json, "data", self.data)?;
            }
        }
        json.end_object()
    }

    /// Returns the message's text, at most [`RECORD_BYTES`] bytes.
    fn text(&self) -> Result<String, TopicError> {
        let mut out = String::new();
        let mut sink = Bounded { out: &mut out, limit: RECORD_BYTES };
        self.write(&mut Writer::new(&mut sink)).map_err(|_| TopicError::TooLarge)?;
        Ok(out)
    }
}

/// One subscriber: its outbox and the phase of each topic.
#[derive(Debug)]
pub struct Subscriber {
    /// The frames and gap notices waiting for the stream's writer.
    pub outbox: Outbox,
    states: [State; TOPIC_COUNT],
    /// The message being fragmented (snapshot or filtered delta).
    payload: String,
    stats_view: String,
    node_view: String,
    pending: Option<Pending>,
    next_topic: usize,
    /// A management peer's stream: it reads the local statistics, never the dashboard.
    peer: bool,
}

impl Subscriber {
    /// Returns a subscriber with every topic off.
    pub fn new(peer: bool) -> Subscriber {
        Subscriber {
            outbox: Outbox::default(),
            states: Default::default(),
            payload: String::new(),
            stats_view: String::new(),
            node_view: String::new(),
            pending: None,
            next_topic: 0,
            peer,
        }
    }

    /// Applies a client command at `epoch`: a subscription or filter starts the topic over
    /// with a snapshot, an unsubscription stops it. Its queued frames are dropped.
    pub fn command(&mut self, input: &Command, epoch: u64) {
        let Some(topic) = input.topic else { return };
        self.outbox.reset(topic);
        if self.pending.is_some_and(|pending| pending.topic == topic) {
            self.pending = None;
        }
        let phase = if input.op == Op::Unsub { Phase::Off } else { Phase::Waiting };
        self.states[topic.index()] =
            State { phase, args: input.args.clone(), epoch, ..State::default() };
    }

    /// Returns true when `topic` is subscribed and not paused by a gap.
    pub fn wants(&self, topic: Topic) -> bool {
        !matches!(self.states[topic.index()].phase, Phase::Off | Phase::Paused)
    }

    /// Queues the next messages from `sources`: snapshots of waiting topics, the fragments
    /// of a pending message, and deltas of live topics.
    ///
    /// Fails with [`TopicError`] when a view or message exceeds its bound; the caller then
    /// calls [`Subscriber::fail`].
    pub fn pump(&mut self, sources: &Sources<'_>) -> Result<(), TopicError> {
        let mut sent = 0;
        for _ in 0..MESSAGES_PER_SECOND * TOPIC_COUNT {
            if sent == MESSAGES_PER_SECOND {
                break;
            }
            let topic = Topic::ALL[self.next_topic % TOPIC_COUNT];
            self.next_topic = (self.next_topic + 1) % TOPIC_COUNT;
            let store = sources.stores[topic.index()];
            if self.states[topic.index()].phase == Phase::Waiting && self.pending.is_none() {
                self.snapshot(sources, topic, store)?;
            }
            if self.pending.is_some_and(|pending| pending.topic == topic) {
                self.fragment(sources)?;
                sent += 1;
            } else if self.states[topic.index()].phase == Phase::Live
                && self.delta(sources, topic, store)?
            {
                sent += 1;
            }
        }
        Ok(())
    }

    /// Invalidates every active topic after a failed pump: the client keeps its last good
    /// views, and nothing incomplete is called a snapshot.
    pub fn fail(&mut self) {
        for (index, state) in self.states.iter_mut().enumerate() {
            if matches!(state.phase, Phase::Off | Phase::Paused) {
                continue;
            }
            self.outbox.invalidate(Topic::ALL[index], state.epoch, 1);
            state.phase = Phase::Paused;
        }
        self.pending = None;
    }

    /// Takes the snapshot of a waiting topic and starts sending it.
    fn snapshot(
        &mut self,
        sources: &Sources<'_>,
        topic: Topic,
        store: &Store,
    ) -> Result<(), TopicError> {
        let state = &self.states[topic.index()];
        self.payload.clear();
        snapshot_view(sources, topic, store, &state.args, &mut self.payload)?;
        if let Some(view) = self.kept_view(topic) {
            let kept = match view {
                View::Stats => &mut self.stats_view,
                View::Nodes => &mut self.node_view,
            };
            keep(kept, &self.payload)?;
        }
        let state = &mut self.states[topic.index()];
        let watermark = store.ring.watermark();
        state.cursor = watermark.saturating_add(1);
        state.phase = Phase::Streaming;
        self.pending = Some(Pending {
            topic,
            snapshot: true,
            step: Step::Begin,
            watermark,
            offset: 0,
            part: 0,
            parts: part_count(&self.payload)?,
        });
        Ok(())
    }

    /// Queues the next message of the pending snapshot or filtered delta.
    fn fragment(&mut self, sources: &Sources<'_>) -> Result<(), TopicError> {
        let Some(mut pending) = self.pending.take() else { return Ok(()) };
        let (part, parts) = (pending.part, pending.parts);
        let (message, data) = match pending.step {
            Step::Begin => {
                pending.step = Step::Chunks;
                (Message::Begin, 0..0)
            }
            Step::Chunks => {
                let remaining = self.payload.get(pending.offset..).unwrap_or_default();
                let length = fragment_length(remaining);
                let range = pending.offset..pending.offset + length;
                pending.offset += length;
                pending.part = pending.part.saturating_add(1);
                if pending.offset >= self.payload.len() {
                    pending.step = Step::End;
                }
                (if pending.snapshot { Message::Chunk } else { Message::Delta }, range)
            }
            Step::End => (Message::End, 0..0),
        };
        let topic = pending.topic;
        let state = &self.states[topic.index()];
        let epoch = format!("{}:{}", sources.boot, state.epoch);
        let text = Envelope {
            message,
            topic,
            epoch: &epoch,
            seq: state.sequence,
            watermark: pending.watermark,
            part,
            parts,
            update: pending.watermark,
            row: false,
            data: self.payload.get(data).unwrap_or_default(),
        }
        .text()?;
        let complete = message == Message::End || (!pending.snapshot && pending.step == Step::End);
        if complete {
            self.states[topic.index()].phase = Phase::Live;
        } else {
            self.pending = Some(pending);
        }
        self.offer(topic, text);
        Ok(())
    }

    /// Sends the next journal record of a live topic; returns true when a message was
    /// queued.
    fn delta(
        &mut self,
        sources: &Sources<'_>,
        topic: Topic,
        store: &Store,
    ) -> Result<bool, TopicError> {
        let cursor = self.states[topic.index()].cursor;
        let record = match store.ring.read(cursor) {
            Read::Empty => return Ok(false),
            Read::Gap { dropped, .. } => {
                self.pause(topic, dropped);
                return Ok(false);
            }
            Read::Record(record) => record,
        };
        if record.metadata.kind == Kind::Gap {
            self.pause(topic, 1);
            return Ok(false);
        }
        if self.filtered_view(sources, topic).is_some() {
            if self.pending.is_none() {
                self.filtered_state(sources, topic, store)?;
            }
            return Ok(false);
        }
        let state = &mut self.states[topic.index()];
        state.cursor = cursor + 1;
        let row = record.metadata.kind == Kind::Row;
        if row && !record.metadata.matches(&state.args) {
            return Ok(false);
        }
        let epoch = format!("{}:{}", sources.boot, state.epoch);
        let text = Envelope {
            message: Message::Delta,
            topic,
            epoch: &epoch,
            seq: state.sequence,
            watermark: cursor,
            part: record.metadata.part,
            parts: record.metadata.parts,
            update: record.metadata.update,
            row,
            data: &record.payload,
        }
        .text()?;
        self.offer(topic, text);
        Ok(true)
    }

    /// Computes a filtered view again and starts sending its delta, if it changed.
    fn filtered_state(
        &mut self,
        sources: &Sources<'_>,
        topic: Topic,
        store: &Store,
    ) -> Result<(), TopicError> {
        let Some(which) = self.filtered_view(sources, topic) else { return Ok(()) };
        let mut view = String::new();
        snapshot_view(sources, topic, store, &self.states[topic.index()].args, &mut view)?;
        let previous = match which {
            View::Stats => &mut self.stats_view,
            View::Nodes => &mut self.node_view,
        };
        self.payload.clear();
        let mut sink = Bounded { out: &mut self.payload, limit: SNAPSHOT_BYTES };
        let changed = json_delta::write(previous.as_bytes(), view.as_bytes(), &mut sink)
            .map_err(|_| TopicError::TooLarge)?;
        keep(previous, &view)?;
        let state = &mut self.states[topic.index()];
        let watermark = store.ring.watermark();
        state.cursor = watermark.saturating_add(1);
        if !changed {
            return Ok(());
        }
        state.phase = Phase::Streaming;
        self.pending = Some(Pending {
            topic,
            snapshot: false,
            step: Step::Chunks,
            watermark,
            offset: 0,
            part: 0,
            parts: part_count(&self.payload)?,
        });
        Ok(())
    }

    /// The per-subscriber view `topic` uses now, if it is filtered.
    fn filtered_view(&self, sources: &Sources<'_>, topic: Topic) -> Option<View> {
        match topic {
            Topic::Stats if sources.dashboard.is_some() && !self.peer => Some(View::Stats),
            Topic::Nodes if self.states[topic.index()].args.node.is_some() => Some(View::Nodes),
            _ => None,
        }
    }

    /// The per-subscriber view a snapshot of `topic` must remember: also a browser's
    /// statistics before the dashboard exists, so its first dashboard delta has a base.
    fn kept_view(&self, topic: Topic) -> Option<View> {
        match topic {
            Topic::Stats if !self.peer => Some(View::Stats),
            Topic::Nodes if self.states[topic.index()].args.node.is_some() => Some(View::Nodes),
            _ => None,
        }
    }

    /// Queues `text`, a message of `topic`, and pauses the topic an overflow invalidated.
    fn offer(&mut self, topic: Topic, text: String) {
        let epoch = self.states[topic.index()].epoch;
        if let Some(invalidated) = self.outbox.offer(Frame { topic, epoch, text }) {
            self.states[invalidated.index()].phase = Phase::Paused;
            if self.pending.is_some_and(|pending| pending.topic == invalidated) {
                self.pending = None;
            }
        }
        let state = &mut self.states[topic.index()];
        state.sequence = state.sequence.saturating_add(1);
    }

    /// Pauses `topic` after `dropped` journal records were lost to it.
    fn pause(&mut self, topic: Topic, dropped: u64) {
        let state = &mut self.states[topic.index()];
        self.outbox.invalidate(topic, state.epoch, dropped);
        state.phase = Phase::Paused;
        if self.pending.is_some_and(|pending| pending.topic == topic) {
            self.pending = None;
        }
    }
}

/// Writes the view of `topic` with `args` into `out`: the dashboard for browsers, `nodes`
/// filtered to one node, otherwise the store's snapshot.
fn snapshot_view(
    sources: &Sources<'_>,
    topic: Topic,
    store: &Store,
    args: &Args,
    out: &mut String,
) -> Result<(), TopicError> {
    let text = match (topic, sources.dashboard, sources.nodes, args.node) {
        (Topic::Stats, Some(dashboard), _, node) => to_json(&dashboard.view(node)),
        (Topic::Nodes, _, Some(nodes), Some(node)) => to_json(&nodes.filtered(node)),
        _ => return store.snapshot(topic, args, out),
    };
    if out.len() + text.len() > SNAPSHOT_BYTES {
        return Err(TopicError::TooLarge);
    }
    out.push_str(&text);
    Ok(())
}

/// Replaces a kept view with `view`, which must fit [`VIEW_BYTES`].
fn keep(kept: &mut String, view: &str) -> Result<(), TopicError> {
    if view.len() > VIEW_BYTES {
        return Err(TopicError::TooLarge);
    }
    view.clone_into(kept);
    Ok(())
}

/// Returns the number of fragments of `payload`.
fn part_count(payload: &str) -> Result<u16, TopicError> {
    u16::try_from(fragments(payload).count()).map_err(|_| TopicError::TooLarge)
}
