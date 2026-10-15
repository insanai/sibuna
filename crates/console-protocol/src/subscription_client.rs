//! Transactional reassembly of subscription views, shared by the browser and peer
//! consoles.
//!
//! The server sends a snapshot as `snapshot_begin`, numbered `snapshot_chunk` fragments
//! and `snapshot_end`; then deltas, each in fragments. A view becomes visible only when it
//! is complete, and a gap keeps the last good view and refuses further deltas until a new
//! subscription epoch supplies a snapshot (SID 0007, "The Real-Time Protocol").
//!
//! The Zig client kept two 64 KiB fixed buffers per topic plus a scratch buffer, and a
//! caller-supplied allocator for parsing. Here each topic owns two `String`s that never
//! grow past [`SNAPSHOT_BYTES`]; parsing borrows them, and the patched view is written into
//! a fresh string that replaces the old one. Buffers are zeroed on [`Client::reset`] and on
//! drop, as Zig's `secureZero` did.

use std::fmt;

use sibuna_json::{Limits, Number, Value, Writer};

use crate::codec::WireEnum;
use crate::json_delta;
use crate::subscriptions::{FRAGMENT_BYTES, SNAPSHOT_BYTES, TOPIC_COUNT, Topic};

/// Fragments a reassembled view may have.
const MAX_PARTS: u64 = (SNAPSHOT_BYTES / (FRAGMENT_BYTES - 3) + 1) as u64;
/// Rows a row-appending topic keeps.
const MAX_ROWS: usize = 64;

/// What a message did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Event {
    /// Nothing visible changed.
    None,
    /// The session ended; return to sign-in.
    Unauthorized,
    /// The topic lost messages; resubscribe for a new snapshot.
    Gap(Topic),
    /// The topic's view changed.
    Changed(Topic),
}

/// Why a message was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClientError {
    /// The message breaks the protocol: wrong fields, order, epoch, sequence or JSON.
    InvalidMessage,
    /// A fragment or view exceeds its bound. (Zig reported a view that outgrew its
    /// buffer while being rewritten as `WriteFailed`.)
    TooLarge,
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ClientError::InvalidMessage => "the subscription message breaks the protocol",
            ClientError::TooLarge => "the subscription view exceeds its bound",
        })
    }
}

impl std::error::Error for ClientError {}

/// A completed view's position, which consumers may acknowledge.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Position {
    /// The last applied sequence.
    pub sequence: u64,
    /// The view's watermark.
    pub watermark: u64,
}

/// One topic's reassembly state.
#[derive(Debug)]
struct Slot {
    epoch: String,
    sequence: u64,
    watermark: u64,
    update: u64,
    part: u64,
    parts: u64,
    pending: bool,
    snapshot: bool,
    row: bool,
    blocked: bool,
    current: String,
    incoming: String,
}

impl Default for Slot {
    fn default() -> Slot {
        Slot {
            epoch: String::new(),
            sequence: 0,
            watermark: 0,
            update: 0,
            part: 0,
            parts: 0,
            pending: false,
            snapshot: false,
            row: false,
            blocked: true,
            current: String::new(),
            incoming: String::new(),
        }
    }
}

/// Overwrites a string's bytes with zeros and empties it, keeping its allocation.
fn wipe(text: &mut String) {
    let mut bytes = std::mem::take(text).into_bytes();
    bytes.fill(0);
    // Keep the zeroing from being optimised away as a dead store.
    std::hint::black_box(&bytes);
    bytes.clear();
    *text = String::from_utf8(bytes).unwrap_or_default();
}

impl Slot {
    fn wipe(&mut self) {
        wipe(&mut self.epoch);
        wipe(&mut self.current);
        wipe(&mut self.incoming);
        let (epoch, current, incoming) = (
            std::mem::take(&mut self.epoch),
            std::mem::take(&mut self.current),
            std::mem::take(&mut self.incoming),
        );
        *self = Slot { epoch, current, incoming, ..Slot::default() };
    }
}

/// The reassembly state of every topic.
#[derive(Debug, Default)]
pub struct Client {
    slots: [Slot; TOPIC_COUNT],
}

impl Drop for Client {
    fn drop(&mut self) {
        self.reset();
    }
}

impl Client {
    /// Returns a client with every topic blocked until its first snapshot.
    pub fn new() -> Client {
        Client::default()
    }

    /// Zeroes every view and blocks every topic.
    pub fn reset(&mut self) {
        for slot in &mut self.slots {
            slot.wipe();
        }
    }

    fn slot(&self, topic: Topic) -> &Slot {
        // The slots array has one entry per topic.
        &self.slots[topic.index()]
    }

    /// Returns the last complete view of `topic`; empty before the first one.
    pub fn view(&self, topic: Topic) -> &str {
        &self.slot(topic).current
    }

    /// Returns the position of a completed, gap-free view.
    pub fn position(&self, topic: Topic) -> Option<Position> {
        let slot = self.slot(topic);
        if slot.pending || slot.blocked {
            return None;
        }
        Some(Position { sequence: slot.sequence, watermark: slot.watermark })
    }

    /// Parses one server message and receives it; see [`Client::receive`].
    ///
    /// # Errors
    ///
    /// [`ClientError::InvalidMessage`] for invalid JSON, and as [`Client::receive`].
    pub fn receive_text(&mut self, message: &[u8]) -> Result<Event, ClientError> {
        let limits = Limits { max_input_bytes: SNAPSHOT_BYTES * 2, ..Limits::default() };
        let value = sibuna_json::parse_with_limits(message, &limits)
            .map_err(|_| ClientError::InvalidMessage)?;
        self.receive(&value)
    }

    /// Receives one parsed server message. As in the Zig client, a refused message may
    /// leave its topic's partial reassembly state changed; consumers resubscribe after any
    /// error.
    ///
    /// # Errors
    ///
    /// [`ClientError::InvalidMessage`] for a message that breaks the protocol and
    /// [`ClientError::TooLarge`] for an oversized fragment or view.
    pub fn receive(&mut self, value: &Value<'_>) -> Result<Event, ClientError> {
        let object = value.as_object().ok_or(ClientError::InvalidMessage)?;
        if object.contains_key("error") {
            return match text(value, "error")? {
                "unauthorized" => Ok(Event::Unauthorized),
                _ => Err(ClientError::InvalidMessage),
            };
        }
        let op = text(value, "op")?;
        if op == "pong" {
            return Ok(Event::None);
        }
        let topic = Topic::from_name(text(value, "topic")?).ok_or(ClientError::InvalidMessage)?;
        let slot = &mut self.slots[topic.index()];
        let epoch = text(value, "epoch")?;
        if op == "snapshot_begin" {
            begin(slot, value, epoch)?;
            return Ok(Event::None);
        }
        if epoch != slot.epoch {
            return Err(ClientError::InvalidMessage);
        }
        if op == "gap" {
            number(value, "dropped")?;
            slot.blocked = true;
            slot.pending = false;
            wipe(&mut slot.incoming);
            return Ok(Event::Gap(topic));
        }
        receive_sequenced(slot, value, op, topic)
    }
}

/// Handles the messages that carry a sequence: chunks, deltas and the snapshot's end.
fn receive_sequenced(
    slot: &mut Slot,
    value: &Value<'_>,
    op: &str,
    topic: Topic,
) -> Result<Event, ClientError> {
    if slot.blocked {
        return Err(ClientError::InvalidMessage);
    }
    let sequence = number(value, "seq")?;
    if slot.sequence == u64::MAX || sequence != slot.sequence + 1 {
        return Err(ClientError::InvalidMessage);
    }
    if op == "snapshot_end" {
        snapshot_flag(value, true)?;
        if !slot.pending
            || !slot.snapshot
            || slot.part != slot.parts
            || number(value, "watermark")? != slot.watermark
        {
            return Err(ClientError::InvalidMessage);
        }
        commit(slot)?;
    } else {
        let snapshot = op == "snapshot_chunk";
        if !snapshot && op != "delta" {
            return Err(ClientError::InvalidMessage);
        }
        append(slot, value, snapshot)?;
        if snapshot || slot.part != slot.parts {
            slot.sequence = sequence;
            return Ok(Event::None);
        }
        commit(slot)?;
    }
    slot.sequence = sequence;
    Ok(Event::Changed(topic))
}

/// Starts a snapshot of a new epoch: 32 hex digits, a colon and a decimal number, at most
/// 64 bytes, different from the current epoch, at sequence zero.
fn begin(slot: &mut Slot, value: &Value<'_>, epoch: &str) -> Result<(), ClientError> {
    snapshot_flag(value, true)?;
    let bytes = epoch.as_bytes();
    if !(34..=64).contains(&bytes.len())
        || bytes.get(32) != Some(&b':')
        || epoch == slot.epoch
        || number(value, "seq")? != 0
    {
        return Err(ClientError::InvalidMessage);
    }
    let (digits, counter) =
        (bytes.get(..32).unwrap_or_default(), epoch.get(33..).unwrap_or_default());
    if !digits.iter().all(u8::is_ascii_hexdigit) || crate::codec::zig_parse_u64(counter).is_none()
    {
        return Err(ClientError::InvalidMessage);
    }
    let parts = number(value, "parts")?;
    if parts == 0 || parts > MAX_PARTS {
        return Err(ClientError::InvalidMessage);
    }
    wipe(&mut slot.epoch);
    slot.epoch.push_str(epoch);
    wipe(&mut slot.incoming);
    slot.sequence = 0;
    slot.watermark = number(value, "watermark")?;
    slot.parts = parts;
    slot.part = 0;
    slot.snapshot = true;
    slot.pending = true;
    slot.blocked = false;
    Ok(())
}

/// Appends one fragment of a snapshot or delta, starting a delta at its part zero.
fn append(slot: &mut Slot, value: &Value<'_>, snapshot: bool) -> Result<(), ClientError> {
    snapshot_flag(value, snapshot)?;
    let part = number(value, "part")?;
    let parts = number(value, "parts")?;
    let watermark = number(value, "watermark")?;
    if parts == 0 || parts > MAX_PARTS {
        return Err(ClientError::InvalidMessage);
    }
    if !snapshot && part == 0 {
        if slot.pending || watermark < slot.watermark {
            return Err(ClientError::InvalidMessage);
        }
        slot.update = number(value, "update")?;
        slot.watermark = watermark;
        slot.part = 0;
        slot.parts = parts;
        slot.snapshot = false;
        slot.pending = true;
        let kind = text(value, "kind")?;
        slot.row = kind == "row";
        if !slot.row && kind != "patch" {
            return Err(ClientError::InvalidMessage);
        }
        wipe(&mut slot.incoming);
    }
    if !slot.pending
        || slot.snapshot != snapshot
        || part != slot.part
        || parts != slot.parts
        || part >= parts
    {
        return Err(ClientError::InvalidMessage);
    }
    if snapshot {
        if watermark != slot.watermark {
            return Err(ClientError::InvalidMessage);
        }
    } else {
        if number(value, "update")? != slot.update || watermark < slot.watermark {
            return Err(ClientError::InvalidMessage);
        }
        slot.watermark = watermark;
    }
    let data = text(value, "data")?;
    if data.is_empty()
        || data.len() > FRAGMENT_BYTES
        || data.len() > SNAPSHOT_BYTES - slot.incoming.len()
    {
        return Err(ClientError::TooLarge);
    }
    slot.incoming.push_str(data);
    slot.part += 1;
    Ok(())
}

/// Parses a reassembled document, which must be a JSON object.
fn parse_object(text: &str) -> Result<Value<'_>, ClientError> {
    let value = sibuna_json::parse(text.as_bytes()).map_err(|_| ClientError::InvalidMessage)?;
    if value.as_object().is_none() {
        return Err(ClientError::InvalidMessage);
    }
    Ok(value)
}

/// Makes the reassembled snapshot or delta the current view.
fn commit(slot: &mut Slot) -> Result<(), ClientError> {
    let incoming = parse_object(&slot.incoming)?;
    if slot.snapshot {
        drop(incoming);
        wipe(&mut slot.current);
        slot.current.push_str(&slot.incoming);
    } else {
        let old = parse_object(&slot.current)?;
        let mut view = String::new();
        let written = if slot.row {
            add_row(&old, &incoming, &mut view)?
        } else {
            let patched =
                json_delta::patch(&old, &incoming).map_err(|_| ClientError::InvalidMessage)?;
            patched.write(&mut Writer::new(&mut view))
        };
        if written.is_err() || view.len() > SNAPSHOT_BYTES {
            return Err(ClientError::TooLarge);
        }
        drop((old, incoming));
        wipe(&mut slot.current);
        slot.current = view;
    }
    slot.pending = false;
    wipe(&mut slot.incoming);
    Ok(())
}

/// Writes `state` with `row` prepended to its `rows`, keeping at most [`MAX_ROWS`] rows.
/// The row's id must be new.
fn add_row(
    state: &Value<'_>,
    row: &Value<'_>,
    out: &mut String,
) -> Result<fmt::Result, ClientError> {
    let object = state.as_object().ok_or(ClientError::InvalidMessage)?;
    let rows = object.get("rows").and_then(Value::as_array).ok_or(ClientError::InvalidMessage)?;
    if rows.len() > MAX_ROWS {
        return Err(ClientError::InvalidMessage);
    }
    let id = number(row, "id")?;
    for item in rows {
        if number(item, "id")? == id {
            return Err(ClientError::InvalidMessage);
        }
    }
    let kept = rows.get(..rows.len().min(MAX_ROWS - 1)).unwrap_or_default();
    let mut json = Writer::new(out);
    let write = |json: &mut Writer<&mut String>| -> fmt::Result {
        json.begin_object()?;
        for (key, value) in object {
            json.key(key)?;
            if key != "rows" {
                json_delta::write_value(json, value)?;
                continue;
            }
            json.begin_array()?;
            json_delta::write_value(json, row)?;
            for item in kept {
                json_delta::write_value(json, item)?;
            }
            json.end_array()?;
        }
        json.end_object()
    };
    Ok(write(&mut json))
}

/// Returns the string member `key` of an object.
fn text<'v>(value: &'v Value<'_>, key: &str) -> Result<&'v str, ClientError> {
    value
        .as_object()
        .and_then(|object| object.get(key))
        .and_then(Value::as_str)
        .ok_or(ClientError::InvalidMessage)
}

/// Returns the counter member `key`: a non-negative integer within `i64` written as an
/// integer, or a string of 1 to 20 decimal digits within `u64`.
fn number(value: &Value<'_>, key: &str) -> Result<u64, ClientError> {
    let item =
        value.as_object().and_then(|object| object.get(key)).ok_or(ClientError::InvalidMessage)?;
    let parsed = match item {
        Value::Number(number) => integer(*number),
        Value::String(text) => {
            let digits =
                (1..=20).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_digit());
            if digits { text.parse::<u64>().ok() } else { None }
        }
        _ => None,
    };
    parsed.ok_or(ClientError::InvalidMessage)
}

/// A number Zig's dynamic parser made a non-negative `i64` integer.
fn integer(number: Number<'_>) -> Option<u64> {
    let text = number.as_str();
    if text == "-0" || text.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
        return None;
    }
    text.parse::<i64>().ok().and_then(|value| u64::try_from(value).ok())
}

/// Checks the `snapshot` flag.
fn snapshot_flag(value: &Value<'_>, expected: bool) -> Result<(), ClientError> {
    let flag =
        value.as_object().and_then(|object| object.get("snapshot")).and_then(Value::as_bool);
    if flag == Some(expected) { Ok(()) } else { Err(ClientError::InvalidMessage) }
}

#[cfg(test)]
mod tests;
