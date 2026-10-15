//! The Chrome DevTools Protocol message layer: commands out, responses and events in.
//!
//! A command is a JSON object `{"id", "method", "params", "sessionId"}`; Chromium answers
//! with `{"id", "result"}` or `{"id", "error"}` and sends events as `{"method", "params",
//! "sessionId"}`. The session id is present for messages of a target attached with
//! `flatten: true`, so one WebSocket carries the browser and all its pages.
//!
//! [`Message`] keeps the received text and the routing fields read from it, and parses the
//! body again on demand: a parsed `sibuna_json::Value` borrows its input, so a value cannot
//! outlive the text, and keeping the text is simpler than copying every value into an
//! owned tree. [`Inbox`] decides what happens to each message while a command is awaited.

use std::collections::VecDeque;
use std::fmt::Write as _;

use sibuna_json::{Limits, Value};

use crate::error::Error;

/// The parameters of a command, built as a JSON object.
///
/// ```
/// use sibuna_browser::cdp::Params;
///
/// let params = Params::new().string("url", "http://a/\"b\"").bool("flatten", true);
/// assert_eq!(params.as_json(), r#"{"url":"http://a/\"b\"","flatten":true}"#);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    /// The members written so far, without the closing brace.
    text: String,
}

impl Default for Params {
    fn default() -> Self {
        Params::new()
    }
}

impl Params {
    /// An empty parameter object.
    pub fn new() -> Params {
        Params { text: String::from("{") }
    }

    /// Writes the separating comma and the key.
    fn key(mut self, key: &str) -> Params {
        if self.text.len() > 1 {
            self.text.push(',');
        }
        // Writing into a String cannot fail.
        let _ = sibuna_json::write_string(&mut self.text, key);
        self.text.push(':');
        self
    }

    /// Adds a string member, escaped as JSON.
    pub fn string(self, key: &str, value: &str) -> Params {
        let mut params = self.key(key);
        let _ = sibuna_json::write_string(&mut params.text, value);
        params
    }

    /// Adds an integer member.
    pub fn int(self, key: &str, value: i64) -> Params {
        let mut params = self.key(key);
        let _ = write!(params.text, "{value}");
        params
    }

    /// Adds a number member; NaN and infinities become `null`, as in JavaScript.
    pub fn float(self, key: &str, value: f64) -> Params {
        let mut params = self.key(key);
        if value.is_finite() {
            let _ = write!(params.text, "{value}");
        } else {
            params.text.push_str("null");
        }
        params
    }

    /// Adds a boolean member.
    pub fn bool(self, key: &str, value: bool) -> Params {
        let mut params = self.key(key);
        params.text.push_str(if value { "true" } else { "false" });
        params
    }

    /// Adds a member whose value is another parameter object.
    pub fn object(self, key: &str, value: &Params) -> Params {
        let mut params = self.key(key);
        params.text.push_str(&value.as_json());
        params
    }

    /// Adds a member whose value is an array of parameter objects.
    pub fn array(self, key: &str, items: &[Params]) -> Params {
        let mut params = self.key(key);
        params.text.push('[');
        for (index, item) in items.iter().enumerate() {
            if index > 0 {
                params.text.push(',');
            }
            params.text.push_str(&item.as_json());
        }
        params.text.push(']');
        params
    }

    /// The object as JSON text.
    pub fn as_json(&self) -> String {
        format!("{}}}", self.text)
    }
}

/// Writes the command `{"id","method","params","sessionId"}` into `out` (cleared first).
pub fn encode_command(
    out: &mut String,
    id: u64,
    session_id: Option<&str>,
    method: &str,
    params: &Params,
) {
    out.clear();
    // Writing into a String cannot fail.
    let _ = write!(out, "{{\"id\":{id},\"method\":");
    let _ = sibuna_json::write_string(out, method);
    out.push_str(",\"params\":");
    out.push_str(&params.text);
    out.push('}');
    if let Some(session) = session_id {
        out.push_str(",\"sessionId\":");
        let _ = sibuna_json::write_string(out, session);
    }
    out.push('}');
}

/// Whether a message answers a command or reports an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageKind<'m> {
    /// A response to the command with this id.
    Response(u64),
    /// An event, such as `Page.loadEventFired`.
    Event(&'m str),
}

/// One message received from Chromium.
#[derive(Clone, Debug)]
pub struct Message {
    text: String,
    id: Option<u64>,
    method: Option<Box<str>>,
    session_id: Option<Box<str>>,
    error: Option<(i64, Box<str>)>,
}

impl Message {
    /// Parses `text` within `limits` and reads its routing fields.
    ///
    /// # Errors
    ///
    /// [`Error::Protocol`] when the text is not a JSON object with either a non-negative
    /// integer `id` or a string `method`.
    pub fn parse(text: String, limits: &Limits) -> Result<Message, Error> {
        let (id, method, session_id, error) = {
            let value = sibuna_json::parse_with_limits(text.as_bytes(), limits)?;
            let object = value
                .as_object()
                .ok_or_else(|| Error::Protocol("a message is not a JSON object".into()))?;
            let id = match object.get("id") {
                Some(id) => {
                    Some(id.as_number().and_then(|n| n.as_u64().ok()).ok_or_else(|| {
                        Error::Protocol("a message id is not a non-negative integer".into())
                    })?)
                }
                None => None,
            };
            let method = object.get("method").and_then(Value::as_str).map(Box::from);
            if id.is_none() && method.is_none() {
                return Err(Error::Protocol("a message has neither id nor method".into()));
            }
            let session_id = object.get("sessionId").and_then(Value::as_str).map(Box::from);
            let error = object.get("error").map(|error| {
                let code = field(error, &["code"])
                    .and_then(Value::as_number)
                    .and_then(|n| n.as_i64().ok())
                    .unwrap_or(0);
                let message = field(error, &["message"]).and_then(Value::as_str).unwrap_or("");
                (code, Box::from(message))
            });
            (id, method, session_id, error)
        };
        Ok(Message { text, id, method, session_id, error })
    }

    /// A response or an event. A message with an id is a response.
    pub fn kind(&self) -> MessageKind<'_> {
        match (self.id, &self.method) {
            (Some(id), _) => MessageKind::Response(id),
            (None, method) => MessageKind::Event(method.as_deref().unwrap_or_default()),
        }
    }

    /// The flattened session the message belongs to; `None` for the browser itself.
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// The error a response carries, as its code and message.
    pub fn error(&self) -> Option<(i64, &str)> {
        self.error.as_ref().map(|(code, message)| (*code, &**message))
    }

    /// The message as received.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The whole message, parsed again. Use [`field`] to reach `result` or `params`.
    ///
    /// # Errors
    ///
    /// Never for a message built by [`Message::parse`], whose text already parsed; the
    /// `Result` is kept because the limits used here are the unbounded ones.
    pub fn body(&self) -> Result<Value<'_>, Error> {
        // The text parsed within the caller's limits once already.
        Ok(sibuna_json::parse_with_limits(self.text.as_bytes(), &Limits::UNBOUNDED)?)
    }
}

/// Follows `path` through nested objects: `field(body, &["result", "value"])`.
pub fn field<'v, 'a>(value: &'v Value<'a>, path: &[&str]) -> Option<&'v Value<'a>> {
    path.iter().try_fold(value, |current, key| current.as_object()?.get(key))
}

/// The string at `path`, or the empty string.
pub fn string_at<'v>(value: &'v Value<'_>, path: &[&str]) -> &'v str {
    field(value, path).and_then(Value::as_str).unwrap_or_default()
}

/// Holds events that arrive while a command is awaited, in arrival order.
///
/// The queue is bounded: past `capacity` events the oldest is dropped and counted, so a
/// page that floods the log cannot exhaust memory.
#[derive(Debug)]
pub struct Inbox {
    events: VecDeque<Message>,
    capacity: usize,
    dropped: u64,
}

impl Inbox {
    /// An empty inbox holding at most `capacity` events.
    pub fn new(capacity: usize) -> Inbox {
        Inbox { events: VecDeque::new(), capacity: capacity.max(1), dropped: 0 }
    }

    /// Routes one message while the command `awaited` (if any) is outstanding.
    ///
    /// Returns the message when it is the awaited response. Events are queued; responses
    /// to other commands (fire-and-forget acknowledgements) are discarded.
    pub fn accept(&mut self, message: Message, awaited: Option<u64>) -> Option<Message> {
        match message.kind() {
            MessageKind::Response(id) if Some(id) == awaited => Some(message),
            MessageKind::Response(_) => None,
            MessageKind::Event(_) => {
                if self.events.len() == self.capacity {
                    self.events.pop_front();
                    self.dropped += 1;
                }
                self.events.push_back(message);
                None
            }
        }
    }

    /// The oldest queued event.
    pub fn pop(&mut self) -> Option<Message> {
        self.events.pop_front()
    }

    /// The number of queued events.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// The number of events dropped because the queue was full.
    pub fn dropped_count(&self) -> u64 {
        self.dropped
    }
}

#[cfg(test)]
mod tests;
