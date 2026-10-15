//! What a page sends over the network: every request, and every WebSocket with its frames,
//! from the `Network` domain's events.
//!
//! Failures and document responses are recorded in `observe.rs`; this log answers the
//! questions "did the page ask for this URL?" and "which sockets did it open, what did they
//! carry, and are they closed?".

use std::time::Instant;

use sibuna_json::Value;

use crate::cdp::{field, string_at};

/// The most requests and frames a page keeps; later ones are counted and dropped.
const MAX_RECORDS: usize = 10_000;

/// The most WebSockets a page tracks; later ones are counted and dropped.
const MAX_SOCKETS: usize = 256;

/// How much of each frame's payload is kept, in bytes.
pub const MAX_FRAME_TEXT: usize = 4096;

/// A request the page sent, in the order they were sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentRequest {
    /// The URL requested.
    pub url: String,
    /// The method, such as `GET`.
    pub method: String,
    /// Chromium's resource type, such as `Document`, `Script`, `Fetch` or `Other`.
    pub resource_type: String,
}

/// A WebSocket the page created.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebSocketRecord {
    /// The DevTools request id, which names the socket in [`WebSocketFrame::socket`].
    pub id: String,
    /// The `ws:` or `wss:` URL.
    pub url: String,
    /// The handshake's HTTP status, or 0 until it is answered.
    pub status: u16,
    /// Frames received from the server.
    pub frames_received: u64,
    /// Frames the page sent.
    pub frames_sent: u64,
    /// True once Chromium reports the socket closed.
    pub closed: bool,
    /// The last frame error Chromium reported, or empty.
    pub error: String,
}

/// One WebSocket frame, sent or received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebSocketFrame {
    /// The id of the socket in [`WebSocketRecord::id`].
    pub socket: String,
    /// True for a frame the page sent, false for one it received.
    pub sent: bool,
    /// The frame's opcode: 1 for text, 2 for binary.
    pub opcode: u8,
    /// The payload (base64 for binary frames), cut to [`MAX_FRAME_TEXT`] bytes.
    pub payload: String,
    /// When the event was processed.
    pub at: Instant,
}

/// The requests and WebSockets of a page.
#[derive(Debug, Default)]
pub(crate) struct NetworkLog {
    pub(crate) requests: Vec<SentRequest>,
    pub(crate) sockets: Vec<WebSocketRecord>,
    pub(crate) frames: Vec<WebSocketFrame>,
}

impl NetworkLog {
    /// Records the `Network` event `method`; returns false for an event this log ignores.
    /// Records beyond the bounds are counted in `dropped`.
    pub(crate) fn record(&mut self, method: &str, params: &Value<'_>, dropped: &mut u64) -> bool {
        let id = string_at(params, &["requestId"]);
        match method {
            "Network.requestWillBeSent" => {
                let request = SentRequest {
                    url: string_at(params, &["request", "url"]).to_owned(),
                    method: string_at(params, &["request", "method"]).to_owned(),
                    resource_type: string_at(params, &["type"]).to_owned(),
                };
                bounded_push(&mut self.requests, request, MAX_RECORDS, dropped);
            }
            "Network.webSocketCreated" => {
                let socket = WebSocketRecord {
                    id: id.to_owned(),
                    url: string_at(params, &["url"]).to_owned(),
                    status: 0,
                    frames_received: 0,
                    frames_sent: 0,
                    closed: false,
                    error: String::new(),
                };
                bounded_push(&mut self.sockets, socket, MAX_SOCKETS, dropped);
            }
            "Network.webSocketHandshakeResponseReceived" => {
                let status = field(params, &["response", "status"])
                    .and_then(Value::as_number)
                    .and_then(|number| number.as_f64().ok())
                    .map_or(0, |status| status.clamp(0.0, 999.0) as u16);
                if let Some(socket) = self.socket(id) {
                    socket.status = status;
                }
            }
            "Network.webSocketFrameReceived" => self.frame(id, params, false, dropped),
            "Network.webSocketFrameSent" => self.frame(id, params, true, dropped),
            "Network.webSocketFrameError" => {
                let message = string_at(params, &["errorMessage"]).to_owned();
                if let Some(socket) = self.socket(id) {
                    socket.error = message;
                }
            }
            "Network.webSocketClosed" => {
                if let Some(socket) = self.socket(id) {
                    socket.closed = true;
                }
            }
            _ => return false,
        }
        true
    }

    fn socket(&mut self, id: &str) -> Option<&mut WebSocketRecord> {
        self.sockets.iter_mut().find(|socket| socket.id == id)
    }

    fn frame(&mut self, id: &str, params: &Value<'_>, sent: bool, dropped: &mut u64) {
        if let Some(socket) = self.socket(id) {
            if sent {
                socket.frames_sent += 1;
            } else {
                socket.frames_received += 1;
            }
        }
        let opcode = field(params, &["response", "opcode"])
            .and_then(Value::as_number)
            .and_then(|number| number.as_i64().ok())
            .and_then(|opcode| u8::try_from(opcode).ok())
            .unwrap_or(0);
        let frame = WebSocketFrame {
            socket: id.to_owned(),
            sent,
            opcode,
            payload: prefix(string_at(params, &["response", "payloadData"]), MAX_FRAME_TEXT)
                .to_owned(),
            at: Instant::now(),
        };
        bounded_push(&mut self.frames, frame, MAX_RECORDS, dropped);
    }

    /// Forgets the requests and frames. Sockets stay: they are the page's connection state,
    /// and a socket opened before the clear must still be seen to close.
    pub(crate) fn clear(&mut self) {
        self.requests.clear();
        self.frames.clear();
    }
}

fn bounded_push<T>(records: &mut Vec<T>, record: T, bound: usize, dropped: &mut u64) {
    if records.len() < bound {
        records.push(record);
    } else {
        *dropped += 1;
    }
}

/// The longest prefix of `text` of at most `limit` bytes that ends on a character boundary.
fn prefix(text: &str, limit: usize) -> &str {
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(log: &mut NetworkLog, method: &str, params: &str) -> bool {
        let value = sibuna_json::parse(params.as_bytes()).unwrap();
        let mut dropped = 0;
        log.record(method, &value, &mut dropped)
    }

    #[test]
    fn records_requests_in_order() {
        let mut log = NetworkLog::default();
        let sent =
            r#"{"requestId":"1","type":"Fetch","request":{"url":"http://a/x","method":"POST"}}"#;
        assert!(record(&mut log, "Network.requestWillBeSent", sent));
        assert!(!record(&mut log, "Network.dataReceived", r#"{"requestId":"1"}"#));
        assert_eq!(
            log.requests,
            vec![SentRequest {
                url: "http://a/x".into(),
                method: "POST".into(),
                resource_type: "Fetch".into(),
            }]
        );
    }

    #[test]
    fn follows_a_websocket_from_creation_to_close() {
        let mut log = NetworkLog::default();
        record(&mut log, "Network.webSocketCreated", r#"{"requestId":"9","url":"ws://a/ws"}"#);
        record(
            &mut log,
            "Network.webSocketHandshakeResponseReceived",
            r#"{"requestId":"9","response":{"status":101}}"#,
        );
        let frame = |text: &str| {
            format!(r#"{{"requestId":"9","response":{{"opcode":1,"payloadData":"{text}"}}}}"#)
        };
        record(&mut log, "Network.webSocketFrameSent", &frame("hello"));
        record(&mut log, "Network.webSocketFrameReceived", &frame("one"));
        record(&mut log, "Network.webSocketFrameReceived", &frame("two"));
        record(
            &mut log,
            "Network.webSocketFrameError",
            r#"{"requestId":"9","errorMessage":"bad"}"#,
        );
        let socket = &log.sockets[0];
        assert_eq!((socket.status, socket.frames_sent, socket.frames_received), (101, 1, 2));
        assert!(!socket.closed);
        assert_eq!(socket.error, "bad");
        record(&mut log, "Network.webSocketClosed", r#"{"requestId":"9"}"#);
        assert!(log.sockets[0].closed);
        let payloads: Vec<(bool, &str)> =
            log.frames.iter().map(|frame| (frame.sent, frame.payload.as_str())).collect();
        assert_eq!(payloads, [(true, "hello"), (false, "one"), (false, "two")]);
        assert_eq!(log.frames[0].opcode, 1);
        log.clear();
        assert_eq!((log.frames.len(), log.sockets.len()), (0, 1));
    }

    #[test]
    fn bounds_sockets_and_cuts_long_payloads() {
        let mut log = NetworkLog::default();
        let mut dropped = 0;
        for index in 0..MAX_SOCKETS + 3 {
            let text = format!(r#"{{"requestId":"{index}","url":"ws://a/"}}"#);
            let value = sibuna_json::parse(text.as_bytes()).unwrap();
            log.record("Network.webSocketCreated", &value, &mut dropped);
        }
        assert_eq!((log.sockets.len(), dropped), (MAX_SOCKETS, 3));
        let long = format!(
            r#"{{"requestId":"0","response":{{"opcode":1,"payloadData":"{}"}}}}"#,
            "\u{e9}".repeat(MAX_FRAME_TEXT)
        );
        record(&mut log, "Network.webSocketFrameReceived", &long);
        let payload = &log.frames[0].payload;
        assert!(payload.len() <= MAX_FRAME_TEXT && payload.len() >= MAX_FRAME_TEXT - 1);
        assert!(payload.chars().all(|c| c == '\u{e9}'));
    }
}
