//! One DevTools WebSocket: commands with deadlines, and the events that arrive meanwhile.

use std::fs::File;
use std::io::{self, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use sibuna_json::Limits;

use crate::cdp::{Inbox, Message, MessageKind, Params, encode_command, field};
use crate::error::Error;
use crate::websocket::{FrameWriter, Incoming, MaskSource, MessageReader, handshake};

/// How many events may wait unprocessed before the oldest are dropped.
const INBOX_CAPACITY: usize = 4096;

/// A WebSocket to Chromium's browser endpoint, speaking the DevTools protocol.
#[derive(Debug)]
pub(crate) struct Connection {
    stream: TcpStream,
    reader: MessageReader,
    writer: FrameWriter,
    inbox: Inbox,
    limits: Limits,
    next_id: u64,
    /// The command being encoded, reused across commands.
    scratch: String,
    closed: bool,
    /// The optional protocol log and the instant its times count from.
    log: Option<(File, Instant)>,
}

/// How much of each message the protocol log keeps.
const LOG_EXCERPT: usize = 400;

impl Connection {
    /// Connects to `127.0.0.1:port`, performs the handshake for `path`, and bounds every
    /// message by `max_message` bytes. `timeout` bounds the connect, the handshake and
    /// every later write.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when connecting fails and [`Error::Handshake`] when the upgrade does.
    pub(crate) fn open(
        port: u16,
        path: &str,
        max_message: usize,
        timeout: Duration,
    ) -> Result<Connection, Error> {
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let mut stream = TcpStream::connect_timeout(&address, timeout)
            .map_err(|error| Error::io(format!("connecting to DevTools at {address}"), error))?;
        let configure = |stream: &TcpStream| -> io::Result<()> {
            stream.set_nodelay(true)?;
            stream.set_write_timeout(Some(timeout))?;
            stream.set_read_timeout(Some(timeout))
        };
        configure(&stream).map_err(|error| Error::io("configuring the DevTools socket", error))?;
        let mut masks = MaskSource::new();
        let key = masks.handshake_key();
        let rest = handshake(&mut stream, &address.to_string(), path, &key)?;
        let limits = Limits {
            max_input_bytes: max_message,
            max_string_bytes: max_message,
            ..Limits::default()
        };
        Ok(Connection {
            stream,
            reader: MessageReader::new(max_message, rest),
            writer: FrameWriter::new(masks),
            inbox: Inbox::new(INBOX_CAPACITY),
            limits,
            next_id: 1,
            scratch: String::new(),
            closed: false,
            log: None,
        })
    }

    /// Writes every later message, sent and received, to `file`.
    pub(crate) fn set_protocol_log(&mut self, file: File) {
        self.log = Some((file, Instant::now()));
    }

    /// Appends one message to the protocol log, if there is one. Logging is best effort:
    /// a full disk must not fail the check being diagnosed.
    fn trace(&mut self, direction: char, text: &str) {
        let Some((file, since)) = self.log.as_mut() else { return };
        let mut end = text.len().min(LOG_EXCERPT);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        let excerpt = text.get(..end).unwrap_or_default();
        let millis = since.elapsed().as_millis();
        let _ = writeln!(file, "{millis:>8} {direction} {excerpt}");
    }

    /// Sends a command without waiting for its response, which will be discarded.
    /// Returns the command's id.
    ///
    /// # Errors
    ///
    /// [`Error::Closed`] after the connection closed, and [`Error::Io`] when writing fails.
    pub(crate) fn send(
        &mut self,
        session_id: Option<&str>,
        method: &str,
        params: &Params,
    ) -> Result<u64, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        let id = self.next_id;
        self.next_id += 1;
        encode_command(&mut self.scratch, id, session_id, method, params);
        self.writer.send_text(&mut self.stream, &self.scratch)?;
        if self.log.is_some() {
            let text = std::mem::take(&mut self.scratch);
            self.trace('>', &text);
            self.scratch = text;
        }
        Ok(id)
    }

    /// Sends a command and waits until `deadline` for its response. Events that arrive
    /// meanwhile are queued for [`Connection::next_event`].
    ///
    /// # Errors
    ///
    /// [`Error::Command`] when Chromium answers with an error, [`Error::Timeout`] at the
    /// deadline, and the errors of [`Connection::send`] and of reading.
    pub(crate) fn call(
        &mut self,
        session_id: Option<&str>,
        method: &str,
        params: &Params,
        deadline: Instant,
    ) -> Result<Message, Error> {
        let started = Instant::now();
        let id = self.send(session_id, method, params)?;
        loop {
            let Some(message) = self.read_message(deadline)? else {
                return Err(Error::Timeout {
                    what: format!("the response to {method}"),
                    waited: started.elapsed(),
                    last_error: None,
                });
            };
            let Some(response) = self.inbox.accept(message, Some(id)) else { continue };
            if let Some((code, text)) = response.error() {
                let message = text.to_owned();
                return Err(Error::Command { method: method.to_owned(), code, message });
            }
            return Ok(response);
        }
    }

    /// The next event: a queued one, or one read before `deadline`. `Ok(None)` when the
    /// deadline passes first.
    ///
    /// # Errors
    ///
    /// [`Error::Closed`] when the connection closes, and reading or protocol errors.
    pub(crate) fn next_event(&mut self, deadline: Instant) -> Result<Option<Message>, Error> {
        loop {
            if let Some(event) = self.inbox.pop() {
                return Ok(Some(event));
            }
            let Some(message) = self.read_message(deadline)? else { return Ok(None) };
            // A response here belongs to a fire-and-forget command and is dropped.
            self.inbox.accept(message, None);
        }
    }

    /// The number of events dropped because they were not processed in time.
    pub(crate) fn dropped_event_count(&self) -> u64 {
        self.inbox.dropped_count()
    }

    /// Sends a close frame, best effort, so Chromium sees an orderly end.
    pub(crate) fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            let _ = self.writer.send_close(&mut self.stream);
        }
    }

    /// Reads the next DevTools message before `deadline`, answering pings on the way.
    fn read_message(&mut self, deadline: Instant) -> Result<Option<Message>, Error> {
        loop {
            if self.closed {
                return Err(Error::Closed);
            }
            match self.reader.next_message()? {
                Some(Incoming::Text(text)) => {
                    self.trace('<', &text);
                    let message = Message::parse(text, &self.limits)?;
                    if message.kind() == MessageKind::Event("Page.screencastFrame") {
                        self.acknowledge_frame(&message)?;
                    }
                    return Ok(Some(message));
                }
                Some(Incoming::Ping(data)) => self.writer.send_pong(&mut self.stream, &data)?,
                Some(Incoming::Pong) => {}
                Some(Incoming::Binary(_)) => {
                    return Err(Error::Protocol("a binary WebSocket message".into()));
                }
                Some(Incoming::Close) => {
                    self.close();
                    return Err(Error::Closed);
                }
                None => {
                    if !self.fill(deadline)? {
                        return Ok(None);
                    }
                }
            }
        }
    }

    /// Acknowledges a screencast frame as soon as it arrives. Chromium sends the next frame,
    /// and paints the fresh frame `Page.captureScreenshot` waits for, only after the ack;
    /// were the ack left to the page's event handling, a screenshot requested while a
    /// frame waits in the inbox would never be answered.
    fn acknowledge_frame(&mut self, frame: &Message) -> Result<(), Error> {
        let screencast = {
            let body = frame.body()?;
            field(&body, &["params", "sessionId"])
                .and_then(|value| value.as_number())
                .and_then(|number| number.as_i64().ok())
                .unwrap_or(0)
        };
        let session = frame.session_id().map(str::to_owned);
        let params = Params::new().int("sessionId", screencast);
        self.send(session.as_deref(), "Page.screencastFrameAck", &params)?;
        Ok(())
    }

    /// Reads more bytes, waiting no later than `deadline`. Returns false at the deadline.
    fn fill(&mut self, deadline: Instant) -> Result<bool, Error> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            // A zero timeout means "block forever" to the socket, so wait at least 1 ms.
            let wait = remaining.max(Duration::from_millis(1));
            self.stream
                .set_read_timeout(Some(wait))
                .map_err(|error| Error::io("setting the DevTools read deadline", error))?;
            match self.reader.read_from(&mut self.stream) {
                Ok(0) => {
                    self.closed = true;
                    return Err(Error::Closed);
                }
                Ok(_) => return Ok(true),
                Err(error) if is_timeout(&error) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(Error::io("reading from DevTools", error)),
            }
        }
    }
}

/// True for the errors a socket read deadline produces (which differ by platform).
fn is_timeout(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.close();
    }
}
