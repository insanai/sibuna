//! The route `/console/ws`: the browser's WebSocket (Zig's `stream.zig`, browser part),
//! upgraded under the browser admission class and served by [`crate::hub::Hub`].
//!
//! The upgrade must carry an `Origin` equal to the console's origin (400 `CONSOLE002`
//! otherwise, as for any malformed upgrade). A 65th browser subscriber is answered 503
//! `CONSOLE503` while HTTP keeps its reserved slots. After the upgrade the connection's
//! worker thread is the writer and a scoped thread the reader:
//!
//! ```text
//! reader thread                              writer (worker thread), every <= 100 ms
//!   frames -> commands -> Hub::command         control replies (pong, close echo)
//!   ping -> pong, close -> echo  ---queue--->  expiry and idle checks (60 s without a frame)
//!   errors -> close code                       authority rechecked every 5 s
//!                                              hub frames and gap notices (<= 64)
//!                                              ping every 20 s
//! ```
//!
//! Only the writer sends, so frames never interleave. When either side stops, the writer
//! sends the close frame the reader chose (1009 too large, 1007 invalid UTF-8, 1002 protocol
//! error, 1008 a refused message), shuts the socket down (which wakes the reader) and joins
//! the reader. A revoked or restricted session receives `{"error":"unauthorized"}` and close
//! 1008; a session that cannot be checked because storage does not answer is closed with
//! 1013, "try again later". A client may send at most 64 commands per second, and a kiosk
//! session may subscribe to `stats` only; anything else closes with 1008.
//!
//! # Changes from the Zig version
//!
//! - The writer waits for hub frames on a condition variable for at most 100 ms instead of
//!   sleeping 100 ms between rounds; the bounds are the same.
//! - A storage failure while the authority is rechecked closes with 1013 (try again later)
//!   instead of reporting the session unauthorized: the session was not refused, only
//!   unverifiable, as the dispatcher's 503 for the same case says.

use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use sibuna_console_protocol::codec::{WireEnum, counter_field, field};
use sibuna_console_protocol::storage::Failure;
use sibuna_console_protocol::subscriptions::{self, MESSAGES_PER_SECOND, Op};
use sibuna_console_protocol::{AuthorizationCheck, CredentialKind, Principal, Topic};
use sibuna_console_storage::access;
use sibuna_http::websocket::{
    Event, FrameError, FrameReader, MAX_CONTROL, Opcode, ReceiveError, Receiver, Role,
};
use sibuna_json::Writer;
use sibuna_serve::{Class, Context, Deadline, Input, Sender, ServeError, stack};

use crate::dispatch::Call;
use crate::http::RouteError;
use crate::hub::{Gap, Hub, HubError, Item, Subscription};
use crate::shared::Shared;
use crate::storage::{HTTP_WAIT, StorageFailure};

/// How often the session is checked again, in seconds.
const AUTHORIZE_SECONDS: u64 = 5;
/// How often the writer pings, in seconds.
const PING_SECONDS: u64 = 20;
/// How long a client may stay silent, in seconds.
const IDLE_SECONDS: u64 = 60;
/// How long the writer waits for a hub frame per round.
const ROUND: Duration = Duration::from_millis(100);
/// The deadline a progressing stream keeps, in seconds.
const PROGRESS_SECONDS: u64 = 10;
/// Control replies the reader may queue for the writer.
const MAX_CONTROLS: usize = 8;
/// Commands a client may send per second.
const COMMANDS_PER_SECOND: u32 = 64;

/// Serves `call.route`, the browser WebSocket, after the dispatcher's checks.
///
/// Fails with 400 `CONSOLE002` for a missing or foreign `Origin` or an invalid upgrade,
/// with 503 `CONSOLE503` when 64 browsers are subscribed, and with 503 `CONSOLE004` while
/// the console stops. Once upgraded, the stream ends without an error.
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let origin = context.header(b"Origin")?;
    if origin != Some(shared.identity.origin.as_bytes()) {
        return Err(RouteError::BadRequest);
    }
    context.websocket_key().map_err(|_| RouteError::BadRequest)?;
    let principal = call.principal()?.clone();
    let digest = call.presented.as_ref().ok_or(RouteError::Unavailable)?.digest;
    let attached = Attached { hub: &shared.hub, subscription: Some(attach(&shared.hub)?) };
    let socket = match context.upgrade(Class::Browser, &[]) {
        Ok(socket) => socket,
        Err(ServeError::Full) => return Err(RouteError::fail(503, "CONSOLE503")),
        Err(error) => return Err(error.into()),
    };
    let Some(subscription) = attached.subscription.as_ref() else {
        return Err(RouteError::Unavailable);
    };
    let link = Link::new(shared.now());
    let mut writer = StreamWriter {
        shared,
        sender: socket.sender,
        deadline: socket.deadline,
        link: &link,
        subscription,
        principal,
        digest,
    };
    let reader = StreamReader {
        shared,
        link: &link,
        subscription,
        kiosk: writer.principal.kiosk,
        second: 0,
        commands: 0,
    };
    let usable = usize::try_from(shared.config.budget.stack_bytes).unwrap_or(stack::USABLE);
    std::thread::scope(|scope| {
        let thread = std::thread::Builder::new()
            .name("sibuna-console-stream".into())
            .stack_size(stack::bytes(usable))
            .spawn_scoped(scope, move || reader.run(socket.reader));
        if thread.is_ok() {
            writer.run();
        }
        // Wakes a reader blocked on the socket, so the scope can join it.
        writer.sender.shutdown();
    });
    Ok(())
}

/// Attaches a browser subscriber, mapping a full table to 503 `CONSOLE503`.
fn attach(hub: &Hub) -> Result<Subscription, RouteError> {
    hub.attach().map_err(|error| match error {
        HubError::Full => RouteError::fail(503, "CONSOLE503"),
        _ => RouteError::Unavailable,
    })
}

/// A subscription that is detached when the handler returns, however it returns.
struct Attached<'h> {
    hub: &'h Hub,
    subscription: Option<Subscription>,
}

impl Drop for Attached<'_> {
    fn drop(&mut self) {
        if let Some(subscription) = self.subscription.take() {
            self.hub.detach(subscription);
        }
    }
}

/// A control frame the reader asks the writer to send.
struct Control {
    opcode: Opcode,
    payload: Vec<u8>,
}

/// What the reader and the writer share.
struct Link {
    /// Either side stopped. Release on store and Acquire on load, so the close code stored
    /// before is seen.
    stopped: AtomicBool,
    /// The close code the reader chose; 0 for none.
    close_code: AtomicU16,
    /// When the last frame arrived, in Unix seconds. Relaxed: a value read on its own.
    last_read: AtomicU64,
    controls: Mutex<Vec<Control>>,
}

impl Link {
    fn new(now: u64) -> Link {
        Link {
            stopped: AtomicBool::new(false),
            close_code: AtomicU16::new(0),
            last_read: AtomicU64::new(now),
            controls: Mutex::new(Vec::new()),
        }
    }

    /// Queues a control reply; false when [`MAX_CONTROLS`] are already waiting.
    fn enqueue(&self, opcode: Opcode, payload: &[u8]) -> bool {
        let mut controls = self.controls.lock().unwrap_or_else(PoisonError::into_inner);
        if controls.len() == MAX_CONTROLS || payload.len() > MAX_CONTROL {
            return false;
        }
        controls.push(Control { opcode, payload: payload.to_vec() });
        true
    }

    /// Ends the stream with `code` (0 for none).
    fn stop(&self, code: u16) {
        self.close_code.store(code, Ordering::Relaxed);
        self.stopped.store(true, Ordering::Release);
    }

    fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }
}

/// The writing half: control replies, hub frames, pings, checks and the close frame.
struct StreamWriter<'a, 's> {
    shared: &'a Shared,
    sender: Sender<'s>,
    deadline: Deadline<'s>,
    link: &'a Link,
    subscription: &'a Subscription,
    principal: Principal,
    digest: [u8; 32],
}

impl StreamWriter<'_, '_> {
    /// Writes until either side stops, the session ends or the console stops.
    fn run(&mut self) {
        let mut last_auth = self.shared.now();
        let mut last_ping = last_auth;
        while !self.link.is_stopped() && !self.shared.is_stopping() {
            if !self.flush_controls() {
                break;
            }
            let now = self.shared.now();
            let idle = now.saturating_sub(self.link.last_read.load(Ordering::Relaxed));
            if now >= self.principal.expires || idle >= IDLE_SECONDS {
                self.close(1008);
                break;
            }
            if now.saturating_sub(last_auth) >= AUTHORIZE_SECONDS {
                if !self.authorize() {
                    break;
                }
                last_auth = now;
            }
            if !self.deliver() {
                break;
            }
            if now.saturating_sub(last_ping) >= PING_SECONDS {
                if !self.send(Opcode::Ping, b"") {
                    break;
                }
                last_ping = now;
            }
            // A progressing idle writer stays alive between pings; a blocked write still
            // expires under the listener's watchdog.
            self.deadline.extend(PROGRESS_SECONDS);
        }
        let code = self.link.close_code.load(Ordering::Relaxed);
        if code != 0 && !self.shared.is_stopping() {
            self.close(code);
        }
        self.link.stop(0);
    }

    /// Sends the reader's queued control replies; false after a close or a failed write.
    fn flush_controls(&mut self) -> bool {
        let controls = {
            let mut queue = self.link.controls.lock().unwrap_or_else(PoisonError::into_inner);
            std::mem::take(&mut *queue)
        };
        for control in controls {
            if !self.send(control.opcode, &control.payload) || control.opcode == Opcode::Close {
                return false;
            }
        }
        true
    }

    /// Sends up to [`MESSAGES_PER_SECOND`] hub items, waiting at most one round for the
    /// first; false after a failed write.
    fn deliver(&mut self) -> bool {
        let hub = &self.shared.hub;
        let mut wait = ROUND;
        for _ in 0..MESSAGES_PER_SECOND {
            let Some(item) = hub.take(self.subscription, wait) else { return true };
            wait = Duration::ZERO;
            let sent = match item {
                Item::Frame(frame) => self.send(Opcode::Text, frame.text.as_bytes()),
                Item::Gap(gap) => {
                    let text = gap_text(hub.boot(), &gap);
                    self.send(Opcode::Text, text.as_bytes())
                }
            };
            if !sent {
                return false;
            }
        }
        true
    }

    /// Checks the session again; false (after closing) when it ended or cannot be checked.
    fn authorize(&mut self) -> bool {
        // Storage may take its whole wait; the deadline must outlast it.
        self.deadline.extend(HTTP_WAIT.as_secs() + 2);
        let check = AuthorizationCheck {
            session_digest: self.digest,
            touch: false,
            kind: CredentialKind::Session,
        };
        let now = self.shared.now();
        let resolved = self
            .shared
            .storage
            .transact(move |tx| Box::pin(async move { access::authorize(tx, &check, now).await }));
        match resolved {
            Ok(principal) if !self.shared.is_restricted(&principal) => {
                self.principal = principal;
                true
            }
            Err(StorageFailure::Console(error)) if error.failure() == Failure::Unavailable => {
                self.close(1013);
                false
            }
            Ok(_) | Err(StorageFailure::Console(_)) => {
                self.send(Opcode::Text, b"{\"error\":\"unauthorized\"}");
                self.close(1008);
                false
            }
            Err(_) => {
                self.close(1013);
                false
            }
        }
    }

    /// Sends one frame, moving the deadline first; false when the write failed.
    fn send(&mut self, opcode: Opcode, payload: &[u8]) -> bool {
        self.deadline.extend(PROGRESS_SECONDS);
        self.sender.send(opcode, payload).is_ok()
    }

    /// Sends a close frame with `code`.
    fn close(&mut self, code: u16) {
        self.send(Opcode::Close, &code.to_be_bytes());
    }
}

/// Returns the gap notice of `gap`: `{"op":"gap","topic":...,"epoch":...,"dropped":...}`.
fn gap_text(boot: &str, gap: &Gap) -> String {
    let mut out = String::new();
    // Writing into a String cannot fail.
    let _ = write_gap(&mut Writer::new(&mut out), boot, gap);
    out
}

fn write_gap<W: std::fmt::Write>(json: &mut Writer<W>, boot: &str, gap: &Gap) -> std::fmt::Result {
    json.begin_object()?;
    field(json, "op", "gap")?;
    field(json, "topic", gap.topic.name())?;
    field(json, "epoch", format!("{boot}:{}", gap.epoch).as_str())?;
    counter_field(json, "dropped", gap.dropped)?;
    json.end_object()
}

/// The reading half: client frames into commands and control replies.
struct StreamReader<'a> {
    shared: &'a Shared,
    link: &'a Link,
    subscription: &'a Subscription,
    kiosk: bool,
    /// The second the command allowance counts in, and the commands in it.
    second: u64,
    commands: u32,
}

impl StreamReader<'_> {
    /// Reads frames until the client closes, a frame is refused or the socket is shut down.
    fn run(mut self, mut frames: FrameReader<Input<'_>>) {
        let mut receiver = Receiver::new();
        while !self.link.is_stopped() {
            let event = match frames.receive(&mut receiver, Role::Server) {
                Ok(event) => event,
                Err(error) => {
                    self.link.stop(close_code(&error));
                    return;
                }
            };
            self.link.last_read.store(self.shared.now(), Ordering::Relaxed);
            let close = matches!(event, Event::Close(_));
            let accepted = match event {
                Event::Fragment | Event::Pong(_) => true,
                Event::Ping(payload) => self.link.enqueue(Opcode::Pong, payload),
                Event::Close(payload) => self.link.enqueue(Opcode::Close, payload),
                Event::Text(text) => self.command(text),
                Event::Binary(_) => false,
            };
            if !accepted {
                self.link.stop(1008);
                return;
            }
            if close {
                return;
            }
        }
    }

    /// Applies one client command; false when it must close the stream.
    fn command(&mut self, text: &str) -> bool {
        let now = self.shared.now();
        if now != self.second {
            (self.second, self.commands) = (now, 0);
        }
        if self.commands == COMMANDS_PER_SECOND {
            return false;
        }
        self.commands += 1;
        let Ok(input) = subscriptions::parse(text.as_bytes()) else { return false };
        if input.op == Op::Ping {
            return self.link.enqueue(Opcode::Text, b"{\"op\":\"pong\"}");
        }
        if self.kiosk && input.topic != Some(Topic::Stats) {
            return false;
        }
        self.shared.hub.command(self.subscription, &input).is_ok()
    }
}

/// The close code for a refused or failed read; 0 when the connection simply ended.
fn close_code(error: &ReceiveError) -> u16 {
    match error {
        ReceiveError::Frame(FrameError::TooLarge | FrameError::NoSpace) => 1009,
        ReceiveError::Frame(FrameError::InvalidUtf8) => 1007,
        ReceiveError::Frame(_) => 1002,
        ReceiveError::EndOfStream | ReceiveError::Io(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gap_notices_and_close_codes_follow_zig() {
        let gap = Gap { topic: Topic::Events, epoch: 7, dropped: 9_007_199_254_740_993 };
        assert_eq!(
            gap_text("ab", &gap),
            "{\"op\":\"gap\",\"topic\":\"events\",\"epoch\":\"ab:7\",\
             \"dropped\":\"9007199254740993\"}"
        );
        assert_eq!(close_code(&ReceiveError::Frame(FrameError::TooLarge)), 1009);
        assert_eq!(close_code(&ReceiveError::Frame(FrameError::InvalidUtf8)), 1007);
        assert_eq!(close_code(&ReceiveError::Frame(FrameError::Protocol)), 1002);
        assert_eq!(close_code(&ReceiveError::EndOfStream), 0);
    }
}
