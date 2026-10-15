//! The bounded byte relay after an accepted upgrade.
//!
//! Each direction runs on a thread of its own with one fixed buffer: the client-to-origin
//! direction on a scoped thread spawned for the upgrade, the origin-to-client direction on
//! the connection's own thread. Each blocks in plain reads and writes. The Zig version served
//! both directions from one thread with `poll(2)`, which `std` does not expose; a second
//! thread per upgraded connection keeps the module free of `unsafe` and costs one small stack
//! per WebSocket, which the connection limit already bounds.
//!
//! The idle deadline is shared by both directions: bytes moving either way refresh one stamp
//! (and the connection's [`Activity`]). Each socket wait carries a timeout equal to the time
//! left before the deadline; a wait that times out re-reads the shared stamp and either waits
//! again for the rest or ends the relay. When one direction reaches end of stream, the other
//! socket's sending side is shut down (a half close); when a direction fails, both sockets are
//! shut down so the other direction ends too.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::buffered::{ReadError, Reader};
use crate::idle::{Activity, now_ms};

/// The stack of the extra relay thread; the relay keeps its buffer on the heap.
const RELAY_STACK: usize = 128 * 1024;

/// How the relay is bounded.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RelayOptions<'a> {
    /// Seconds of silence in both directions after which the relay ends; zero never.
    pub(crate) idle_timeout_seconds: u32,
    /// The connection's activity, refreshed on every movement and given the relay's bound.
    pub(crate) activity: Option<&'a Activity>,
}

/// Why the relay ended abnormally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DuplexError {
    /// A read or write failed, or the extra thread could not start.
    ConnectionFailed,
    /// Nothing moved either way for the idle timeout.
    IdleTimeout,
}

impl fmt::Display for DuplexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DuplexError::ConnectionFailed => "relay connection failed",
            DuplexError::IdleTimeout => "relay idle timeout",
        })
    }
}

impl std::error::Error for DuplexError {}

/// The shared idle deadline.
struct Clock<'a> {
    /// The [`now_ms`] of the last movement either way. Relaxed: a standalone stamp; a reader
    /// that sees an older value waits once more and then sees the newer one.
    last_ms: AtomicU64,
    timeout_ms: Option<u64>,
    activity: Option<&'a Activity>,
}

impl Clock<'_> {
    fn moved(&self) {
        self.last_ms.store(now_ms(), Ordering::Relaxed);
        if let Some(activity) = self.activity {
            activity.touch();
        }
    }

    /// The time left before the deadline, or the idle error once it has passed.
    fn remaining(&self) -> Result<Option<Duration>, DuplexError> {
        let Some(timeout) = self.timeout_ms else { return Ok(None) };
        let deadline = self.last_ms.load(Ordering::Relaxed).saturating_add(timeout);
        match deadline.checked_sub(now_ms()) {
            Some(left) if left > 0 => Ok(Some(Duration::from_millis(left))),
            _ => Err(DuplexError::IdleTimeout),
        }
    }
}

/// A socket wait that ended by its timeout rather than by data or failure.
fn timed_out(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

/// Relays bytes between `client` and `origin` until both directions reach end of stream.
///
/// `client_prefix` holds client bytes the daemon already read after the upgrade request, and
/// `origin_reader` may hold origin bytes read after the 101 head; both are sent first, in
/// order. `upload_buffer` is the client direction's read buffer. Both sockets are shut down
/// when the relay returns.
pub(crate) fn relay(
    client: &TcpStream,
    client_prefix: &[u8],
    origin: &TcpStream,
    mut origin_reader: Reader<'_, &TcpStream>,
    upload_buffer: &mut [u8],
    options: RelayOptions<'_>,
) -> Result<(), DuplexError> {
    let timeout_ms = match options.idle_timeout_seconds {
        0 => None,
        seconds => Some(u64::from(seconds) * 1000),
    };
    let clock =
        Clock { last_ms: AtomicU64::new(now_ms()), timeout_ms, activity: options.activity };
    if let Some(activity) = options.activity {
        activity.touch();
        activity.set_timeout_ms(timeout_ms.unwrap_or(u64::MAX));
    }
    let result = std::thread::scope(|scope| {
        let upward =
            std::thread::Builder::new().stack_size(RELAY_STACK).spawn_scoped(scope, || {
                let mut source = Reader::new(client, upload_buffer);
                let result = send_all(origin, client_prefix, &clock)
                    .and_then(|()| pump(&mut source, origin, &clock));
                if result.is_err() {
                    cut(client, origin);
                }
                result
            });
        let Ok(upward) = upward else {
            cut(client, origin);
            return Err(DuplexError::ConnectionFailed);
        };
        let downward = pump(&mut origin_reader, client, &clock);
        if downward.is_err() {
            cut(client, origin);
        }
        let upward = upward.join().unwrap_or(Err(DuplexError::ConnectionFailed));
        downward.and(upward)
    });
    cut(client, origin);
    result
}

fn cut(client: &TcpStream, origin: &TcpStream) {
    let _ = client.shutdown(Shutdown::Both);
    let _ = origin.shutdown(Shutdown::Both);
}

/// Sets the time a socket read may wait.
trait Waits {
    fn wait_reads(&self, limit: Option<Duration>);
    fn wait_writes(&self, limit: Option<Duration>);
    fn close_sending(&self);
}

impl Waits for &TcpStream {
    fn wait_reads(&self, limit: Option<Duration>) {
        let _ = self.set_read_timeout(limit.map(at_least_a_millisecond));
    }

    fn wait_writes(&self, limit: Option<Duration>) {
        let _ = self.set_write_timeout(limit.map(at_least_a_millisecond));
    }

    fn close_sending(&self) {
        let _ = self.shutdown(Shutdown::Write);
    }
}

/// A zero timeout means "no timeout" to the socket API.
fn at_least_a_millisecond(limit: Duration) -> Duration {
    limit.max(Duration::from_millis(1))
}

/// Sends all of `bytes`, refreshing the clock on every write.
fn send_all<W: Write + Waits>(
    mut sink: W,
    bytes: &[u8],
    clock: &Clock<'_>,
) -> Result<(), DuplexError> {
    let mut sent = 0;
    while let Some(rest) = bytes.get(sent..).filter(|rest| !rest.is_empty()) {
        sink.wait_writes(clock.remaining()?);
        match sink.write(rest) {
            Ok(0) => return Err(DuplexError::ConnectionFailed),
            Ok(count) => {
                sent += count;
                clock.moved();
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if timed_out(&error) => {}
            Err(_) => return Err(DuplexError::ConnectionFailed),
        }
    }
    Ok(())
}

/// Moves bytes from `source` (its buffered bytes first) to `sink` until end of stream, then
/// half-closes `sink`.
fn pump<R: Read + Waits, W: Write + Waits + Copy>(
    source: &mut Reader<'_, R>,
    sink: W,
    clock: &Clock<'_>,
) -> Result<(), DuplexError> {
    loop {
        if source.buffered_len() > 0 {
            send_all(sink, source.buffered(), clock)?;
            source.consume(usize::MAX);
        }
        source.inner().wait_reads(clock.remaining()?);
        match source.fill_more() {
            Ok(_) => clock.moved(),
            Err(ReadError::EndOfStream) => break,
            Err(ReadError::Io(error)) if timed_out(&error) => {}
            Err(_) => return Err(DuplexError::ConnectionFailed),
        }
    }
    sink.close_sending();
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    /// A sink that accepts at most three bytes per write, as a congested socket does.
    #[derive(Clone, Copy)]
    struct Congested<'a>(&'a RefCell<Vec<u8>>);

    impl Write for Congested<'_> {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            let count = data.len().min(3);
            self.0.borrow_mut().extend_from_slice(&data[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Waits for Congested<'_> {
        fn wait_reads(&self, _: Option<Duration>) {}
        fn wait_writes(&self, _: Option<Duration>) {}
        fn close_sending(&self) {}
    }

    struct Source<'a>(&'a [u8]);

    impl Read for Source<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            self.0.read(out)
        }
    }

    impl Waits for Source<'_> {
        fn wait_reads(&self, _: Option<Duration>) {}
        fn wait_writes(&self, _: Option<Duration>) {}
        fn close_sending(&self) {}
    }

    fn clock() -> Clock<'static> {
        Clock { last_ms: AtomicU64::new(now_ms()), timeout_ms: Some(60_000), activity: None }
    }

    #[test]
    fn prefetched_upgrade_bytes_larger_than_one_relay_buffer_remain_ordered_under_backpressure() {
        const CAPACITY: usize = 16 * 1024;
        let mut prefix = vec![1u8; CAPACITY + 17];
        prefix[CAPACITY..].fill(2);
        let output = RefCell::new(Vec::new());
        let clock = clock();
        send_all(Congested(&output), &prefix, &clock).unwrap();
        let more = [3u8; 40];
        let mut storage = vec![0u8; 32];
        let mut source = Reader::new(Source(&more), &mut storage);
        pump(&mut source, Congested(&output), &clock).unwrap();
        let output = output.into_inner();
        assert_eq!(output.len(), CAPACITY + 17 + 40);
        assert!(output[..CAPACITY].iter().all(|&byte| byte == 1));
        assert!(output[CAPACITY..CAPACITY + 17].iter().all(|&byte| byte == 2));
        assert!(output[CAPACITY + 17..].iter().all(|&byte| byte == 3));
    }

    #[test]
    fn the_clock_expires_after_the_timeout() {
        let clock =
            Clock { last_ms: AtomicU64::new(now_ms()), timeout_ms: Some(5), activity: None };
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(clock.remaining(), Err(DuplexError::IdleTimeout));
        clock.moved();
        assert!(clock.remaining().unwrap().is_some());
        let unbounded = Clock { timeout_ms: None, ..clock };
        assert_eq!(unbounded.remaining(), Ok(None));
    }
}
