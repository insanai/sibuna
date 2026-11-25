//! The agent tier: a process on a Unix socket (SID 0030, "The agent tier").
//!
//! ```text
//!  offset  size  field
//!  0       4     length of the rest of the frame, little-endian, at most 65,532
//!  4       1     protocol version, 1
//!  5       1     kind: 1 decide, 2 verdict, 3 sample
//!  6       2     zero
//!  8       8     identifier of the call
//!  16            payload
//! ```
//!
//! The payload of `decide` and `sample` is the wire form of the view. The payload of
//! `verdict` is one byte (0 admit, 1 deny, 2 challenge) and then field lines to add.
//!
//! Each thread owns one [`AgentClient`]: a connection, a breaker and a backlog of
//! telemetry frames. Threads share only [`AgentShared`]: the options, a count of waiting
//! calls and a connector thread. The connector makes the blocking `connect` calls, so a
//! listener whose queue is full can stall the connector and never a thread that serves
//! traffic.

use std::io::{self, Read};

use crate::verdict::Failure;

/// The version byte of a frame.
pub const PROTOCOL_VERSION: u8 = 1;
/// The bytes of a frame before its payload.
pub const FRAME_HEADER: usize = 16;
/// The most bytes of one frame, header included.
pub const MAX_FRAME: usize = 65_536;

/// The kind of a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
    /// Sibuna asks for a verdict on the view in the payload.
    Decide,
    /// The agent answers a `Decide` of the same identifier.
    Verdict,
    /// Sibuna reports an ended request. There is no answer.
    Sample,
}

impl FrameKind {
    fn wire(self) -> u8 {
        match self {
            FrameKind::Decide => 1,
            FrameKind::Verdict => 2,
            FrameKind::Sample => 3,
        }
    }

    fn from_wire(byte: u8) -> Option<FrameKind> {
        match byte {
            1 => Some(FrameKind::Decide),
            2 => Some(FrameKind::Verdict),
            3 => Some(FrameKind::Sample),
            _ => None,
        }
    }
}

/// One frame of the agent protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// The kind of the frame.
    pub kind: FrameKind,
    /// The identifier of the call.
    pub id: u64,
    /// The payload.
    pub payload: Vec<u8>,
}

/// Appends a frame of `kind` with `id` and `payload` to `out`.
///
/// # Errors
///
/// [`Failure::Overload`] when the frame would exceed [`MAX_FRAME`] bytes. Nothing is
/// appended then.
pub fn write_frame(
    out: &mut Vec<u8>,
    kind: FrameKind,
    id: u64,
    payload: &[u8],
) -> Result<(), Failure> {
    let total = FRAME_HEADER + payload.len();
    if total > MAX_FRAME {
        return Err(Failure::Overload);
    }
    out.extend_from_slice(&((total - 4) as u32).to_le_bytes());
    out.extend_from_slice(&[PROTOCOL_VERSION, kind.wire(), 0, 0]);
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

/// Checks the 16 bytes of a frame header and returns the kind, the identifier and the
/// length of the payload.
fn parse_header(header: &[u8; FRAME_HEADER]) -> io::Result<(FrameKind, u64, usize)> {
    let invalid = |what: &'static str| io::Error::new(io::ErrorKind::InvalidData, what);
    let [l0, l1, l2, l3, version, kind, z0, z1, id @ ..] = *header;
    let rest = u32::from_le_bytes([l0, l1, l2, l3]) as usize;
    if !(FRAME_HEADER - 4..=MAX_FRAME - 4).contains(&rest) {
        return Err(invalid("frame length out of range"));
    }
    if version != PROTOCOL_VERSION {
        return Err(invalid("unknown protocol version"));
    }
    if (z0, z1) != (0, 0) {
        return Err(invalid("reserved bytes are not zero"));
    }
    let kind = FrameKind::from_wire(kind).ok_or_else(|| invalid("unknown frame kind"))?;
    Ok((kind, u64::from_le_bytes(id), rest - (FRAME_HEADER - 4)))
}

/// Reads one frame from `reader`, waiting as the reader waits. An agent uses this to
/// read what Sibuna sends.
///
/// # Errors
///
/// The error of the reader, `UnexpectedEof` at a closed connection, and `InvalidData`
/// for a header that is not of this protocol.
pub fn read_frame(reader: &mut impl Read) -> io::Result<Frame> {
    let mut header = [0u8; FRAME_HEADER];
    reader.read_exact(&mut header)?;
    let (kind, id, length) = parse_header(&header)?;
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload)?;
    Ok(Frame { kind, id, payload })
}

#[cfg(unix)]
pub(crate) use unix::{AgentClient, AgentShared};

#[cfg(unix)]
mod unix {
    use std::io::{self, Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError};
    use std::time::{Duration, Instant};

    use super::{FRAME_HEADER, FrameKind, parse_header, write_frame};
    use crate::breaker::Breaker;
    use crate::spec::AgentSpec;
    use crate::verdict::{Failure, Verdict};
    use crate::view::Edits;

    /// A connection, or why there is none.
    type Connected = io::Result<UnixStream>;

    /// What the threads share for one agent.
    pub(crate) struct AgentShared {
        pub spec: AgentSpec,
        /// Calls that wait for the agent now, on all threads.
        waiting: AtomicU32,
        /// Threads whose breaker is open.
        pub open_breakers: AtomicU32,
        /// Requests for a connection, served by the connector thread.
        connector: SyncSender<mpsc::Sender<Connected>>,
    }

    impl AgentShared {
        /// Starts the connector thread of an agent. The thread ends when the last
        /// holder of the result is dropped.
        ///
        /// # Errors
        ///
        /// The error of starting a thread.
        pub fn start(spec: AgentSpec) -> io::Result<Arc<AgentShared>> {
            let (connector, requests) = mpsc::sync_channel::<mpsc::Sender<Connected>>(64);
            let path = spec.socket.clone();
            std::thread::Builder::new().name("sibuna-hook-connect".to_owned()).spawn(
                move || {
                    for reply in requests {
                        // The receiver may have given up. Its connection is then dropped.
                        let _ = reply.send(UnixStream::connect(&path));
                    }
                },
            )?;
            let (waiting, open_breakers) = (AtomicU32::new(0), AtomicU32::new(0));
            Ok(Arc::new(AgentShared { spec, waiting, open_breakers, connector }))
        }

        /// Takes a place among the calls that may wait. Returns false when all
        /// `queue` places are taken.
        fn enter(&self) -> bool {
            if self.waiting.fetch_add(1, Ordering::Relaxed) < self.spec.queue {
                return true;
            }
            self.waiting.fetch_sub(1, Ordering::Relaxed);
            false
        }

        fn leave(&self) {
            self.waiting.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// One thread's side of an agent.
    pub(crate) struct AgentClient {
        shared: Arc<AgentShared>,
        stream: Option<UnixStream>,
        /// A connection that the connector was asked for and has not delivered.
        pending: Option<Receiver<Connected>>,
        breaker: Breaker,
        /// The zero of the breaker's clock.
        origin: Instant,
        next_id: u64,
        /// Telemetry frames, or the rest of one, that the socket did not take yet.
        backlog: Vec<u8>,
        frame: Vec<u8>,
        /// The stream is in non-blocking mode, as the telemetry path leaves it.
        nonblocking: bool,
    }

    /// The failure that an I/O error of the socket means.
    fn failure_of(error: &io::Error) -> Failure {
        match error.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Failure::Timeout,
            io::ErrorKind::InvalidData => Failure::Trap,
            _ => Failure::Unavailable,
        }
    }

    /// The time left until `deadline`, or a timeout when it has passed.
    fn left(deadline: Instant) -> Result<Duration, Failure> {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() { Err(Failure::Timeout) } else { Ok(left) }
    }

    impl AgentClient {
        pub fn new(shared: Arc<AgentShared>) -> Self {
            AgentClient {
                shared,
                stream: None,
                pending: None,
                breaker: Breaker::default(),
                origin: Instant::now(),
                next_id: 0,
                backlog: Vec::new(),
                frame: Vec::new(),
                nonblocking: false,
            }
        }

        fn now(&self) -> u64 {
            u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
        }

        /// Records the end of a call in the breaker and keeps the shared count of open
        /// breakers.
        fn note(&mut self, ok: bool) {
            if self.breaker.record(ok, self.now(), self.shared.spec.breaker) {
                if self.breaker.is_open() {
                    self.shared.open_breakers.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.shared.open_breakers.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }

        fn close(&mut self) {
            self.stream = None;
            self.backlog.clear();
            self.nonblocking = false;
        }

        /// Asks the agent for a verdict on the encoded view `encoded`. At the request
        /// stage `edits` receives the fields the agent adds.
        ///
        /// # Errors
        ///
        /// [`Failure::Overload`] when the view does not fit a frame or `queue` calls
        /// wait already, [`Failure::Unavailable`] when the breaker is open or the agent
        /// cannot be reached, [`Failure::Timeout`] past the deadline and
        /// [`Failure::Trap`] for an answer outside the protocol.
        pub fn decide(
            &mut self,
            encoded: &[u8],
            edits: Option<&mut Edits>,
        ) -> Result<Verdict, Failure> {
            self.next_id = self.next_id.wrapping_add(1);
            self.frame.clear();
            write_frame(&mut self.frame, FrameKind::Decide, self.next_id, encoded)?;
            // An overload is our own doing. It neither asks nor blames the breaker.
            if !self.shared.enter() {
                return Err(Failure::Overload);
            }
            let result = if self.breaker.allow(self.now()) {
                let deadline =
                    Instant::now() + Duration::from_millis(self.shared.spec.deadline_ms);
                let result = self.exchange(deadline, edits);
                self.note(result.is_ok());
                result
            } else {
                Err(Failure::Unavailable)
            };
            self.shared.leave();
            result
        }

        /// Sends the call and reads its answer. A kept connection that turns out to be
        /// closed is replaced once: the agent may have restarted.
        fn exchange(
            &mut self,
            deadline: Instant,
            mut edits: Option<&mut Edits>,
        ) -> Result<Verdict, Failure> {
            for _ in 0..2 {
                let kept = self.stream.is_some();
                self.connect(deadline)?;
                match self.round_trip(deadline, edits.as_deref_mut()) {
                    Err(Failure::Unavailable) if kept => self.close(),
                    Err(failure) => {
                        self.close();
                        return Err(failure);
                    }
                    Ok(verdict) => return Ok(verdict),
                }
            }
            Err(Failure::Unavailable)
        }

        /// Makes sure that there is a connection, waiting for the connector until
        /// `deadline`.
        fn connect(&mut self, deadline: Instant) -> Result<(), Failure> {
            if self.stream.is_some() {
                return Ok(());
            }
            if self.pending.is_none() {
                self.request()?;
            }
            let Some(pending) = &self.pending else { return Err(Failure::Unavailable) };
            match pending.recv_timeout(left(deadline)?) {
                Ok(connected) => {
                    self.pending = None;
                    self.stream = Some(connected.map_err(|_| Failure::Unavailable)?);
                    Ok(())
                }
                // The connector is still inside `connect`. Its answer may serve a
                // later call.
                Err(RecvTimeoutError::Timeout) => Err(Failure::Timeout),
                Err(RecvTimeoutError::Disconnected) => {
                    self.pending = None;
                    Err(Failure::Unavailable)
                }
            }
        }

        /// Asks the connector for a connection without waiting.
        fn request(&mut self) -> Result<(), Failure> {
            let (reply, pending) = mpsc::channel();
            self.shared.connector.try_send(reply).map_err(|_| Failure::Unavailable)?;
            self.pending = Some(pending);
            Ok(())
        }

        fn round_trip(
            &mut self,
            deadline: Instant,
            edits: Option<&mut Edits>,
        ) -> Result<Verdict, Failure> {
            let Some(stream) = &mut self.stream else { return Err(Failure::Unavailable) };
            if self.nonblocking {
                stream.set_nonblocking(false).map_err(|error| failure_of(&error))?;
                self.nonblocking = false;
            }
            // Telemetry that waits goes first, so that frames stay whole on the wire.
            for bytes in [&self.backlog[..], &self.frame[..]] {
                let mut rest = bytes;
                while !rest.is_empty() {
                    let timeout = Some(left(deadline)?);
                    stream.set_write_timeout(timeout).map_err(|error| failure_of(&error))?;
                    match stream.write(rest) {
                        Ok(0) => return Err(Failure::Unavailable),
                        Ok(count) => rest = rest.get(count..).unwrap_or_default(),
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        Err(error) => return Err(failure_of(&error)),
                    }
                }
            }
            self.backlog.clear();
            let mut header = [0u8; FRAME_HEADER];
            read_until(stream, &mut header, deadline)?;
            let (kind, id, length) = parse_header(&header).map_err(|_| Failure::Trap)?;
            self.frame.clear();
            self.frame.resize(length, 0);
            read_until(stream, &mut self.frame, deadline)?;
            if kind != FrameKind::Verdict || id != self.next_id {
                return Err(Failure::Trap);
            }
            let (&code, lines) = self.frame.split_first().ok_or(Failure::Trap)?;
            let verdict = match code {
                0 => Verdict::Admit,
                1 => Verdict::Deny,
                2 => Verdict::Challenge,
                _ => return Err(Failure::Trap),
            };
            if let (Verdict::Admit, Some(edits)) = (verdict, edits) {
                edits.add_block(lines);
            }
            Ok(verdict)
        }

        /// Sends the encoded view `encoded` as a sample. Never waits.
        ///
        /// # Errors
        ///
        /// The failure for which the sample was dropped.
        pub fn sample(&mut self, encoded: &[u8]) -> Result<(), Failure> {
            if self.stream.is_none() {
                self.poll_connect();
            }
            if self.stream.is_none() {
                return Err(Failure::Unavailable);
            }
            self.next_id = self.next_id.wrapping_add(1);
            let limit = self.shared.spec.queue as usize * 1024;
            let room = self.backlog.len() + FRAME_HEADER + encoded.len() <= limit;
            let framed = if room {
                write_frame(&mut self.backlog, FrameKind::Sample, self.next_id, encoded)
            } else {
                Err(Failure::Overload)
            };
            self.flush()?;
            framed
        }

        /// Takes a connection that the connector delivered, or asks for one when the
        /// breaker allows.
        fn poll_connect(&mut self) {
            if let Some(pending) = &self.pending {
                let delivered = match pending.try_recv() {
                    Ok(connected) => connected.ok(),
                    Err(TryRecvError::Empty) => return,
                    Err(TryRecvError::Disconnected) => None,
                };
                self.pending = None;
                self.note(delivered.is_some());
                self.stream = delivered;
            } else if self.breaker.allow(self.now()) && self.request().is_err() {
                self.note(false);
            }
        }

        /// Writes what the socket takes of the backlog at once.
        fn flush(&mut self) -> Result<(), Failure> {
            let Some(stream) = &mut self.stream else { return Err(Failure::Unavailable) };
            if !self.nonblocking {
                if stream.set_nonblocking(true).is_err() {
                    self.close();
                    return Err(Failure::Unavailable);
                }
                self.nonblocking = true;
            }
            let mut written = 0;
            let failed = loop {
                let Some(rest) = self.backlog.get(written..).filter(|rest| !rest.is_empty())
                else {
                    break false;
                };
                match stream.write(rest) {
                    Ok(0) => break true,
                    Ok(count) => written += count,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break false,
                    Err(_) => break true,
                }
            };
            if failed {
                self.close();
                self.note(false);
                return Err(Failure::Unavailable);
            }
            self.backlog.drain(..written);
            Ok(())
        }
    }

    impl Drop for AgentClient {
        fn drop(&mut self) {
            if self.breaker.is_open() {
                self.shared.open_breakers.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    /// Fills `buffer` from `stream`, waiting until `deadline` at most.
    fn read_until(
        stream: &mut UnixStream,
        buffer: &mut [u8],
        deadline: Instant,
    ) -> Result<(), Failure> {
        let mut filled = 0;
        while let Some(rest) = buffer.get_mut(filled..).filter(|rest| !rest.is_empty()) {
            stream.set_read_timeout(Some(left(deadline)?)).map_err(|error| failure_of(&error))?;
            match stream.read(rest) {
                Ok(0) => return Err(Failure::Unavailable),
                Ok(count) => filled += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(failure_of(&error)),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_has_the_documented_layout_and_reads_back() {
        let mut out = Vec::new();
        write_frame(&mut out, FrameKind::Decide, 0x0102_0304_0506_0708, b"view").unwrap();
        assert_eq!(&out[..4], &16u32.to_le_bytes());
        assert_eq!(&out[4..8], &[1, 1, 0, 0]);
        assert_eq!(&out[8..16], &[8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(&out[16..], b"view");
        let frame = read_frame(&mut &out[..]).unwrap();
        assert_eq!(
            frame,
            Frame {
                kind: FrameKind::Decide,
                id: 0x0102_0304_0506_0708,
                payload: b"view".to_vec()
            }
        );
    }

    #[test]
    fn a_frame_larger_than_the_limit_is_an_overload() {
        let mut out = Vec::new();
        let payload = vec![0; MAX_FRAME - FRAME_HEADER + 1];
        assert_eq!(write_frame(&mut out, FrameKind::Sample, 1, &payload), Err(Failure::Overload));
        assert!(out.is_empty());
        assert!(write_frame(&mut out, FrameKind::Sample, 1, &payload[1..]).is_ok());
    }

    #[test]
    fn a_header_outside_the_protocol_is_refused() {
        let mut good = Vec::new();
        write_frame(&mut good, FrameKind::Verdict, 7, &[0]).unwrap();
        for (at, byte) in [(4, 2u8), (5, 9), (6, 1), (3, 0xff), (0, 3)] {
            let mut bad = good.clone();
            bad[at] = byte;
            let error = read_frame(&mut &bad[..]).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "byte {at}");
        }
        let error = read_frame(&mut &good[..10]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }
}
