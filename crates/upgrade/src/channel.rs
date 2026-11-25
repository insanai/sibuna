//! Frames with descriptors over a Unix stream socket, with a deadline on every read.
//!
//! The descriptors of a frame travel with the first byte of its header. The receiver
//! reads every byte with `recvmsg`, so a descriptor that arrives anywhere is owned and
//! counted, and a frame whose count is wrong is refused with nothing left open.

use std::io::{self, Write};
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use crate::error::protocol;
use crate::{Failure, UpgradeError, sys, wire};

/// One received frame.
pub(crate) struct Frame {
    pub kind: u8,
    pub payload: Vec<u8>,
    pub descriptors: Vec<OwnedFd>,
}

/// One end of the connection of a handoff.
pub(crate) struct Channel {
    stream: UnixStream,
}

/// Classifies an error of the socket. Only an error that the kernel gives for a closed
/// peer counts as closed, because the giver takes that as proof.
fn failed(error: &io::Error, doing: &str) -> UpgradeError {
    use io::ErrorKind::{
        BrokenPipe, ConnectionAborted, ConnectionReset, TimedOut, UnexpectedEof, Unsupported,
        WouldBlock,
    };
    let failure = match error.kind() {
        BrokenPipe | ConnectionReset | ConnectionAborted | UnexpectedEof => Failure::Closed,
        WouldBlock | TimedOut => Failure::Timeout,
        Unsupported => Failure::Unsupported,
        _ => Failure::Protocol,
    };
    UpgradeError::new(failure, format!("{doing}: {error}"))
}

fn closed(doing: &str) -> UpgradeError {
    UpgradeError::new(Failure::Closed, format!("{doing}: the peer closed the connection"))
}

impl Channel {
    /// Wraps a connected socket. A write blocks for at most `write`.
    ///
    /// Fails when the timeout cannot be set.
    pub fn new(stream: UnixStream, write: Duration) -> Result<Self, UpgradeError> {
        stream
            .set_write_timeout(Some(write.max(Duration::from_millis(1))))
            .map_err(|error| failed(&error, "preparing the upgrade socket"))?;
        Ok(Self { stream })
    }

    /// The socket, for the credentials of its peer.
    pub fn stream(&self) -> &UnixStream {
        &self.stream
    }

    /// Sends one frame. `descriptors` stay open here: the peer is given copies.
    ///
    /// Fails with [`Failure::Closed`] when the peer is gone and [`Failure::Timeout`]
    /// when it does not read.
    pub fn send(
        &mut self,
        kind: u8,
        payload: &[u8],
        descriptors: &[BorrowedFd<'_>],
    ) -> Result<(), UpgradeError> {
        if payload.len() > wire::MAX_PAYLOAD || descriptors.len() > wire::PER_FRAME {
            return Err(protocol("a frame to send is out of bounds"));
        }
        let header = wire::header(kind, payload.len(), descriptors.len());
        let doing = "sending on the upgrade socket";
        let sent = loop {
            match sys::send(&self.stream, &header, descriptors) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(failed(&error, doing)),
                Ok(sent) => break sent,
            }
        };
        let mut stream = &self.stream;
        stream.write_all(&header[sent..]).map_err(|error| failed(&error, doing))?;
        stream.write_all(payload).map_err(|error| failed(&error, doing))
    }

    /// Fills `buffer` before `deadline`, keeping every descriptor that arrives.
    fn fill(
        &mut self,
        buffer: &mut [u8],
        descriptors: &mut Vec<OwnedFd>,
        deadline: Instant,
    ) -> Result<(), UpgradeError> {
        let doing = "reading the upgrade socket";
        let mut filled = 0;
        while filled < buffer.len() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(UpgradeError::new(Failure::Timeout, format!("{doing}: no answer")));
            }
            self.stream
                .set_read_timeout(Some(left.max(Duration::from_millis(1))))
                .map_err(|error| failed(&error, doing))?;
            match sys::receive(&self.stream, &mut buffer[filled..], descriptors) {
                Ok(0) => return Err(closed(doing)),
                Ok(count) => filled += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(failed(&error, doing)),
            }
        }
        Ok(())
    }

    /// Receives one frame before `deadline`.
    ///
    /// Fails with [`Failure::Closed`], [`Failure::Timeout`], or [`Failure::Protocol`]
    /// for a frame out of bounds or with a wrong descriptor count. The descriptors of
    /// a refused frame are closed.
    pub fn receive(&mut self, deadline: Instant) -> Result<Frame, UpgradeError> {
        let mut descriptors = Vec::new();
        let mut header = [0u8; wire::HEADER];
        self.fill(&mut header, &mut descriptors, deadline)?;
        let (kind, length, announced) = wire::parse_header(&header)?;
        let mut payload = vec![0u8; length];
        self.fill(&mut payload, &mut descriptors, deadline)?;
        if descriptors.len() != announced {
            return Err(protocol(format!(
                "a frame announced {announced} descriptors and brought {}",
                descriptors.len()
            )));
        }
        Ok(Frame { kind, payload, descriptors })
    }

    /// Receives a frame of `kind` before `deadline`. A `REFUSE` becomes the failure it
    /// names, and any other frame a protocol failure.
    pub fn expect(&mut self, kind: u8, deadline: Instant) -> Result<Frame, UpgradeError> {
        let frame = self.receive(deadline)?;
        if frame.kind == kind {
            return Ok(frame);
        }
        if frame.kind != wire::REFUSE {
            return Err(protocol(format!("expected frame {kind}, received {}", frame.kind)));
        }
        let (code, reason) = wire::parse_refuse(&frame.payload)?;
        let failure = match code {
            wire::REFUSED_PEER => Failure::Refused,
            wire::REFUSED_VERSION => Failure::Version,
            wire::REFUSED_BUSY => Failure::Busy,
            _ => Failure::Protocol,
        };
        Err(UpgradeError::new(failure, format!("the other end refused: {reason}")))
    }

    /// Tells the peer why the handoff ends. The peer may be gone; nothing is reported.
    pub fn refuse(&mut self, code: u16, reason: &str) {
        let _ = self.send(wire::REFUSE, &wire::refuse(code, reason), &[]);
    }

    /// Waits up to `patience` for the peer to close. True when it has closed. Frames
    /// that still arrive are discarded.
    pub fn wait_closed(&mut self, patience: Duration) -> bool {
        let deadline = Instant::now() + patience;
        let mut scratch = [0u8; 512];
        loop {
            let mut descriptors = Vec::new();
            match self.fill(&mut scratch, &mut descriptors, deadline) {
                Ok(()) => {}
                Err(error) => return error.failure == Failure::Closed,
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::net::UdpSocket;
    use std::os::fd::AsFd;

    use super::*;

    fn pair() -> (Channel, Channel) {
        let (left, right) = UnixStream::pair().expect("pair");
        let write = Duration::from_secs(1);
        (Channel::new(left, write).expect("left"), Channel::new(right, write).expect("right"))
    }

    fn soon() -> Instant {
        Instant::now() + Duration::from_millis(300)
    }

    #[test]
    fn a_frame_arrives_with_its_payload_and_descriptors() {
        let (mut left, mut right) = pair();
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let payload = vec![7u8; 5000];
        left.send(wire::FLOWS, &payload, &[socket.as_fd(), socket.as_fd()]).expect("send");
        left.send(wire::READY, &[], &[]).expect("send");
        let frame = right.receive(soon()).expect("frame");
        assert_eq!(
            (frame.kind, frame.payload.len(), frame.descriptors.len()),
            (wire::FLOWS, 5000, 2)
        );
        let frame = right.receive(soon()).expect("frame");
        assert_eq!(
            (frame.kind, frame.payload.len(), frame.descriptors.len()),
            (wire::READY, 0, 0)
        );
    }

    #[test]
    fn silence_is_a_timeout_and_a_closed_peer_is_closed() {
        let (left, mut right) = pair();
        assert_eq!(right.receive(soon()).err().expect("silence").failure, Failure::Timeout);
        drop(left);
        assert_eq!(right.receive(soon()).err().expect("closed").failure, Failure::Closed);
        assert!(right.wait_closed(Duration::from_millis(100)));
    }

    #[test]
    fn a_header_that_lies_about_its_descriptors_is_refused() {
        let (left, mut right) = pair();
        // Two descriptors announced, none sent.
        let header = wire::header(wire::FLOWS, 0, 2);
        (&left.stream).write_all(&header).expect("write");
        assert_eq!(right.receive(soon()).err().expect("lie").failure, Failure::Protocol);
        // One descriptor sent, none announced.
        let (left, mut right) = pair();
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let header = wire::header(wire::READY, 0, 0);
        sys::send(&left.stream, &header, &[socket.as_fd()]).expect("send");
        assert_eq!(right.receive(soon()).err().expect("lie").failure, Failure::Protocol);
    }

    #[test]
    fn an_oversized_frame_is_refused_before_its_payload_is_read() {
        let (left, mut right) = pair();
        let header = wire::header(wire::FLOWS, wire::MAX_PAYLOAD + 1, 0);
        (&left.stream).write_all(&header).expect("write");
        assert_eq!(right.receive(soon()).err().expect("large").failure, Failure::Protocol);
    }

    #[test]
    fn a_frame_cut_short_times_out_or_closes() {
        let (left, mut right) = pair();
        let header = wire::header(wire::FLOWS, 100, 0);
        (&left.stream).write_all(&header).expect("write");
        (&left.stream).write_all(&[0u8; 40]).expect("write");
        assert_eq!(right.receive(soon()).err().expect("cut").failure, Failure::Timeout);
        let (left, mut right) = pair();
        (&left.stream).write_all(&header[..3]).expect("write");
        drop(left);
        assert_eq!(right.receive(soon()).err().expect("cut").failure, Failure::Closed);
    }

    #[test]
    fn a_refusal_becomes_the_failure_it_names() {
        let (mut left, mut right) = pair();
        left.refuse(wire::REFUSED_VERSION, "no version");
        let error = right.expect(wire::LISTENERS, soon()).err().expect("refused");
        assert_eq!(error.failure, Failure::Version);
        assert!(error.message.contains("no version"));
        left.send(wire::DONE, &[], &[]).expect("send");
        let error = right.expect(wire::LISTENERS, soon()).err().expect("unexpected");
        assert_eq!(error.failure, Failure::Protocol);
    }
}
