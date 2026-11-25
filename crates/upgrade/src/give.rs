//! The old process's end of the handoff.

use std::os::fd::BorrowedFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use crate::channel::Channel;
use crate::error::protocol;
use crate::{
    Failure, Flow, Listener, MAX_FLOWS, MAX_LISTENERS, Peer, Timeouts, UpgradeError, VERSION, sys,
    wire,
};

/// What the replacement reported when it took the service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Done {
    /// The mappings the replacement serves now.
    pub adopted: u32,
    /// The mappings it could not take. Their clients are given a server anew.
    pub dropped: u32,
}

/// A handoff in progress, seen from the old process. The peer is authenticated.
pub struct Giving {
    channel: Channel,
    peer: Peer,
    timeouts: Timeouts,
    /// When the cutover must be over. Set when `READY` arrives.
    cutover: Option<Instant>,
    /// The mappings given so far.
    given: usize,
}

/// Starts a handoff on a connection that the [`crate::Gate`] accepted: checks that the
/// peer runs as this process's user, reads its `HELLO` and agrees on the version.
///
/// # Errors
///
/// [`Failure::Refused`] for a peer of another user, [`Failure::Version`] when the peer
/// does not speak version 1, [`Failure::Protocol`] for anything that is not a `HELLO`,
/// and [`Failure::Timeout`] or [`Failure::Closed`] for a peer that says nothing. The
/// peer was told why where that is possible. Nothing was given.
pub fn begin_give(stream: UnixStream, timeouts: &Timeouts) -> Result<Giving, UpgradeError> {
    begin_give_as(stream, timeouts, sys::effective_user())
}

/// As [`begin_give`], for a process whose user is `user`.
pub(crate) fn begin_give_as(
    stream: UnixStream,
    timeouts: &Timeouts,
    user: u32,
) -> Result<Giving, UpgradeError> {
    let mut channel = Channel::new(stream, timeouts.write)?;
    let peer = peer_of(&channel)?;
    if peer.uid != user {
        let reason = format!("user {} is not user {user}", peer.uid);
        channel.refuse(wire::REFUSED_PEER, &reason);
        return Err(UpgradeError::new(Failure::Refused, reason));
    }
    let hello = channel
        .expect(wire::HELLO, Instant::now() + timeouts.hello)
        .and_then(|frame| wire::parse_hello(&frame.payload));
    let (lowest, highest) = match hello {
        Ok(range) => range,
        Err(error) => {
            if error.failure == Failure::Protocol {
                channel.refuse(wire::REFUSED_PROTOCOL, "expected the HELLO of a replacement");
            }
            return Err(error);
        }
    };
    if !(lowest..=highest).contains(&VERSION) {
        let reason =
            format!("the peer speaks versions {lowest} to {highest}, this process {VERSION}");
        channel.refuse(wire::REFUSED_VERSION, &reason);
        return Err(UpgradeError::new(Failure::Version, reason));
    }
    Ok(Giving { channel, peer, timeouts: *timeouts, cutover: None, given: 0 })
}

/// Reads the credentials of the peer of `channel`.
pub(crate) fn peer_of(channel: &Channel) -> Result<Peer, UpgradeError> {
    sys::peer(channel.stream()).map_err(|error| {
        let failure = if error.kind() == std::io::ErrorKind::Unsupported {
            Failure::Unsupported
        } else {
            Failure::Protocol
        };
        UpgradeError::new(failure, format!("reading the credentials of the peer: {error}"))
    })
}

impl Giving {
    /// The replacement, as the kernel recorded it.
    pub fn peer(&self) -> Peer {
        self.peer
    }

    /// Tells the replacement that nothing can be given now, and ends the handoff.
    pub fn refuse_busy(mut self, reason: &str) {
        self.channel.refuse(wire::REFUSED_BUSY, reason);
    }

    /// Gives the listening sockets. The descriptors stay open here.
    ///
    /// # Errors
    ///
    /// [`Failure::Busy`] for more than [`MAX_LISTENERS`], after telling the peer, and
    /// the failure of sending.
    pub fn give_listeners(
        &mut self,
        listeners: &[(Listener, BorrowedFd<'_>)],
    ) -> Result<(), UpgradeError> {
        if listeners.len() > MAX_LISTENERS {
            let reason = format!("{} listeners are more than a handoff carries", listeners.len());
            self.channel.refuse(wire::REFUSED_BUSY, &reason);
            return Err(UpgradeError::new(Failure::Busy, reason));
        }
        let mut chunks = listeners.chunks(wire::PER_FRAME).peekable();
        if chunks.peek().is_none() {
            return self.channel.send(wire::LISTENERS, &wire::listeners(VERSION, false, &[]), &[]);
        }
        while let Some(chunk) = chunks.next() {
            let list: Vec<Listener> = chunk.iter().map(|(listener, _)| *listener).collect();
            let sockets: Vec<BorrowedFd<'_>> = chunk.iter().map(|(_, socket)| *socket).collect();
            let payload = wire::listeners(VERSION, chunks.peek().is_some(), &list);
            self.channel.send(wire::LISTENERS, &payload, &sockets)?;
        }
        Ok(())
    }

    /// Waits for `READY`, at most [`Timeouts::ready`]. The cutover deadline starts when
    /// it arrives. Until this returns the old process has changed nothing.
    ///
    /// # Errors
    ///
    /// The failure of the replacement to become ready. Nothing needs to be undone.
    pub fn wait_ready(&mut self) -> Result<(), UpgradeError> {
        let frame = self.channel.expect(wire::READY, Instant::now() + self.timeouts.ready)?;
        if !frame.payload.is_empty() {
            return Err(protocol("READY carries a payload"));
        }
        self.cutover = Some(Instant::now() + self.timeouts.cutover);
        Ok(())
    }

    /// Gives UDP mappings with their server sockets. The caller has stopped reading
    /// those sockets. It may call this several times, with a piece of the mappings each
    /// time, and then calls [`Giving::commit`]. The descriptors stay open here.
    ///
    /// # Errors
    ///
    /// [`Failure::Protocol`] for more than [`MAX_FLOWS`] in all, and the failure of
    /// sending. After any error but [`Failure::Closed`] the caller must call
    /// [`Giving::end_peer`] before it reads the sockets again.
    pub fn give_flows(&mut self, flows: &[(Flow, BorrowedFd<'_>)]) -> Result<(), UpgradeError> {
        if self.given + flows.len() > MAX_FLOWS {
            return Err(protocol("more mappings than a handoff carries"));
        }
        for chunk in flows.chunks(wire::PER_FRAME) {
            let list: Vec<Flow> = chunk.iter().map(|(flow, _)| *flow).collect();
            let sockets: Vec<BorrowedFd<'_>> = chunk.iter().map(|(_, socket)| *socket).collect();
            self.channel.send(wire::FLOWS, &wire::flows(&list), &sockets)?;
            self.given += chunk.len();
        }
        Ok(())
    }

    /// Says that every mapping was given: sends `COMMIT` with their number.
    ///
    /// # Errors
    ///
    /// The failure of sending, with the same duty as for [`Giving::give_flows`].
    pub fn commit(&mut self) -> Result<(), UpgradeError> {
        self.channel.send(wire::COMMIT, &wire::numbers(&[self.given as u32]), &[])
    }

    /// Waits for `DONE` until the cutover deadline. When this returns `Ok` the
    /// replacement serves, and the caller stops.
    ///
    /// # Errors
    ///
    /// [`Failure::Closed`] when the replacement is gone: the caller may serve again at
    /// once. Any other failure leaves a replacement that may still run: the caller
    /// must call [`Giving::end_peer`] first.
    pub fn wait_done(&mut self) -> Result<Done, UpgradeError> {
        let deadline = self.cutover.unwrap_or_else(Instant::now);
        let frame = self.channel.expect(wire::DONE, deadline)?;
        let [adopted, dropped] = wire::parse_numbers::<2>(&frame.payload)?;
        Ok(Done { adopted, dropped })
    }

    /// Ends the replacement with SIGKILL and waits up to `patience` for its connection
    /// to close. Returns true when it has closed, which proves that the replacement
    /// reads no socket. On false the caller must call again, and must not read the
    /// UDP sockets meanwhile.
    pub fn end_peer(&mut self, patience: Duration) -> bool {
        // The signal can fail when the process is gone already. The closed connection
        // is the proof either way.
        let _ = sys::end_process(self.peer.pid);
        self.channel.wait_closed(patience)
    }
}
