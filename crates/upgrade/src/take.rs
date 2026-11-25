//! The replacement's end of the handoff.

use std::io;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Instant;

use crate::channel::Channel;
use crate::error::protocol;
use crate::give::peer_of;
use crate::sys::SocketKind;
use crate::{
    Failure, Flow, Kind, Listener, MAX_FLOWS, MAX_LISTENERS, Peer, SUPPORTED, Timeouts,
    UpgradeError, VERSION, sys, wire,
};

/// A handoff in progress, seen from the replacement. The old process is authenticated,
/// and the listening sockets are received and checked.
pub struct Taking {
    channel: Channel,
    peer: Peer,
    timeouts: Timeouts,
    listeners: Vec<(Listener, OwnedFd)>,
    /// The kind of each listener, for the check of the mappings.
    kinds: Vec<Kind>,
    /// The mappings that came with a wrong listener or a wrong socket.
    rejected: u32,
}

/// Everything one handoff gave, for [`take_all`].
pub struct Taken {
    /// The old process.
    pub peer: Peer,
    /// The listening sockets, checked.
    pub listeners: Vec<(Listener, OwnedFd)>,
    /// The UDP mappings with their connected server sockets, checked.
    pub flows: Vec<(Flow, UdpSocket)>,
}

/// Connects to the upgrade socket at `path` and takes the listening sockets of the
/// process that answers. `Ok(None)` means that nobody answers: no socket file, or a
/// file that no process listens on. The caller then starts as a first process does.
///
/// The caller has checked its configuration before it calls. After this call it
/// prepares to serve on the sockets without reading them, then calls
/// [`Taking::ready`].
///
/// # Errors
///
/// [`Failure::Unsupported`] off Linux, [`Failure::Refused`] when the socket is served
/// by another user, or when that process refuses this one, [`Failure::Version`],
/// [`Failure::Busy`], and [`Failure::Protocol`] for a descriptor that is not the
/// socket its frame names. The old process keeps serving in every case.
pub fn begin_take(path: &Path, timeouts: &Timeouts) -> Result<Option<Taking>, UpgradeError> {
    if !SUPPORTED {
        return Err(UpgradeError::new(Failure::Unsupported, "this platform passes no sockets"));
    }
    let stream = match UnixStream::connect(path) {
        Ok(stream) => stream,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(None);
        }
        Err(error) => {
            return Err(protocol(format!("connecting to {}: {error}", path.display())));
        }
    };
    begin_take_as(stream, timeouts, sys::effective_user()).map(Some)
}

/// As [`begin_take`] on a connected socket, for a process whose user is `user`.
pub(crate) fn begin_take_as(
    stream: UnixStream,
    timeouts: &Timeouts,
    user: u32,
) -> Result<Taking, UpgradeError> {
    let mut channel = Channel::new(stream, timeouts.write)?;
    let peer = peer_of(&channel)?;
    if peer.uid != user {
        let reason = format!("the socket is served by user {}, not user {user}", peer.uid);
        channel.refuse(wire::REFUSED_PEER, &reason);
        return Err(UpgradeError::new(Failure::Refused, reason));
    }
    channel.send(wire::HELLO, &wire::hello(VERSION, VERSION), &[])?;
    let deadline = Instant::now() + timeouts.hello;
    let mut listeners = Vec::new();
    loop {
        let frame = channel.expect(wire::LISTENERS, deadline)?;
        let (version, more, list) = wire::parse_listeners(&frame.payload)?;
        if version != VERSION {
            return Err(UpgradeError::new(
                Failure::Version,
                format!("the old process chose version {version}"),
            ));
        }
        if list.len() != frame.descriptors.len() {
            return Err(protocol("a listener frame has not one descriptor for each listener"));
        }
        for (listener, socket) in list.into_iter().zip(frame.descriptors) {
            listeners.push((listener, checked_listener(listener, socket)?));
        }
        if listeners.len() > MAX_LISTENERS {
            return Err(protocol("more listeners than a handoff carries"));
        }
        if !more {
            break;
        }
    }
    let kinds = listeners.iter().map(|(listener, _)| listener.kind).collect();
    Ok(Taking { channel, peer, timeouts: *timeouts, listeners, kinds, rejected: 0 })
}

/// True when two addresses name the same IP address and port.
fn same_endpoint(left: SocketAddr, right: SocketAddr) -> bool {
    left.ip() == right.ip() && left.port() == right.port()
}

/// Checks that `socket` is the listening socket that `listener` describes.
fn checked_listener(listener: Listener, socket: OwnedFd) -> Result<OwnedFd, UpgradeError> {
    let wrong = |what: &str| protocol(format!("the descriptor of {:?} {what}", listener.address));
    let kind = sys::socket_kind(socket.as_fd()).map_err(|_| wrong("is not a socket"))?;
    let (expected, local, socket) = match listener.kind {
        Kind::Tcp | Kind::Http => {
            let typed = TcpListener::from(socket);
            (SocketKind::Listening, typed.local_addr(), OwnedFd::from(typed))
        }
        Kind::Udp => {
            let typed = UdpSocket::from(socket);
            (SocketKind::Datagram, typed.local_addr(), OwnedFd::from(typed))
        }
    };
    if kind != expected {
        return Err(wrong("has the wrong type"));
    }
    match local {
        Ok(local) if same_endpoint(local, listener.address) => Ok(socket),
        _ => Err(wrong("is bound to another address")),
    }
}

impl Taking {
    /// The old process, as the kernel recorded it.
    pub fn peer(&self) -> Peer {
        self.peer
    }

    /// Takes the listening sockets. Each is of the type and at the address that its
    /// [`Listener`] says. A second call returns nothing.
    pub fn listeners(&mut self) -> Vec<(Listener, OwnedFd)> {
        std::mem::take(&mut self.listeners)
    }

    /// Says that this process is prepared to serve, and receives the UDP mappings.
    /// From this call until [`Taking::done`] nobody reads the UDP sockets, so the
    /// caller goes on without delay.
    ///
    /// A mapping whose listener is not a UDP listener of this handoff, or whose socket
    /// is not a datagram socket connected to its server, is closed and counted in the
    /// `dropped` number of `DONE`.
    ///
    /// # Errors
    ///
    /// The failure of the old process to give the mappings in time. The caller must
    /// end without reading any socket it was given.
    pub fn ready(&mut self) -> Result<Vec<(Flow, UdpSocket)>, UpgradeError> {
        self.channel.send(wire::READY, &[], &[])?;
        let deadline = Instant::now() + self.timeouts.cutover;
        let mut flows = Vec::new();
        let mut received: usize = 0;
        loop {
            let frame = self.channel.receive(deadline)?;
            match frame.kind {
                wire::FLOWS => {
                    let list = wire::parse_flows(&frame.payload)?;
                    if list.len() != frame.descriptors.len() {
                        return Err(protocol("a mapping frame has not one descriptor for each"));
                    }
                    received += list.len();
                    if received > MAX_FLOWS {
                        return Err(protocol("more mappings than a handoff carries"));
                    }
                    for (flow, socket) in list.into_iter().zip(frame.descriptors) {
                        match self.checked_flow(&flow, socket) {
                            Some(socket) => flows.push((flow, socket)),
                            None => self.rejected += 1,
                        }
                    }
                }
                wire::COMMIT => {
                    let [count] = wire::parse_numbers::<1>(&frame.payload)?;
                    if count as usize != received {
                        return Err(protocol("COMMIT counts other mappings than were sent"));
                    }
                    return Ok(flows);
                }
                other => return Err(protocol(format!("unexpected frame {other} in the cutover"))),
            }
        }
    }

    /// The server socket of `flow`, when the mapping belongs to a UDP listener of this
    /// handoff and the socket is a datagram socket connected to the server.
    fn checked_flow(&self, flow: &Flow, socket: OwnedFd) -> Option<UdpSocket> {
        if self.kinds.get(usize::from(flow.listener)) != Some(&Kind::Udp) {
            return None;
        }
        if sys::socket_kind(socket.as_fd()).ok()? != SocketKind::Datagram {
            return None;
        }
        let socket = UdpSocket::from(socket);
        let peer = socket.peer_addr().ok()?;
        same_endpoint(peer, flow.server).then_some(socket)
    }

    /// Tells the old process that this process serves: `adopted` mappings are kept and
    /// `dropped` were not. The caller accepts on the TCP listeners already. It reads
    /// the UDP sockets only after this call returned `Ok`.
    ///
    /// # Errors
    ///
    /// The failure of sending. The old process has not stopped, and the caller must
    /// end without reading a UDP socket.
    pub fn done(mut self, adopted: u32, dropped: u32) -> Result<(), UpgradeError> {
        let dropped = dropped.saturating_add(self.rejected);
        self.channel.send(wire::DONE, &wire::numbers(&[adopted, dropped]), &[])
    }
}

/// The whole handoff in one call, for a caller that can serve the moment it has the
/// sockets: takes the listeners, says `READY`, takes the mappings and says `DONE`.
/// `Ok(None)` means that nobody answers at `path`.
///
/// # Errors
///
/// As [`begin_take`], [`Taking::ready`] and [`Taking::done`].
pub fn take_all(path: &Path, timeouts: &Timeouts) -> Result<Option<Taken>, UpgradeError> {
    let Some(mut taking) = begin_take(path, timeouts)? else { return Ok(None) };
    let listeners = taking.listeners();
    let flows = taking.ready()?;
    let peer = taking.peer();
    taking.done(flows.len() as u32, 0)?;
    Ok(Some(Taken { peer, listeners, flows }))
}
