//! TLS on a worker (SID 0024).
//!
//! A worker ends the TLS of an HTTP/1.1 connection itself. It first reads the
//! ClientHello. A client that offers HTTP/2, or a validation of automatic HTTPS, goes
//! to the protocol runtime with the bytes read so far. Every other client stays, and
//! the worker reads and writes its clear bytes through a [`Secure`] session.
//!
//! Without the `https` feature no connection has such a session, and the types here
//! have no value.

#[cfg(feature = "https")]
pub(super) use with_tls::Secure;
#[cfg(feature = "https")]
pub(in crate::edge) use with_tls::Started;
#[cfg(not(feature = "https"))]
pub(super) use without_tls::Secure;
#[cfg(not(feature = "https"))]
pub(in crate::edge) use without_tls::Started;

/// The longest time from the accept to the end of the handshake: that of the runtime.
pub(super) const HANDSHAKE_TIME: std::time::Duration = std::time::Duration::from_secs(15);

#[cfg(feature = "https")]
mod with_tls {
    use std::net::{SocketAddr, TcpStream};
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, PoisonError, RwLock};

    use sibuna_ingress::{Greeted, Greeting, Sealed};
    use sibuna_reactor::{Io, handle, read_once as read, write_once as write};

    use super::super::worker::Worker;
    use crate::connection::Ingress;
    use crate::server::Admitted;

    /// The protocol runtime, which serves the connections a worker does not keep. It is
    /// empty once the server has stopped.
    pub(in crate::edge) type Front = Arc<RwLock<Option<sibuna_ingress::Ingress>>>;

    /// What an accepted TLS connection brings to a worker besides its socket.
    pub(in crate::edge) struct Started {
        /// The listener that accepted the connection.
        pub bind: SocketAddr,
        /// The source of the PROXY header, when the connection had one.
        pub client: Option<SocketAddr>,
        /// The place under the node bound and the bound of the client.
        pub place: Admitted,
        pub greeting: Greeting,
        pub front: Front,
    }

    impl Started {
        /// The session of a connection that came with a handshake to begin, and its
        /// place under the bounds.
        pub(in crate::edge::workers) fn begin(
            started: Option<Self>,
        ) -> Option<(Secure, Admitted)> {
            let Self { bind, client, place, greeting, front } = started?;
            Some((Secure::Greeting(Box::new(Greet { bind, client, greeting, front })), place))
        }
    }

    /// A connection whose ClientHello is not whole yet.
    pub(in crate::edge::workers) struct Greet {
        bind: SocketAddr,
        client: Option<SocketAddr>,
        greeting: Greeting,
        front: Front,
    }

    /// The TLS state of a connection on a worker.
    pub(in crate::edge::workers) enum Secure {
        /// Nothing is answered yet: the connection may still go to the runtime.
        Greeting(Box<Greet>),
        /// The worker serves the connection through this session.
        Sealed(Box<Sealed>),
    }

    impl Secure {
        /// True until the handshake has ended.
        pub fn is_starting(&self) -> bool {
            match self {
                Self::Greeting(_) => true,
                Self::Sealed(sealed) => sealed.is_handshaking(),
            }
        }

        /// True while the ClientHello is not whole.
        pub fn is_greeting(&self) -> bool {
            matches!(self, Self::Greeting(_))
        }

        /// Reads clear bytes of the client. See [`Sealed::read`].
        pub fn read(&mut self, socket: &TcpStream, plain: &mut [u8]) -> Io {
            match self {
                Self::Greeting(_) => Io::Blocked,
                Self::Sealed(sealed) => sealed.read(socket, plain),
            }
        }

        /// Takes clear bytes for the client. See [`Sealed::write`].
        pub fn write(&mut self, socket: &TcpStream, plain: &[u8]) -> Io {
            match self {
                Self::Greeting(_) => Io::Blocked,
                Self::Sealed(sealed) => sealed.write(socket, plain),
            }
        }

        /// Writes what the session holds. Returns false when the socket failed.
        pub fn flush(&mut self, socket: &TcpStream) -> bool {
            match self {
                Self::Greeting(_) => true,
                Self::Sealed(sealed) => sealed.flush(socket),
            }
        }

        /// True while the session holds encrypted bytes for the socket.
        pub fn wants_write(&self) -> bool {
            match self {
                Self::Greeting(_) => false,
                Self::Sealed(sealed) => sealed.wants_write(),
            }
        }

        /// True when the session may hold clear bytes that no socket event announces.
        pub fn holds_clear(&self) -> bool {
            match self {
                Self::Greeting(_) => false,
                Self::Sealed(sealed) => sealed.holds_clear(),
            }
        }

        /// Records what the handshake settled, once it has ended.
        pub fn settle(&self, ingress: &mut Ingress) {
            if let Self::Sealed(sealed) = self
                && let Some(secured) = sealed.secured()
            {
                ingress.cert = secured.cert;
                ingress.tls = (secured.version, secured.cipher);
            }
        }

        /// Tells the client that the connection ends.
        pub fn end(&mut self, socket: &TcpStream) {
            if let Self::Sealed(sealed) = self {
                sealed.end(socket);
            }
        }
    }

    impl Worker {
        /// Reads the socket of a connection that is still in its greeting. Returns
        /// false when the connection left the worker: it was closed or went to the
        /// protocol runtime.
        pub(in crate::edge::workers) fn greet(&mut self, index: u32) -> bool {
            let Some(conn) = self.conns.at(index) else { return false };
            let Some(Secure::Greeting(greet)) = conn.secure.as_mut() else { return true };
            let greeted = match read(&conn.stream, &mut self.block) {
                Io::Bytes(count) => {
                    greet.greeting.feed(self.block.get(..count).unwrap_or_default())
                }
                Io::Blocked => Greeted::More,
                Io::Closed | Io::Failed => Greeted::Failed(Vec::new()),
            };
            match greeted {
                Greeted::More => true,
                Greeted::Kept(sealed) => {
                    self.server.metrics.tls_kept.bump();
                    conn.secure = Some(Secure::Sealed(sealed));
                    true
                }
                Greeted::Passed(seen) => {
                    self.server.metrics.tls_passed.bump();
                    self.pass(index, seen);
                    false
                }
                Greeted::Failed(alert) => {
                    if !alert.is_empty() {
                        let _ = write(&conn.stream, &alert);
                    }
                    self.close(index);
                    false
                }
            }
        }

        /// Gives a connection to the protocol runtime with the bytes read from it.
        /// Nothing was written, so the runtime starts the handshake from those bytes.
        fn pass(&mut self, index: u32, seen: Vec<u8>) {
            let Some(mut conn) = self.conns.remove(index) else { return };
            self.load.fetch_sub(1, Ordering::Relaxed);
            self.poll.remove(handle(&conn.stream));
            let Some(Secure::Greeting(greet)) = conn.secure.take() else { return };
            let (Some(permit), place) = (conn.permit.take(), conn.admission.take()) else {
                return;
            };
            let Greet { bind, client, front, .. } = *greet;
            let front = front.read().unwrap_or_else(PoisonError::into_inner);
            if let Some(runtime) = front.as_ref() {
                runtime.accept_started(bind, conn.stream, permit, Box::new(place), client, seen);
            }
        }
    }
}

#[cfg(not(feature = "https"))]
mod without_tls {
    use std::net::TcpStream;

    use sibuna_reactor::Io;

    use super::super::worker::Worker;
    use crate::connection::Ingress;
    use crate::server::Admitted;

    /// Never built: without TLS no connection starts a handshake.
    pub(in crate::edge) enum Started {}

    impl Started {
        pub(in crate::edge::workers) fn begin(_: Option<Self>) -> Option<(Secure, Admitted)> {
            None
        }
    }

    /// Never built: without TLS no connection has a session.
    pub(in crate::edge::workers) enum Secure {}

    impl Secure {
        pub fn is_starting(&self) -> bool {
            match *self {}
        }

        pub fn is_greeting(&self) -> bool {
            match *self {}
        }

        pub fn read(&mut self, _socket: &TcpStream, _plain: &mut [u8]) -> Io {
            match *self {}
        }

        pub fn write(&mut self, _socket: &TcpStream, _plain: &[u8]) -> Io {
            match *self {}
        }

        pub fn flush(&mut self, _socket: &TcpStream) -> bool {
            match *self {}
        }

        pub fn wants_write(&self) -> bool {
            match *self {}
        }

        pub fn holds_clear(&self) -> bool {
            match *self {}
        }

        pub fn settle(&self, _ingress: &mut Ingress) {
            match *self {}
        }

        pub fn end(&mut self, _socket: &TcpStream) {
            match *self {}
        }
    }

    impl Worker {
        pub(in crate::edge::workers) fn greet(&mut self, _index: u32) -> bool {
            true
        }
    }
}
