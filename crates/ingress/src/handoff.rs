//! Private connections from the protocol runtime to the synchronous firewall.
//!
//! The firewall serves `std::net::TcpStream` values on its own threads. The client's
//! identity always comes from the terminated transport, never from this connection.
//!
//! On Unix a handoff is a socket pair. It has no address, so no other process can reach
//! it, and it uses no port, so a burst of exchanges cannot exhaust the ephemeral range.
//! Elsewhere one loopback listener lives as long as the ingress, and its acceptor gives a
//! connection only to the waiter that registered its source address.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::Handler;

/// The runtime's end of a handoff.
#[cfg(unix)]
pub(crate) type Pipe = tokio::net::UnixStream;
/// The runtime's end of a handoff.
#[cfg(not(unix))]
pub(crate) type Pipe = tokio::net::TcpStream;

/// The firewall entry point and the way to reach it.
pub(crate) struct Handoff {
    handler: Handler,
    #[cfg(not(unix))]
    loopback: loopback::Listener,
}

impl Handoff {
    /// Prepares handoffs on the current runtime.
    pub fn start(handler: Handler) -> io::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            handler,
            #[cfg(not(unix))]
            loopback: loopback::Listener::start()?,
        }))
    }

    /// Opens a connection whose far end the firewall serves for `peer` on `vip`.
    #[cfg(unix)]
    #[allow(clippy::unused_async)] // The loopback variant awaits its acceptor.
    pub async fn open(&self, peer: SocketAddr, vip: SocketAddr) -> io::Result<Pipe> {
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixStream;

        let (near, far) = UnixStream::pair()?;
        near.set_nonblocking(true)?;
        let near = Pipe::from_std(near)?;
        // The firewall reads, writes, shuts down and sets timeouts, which every stream
        // socket supports. It takes the client address from `peer`, never from the socket.
        let far = std::net::TcpStream::from(OwnedFd::from(far));
        (self.handler)(far, peer, vip);
        Ok(near)
    }

    /// Opens a connection whose far end the firewall serves for `peer` on `vip`.
    #[cfg(not(unix))]
    pub async fn open(&self, peer: SocketAddr, vip: SocketAddr) -> io::Result<Pipe> {
        let (near, far) = self.loopback.pair().await?;
        (self.handler)(far, peer, vip);
        Ok(near)
    }
}

#[cfg(not(unix))]
mod loopback {
    use std::collections::HashMap;
    use std::io;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex, PoisonError};

    use tokio::net::{TcpListener, TcpSocket, TcpStream};
    use tokio::sync::oneshot;
    use tokio::time::timeout;

    use crate::DEADLINE;

    type Waiting = Mutex<HashMap<SocketAddr, oneshot::Sender<TcpStream>>>;

    /// One loopback listener for every handoff of an ingress.
    pub(super) struct Listener {
        address: SocketAddr,
        waiting: Arc<Waiting>,
    }

    impl Listener {
        /// Binds the listener and starts its acceptor on the current runtime.
        pub fn start() -> io::Result<Self> {
            let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            listener.set_nonblocking(true)?;
            let listener = TcpListener::from_std(listener)?;
            let address = listener.local_addr()?;
            let waiting = Arc::new(Waiting::default());
            tokio::spawn(accept(listener, Arc::clone(&waiting)));
            Ok(Self { address, waiting })
        }

        /// Connects a registered client socket and returns both ends.
        pub async fn pair(&self) -> io::Result<(TcpStream, std::net::TcpStream)> {
            let socket = TcpSocket::new_v4()?;
            socket.bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
            let source = socket.local_addr()?;
            let (tx, rx) = oneshot::channel();
            self.waiting.lock().unwrap_or_else(PoisonError::into_inner).insert(source, tx);
            let _registration = Registration { waiting: &self.waiting, source };
            let connected = timeout(DEADLINE, async {
                let near = socket.connect(self.address).await?;
                let far = rx.await.map_err(|_| io::Error::other("handoff acceptor stopped"))?;
                io::Result::Ok((near, far))
            })
            .await;
            let (near, far) = connected.map_err(|_| io::ErrorKind::TimedOut)??;
            near.set_nodelay(true)?;
            let far = far.into_std()?;
            far.set_nonblocking(false)?;
            Ok((near, far))
        }
    }

    /// Removes an unanswered registration when the handoff fails or is cancelled.
    struct Registration<'a> {
        waiting: &'a Waiting,
        source: SocketAddr,
    }

    impl Drop for Registration<'_> {
        fn drop(&mut self) {
            self.waiting.lock().unwrap_or_else(PoisonError::into_inner).remove(&self.source);
        }
    }

    async fn accept(listener: TcpListener, waiting: Arc<Waiting>) {
        loop {
            match listener.accept().await {
                Ok((stream, source)) => {
                    let waiter =
                        waiting.lock().unwrap_or_else(PoisonError::into_inner).remove(&source);
                    // A connection nobody registered is closed by dropping it.
                    if let Some(waiter) = waiter {
                        let _ = waiter.send(stream);
                    }
                }
                // Descriptor pressure clears as exchanges finish.
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            }
        }
    }
}
