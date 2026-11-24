//! Private loopback connections from the protocol runtime to the synchronous firewall.
//!
//! The firewall serves `std::net::TcpStream` values on its own threads. One loopback
//! listener lives as long as the ingress. For each handoff we bind a client socket, record
//! its address, and connect. The acceptor gives a connection only to the waiter that
//! registered its source address, so another local process cannot inject an exchange. The
//! client's identity always comes from the terminated transport, never from this socket.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};

use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::oneshot;
use tokio::time::timeout;

use crate::{DEADLINE, Handler};

type Waiting = Mutex<HashMap<SocketAddr, oneshot::Sender<TcpStream>>>;

/// The loopback listener and the firewall entry point behind it.
pub(crate) struct Handoff {
    address: SocketAddr,
    waiting: Arc<Waiting>,
    handler: Handler,
}

impl Handoff {
    /// Binds the listener and starts its acceptor on the current runtime.
    pub fn start(handler: Handler) -> io::Result<Arc<Self>> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let listener = TcpListener::from_std(listener)?;
        let address = listener.local_addr()?;
        let waiting = Arc::new(Waiting::default());
        tokio::spawn(accept(listener, Arc::clone(&waiting)));
        Ok(Arc::new(Self { address, waiting, handler }))
    }

    /// Opens a connection whose far end the firewall serves for `peer` on `vip`.
    pub async fn open(&self, peer: SocketAddr, vip: SocketAddr) -> io::Result<TcpStream> {
        let socket = TcpSocket::new_v4()?;
        socket.bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
        let source = socket.local_addr()?;
        let (tx, rx) = oneshot::channel();
        self.waiting.lock().unwrap_or_else(PoisonError::into_inner).insert(source, tx);
        let _registration = Registration { waiting: &self.waiting, source };
        let connected = timeout(DEADLINE, async {
            let client = socket.connect(self.address).await?;
            let server = rx.await.map_err(|_| io::Error::other("handoff acceptor stopped"))?;
            io::Result::Ok((client, server))
        })
        .await;
        let (client, server) = connected.map_err(|_| io::ErrorKind::TimedOut)??;
        client.set_nodelay(true)?;
        let server = server.into_std()?;
        server.set_nonblocking(false)?;
        (self.handler)(server, peer, vip);
        Ok(client)
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
