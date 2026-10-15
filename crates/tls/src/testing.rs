//! A TLS-terminating test ingress (feature `testing`, never in a release build).
//!
//! The console terminates no TLS; in production a proxy such as Caddy or Nginx does, and
//! sets `X-Forwarded-Proto: https`. Tests of the management peers (SID 0012, acceptance
//! criterion 3) need the same shape on one machine: [`Ingress`] accepts TLS on a loopback
//! port with one of the fixed test certificates of `tests/data`, replaces any
//! `X-Forwarded-Proto` of the request head with `https`, and relays bytes both ways to a
//! plain TCP target. [`ca_file`] is the private CA that signed the good certificates.
//!
//! ```text
//! client --TLS--> Ingress (127.0.0.1:port, leaf certificate) --TCP--> target
//!                   head: X-Forwarded-Proto: https
//! ```
//!
//! Each connection uses two threads: one reads the client's TLS records and writes the
//! plaintext to the target, the other reads the target and writes TLS records back; they
//! share the rustls connection under a mutex. Dropping the ingress closes every connection
//! and joins every thread.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection};

/// The longest request head the ingress reads, as the console's own bound.
const MAX_HEAD: usize = 16 * 1024;
/// How long a handshake and the request head may take.
const SETUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Which fixed test certificate the ingress presents.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Leaf {
    /// Signed by the test CA for `localhost`, `127.0.0.1` and `::1`.
    Localhost,
    /// Signed by the test CA for `wrong.example` only.
    WrongName,
    /// Self-signed for `localhost`; no CA we trust signed it.
    Untrusted,
    /// Signed by the test CA, expired in 2001.
    Expired,
}

impl Leaf {
    fn stem(self) -> &'static str {
        match self {
            Leaf::Localhost => "localhost",
            Leaf::WrongName => "wrong-name",
            Leaf::Untrusted => "untrusted",
            Leaf::Expired => "expired",
        }
    }
}

/// Returns the path of a fixed test file, `tests/data/<name>` of this crate.
pub fn data_file(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(name)
}

/// Returns the path of the test CA ("Sibuna Test CA", PEM).
pub fn ca_file() -> PathBuf {
    data_file("ca.pem")
}

/// What the ingress counted.
#[derive(Debug, Default)]
struct Counters {
    /// Connections whose handshake completed and that were relayed to the target.
    forwarded: AtomicU64,
    /// Connections whose TLS handshake failed (a client refusing the certificate).
    refused: AtomicU64,
}

/// State shared by the acceptor and the connection threads.
#[derive(Debug, Default)]
struct Shared {
    target: Mutex<Option<SocketAddr>>,
    counters: Counters,
    stopping: AtomicBool,
    /// Every socket the ingress opened, so dropping it can cut them.
    sockets: Mutex<Vec<TcpStream>>,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl Shared {
    fn register(&self, socket: &TcpStream) {
        if let Ok(clone) = socket.try_clone() {
            self.sockets.lock().unwrap_or_else(PoisonError::into_inner).push(clone);
        }
    }
}

/// A TLS-terminating test proxy on a loopback port. Dropping it stops it.
#[derive(Debug)]
pub struct Ingress {
    address: SocketAddr,
    shared: Arc<Shared>,
    acceptor: Option<JoinHandle<()>>,
}

impl Ingress {
    /// Starts an ingress on an ephemeral port of 127.0.0.1 presenting `leaf`. It forwards
    /// nothing until [`Ingress::forward_to`] names a target; earlier connections are closed.
    ///
    /// # Errors
    ///
    /// The I/O error of binding, or [`io::ErrorKind::InvalidData`] when the test certificate
    /// cannot be loaded.
    pub fn start(leaf: Leaf) -> io::Result<Ingress> {
        let config = Arc::new(server_config(leaf)?);
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let shared = Arc::new(Shared::default());
        let acceptor = {
            let shared = Arc::clone(&shared);
            std::thread::Builder::new()
                .name("sibuna-test-ingress".into())
                .spawn(move || accept(&listener, &config, &shared))?
        };
        Ok(Ingress { address, shared, acceptor: Some(acceptor) })
    }

    /// Returns the address clients connect to.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Relays later connections to the plain TCP `target`.
    pub fn forward_to(&self, target: SocketAddr) {
        *self.shared.target.lock().unwrap_or_else(PoisonError::into_inner) = Some(target);
    }

    /// Returns how many connections completed the handshake and were relayed.
    pub fn forwarded(&self) -> u64 {
        self.shared.counters.forwarded.load(Ordering::Relaxed)
    }

    /// Returns how many TLS handshakes failed, for example because the client refused the
    /// certificate.
    pub fn refused(&self) -> u64 {
        self.shared.counters.refused.load(Ordering::Relaxed)
    }
}

impl Drop for Ingress {
    fn drop(&mut self) {
        self.shared.stopping.store(true, Ordering::Release);
        // Wakes the acceptor; it sees the flag and returns.
        let _ = TcpStream::connect(self.address);
        if let Some(acceptor) = self.acceptor.take() {
            let _ = acceptor.join();
        }
        for socket in self.shared.sockets.lock().unwrap_or_else(PoisonError::into_inner).iter() {
            let _ = socket.shutdown(Shutdown::Both);
        }
        let threads = std::mem::take(
            &mut *self.shared.threads.lock().unwrap_or_else(PoisonError::into_inner),
        );
        for thread in threads {
            let _ = thread.join();
        }
    }
}

/// Builds the server configuration for `leaf` with the `ring` provider.
fn server_config(leaf: Leaf) -> io::Result<ServerConfig> {
    let invalid = |error: &dyn std::fmt::Display| {
        io::Error::new(io::ErrorKind::InvalidData, error.to_string())
    };
    let stem = leaf.stem();
    let certificate = CertificateDer::from_pem_file(data_file(&format!("{stem}.pem")))
        .map_err(|error| invalid(&error))?;
    let key = PrivateKeyDer::from_pem_file(data_file(&format!("{stem}.key")))
        .map_err(|error| invalid(&error))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| invalid(&error))?
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .map_err(|error| invalid(&error))
}

/// Accepts connections until the ingress is dropped, one thread each.
fn accept(listener: &TcpListener, config: &Arc<ServerConfig>, shared: &Arc<Shared>) {
    for incoming in listener.incoming() {
        if shared.stopping.load(Ordering::Acquire) {
            return;
        }
        let Ok(front) = incoming else { continue };
        shared.register(&front);
        let config = Arc::clone(config);
        let connection_shared = Arc::clone(shared);
        let spawned = std::thread::Builder::new()
            .name("sibuna-test-ingress-conn".into())
            .spawn(move || serve(front, &config, &connection_shared));
        if let Ok(thread) = spawned {
            shared.threads.lock().unwrap_or_else(PoisonError::into_inner).push(thread);
        }
    }
}

/// Serves one connection and closes it, however it ended: the registry holds a clone of
/// each socket, so dropping ours alone would leave the connection open.
fn serve(front: TcpStream, config: &Arc<ServerConfig>, shared: &Arc<Shared>) {
    let closer = front.try_clone();
    forward(front, config, shared);
    if let Ok(socket) = closer {
        let _ = socket.shutdown(Shutdown::Both);
    }
}

/// Handshake, head, then the relay in both directions.
fn forward(mut front: TcpStream, config: &Arc<ServerConfig>, shared: &Arc<Shared>) {
    let Ok(mut connection) = ServerConnection::new(Arc::clone(config)) else { return };
    let _ = front.set_read_timeout(Some(SETUP_TIMEOUT));
    let _ = front.set_nodelay(true);
    while connection.is_handshaking() {
        if connection.complete_io(&mut front).is_err() {
            shared.counters.refused.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }
    let target = *shared.target.lock().unwrap_or_else(PoisonError::into_inner);
    let Some(target) = target else { return };
    let Ok(head) = read_head(&mut connection, &mut front) else { return };
    let Ok(mut back) = TcpStream::connect(target) else { return };
    shared.register(&back);
    let _ = back.set_nodelay(true);
    if back.write_all(&rewrite(&head)).is_err() {
        let _ = back.shutdown(Shutdown::Both);
        return;
    }
    shared.counters.forwarded.fetch_add(1, Ordering::Relaxed);
    let _ = front.set_read_timeout(None);
    relay(connection, front, back);
}

/// Reads the request head through the TLS connection, one byte at a time so that nothing
/// behind it is consumed, at most [`MAX_HEAD`] bytes.
fn read_head(connection: &mut ServerConnection, front: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut stream = rustls::Stream::new(connection, front);
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() == MAX_HEAD || stream.read(&mut byte)? == 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        head.push(byte[0]);
    }
    Ok(head)
}

/// Returns `head` without any `X-Forwarded-Proto` field and with `X-Forwarded-Proto:
/// https` before the blank line.
fn rewrite(head: &[u8]) -> Vec<u8> {
    let body = head.strip_suffix(b"\r\n\r\n").unwrap_or(head);
    let mut out = Vec::with_capacity(head.len() + 32);
    for (index, line) in body.split(|&byte| byte == b'\n').enumerate() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let name = line.split(|&byte| byte == b':').next().unwrap_or_default();
        if index > 0 && name.eq_ignore_ascii_case(b"x-forwarded-proto") {
            continue;
        }
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"X-Forwarded-Proto: https\r\n\r\n");
    out
}

/// Relays plaintext both ways until either side closes; the other direction runs on a
/// thread of its own, and both share the TLS connection.
fn relay(connection: ServerConnection, front: TcpStream, back: TcpStream) {
    let connection = Arc::new(Mutex::new(connection));
    let (Ok(front_writer), Ok(back_reader)) = (front.try_clone(), back.try_clone()) else {
        return;
    };
    let outbound = {
        let connection = Arc::clone(&connection);
        std::thread::spawn(move || to_client(&connection, back_reader, front_writer))
    };
    from_client(&connection, &front, &back);
    let _ = front.shutdown(Shutdown::Both);
    let _ = back.shutdown(Shutdown::Both);
    let _ = outbound.join();
}

/// Decrypts what the client sends and writes it to the target.
fn from_client(connection: &Mutex<ServerConnection>, mut front: &TcpStream, mut back: &TcpStream) {
    let mut records = vec![0u8; 16 * 1024];
    let mut plain = Vec::new();
    // Plaintext that arrived behind the head is still in the connection.
    let _ =
        connection.lock().unwrap_or_else(PoisonError::into_inner).reader().read_to_end(&mut plain);
    if back.write_all(&plain).is_err() {
        return;
    }
    loop {
        let read = match front.read(&mut records) {
            Ok(0) | Err(_) => return,
            Ok(read) => read,
        };
        plain.clear();
        {
            let mut tls = connection.lock().unwrap_or_else(PoisonError::into_inner);
            let mut input = records.get(..read).unwrap_or_default();
            while !input.is_empty() {
                if tls.read_tls(&mut input).is_err() || tls.process_new_packets().is_err() {
                    return;
                }
                let _ = tls.reader().read_to_end(&mut plain);
            }
            // Alerts or key updates the client asked for go back at once.
            while tls.wants_write() {
                if tls.write_tls(&mut front).is_err() {
                    return;
                }
            }
        }
        if back.write_all(&plain).is_err() {
            return;
        }
    }
}

/// Encrypts what the target sends and writes it to the client.
fn to_client(connection: &Mutex<ServerConnection>, mut back: TcpStream, mut front: TcpStream) {
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        let read = match back.read(&mut buffer) {
            Ok(0) | Err(_) => 0,
            Ok(read) => read,
        };
        let mut tls = connection.lock().unwrap_or_else(PoisonError::into_inner);
        if read == 0 {
            tls.send_close_notify();
        } else if tls.writer().write_all(buffer.get(..read).unwrap_or_default()).is_err() {
            return;
        }
        while tls.wants_write() {
            if tls.write_tls(&mut front).is_err() {
                return;
            }
        }
        if read == 0 {
            let _ = front.shutdown(Shutdown::Both);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_forwarded_scheme_is_replaced_by_https() {
        let head = b"GET /console/peer HTTP/1.1\r\nHost: a\r\nx-forwarded-proto: http\r\n\r\n";
        assert_eq!(
            rewrite(head),
            b"GET /console/peer HTTP/1.1\r\nHost: a\r\nX-Forwarded-Proto: https\r\n\r\n"
        );
    }
}
