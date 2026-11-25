//! TLS for a caller that owns the socket and its readiness (SID 0024).
//!
//! An event-driven worker serves an HTTP/1.1 connection on one thread. With the types
//! here it ends the TLS of such a connection itself: nothing is copied to the protocol
//! runtime and back. The worker first reads the ClientHello through a [`Greeting`].
//! That tells whether the connection stays ([`Sealed`]) or goes to the runtime, which
//! serves HTTP/2, the validations of automatic HTTPS and the handshakes that wait for
//! a certificate on demand.
//!
//! ```text
//!  socket --> Greeting --+--> Kept:   Sealed, read and written by the worker
//!                        +--> Passed: the bytes read, for `Ingress::accept_started`
//! ```

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::server::{Accepted, AcceptedAlert, Acceptor};
use rustls::{ServerConfig, ServerConnection};
use sibuna_reactor::Io;

use crate::certs::Certificates;
use crate::{Secured, auto};

/// The most bytes a client may send before its ClientHello is whole.
pub const MAX_HELLO: usize = 16 * 1024;
/// The most encrypted bytes a session holds for a socket that does not take them.
const HELD: usize = 64 * 1024;
/// How often one call reads the socket, so that one client cannot hold its thread.
const ROUNDS: usize = 32;

/// What a [`Greeting`] knows after some bytes.
pub enum Greeted {
    /// The ClientHello is not whole yet.
    More,
    /// The client offers neither HTTP/2 nor a validation, and its certificate is
    /// there: the caller keeps the connection and serves HTTP/1.1 through this session.
    Kept(Box<Sealed>),
    /// The protocol runtime serves this client: it offers HTTP/2 or a validation, or
    /// its certificate must first be obtained. These are all the bytes read so far,
    /// for [`crate::Ingress::accept_started`].
    Passed(Vec<u8>),
    /// The bytes are not a ClientHello that the listener can answer. The caller writes
    /// these bytes, a TLS alert or nothing, and closes.
    Failed(Vec<u8>),
}

/// The start of a TLS connection, before anything is answered.
pub struct Greeting {
    acceptor: Acceptor,
    config: Arc<ServerConfig>,
    /// The certificates and the port of a listener that obtains them on demand.
    on_demand: Option<(Arc<Certificates>, u16)>,
    seen: Vec<u8>,
}

impl Greeting {
    pub(crate) fn new(
        config: Arc<ServerConfig>,
        on_demand: Option<(Arc<Certificates>, u16)>,
    ) -> Self {
        Self { acceptor: Acceptor::default(), config, on_demand, seen: Vec::new() }
    }

    /// Takes the next bytes of the client, in the order they arrived. After any answer
    /// but [`Greeted::More`] the greeting is over and must not be fed again.
    pub fn feed(&mut self, bytes: &[u8]) -> Greeted {
        if self.seen.len() + bytes.len() > MAX_HELLO {
            return Greeted::Failed(Vec::new());
        }
        self.seen.extend_from_slice(bytes);
        let mut rest = bytes;
        while !rest.is_empty() {
            if self.acceptor.read_tls(&mut rest).is_err() {
                return Greeted::Failed(Vec::new());
            }
            match self.acceptor.accept() {
                Ok(None) => {}
                Ok(Some(accepted)) => return self.settle(accepted, rest),
                Err((_, alert)) => return Greeted::Failed(alert_bytes(alert)),
            }
        }
        Greeted::More
    }

    /// Decides who serves the client of a whole ClientHello. `rest` holds bytes that
    /// arrived behind it.
    fn settle(&mut self, accepted: Accepted, mut rest: &[u8]) -> Greeted {
        let for_runtime = accepted.client_hello().alpn().is_some_and(|mut offered| {
            offered.any(|protocol| protocol == b"h2" || protocol == auto::ACME_TLS)
        });
        // A name whose certificate must first be obtained waits for it, and only the
        // runtime can wait (SID 0021). A name that has its certificate stays.
        let must_wait = self.on_demand.as_ref().is_some_and(|(certificates, port)| {
            let name = accepted.client_hello().server_name().map(str::to_owned);
            name.is_some_and(|name| certificates.demand(&name, *port).is_some())
        });
        if for_runtime || must_wait {
            return Greeted::Passed(std::mem::take(&mut self.seen));
        }
        let mut conn = match accepted.into_connection(Arc::clone(&self.config)) {
            Ok(conn) => conn,
            Err((_, alert)) => return Greeted::Failed(alert_bytes(alert)),
        };
        conn.set_buffer_limit(Some(HELD));
        while !rest.is_empty() {
            if conn.read_tls(&mut rest).is_err() || conn.process_new_packets().is_err() {
                return Greeted::Failed(Vec::new());
            }
        }
        Greeted::Kept(Box::new(Sealed { conn, full: false }))
    }
}

fn alert_bytes(mut alert: AcceptedAlert) -> Vec<u8> {
    let mut bytes = Vec::new();
    let _ = alert.write_all(&mut bytes);
    bytes
}

/// One TLS session whose socket the caller reads and writes when it is ready.
pub struct Sealed {
    conn: ServerConnection,
    /// The last read filled its buffer, so the session may hold more clear bytes.
    full: bool,
}

impl Sealed {
    /// Moves what the client sent into `plain`, as clear bytes. It reads the socket only
    /// when the session has no clear bytes left, and stops when `plain` is full or the
    /// socket has nothing. A handshake message gives [`Io::Blocked`]: call
    /// [`Sealed::flush`] afterwards, because the session may have an answer to write.
    pub fn read(&mut self, mut socket: &TcpStream, plain: &mut [u8]) -> Io {
        if plain.is_empty() {
            return Io::Blocked;
        }
        let mut total = 0;
        let mut end = Io::Blocked;
        for _ in 0..ROUNDS {
            match self.conn.reader().read(plain.get_mut(total..).unwrap_or_default()) {
                Ok(0) => end = Io::Closed,
                Ok(count) => {
                    total += count;
                    if total < plain.len() {
                        continue;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    match self.receive(&mut socket) {
                        Io::Bytes(_) => continue,
                        other => end = other,
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => end = Io::Closed,
                Err(_) => end = Io::Failed,
            }
            break;
        }
        self.full = total == plain.len();
        if total > 0 { Io::Bytes(total) } else { end }
    }

    /// Reads the socket once into the session.
    fn receive(&mut self, socket: &mut &TcpStream) -> Io {
        loop {
            return match self.conn.read_tls(socket) {
                Ok(0) => Io::Closed,
                Ok(count) => match self.conn.process_new_packets() {
                    Ok(_) => Io::Bytes(count),
                    Err(_) => {
                        // The session has an alert for the client. Send it if we can.
                        let _ = self.conn.write_tls(socket);
                        Io::Failed
                    }
                },
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Io::Blocked,
                Err(_) => Io::Failed,
            };
        }
    }

    /// True when the session may hold clear bytes that no socket event announces: the
    /// last [`Sealed::read`] filled its buffer. The caller reads again when it has room.
    pub fn holds_clear(&self) -> bool {
        self.full
    }

    /// Takes clear bytes for the client and writes what the socket accepts. Reports how
    /// many bytes of `plain` the session took, or [`Io::Blocked`] when it holds as much
    /// as it may. Bytes it took are written by this call or by a later
    /// [`Sealed::flush`].
    pub fn write(&mut self, socket: &TcpStream, plain: &[u8]) -> Io {
        let mut taken = 0;
        for _ in 0..2 {
            match self.conn.writer().write(plain.get(taken..).unwrap_or_default()) {
                Ok(count) => taken += count,
                Err(_) => return Io::Failed,
            }
            if !self.flush(socket) {
                return Io::Failed;
            }
            if taken == plain.len() || self.conn.wants_write() {
                break;
            }
        }
        if taken > 0 { Io::Bytes(taken) } else { Io::Blocked }
    }

    /// Writes encrypted bytes that the session holds, as far as the socket accepts
    /// them. Returns false when the socket failed.
    pub fn flush(&mut self, mut socket: &TcpStream) -> bool {
        while self.conn.wants_write() {
            match self.conn.write_tls(&mut socket) {
                Ok(0) => return false,
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => return false,
            }
        }
        true
    }

    /// True while the session holds encrypted bytes for the socket.
    pub fn wants_write(&self) -> bool {
        self.conn.wants_write()
    }

    /// True until the handshake has ended.
    pub fn is_handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }

    /// What the handshake settled, or `None` while it is not finished.
    pub fn secured(&self) -> Option<Secured> {
        (!self.conn.is_handshaking()).then(|| Secured::of(&self.conn))
    }

    /// Tells the client that no more bytes follow, and writes that if the socket
    /// accepts it. The caller then closes its side of the socket.
    pub fn end(&mut self, socket: &TcpStream) {
        self.conn.send_close_notify();
        let _ = self.flush(socket);
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::time::{Duration, Instant};

    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

    use super::*;

    fn data(name: &str) -> String {
        format!("{}/../tls/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    fn server_config() -> Arc<ServerConfig> {
        let chain = CertificateDer::pem_file_iter(data("localhost.pem")).unwrap();
        let chain = chain.map(Result::unwrap).collect();
        let key = PrivateKeyDer::from_pem_file(data("localhost.key")).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ServerConfig::builder_with_provider(provider);
        let builder = builder.with_safe_default_protocol_versions().unwrap();
        let mut config = builder.with_no_client_auth().with_single_cert(chain, key).unwrap();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Arc::new(config)
    }

    fn client(offers: &[&[u8]]) -> ClientConnection {
        let mut trust = RootCertStore::empty();
        trust.add(CertificateDer::from_pem_file(data("ca.pem")).unwrap()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ClientConfig::builder_with_provider(provider);
        let builder = builder.with_safe_default_protocol_versions().unwrap();
        let mut config = builder.with_root_certificates(trust).with_no_client_auth();
        config.alpn_protocols = offers.iter().map(|offer| offer.to_vec()).collect();
        ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap()
    }

    fn hello(offers: &[&[u8]]) -> Vec<u8> {
        let mut bytes = Vec::new();
        client(offers).write_tls(&mut bytes).unwrap();
        bytes
    }

    /// Feeds `bytes` one at a time and returns the first answer that is not `More`,
    /// with the number of bytes it took.
    fn feed_slowly(bytes: &[u8]) -> (Greeted, usize) {
        let mut greeting = Greeting::new(server_config(), None);
        for (index, byte) in bytes.iter().enumerate() {
            match greeting.feed(std::slice::from_ref(byte)) {
                Greeted::More => {}
                other => return (other, index + 1),
            }
        }
        (Greeted::More, bytes.len())
    }

    #[test]
    fn a_client_without_http2_stays_only_when_its_hello_is_whole() {
        for offers in [&[][..], &[&b"http/1.1"[..]]] {
            let bytes = hello(offers);
            let (greeted, taken) = feed_slowly(&bytes);
            assert!(matches!(greeted, Greeted::Kept(_)));
            assert_eq!(taken, bytes.len(), "no answer before the last byte");
        }
    }

    #[test]
    fn a_client_that_offers_http2_or_a_validation_is_passed_with_every_byte() {
        for offers in [&[&b"h2"[..], b"http/1.1"][..], &[b"http/1.1", b"h2"], &[b"acme-tls/1"]] {
            let bytes = hello(offers);
            let (greeted, _) = feed_slowly(&bytes);
            let Greeted::Passed(seen) = greeted else { panic!("not passed: {offers:?}") };
            assert_eq!(seen, bytes);
        }
    }

    #[test]
    fn bytes_that_are_no_hello_and_a_hello_without_end_fail() {
        let (greeted, _) = feed_slowly(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
        assert!(matches!(greeted, Greeted::Failed(_)));
        // A handshake record that announces more than a greeting may hold.
        let mut greeting = Greeting::new(server_config(), None);
        let piece = [22, 3, 1, 0x40, 0, 1, 0, 0xff, 0xff];
        assert!(matches!(greeting.feed(&piece), Greeted::More));
        let mut answer = Greeted::More;
        for _ in 0..40 {
            if !matches!(answer, Greeted::More) {
                break;
            }
            answer = greeting.feed(&[0; 512]);
        }
        assert!(matches!(answer, Greeted::Failed(_)));
    }

    /// The server side of one connection: a session kept from the hello of `far`.
    fn keep(near: &TcpStream) -> Sealed {
        let mut greeting = Greeting::new(server_config(), None);
        let mut block = [0; 4096];
        loop {
            match sibuna_reactor::read_once(near, &mut block) {
                Io::Bytes(count) => match greeting.feed(&block[..count]) {
                    Greeted::More => {}
                    Greeted::Kept(sealed) => return *sealed,
                    _ => panic!("the hello was not kept"),
                },
                Io::Blocked => std::thread::sleep(Duration::from_millis(1)),
                _ => panic!("the client left"),
            }
        }
    }

    #[test]
    fn a_session_carries_bytes_both_ways_and_tells_when_it_holds_more() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let far = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (near, _) = listener.accept().unwrap();
        near.set_nonblocking(true).unwrap();
        let payload: Vec<u8> = (0..300_000).map(|index| (index % 251) as u8).collect();
        let sent = payload.clone();
        let peer = std::thread::spawn(move || {
            let mut stream = StreamOwned::new(client(&[]), far);
            stream.write_all(&sent).unwrap();
            let mut echoed = vec![0; sent.len()];
            stream.read_exact(&mut echoed).unwrap();
            echoed
        });
        let mut sealed = keep(&near);
        let (mut held, mut written, mut held_more) = (Vec::new(), 0, false);
        let mut small = [0; 1000];
        let deadline = Instant::now() + Duration::from_secs(20);
        while written < payload.len() {
            assert!(Instant::now() < deadline, "{written} of {} bytes echoed", payload.len());
            match sealed.read(&near, &mut small) {
                Io::Bytes(count) => held.extend_from_slice(&small[..count]),
                Io::Blocked => std::thread::sleep(Duration::from_millis(1)),
                other => panic!("the read ended: {other:?}"),
            }
            held_more |= sealed.holds_clear();
            assert!(sealed.flush(&near));
            if let Io::Bytes(count) = sealed.write(&near, &held[written..]) {
                written += count;
            }
        }
        assert!(sealed.secured().is_some_and(|secured| secured.version == "1.3"));
        while sealed.wants_write() {
            assert!(sealed.flush(&near));
        }
        assert!(held_more, "a small buffer leaves clear bytes in the session");
        assert!(peer.join().unwrap() == payload);
    }
}
