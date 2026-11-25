//! A certificate authority for tests: the ACME endpoints of RFC 8555 over plain HTTP on
//! the loopback address. It validates a name by connecting back to the daemon, with
//! HTTP-01 or with TLS-ALPN-01 (RFC 8737), or by asking a DNS server of the test for the
//! TXT record of DNS-01, and signs with a key of its own.
//!
//! It does not verify the signature of a request. The client's requests are checked by
//! the unit tests of `sibuna-acme` and by the run against Pebble (SID 0021). It does
//! verify the MAC of an external account binding when the test sets one, and it answers
//! the renewal information of RFC 9773 with the windows that the test queues.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sibuna_acme::dns::{transport, wire};
use sibuna_acme::{KeyPair, csr, jws, pem, x509};
use sibuna_crypto::sha256::Sha256;
use sibuna_encoding::base64;

/// The issuer name in every certificate of the authority.
pub const ISSUER: &str = "Sibuna Test Authority";

/// One order: its name, its token, and what became of it.
struct Order {
    name: String,
    token: String,
    valid: Option<bool>,
    certificate: Option<String>,
}

/// What the test sets and reads.
pub struct Authority {
    /// The URL of the directory.
    pub directory: String,
    base: String,
    key: KeyPair,
    root_pem: String,
    /// The daemon's plain HTTP port, where HTTP-01 is validated.
    pub http_port: AtomicU16,
    /// The daemon's TLS port, where TLS-ALPN-01 is validated.
    pub tls_port: AtomicU16,
    /// The DNS server that DNS-01 is validated at. Without one DNS-01 fails.
    pub dns_server: Mutex<Option<SocketAddr>>,
    /// The lifetime of the next certificate, in seconds.
    pub lifetime: AtomicU64,
    /// Refuse the next orders with `rejectedIdentifier`.
    pub refuse: AtomicBool,
    /// The orders accepted so far.
    pub order_count: AtomicUsize,
    /// The challenge type of every validation that succeeded.
    pub validated: Mutex<Vec<String>>,
    /// The key identifier and the MAC key of the binding that a new account must carry.
    pub binding: Mutex<Option<(String, Vec<u8>)>>,
    /// The signed requests received so far.
    pub signed_count: AtomicUsize,
    /// Offer renewal information in the directory.
    pub renewal_info: AtomicBool,
    /// The windows of the next answers about a renewal: start and end in seconds from
    /// now. The last one stays for every later answer. Without one: a day from now.
    pub windows: Mutex<VecDeque<(i64, i64)>>,
    /// The certificate identifier of every question about a renewal.
    pub asked_renewal: Mutex<Vec<String>>,
    /// The `replaces` member of every order placed, empty without one.
    pub replaces: Mutex<Vec<String>>,
    /// The first signed request is answered with `badNonce`, once.
    bad_nonce_pending: AtomicBool,
    nonce: AtomicU64,
    thumbprint: Mutex<String>,
    orders: Mutex<Vec<Order>>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// The string value of `key` in a JSON text. Enough for the documents of the client.
fn member(json: &str, key: &str) -> Option<String> {
    let start = json.find(&format!("\"{key}\""))? + key.len() + 2;
    let rest = json[start..].trim_start().strip_prefix(':')?.trim_start().strip_prefix('"')?;
    Some(rest[..rest.find('"')?].to_owned())
}

/// A base64url member of a JSON text, decoded.
fn decoded(json: &str, key: &str) -> Vec<u8> {
    let text = member(json, key).unwrap_or_default();
    base64::decode(base64::URL_SAFE_NO_PAD, text.as_bytes()).unwrap_or_default()
}

/// One answer of the authority.
struct Answer {
    status: u16,
    content_type: &'static str,
    location: Option<String>,
    body: String,
}

impl Answer {
    fn json(status: u16, body: String) -> Self {
        Self { status, content_type: "application/json", location: None, body }
    }

    fn problem(status: u16, kind: &str, detail: &str) -> Self {
        let body =
            format!(r#"{{"type":"urn:ietf:params:acme:error:{kind}","detail":"{detail}"}}"#);
        Self { status, content_type: "application/problem+json", location: None, body }
    }
}

impl Authority {
    /// Starts the authority on a free loopback port.
    pub fn start() -> Arc<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let key = KeyPair::generate().unwrap();
        let template = x509::Template {
            issuer: ISSUER,
            subject: ISSUER,
            not_before: now() - 60,
            not_after: now() + 86400,
            serial: 1,
            authority: true,
            ..x509::Template::default()
        };
        let root = x509::write(&template, &key.subject_public_key_info(), &key).unwrap();
        let authority = Arc::new(Self {
            directory: format!("{base}/dir"),
            base,
            key,
            root_pem: pem::encode("CERTIFICATE", &root),
            http_port: AtomicU16::new(0),
            tls_port: AtomicU16::new(0),
            dns_server: Mutex::default(),
            lifetime: AtomicU64::new(3600),
            refuse: AtomicBool::new(false),
            order_count: AtomicUsize::new(0),
            validated: Mutex::default(),
            binding: Mutex::default(),
            signed_count: AtomicUsize::new(0),
            renewal_info: AtomicBool::new(false),
            windows: Mutex::default(),
            asked_renewal: Mutex::default(),
            replaces: Mutex::default(),
            bad_nonce_pending: AtomicBool::new(true),
            nonce: AtomicU64::new(1),
            thumbprint: Mutex::default(),
            orders: Mutex::default(),
        });
        let serving = Arc::clone(&authority);
        std::thread::spawn(move || {
            for socket in listener.incoming().flatten() {
                let authority = Arc::clone(&serving);
                std::thread::spawn(move || authority.serve(socket));
            }
        });
        authority
    }

    /// Reads one request and answers it. Every answer carries a fresh nonce.
    fn serve(&self, mut socket: TcpStream) {
        let _ = socket.set_read_timeout(Some(Duration::from_secs(10)));
        let mut reader = BufReader::new(socket.try_clone().unwrap());
        let mut start = String::new();
        if reader.read_line(&mut start).unwrap_or(0) == 0 {
            return;
        }
        let mut length = 0;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) <= 2 {
                break;
            }
            if let Some((name, value)) = line.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                length = value.trim().parse().unwrap_or(0);
            }
        }
        let mut body = vec![0; length];
        if reader.read_exact(&mut body).is_err() {
            return;
        }
        let mut words = start.split(' ');
        let (method, path) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
        let answer = self.answer(method, path, &String::from_utf8_lossy(&body));
        let nonce = self.nonce.fetch_add(1, Ordering::Relaxed);
        let location = answer.location.map_or(String::new(), |url| format!("Location: {url}\r\n"));
        let head = format!(
            "HTTP/1.1 {} X\r\nContent-Type: {}\r\nContent-Length: {}\r\nReplay-Nonce: n{nonce}\r\n\
             {location}Connection: close\r\n\r\n",
            answer.status,
            answer.content_type,
            answer.body.len()
        );
        let _ = socket.write_all(head.as_bytes());
        if method != "HEAD" {
            let _ = socket.write_all(answer.body.as_bytes());
        }
    }

    fn answer(&self, method: &str, path: &str, body: &str) -> Answer {
        let base = &self.base;
        if method != "POST" {
            return match path {
                "/dir" => {
                    let url = |name: &str, path: &str| format!(r#""{name}":"{base}/{path}""#);
                    let nonce = url("newNonce", "nonce");
                    let account = url("newAccount", "account");
                    let order = url("newOrder", "order");
                    let required = self.binding.lock().unwrap().is_some();
                    let meta = format!(r#""meta":{{"externalAccountRequired":{required}}}"#);
                    let renewal = match self.renewal_info.load(Ordering::Relaxed) {
                        true => format!(",{}", url("renewalInfo", "ari")),
                        false => String::new(),
                    };
                    Answer::json(200, format!("{{{nonce},{account},{order},{meta}{renewal}}}"))
                }
                _ => match path.strip_prefix("/ari/") {
                    Some(id) => self.renewal(id),
                    None => Answer::json(200, String::new()),
                },
            };
        }
        self.signed_count.fetch_add(1, Ordering::Relaxed);
        if self.bad_nonce_pending.swap(false, Ordering::Relaxed) {
            return Answer::problem(400, "badNonce", "the test rejects the first nonce");
        }
        let payload = String::from_utf8(decoded(body, "payload")).unwrap_or_default();
        let mut parts = path.trim_start_matches('/').split('/');
        let (first, id, kind) = (parts.next(), parts.next(), parts.next());
        let id = id.and_then(|id| id.parse::<usize>().ok());
        match (first, id) {
            (Some("account"), None) => self.account(body),
            (Some("order"), None) => self.new_order(&payload),
            (Some("order"), Some(id)) => self.order(id),
            (Some("authz"), Some(id)) => self.authorization(id),
            (Some("chall"), Some(id)) => self.challenge(id, kind.unwrap_or("")),
            (Some("finalize"), Some(id)) => self.finalize(id, &payload),
            (Some("cert"), Some(id)) => self.certificate(id),
            _ => Answer::problem(404, "malformed", "no such resource"),
        }
    }

    /// Answers a question about the renewal of the certificate `id` with the next
    /// window of the test.
    fn renewal(&self, id: &str) -> Answer {
        self.asked_renewal.lock().unwrap().push(id.to_owned());
        let mut windows = self.windows.lock().unwrap();
        let (start, end) = match windows.len() {
            0 => (86_400, 90_000),
            1 => windows[0],
            _ => windows.pop_front().unwrap(),
        };
        let at = |offset: i64| sibuna_acme::format_rfc3339(now().saturating_add_signed(offset));
        let window = format!(r#"{{"start":"{}","end":"{}"}}"#, at(start), at(end));
        Answer::json(200, format!(r#"{{"suggestedWindow":{window}}}"#))
    }

    /// Whether a registration carries the binding that the test wants: the header names
    /// the algorithm, the key identifier and this URL, and the MAC verifies. The unit
    /// tests of `sibuna-acme` verify the same MAC with another library.
    fn is_bound(&self, body: &str) -> bool {
        let Some((kid, key)) = self.binding.lock().unwrap().clone() else { return true };
        let payload = String::from_utf8(decoded(body, "payload")).unwrap_or_default();
        let Some(at) = payload.find("\"externalAccountBinding\"") else { return false };
        let binding = &payload[at..];
        let (protected, bound) = (member(binding, "protected"), member(binding, "payload"));
        let (Some(protected), Some(bound)) = (protected, bound) else { return false };
        let header = String::from_utf8(decoded(binding, "protected")).unwrap_or_default();
        let url = format!("{}/account", self.base);
        let header_ok = member(&header, "alg").as_deref() == Some("HS256")
            && member(&header, "kid") == Some(kid)
            && member(&header, "url") == Some(url);
        let signed = format!("{protected}.{bound}");
        let mac = sibuna_crypto::hmac::hmac_sha256(&key, signed.as_bytes());
        header_ok && decoded(binding, "signature") == mac
    }

    /// Registers the account and remembers the thumbprint of its key.
    fn account(&self, body: &str) -> Answer {
        if !self.is_bound(body) {
            return Answer::problem(401, "unauthorized", "the binding does not verify");
        }
        let protected = String::from_utf8(decoded(body, "protected")).unwrap_or_default();
        let (x, y) = (member(&protected, "x"), member(&protected, "y"));
        let (Some(x), Some(y)) = (x, y) else {
            return Answer::problem(400, "malformed", "the account request has no key");
        };
        let jwk = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
        *self.thumbprint.lock().unwrap() = jws::thumbprint_of(&jwk);
        let mut answer = Answer::json(201, r#"{"status":"valid"}"#.to_owned());
        answer.location = Some(format!("{}/acct/1", self.base));
        answer
    }

    fn new_order(&self, payload: &str) -> Answer {
        if self.refuse.load(Ordering::Relaxed) {
            return Answer::problem(403, "rejectedIdentifier", "the test refuses this name");
        }
        let Some(name) = member(payload, "value") else {
            return Answer::problem(400, "malformed", "the order names no host");
        };
        self.replaces.lock().unwrap().push(member(payload, "replaces").unwrap_or_default());
        let mut orders = self.orders.lock().unwrap();
        let id = orders.len();
        let token = format!("token_{id}-{}", self.nonce.load(Ordering::Relaxed));
        orders.push(Order { name, token, valid: None, certificate: None });
        self.order_count.fetch_add(1, Ordering::Relaxed);
        drop(orders);
        let mut answer = self.order(id);
        answer.status = 201;
        answer
    }

    fn order(&self, id: usize) -> Answer {
        let base = &self.base;
        let orders = self.orders.lock().unwrap();
        let Some(order) = orders.get(id) else {
            return Answer::problem(404, "malformed", "no such order");
        };
        let (status, certificate) = match (&order.certificate, order.valid) {
            (Some(_), _) => ("valid", format!(r#","certificate":"{base}/cert/{id}""#)),
            (None, Some(true)) => ("ready", String::new()),
            (None, Some(false)) => ("invalid", String::new()),
            (None, None) => ("pending", String::new()),
        };
        let authorizations = format!(r#""authorizations":["{base}/authz/{id}"]"#);
        let finalize = format!(r#""finalize":"{base}/finalize/{id}""#);
        let body = format!(r#"{{"status":"{status}",{authorizations},{finalize}{certificate}}}"#);
        let mut answer = Answer::json(200, body);
        answer.location = Some(format!("{base}/order/{id}"));
        answer
    }

    fn authorization(&self, id: usize) -> Answer {
        let base = &self.base;
        let orders = self.orders.lock().unwrap();
        let Some(order) = orders.get(id) else {
            return Answer::problem(404, "malformed", "no such authorization");
        };
        let status = match order.valid {
            Some(true) => "valid",
            Some(false) => "invalid",
            None => "pending",
        };
        let (name, token) = (&order.name, &order.token);
        let challenge = |kind: &str| {
            let url = format!("{base}/chall/{id}/{kind}");
            format!(r#"{{"type":"{kind}","url":"{url}","token":"{token}","status":"{status}"}}"#)
        };
        // A wildcard is proved with DNS-01 only, at the name without `*.` (RFC 8555).
        let (challenges, wildcard) = match name.strip_prefix("*.") {
            Some(_) => (format!("[{}]", challenge("dns-01")), r#""wildcard":true,"#),
            None => {
                let all = ["http-01", "tls-alpn-01", "dns-01"].map(challenge);
                (format!("[{}]", all.join(",")), "")
            }
        };
        let base = name.strip_prefix("*.").unwrap_or(name);
        let identifier = format!(r#"{{"type":"dns","value":"{base}"}}"#);
        let members = format!(r#"{wildcard}"identifier":{identifier},"challenges":{challenges}"#);
        Answer::json(200, format!(r#"{{"status":"{status}",{members}}}"#))
    }

    /// Validates the name of an order by connecting back to the daemon.
    fn challenge(&self, id: usize, kind: &str) -> Answer {
        let found = {
            let orders = self.orders.lock().unwrap();
            orders.get(id).map(|order| (order.name.clone(), order.token.clone()))
        };
        let Some((name, token)) = found else {
            return Answer::problem(404, "malformed", "no such challenge");
        };
        let expected = format!("{token}.{}", self.thumbprint.lock().unwrap());
        let valid = match kind {
            "http-01" => self.validate_http(&name, &token, &expected),
            "tls-alpn-01" => self.validate_alpn(&name, &expected),
            "dns-01" => self.validate_dns(&name, &expected),
            _ => false,
        };
        if valid {
            self.validated.lock().unwrap().push(kind.to_owned());
        }
        self.orders.lock().unwrap()[id].valid = Some(valid);
        let status = if valid { "valid" } else { "invalid" };
        let url = format!("{}/chall/{id}/{kind}", self.base);
        Answer::json(
            200,
            format!(r#"{{"type":"{kind}","url":"{url}","token":"{token}","status":"{status}"}}"#),
        )
    }

    fn validate_http(&self, name: &str, token: &str, expected: &str) -> bool {
        let port = self.http_port.load(Ordering::Relaxed);
        let Ok(mut socket) = TcpStream::connect(("127.0.0.1", port)) else { return false };
        let _ = socket.set_read_timeout(Some(Duration::from_secs(5)));
        let request = format!(
            "GET /.well-known/acme-challenge/{token} HTTP/1.1\r\nHost: {name}\r\n\
             Connection: close\r\n\r\n"
        );
        let mut answer = String::new();
        let _ = socket.write_all(request.as_bytes());
        let _ = socket.read_to_string(&mut answer);
        answer.starts_with("HTTP/1.1 200")
            && answer.split_once("\r\n\r\n").is_some_and(|(_, body)| body == expected)
    }

    /// Asks the DNS server of the test for the TXT record `_acme-challenge.NAME` and
    /// compares it with the digest of the key authorization.
    fn validate_dns(&self, name: &str, expected: &str) -> bool {
        let Some(server) = *self.dns_server.lock().unwrap() else { return false };
        let owner = format!("_acme-challenge.{}", name.strip_prefix("*.").unwrap_or(name));
        let value = jws::base64url(&Sha256::digest(expected.as_bytes()));
        let request = wire::query(7, &owner, wire::TYPE_TXT, false).unwrap();
        let Ok(answer) = transport::exchange(server, &request, Duration::from_secs(3)) else {
            return false;
        };
        wire::parse(&answer).is_some_and(|message| {
            message.answers().iter().any(
                |record| matches!(&record.data, wire::Data::Txt(text) if text == value.as_bytes()),
            )
        })
    }

    /// Opens a TLS session with the protocol `acme-tls/1` and reads the certificate.
    fn validate_alpn(&self, name: &str, expected: &str) -> bool {
        let address = SocketAddr::from(([127, 0, 0, 1], self.tls_port.load(Ordering::Relaxed)));
        let Some(leaf) = peer_certificate(address, name, Some(b"acme-tls/1")) else {
            return false;
        };
        // id-pe-acmeIdentifier, critical, with the digest of the key authorization.
        let mut extension = vec![0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1f];
        extension.extend_from_slice(&[0x01, 0x01, 0xff, 0x04, 0x22, 0x04, 0x20]);
        extension.extend_from_slice(&Sha256::digest(expected.as_bytes()));
        let names = x509::read(&leaf).is_some_and(|fields| fields.names_host(name));
        names && leaf.windows(extension.len()).any(|window| window == extension)
    }

    /// Signs the certificate that the request of the order asks for.
    fn finalize(&self, id: usize, payload: &str) -> Answer {
        let request = csr::read(&decoded(payload, "csr"));
        let mut orders = self.orders.lock().unwrap();
        let Some(order) = orders.get_mut(id) else {
            return Answer::problem(404, "malformed", "no such order");
        };
        let Some(request) = request.filter(|request| request.names == [order.name.clone()]) else {
            return Answer::problem(400, "badCSR", "the request does not fit the order");
        };
        if order.valid != Some(true) {
            return Answer::problem(403, "orderNotReady", "the name is not validated");
        }
        let template = x509::Template {
            issuer: ISSUER,
            subject: &order.name,
            names: &[&order.name],
            not_before: now(),
            not_after: now() + self.lifetime.load(Ordering::Relaxed),
            serial: 100 + id as u64,
            authority_key_id: Some(x509::key_id(&self.key.subject_public_key_info())),
            ..x509::Template::default()
        };
        let leaf = x509::write(&template, &request.public_key, &self.key).unwrap();
        order.certificate = Some(pem::encode("CERTIFICATE", &leaf) + &self.root_pem);
        drop(orders);
        self.order(id)
    }

    fn certificate(&self, id: usize) -> Answer {
        let orders = self.orders.lock().unwrap();
        match orders.get(id).and_then(|order| order.certificate.clone()) {
            Some(body) => Answer {
                status: 200,
                content_type: "application/pem-certificate-chain",
                location: None,
                body,
            },
            None => Answer::problem(404, "malformed", "no certificate yet"),
        }
    }
}

/// Accepts every certificate: the tests compare what is served, they do not trust it.
#[derive(Debug)]
struct AcceptAny(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _certificate: &CertificateDer<'_>,
        _signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _certificate: &CertificateDer<'_>,
        _signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A TLS session with `address` for the host `name`, offering `protocol` when given.
pub fn connect(
    address: SocketAddr,
    name: &str,
    protocol: Option<&[u8]>,
) -> Option<(rustls::ClientConnection, TcpStream)> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .ok()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
        .with_no_client_auth();
    config.alpn_protocols = protocol.map(<[u8]>::to_vec).into_iter().collect();
    let server = ServerName::try_from(name.to_owned()).ok()?;
    let mut session = rustls::ClientConnection::new(Arc::new(config), server).ok()?;
    let mut socket = TcpStream::connect(address).ok()?;
    socket.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    while session.is_handshaking() {
        session.complete_io(&mut socket).ok()?;
    }
    Some((session, socket))
}

/// A TLS session with `address` that trusts the PEM root `root_pem` and nothing else.
/// `name` is a host name or an IP address. For an address the client sends no server
/// name, as every TLS client does. Fails with the reason of the TLS library when the
/// chain does not lead to the root or does not name `name`.
pub fn connect_trusting(
    address: SocketAddr,
    name: &str,
    root_pem: &str,
) -> Result<(rustls::ClientConnection, TcpStream), String> {
    let mut roots = rustls::RootCertStore::empty();
    for root in pem::decode("CERTIFICATE", root_pem).unwrap_or_default() {
        roots.add(CertificateDer::from(root)).map_err(|error| error.to_string())?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = ServerName::try_from(name.to_owned()).map_err(|error| error.to_string())?;
    let mut session = rustls::ClientConnection::new(Arc::new(config), server)
        .map_err(|error| error.to_string())?;
    let mut socket = TcpStream::connect(address).map_err(|error| error.to_string())?;
    socket.set_read_timeout(Some(Duration::from_secs(5))).map_err(|error| error.to_string())?;
    while session.is_handshaking() {
        session.complete_io(&mut socket).map_err(|error| error.to_string())?;
    }
    Ok((session, socket))
}

/// The leaf certificate that `address` serves for the host `name`, in DER.
pub fn peer_certificate(
    address: SocketAddr,
    name: &str,
    protocol: Option<&[u8]>,
) -> Option<Vec<u8>> {
    let (session, _socket) = connect(address, name, protocol)?;
    Some(session.peer_certificates()?.first()?.to_vec())
}
