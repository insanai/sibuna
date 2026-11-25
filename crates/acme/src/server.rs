//! An ACME server in front of the local authority (RFC 8555, SID 0021), so that other
//! machines of an internal network obtain certificates with a standard ACME client.
//!
//! ```text
//!   request path                    Server                      thread of the caller
//!   ------------                    ------                      --------------------
//!   handle(exchange) ------------>  verify the JWS, take the
//!                                   nonce, change an order
//!   <-- Reply                       queue a Task  ------------> next_task()
//!                                                               perform(task):
//!                                                                 HTTP-01, or sign
//!                                   record the result <---------
//! ```
//!
//! [`Server::handle`] performs no I/O: it reads and changes memory. The work that
//! waits for a network or a file is a [`Task`], which [`Server::perform`] runs on a
//! thread of the caller. Accounts keep no state: the account URL carries the key.
//! Nonces, orders and issued chains live in memory and have bounds.

mod jose;
mod orders;
pub mod validate;

use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use ring::rand::{SecureRandom as _, SystemRandom};

use self::jose::{Refusal, Signed};
use self::orders::{Authorization, Order, State, Status, Step};
use crate::local::LocalAuthority;
use crate::{csr, jws};

/// The longest body of a request.
pub const MAX_BODY: usize = 32 * 1024;
/// The longest path of a request.
pub const MAX_PATH: usize = 2048;
/// The most nonces that wait to be used.
pub const MAX_NONCES: usize = 4096;
/// How long a nonce may wait, in seconds.
pub const NONCE_LIFETIME: u64 = 3600;
/// The most orders at one time.
pub const MAX_ORDERS: usize = 1024;
/// The most orders of one account at one time.
pub const MAX_ACCOUNT_ORDERS: usize = 16;
/// How long an order lives, in seconds, whatever its state.
pub const ORDER_LIFETIME: u64 = 3600;
/// The most names of one order.
pub const MAX_NAMES: usize = 16;
/// The most validations and signings that wait for the thread.
pub const MAX_TASKS: usize = 64;
/// The longest certificate request, in bytes of DER.
pub const MAX_REQUEST: usize = 8 * 1024;

/// What the server is configured with: `global.acme.internal.server`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerOptions {
    /// The base URL of the server, without a final slash.
    pub url: String,
    /// The DNS suffixes that a client may order names under, in lower case.
    pub names: Vec<String>,
    /// The address ranges that a validation may connect into.
    pub ranges: Vec<validate::Range>,
    /// The name constraints of the root, as the configuration lists them: suffixes and
    /// ranges. Empty: the root signs for every name.
    pub constraints: Vec<String>,
    /// The port of the HTTP-01 validation.
    pub http_port: u16,
}

/// One request to the server, as the HTTP frontend read it.
#[derive(Clone, Copy, Debug)]
pub struct Exchange<'a> {
    /// The method, in upper case.
    pub method: &'a str,
    /// The path below the path of the base URL, with its leading slash.
    pub path: &'a str,
    /// The whole body.
    pub body: &'a [u8],
}

/// The answer to one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    /// The status code: 200, 201, 400, 403, 404, 413, 429 or 500.
    pub status: u16,
    /// The media type of the body.
    pub content_type: &'static str,
    /// Header fields beside the type: `Replay-Nonce`, `Location`, `Link`, `Retry-After`.
    pub headers: Vec<(&'static str, String)>,
    /// The body.
    pub body: Vec<u8>,
}

/// Work that waits for a network or a file. See [`Server::perform`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Task {
    /// Validate one name of an order with HTTP-01.
    Validate {
        /// The order.
        order: String,
        /// The index of the authorization in the order.
        index: usize,
        /// The name under validation.
        name: String,
        /// The token of the challenge.
        token: String,
        /// The body that proves the name.
        key_authorization: String,
    },
    /// Sign the certificate of an order.
    Issue {
        /// The order.
        order: String,
        /// The names of the certificate.
        names: Vec<String>,
        /// The public key of the certificate, a DER `SubjectPublicKeyInfo`.
        public_key: Vec<u8>,
    },
}

/// What a performed task did, for the log of the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A name was validated, or not, with the reason.
    Validated {
        /// The name.
        name: String,
        /// Why the validation failed.
        failure: Option<String>,
    },
    /// A certificate was issued for these names.
    Issued {
        /// The names of the certificate.
        names: Vec<String>,
    },
    /// The local authority could not sign.
    NotIssued {
        /// The names of the certificate.
        names: Vec<String>,
        /// The failure of the local authority.
        error: crate::Error,
    },
}

/// Whether `name` is a host name that an order may carry: lower case, labels of
/// letters, digits and hyphens, at most 253 bytes, at least one letter, no wildcard.
fn is_host_name(name: &str) -> bool {
    let label = |label: &str| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    name.len() <= 253 && name.split('.').all(label) && name.parse::<IpAddr>().is_err()
}

/// Whether the DNS suffix `suffix` covers `name`: the name itself, or a name below it.
/// The comparison is by whole labels.
pub fn covers(suffix: &str, name: &str) -> bool {
    name == suffix || name.strip_suffix(suffix).is_some_and(|rest| rest.ends_with('.'))
}

/// A reply with a JSON body.
fn json(status: u16, body: String) -> Reply {
    Reply { status, content_type: "application/json", headers: Vec::new(), body: body.into() }
}

/// A reply with a problem document.
fn refuse(status: u16, kind: &str, detail: &str) -> Reply {
    let body = orders::problem(kind, detail, status).into_bytes();
    Reply { status, content_type: "application/problem+json", headers: Vec::new(), body }
}

impl From<Refusal> for Reply {
    fn from(refusal: Refusal) -> Self {
        let status = match refusal.kind {
            "unauthorized" => 403,
            "rateLimited" => 429,
            _ => 400,
        };
        let mut reply = refuse(status, refusal.kind, &refusal.detail);
        if status == 429 {
            reply.headers.push(("Retry-After", "60".to_owned()));
        }
        reply
    }
}

/// The ACME server of one local authority.
pub struct Server {
    options: ServerOptions,
    state: Mutex<State>,
    /// Signals the thread that a task is queued.
    work: Condvar,
    random: SystemRandom,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server").field("url", &self.options.url).finish_non_exhaustive()
    }
}

impl Server {
    /// A server with no nonce and no order. Fails with a sentence when the base URL
    /// has a byte that cannot stand in a JSON string or in a header.
    pub fn new(options: ServerOptions) -> Result<Self, String> {
        let plain = |byte: u8| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\';
        if options.url.is_empty() || options.url.ends_with('/') || !options.url.bytes().all(plain)
        {
            return Err(format!("`{}` cannot be the base URL of the ACME server.", options.url));
        }
        let (state, work) = (Mutex::default(), Condvar::new());
        Ok(Self { options, state, work, random: SystemRandom::new() })
    }

    /// The options that the server runs with.
    pub fn options(&self) -> &ServerOptions {
        &self.options
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Sixteen random bytes in base64url: a nonce, a token, or the name of an order.
    fn random_word(&self) -> String {
        let mut bytes = [0; 16];
        // The random source of the system does not fail in a running process. If it
        // did, the word would be all zeros, and a second such word is refused as known.
        let _ = self.random.fill(&mut bytes);
        jws::base64url(&bytes)
    }

    /// Sets the revocation list that `GET /crl` answers with, in DER.
    pub fn set_crl(&self, der: Vec<u8>) {
        self.state().crl = der;
    }

    /// Answers one request. Performs no I/O and never waits for the network: it
    /// verifies, reads and changes the state, and queues work for [`Server::perform`].
    /// `now` is in seconds since 1970. Whatever the request holds, the answer is a
    /// reply and never a panic.
    pub fn handle(&self, exchange: &Exchange<'_>, now: u64) -> Reply {
        if exchange.path.len() > MAX_PATH {
            return refuse(404, "malformed", "The path is too long.");
        }
        let mut reply = match (exchange.method, exchange.path) {
            ("GET", "/directory") => self.directory(),
            ("GET" | "HEAD", "/new-nonce") => json(200, String::new()),
            ("GET", "/crl") => self.crl(),
            ("POST", _) if exchange.body.len() > MAX_BODY => {
                refuse(413, "malformed", "The body is longer than 32 KiB.")
            }
            ("POST", path) => self.post(path, exchange.body, now),
            _ => refuse(404, "malformed", "This server has no such resource."),
        };
        let with_nonce = exchange.method != "GET" || exchange.path == "/new-nonce";
        self.finish(&mut reply, with_nonce, now);
        reply
    }

    /// The answer to a request whose body the frontend did not read to its end: too
    /// long, or in a transfer coding that the frontend does not buffer. It carries a
    /// fresh nonce, as every refusal of a POST does.
    pub fn refuse_body(&self, now: u64) -> Reply {
        let mut reply = refuse(413, "malformed", "The body is longer than 32 KiB, or chunked.");
        self.finish(&mut reply, true, now);
        reply
    }

    /// Adds the header fields that every reply carries, and a new nonce when asked.
    fn finish(&self, reply: &mut Reply, with_nonce: bool, now: u64) {
        if with_nonce {
            let nonce = self.random_word();
            self.state().nonces.add(nonce.clone(), now);
            reply.headers.push(("Replay-Nonce", nonce));
        }
        let index = format!("<{}/directory>;rel=\"index\"", self.options.url);
        reply.headers.push(("Link", index));
    }

    fn directory(&self) -> Reply {
        let base = &self.options.url;
        let nonce = format!(r#""newNonce":"{base}/new-nonce""#);
        let account = format!(r#""newAccount":"{base}/new-account""#);
        let order = format!(r#""newOrder":"{base}/new-order""#);
        json(200, format!("{{{nonce},{account},{order}}}"))
    }

    fn crl(&self) -> Reply {
        let body = self.state().crl.clone();
        if body.is_empty() {
            return refuse(404, "malformed", "The revocation list is not written yet.");
        }
        Reply { status: 200, content_type: "application/pkix-crl", headers: Vec::new(), body }
    }

    /// Answers a POST: verifies the signature, takes the nonce, and routes.
    fn post(&self, path: &str, body: &[u8], now: u64) -> Reply {
        let url = format!("{}{path}", self.options.url);
        let accounts = format!("{}/account/", self.options.url);
        let signed = match jose::verify(body, &url, &accounts) {
            Ok(signed) => signed,
            Err(refusal) => return refusal.into(),
        };
        let mut state = self.state();
        if !state.nonces.take(&signed.nonce, now) {
            return refuse(400, "badNonce", "The nonce is unknown or was used. Take the new one.");
        }
        state.expire(now);
        let (resource, id) = match path.get(1..).and_then(|rest| rest.split_once('/')) {
            Some((resource, id)) => (resource, id),
            None => (path.get(1..).unwrap_or_default(), ""),
        };
        let answer = match (resource, signed.by_kid) {
            ("new-account", false) => Ok(self.account(&signed, true)),
            ("new-account", true) => {
                Err(Refusal::new("malformed", "A registration carries its key as `jwk`."))
            }
            (_, false) => {
                Err(Refusal::new("malformed", "This request names its account by `kid`."))
            }
            ("account", true) if id == signed.key.account_id() => self.account_update(&signed),
            ("new-order", true) => self.new_order(&mut state, &signed, now),
            ("order" | "authz" | "chall" | "finalize" | "cert", true) => {
                self.order_resource(&mut state, resource, id, &signed)
            }
            _ => Err(Refusal::new("malformed", "This server has no such resource.")),
        };
        drop(state);
        self.work.notify_all();
        answer.unwrap_or_else(Reply::from)
    }

    /// The account object of the key of the request, with its URL.
    fn account(&self, signed: &Signed, registration: bool) -> Reply {
        let existing = jose::parse(&signed.payload)
            .and_then(|payload| payload.as_object()?.get("onlyReturnExisting")?.as_bool())
            .unwrap_or(false);
        let created = registration && !existing;
        let mut reply = json(if created { 201 } else { 200 }, r#"{"status":"valid"}"#.to_owned());
        let url = format!("{}/account/{}", self.options.url, signed.key.account_id());
        reply.headers.push(("Location", url));
        reply
    }

    /// A POST to the account URL: the account object. An account keeps no state, so
    /// it cannot be deactivated.
    fn account_update(&self, signed: &Signed) -> Result<Reply, Refusal> {
        let payload = jose::parse(&signed.payload);
        let status = payload.as_ref().and_then(|payload| payload.as_object()?.get("status"));
        if status.is_some() {
            let detail = "An account of this server cannot be deactivated.";
            return Err(Refusal::new("unauthorized", detail));
        }
        Ok(self.account(signed, false))
    }

    /// Whether a client may order `name`: a host name that a suffix of `allow` covers
    /// and that the constraints of the root permit.
    fn permits(&self, name: &str) -> Result<(), Refusal> {
        let refuse = |detail: String| Err(Refusal::new("rejectedIdentifier", detail));
        if name.starts_with("*.") {
            return refuse(format!("`{name}` is a wildcard, which HTTP-01 cannot prove."));
        }
        if !is_host_name(name) {
            return refuse(format!("`{name}` is no host name in lower case."));
        }
        if !self.options.names.iter().any(|suffix| covers(suffix, name)) {
            return refuse(format!("`{name}` is under no name that this server issues for."));
        }
        let constraints = &self.options.constraints;
        let is_suffix = |entry: &&String| !entry.contains('/') && entry.parse::<IpAddr>().is_err();
        let permitted = constraints.iter().filter(is_suffix).any(|suffix| covers(suffix, name));
        if !constraints.is_empty() && !permitted {
            return refuse(format!("`{name}` is outside the name constraints of the root."));
        }
        Ok(())
    }

    /// `newOrder`: a new order with one authorization for each name.
    fn new_order(&self, state: &mut State, signed: &Signed, now: u64) -> Result<Reply, Refusal> {
        let payload = jose::parse(&signed.payload);
        let identifiers = payload
            .as_ref()
            .and_then(|payload| payload.as_object()?.get("identifiers")?.as_array())
            .ok_or_else(|| Refusal::new("malformed", "The order has no identifiers."))?;
        if !(1..=MAX_NAMES).contains(&identifiers.len()) {
            return Err(Refusal::new("malformed", "An order has 1 to 16 identifiers."));
        }
        let mut names = Vec::with_capacity(identifiers.len());
        for identifier in identifiers {
            let member = |name: &str| identifier.as_object()?.get(name)?.as_str();
            let (Some(kind), Some(value)) = (member("type"), member("value")) else {
                return Err(Refusal::new("malformed", "An identifier has a type and a value."));
            };
            if kind != "dns" {
                let detail = format!("This server issues for DNS names, not for `{kind}`.");
                return Err(Refusal::new("unsupportedIdentifier", detail));
            }
            let name = value.to_ascii_lowercase();
            self.permits(&name)?;
            if !names.contains(&name) {
                names.push(name);
            }
        }
        let owner = signed.key.thumbprint();
        if !state.has_room(&owner) {
            return Err(Refusal::new("rateLimited", "This server holds too many orders now."));
        }
        let authorizations = names
            .into_iter()
            .map(|name| Authorization {
                name,
                token: self.random_word(),
                step: Step::Pending,
                error: None,
            })
            .collect();
        let order = Order {
            owner,
            created: now,
            authorizations,
            status: Status::Pending,
            certificate: None,
            error: None,
        };
        let id = self.random_word();
        let base = &self.options.url;
        let mut reply = json(201, orders::order_json(base, &id, &order));
        reply.headers.push(("Location", format!("{base}/order/{id}")));
        state.orders.insert(id, order);
        Ok(reply)
    }

    /// A request for an order or for a part of it. `id` is `ORDER` or `ORDER.INDEX`.
    fn order_resource(
        &self,
        state: &mut State,
        resource: &str,
        id: &str,
        signed: &Signed,
    ) -> Result<Reply, Refusal> {
        let (id, index) = match id.split_once('.') {
            Some((id, index)) => (id, index.parse::<usize>().ok()),
            None => (id, None),
        };
        let owner = signed.key.thumbprint();
        let base = &self.options.url;
        let gone =
            || Refusal::new("malformed", "This server has no such order. It may have expired.");
        let order = state.orders.get(id).filter(|order| order.owner == owner).ok_or_else(gone)?;
        let part = index.filter(|index| *index < order.authorizations.len());
        match (resource, part) {
            ("order", None) => Ok(json(200, orders::order_json(base, id, order))),
            ("authz", Some(index)) => {
                Ok(json(200, orders::authorization_json(base, id, index, order)))
            }
            ("cert", None) => match &order.certificate {
                Some(chain) => Ok(Reply {
                    status: 200,
                    content_type: "application/pem-certificate-chain",
                    headers: Vec::new(),
                    body: chain.clone().into_bytes(),
                }),
                None => Err(Refusal::new("malformed", "The order has no certificate yet.")),
            },
            ("chall", Some(index)) => self.respond(state, id, index, &signed.key.thumbprint()),
            ("finalize", None) => self.finalize(state, id, &signed.payload),
            _ => Err(gone()),
        }
    }

    /// The client says that the challenge is answered: the validation is queued.
    fn respond(
        &self,
        state: &mut State,
        id: &str,
        index: usize,
        thumbprint: &str,
    ) -> Result<Reply, Refusal> {
        let base = &self.options.url;
        let gone = || Refusal::new("malformed", "This server has no such challenge.");
        let authz = state.orders.get(id).and_then(|order| order.authorizations.get(index));
        let authz = authz.ok_or_else(gone)?;
        if authz.step == Step::Pending {
            let task = Task::Validate {
                order: id.to_owned(),
                index,
                name: authz.name.clone(),
                token: authz.token.clone(),
                key_authorization: format!("{}.{thumbprint}", authz.token),
            };
            if !state.queue(task) {
                return Err(Refusal::new("rateLimited", "Too many validations wait. Try again."));
            }
            let authz = state.orders.get_mut(id).and_then(|o| o.authorizations.get_mut(index));
            authz.ok_or_else(gone)?.step = Step::Processing;
        }
        let authz = state.orders.get(id).and_then(|order| order.authorizations.get(index));
        Ok(json(200, orders::challenge_json(base, id, index, authz.ok_or_else(gone)?)))
    }

    /// `finalize`: takes the certificate request of a ready order and queues the signing.
    fn finalize(&self, state: &mut State, id: &str, payload: &[u8]) -> Result<Reply, Refusal> {
        let base = &self.options.url;
        let gone = || Refusal::new("malformed", "This server has no such order.");
        let order = state.orders.get(id).ok_or_else(gone)?;
        if order.status != Status::Ready {
            let detail = "The order is not ready: prove every name first, and finalize once.";
            return Err(Refusal::new("orderNotReady", detail));
        }
        let bad = |detail: &str| Refusal::new("badCSR", detail);
        let request = jose::parse(payload)
            .and_then(|payload| jose::decode(payload.as_object()?.get("csr")?.as_str()?))
            .ok_or_else(|| bad("The payload has no certificate request."))?;
        if request.len() > MAX_REQUEST {
            return Err(bad("The certificate request is longer than 8 KiB."));
        }
        let parsed = csr::read(&request).ok_or_else(|| {
            bad("The certificate request is unreadable, or its signature fails.")
        })?;
        let mut asked: Vec<String> = parsed.names.iter().map(|n| n.to_ascii_lowercase()).collect();
        let mut ordered: Vec<String> =
            order.authorizations.iter().map(|a| a.name.clone()).collect();
        asked.sort_unstable();
        asked.dedup();
        ordered.sort_unstable();
        if asked != ordered {
            return Err(bad("The names of the certificate request are not those of the order."));
        }
        let task =
            Task::Issue { order: id.to_owned(), names: ordered, public_key: parsed.public_key };
        if !state.queue(task) {
            return Err(Refusal::new("rateLimited", "Too many requests wait. Try again."));
        }
        let order = state.orders.get_mut(id).ok_or_else(gone)?;
        order.status = Status::Processing;
        let mut reply = json(200, orders::order_json(base, id, order));
        reply.headers.push(("Location", format!("{base}/order/{id}")));
        Ok(reply)
    }

    /// Takes the next task, and waits for one at most `timeout`.
    pub fn next_task(&self, timeout: Duration) -> Option<Task> {
        let state = self.state();
        let (mut state, _) = self
            .work
            .wait_timeout_while(state, timeout, |state| state.tasks.is_empty())
            .unwrap_or_else(PoisonError::into_inner);
        state.tasks.pop_front()
    }

    /// Runs one task and records its result. A validation connects out, as
    /// [`validate::http01`] describes, and blocks for seconds. A signing asks
    /// `authority` for a leaf of `lifetime` seconds from `now`, which reads and writes
    /// files. Neither holds the lock of the state while it works.
    pub fn perform(
        &self,
        task: Task,
        authority: &LocalAuthority,
        lifetime: u64,
        now: u64,
    ) -> Outcome {
        match task {
            Task::Validate { order, index, name, token, key_authorization } => {
                let target = validate::Target {
                    name: &name,
                    token: &token,
                    expected: &key_authorization,
                    port: self.options.http_port,
                    ranges: &self.options.ranges,
                };
                let result = validate::http01(&target);
                let failure = result.clone().err();
                self.state().validated(&order, index, result);
                Outcome::Validated { name, failure }
            }
            Task::Issue { order, names, public_key } => {
                let listed: Vec<&str> = names.iter().map(String::as_str).collect();
                let result = authority.issue_for(&public_key, &listed, lifetime, now);
                let mut state = self.state();
                match result {
                    Ok(chain) => {
                        state.issued(&order, Ok(chain));
                        Outcome::Issued { names }
                    }
                    Err(error) => {
                        let reason =
                            "The local authority could not sign. Its operator has the reason.";
                        state.issued(&order, Err(reason.to_owned()));
                        Outcome::NotIssued { names, error }
                    }
                }
            }
        }
    }
}

/// Writes the header fields of a reply as lines, each ended by CRLF, for a writer that
/// takes them preformatted.
pub fn header_lines(reply: &Reply) -> String {
    let mut lines = String::new();
    for (name, value) in &reply.headers {
        let _ = write!(lines, "{name}: {value}\r\n");
    }
    lines
}

#[cfg(test)]
mod tests;
