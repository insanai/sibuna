//! Automatic HTTPS (SID 0021): the tables that handshakes and requests read, and the
//! handle of the thread that fills them.
//!
//! ```text
//!   edge-acme thread                 shared tables               readers
//!   ----------------                 -------------               -------
//!   order, renew, retry  --write-->  certificates by name  <--  TLS handshake (resolver)
//!                        --write-->  TLS-ALPN-01 answers   <--  TLS handshake (acme-tls/1)
//!                        --write-->  HTTP-01 answers       <--  request dispatch
//!                        --write-->  status by name        <--  `show certs`
//!   decide, hold, deny   <--read---  names on demand       <--  TLS handshake (queue)
//! ```
//!
//! A reader takes a read lock on a small map and nothing else. Only the thread talks to
//! the certificate authority.

mod client;
pub(crate) mod demand;
mod dns;
mod driver;
mod revoke;
mod server;
mod supervise;

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError, RwLock};
use std::time::Duration;

use rustls::sign::CertifiedKey;
use sibuna_acme::{Challenge, ChallengeKind, Error as AcmeError, KeyPair, x509};
use sibuna_lb::{AcmeOptions, AutoName, AutomaticHttps};

pub use revoke::RevokeError;

/// The ALPN protocol of the TLS-ALPN-01 challenge (RFC 8737).
pub(crate) const ACME_TLS: &[u8] = b"acme-tls/1";
/// The longest token we answer.
const MAX_TOKEN: usize = 128;
/// The origin of a name under `auto`.
const LISTED: &str = "listed";
/// The origin of a name that a handshake asked for.
const ON_DEMAND: &str = "on-demand";

/// Milliseconds since 1970.
pub(crate) fn now_ms() -> u64 {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    since.map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
}

/// What the thread tells the daemon, for its log.
#[derive(Clone, Debug)]
pub enum Event {
    /// A certificate was issued and is served. `renewed` says that it replaced one.
    Obtained {
        /// The name of the certificate.
        name: String,
        /// The expiry, in seconds since 1970.
        not_after: u64,
        /// Whether a certificate was served before.
        renewed: bool,
    },
    /// A stored certificate was loaded and is served.
    Loaded {
        /// The name of the certificate.
        name: String,
        /// The expiry, in seconds since 1970.
        not_after: u64,
    },
    /// The DNS-01 record of an order could not be removed. The order is not affected.
    CleanupFailed {
        /// The name of the certificate.
        name: String,
        /// What failed, with a hint.
        error: AcmeError,
    },
    /// A name that a handshake asked for on demand was refused by a guard.
    Refused {
        /// The name.
        name: String,
        /// Which guard refused it.
        reason: &'static str,
        /// For how many seconds the refusal is remembered.
        seconds: u64,
    },
    /// A name held on demand was released at its renewal. It is no longer served.
    Released {
        /// The name.
        name: String,
        /// Why it was released.
        reason: &'static str,
    },
    /// An authority failed to issue, and the attempt goes on with the next one.
    Fallback {
        /// The name of the certificate.
        name: String,
        /// The directory of the authority that failed.
        authority: String,
        /// The directory of the authority that is asked next.
        next: String,
        /// What failed, with a hint.
        error: AcmeError,
    },
    /// An OCSP response is stapled to the certificate of a name for the first time.
    Stapled {
        /// The name of the certificate.
        name: String,
        /// The end of the window of the response, in seconds since 1970.
        until: u64,
    },
    /// The OCSP responder of a certificate did not give a response that can be stapled.
    /// The certificate is served without one.
    StapleFailed {
        /// The name of the certificate.
        name: String,
        /// What failed, with a hint.
        error: AcmeError,
        /// The time of the next question, in seconds since 1970.
        retry_at: u64,
    },
    /// The OCSP responder says that the served certificate is revoked. It is renewed.
    Revoked {
        /// The name of the certificate.
        name: String,
    },
    /// The ACME server of the local authority validated a name for a client, or
    /// failed to.
    ServerValidated {
        /// The name.
        name: String,
        /// Why the validation failed, in a sentence for the client.
        failure: Option<String>,
    },
    /// The ACME server of the local authority issued a certificate to a client.
    ServerIssued {
        /// The names of the certificate.
        names: Vec<String>,
    },
    /// An attempt failed. The served certificate, if any, stays.
    Failed {
        /// The name, or `None` for a failure of the storage or the account.
        name: Option<String>,
        /// What failed, with a hint.
        error: AcmeError,
        /// The time of the next attempt, in seconds since 1970.
        retry_at: u64,
    },
    /// The thread panicked: a defect of ours. The served certificates stay. A new
    /// thread state starts after the delay and reads the storage as after a restart.
    Panicked {
        /// What the panic said, in one printable line.
        message: String,
        /// The seconds until the thread works again.
        restart_in: u64,
    },
}

/// Receives the events of the thread. It is called on that thread and must not block.
pub type Notify = Arc<dyn Fn(&Event) + Send + Sync>;

/// Where a managed name stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateState {
    /// No attempt was made yet.
    Pending,
    /// A certificate is served and not due.
    Ready,
    /// An order is running.
    Ordering,
    /// Another node holds the lock of the name.
    Waiting,
    /// The last attempt failed. The next one is scheduled.
    Retry,
}

impl CertificateState {
    /// The word of `show certs`.
    pub fn word(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Ordering => "ordering",
            Self::Waiting => "waiting",
            Self::Retry => "retry",
        }
    }
}

/// One line of `show certs`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateStatus {
    /// The managed name.
    pub name: String,
    /// Why the name is managed: `listed` under `auto`, or `on-demand`.
    pub origin: &'static str,
    /// The OCSP status of the certificate: `good` while handshakes staple a response,
    /// `revoked` when the responder said so, else `-`.
    pub staple: &'static str,
    /// How the certificate is obtained: `http-01`, `tls-alpn-01`, `dns-01` or `local`.
    pub via: &'static str,
    /// The issuer of the served certificate.
    pub issuer: Option<String>,
    /// The expiry of the served certificate, in seconds since 1970.
    pub not_after: Option<u64>,
    /// The time of the next order or renewal, in seconds since 1970.
    pub next_attempt: Option<u64>,
    /// Where the name stands.
    pub state: CertificateState,
    /// The title and code of the last failure, for example `VALIDATION FAILED (ACME005)`.
    pub error: Option<String>,
}

impl CertificateStatus {
    fn pending(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            origin: LISTED,
            staple: "-",
            via: "-",
            issuer: None,
            not_after: None,
            next_attempt: None,
            state: CertificateState::Pending,
            error: None,
        }
    }
}

fn read<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(PoisonError::into_inner)
}

fn write<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(PoisonError::into_inner)
}

/// The tables. The thread writes them. Handshakes, requests and the admin socket read.
pub(crate) struct Shared {
    pub options: AcmeOptions,
    /// The managed names, and whether the topology has a plain HTTP frontend. A reload
    /// replaces both.
    wanted: RwLock<(BTreeMap<String, AutoName>, bool)>,
    certificates: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    alpn_answers: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    http_answers: RwLock<HashMap<String, String>>,
    /// The thumbprint of the account key, once the account is loaded.
    thumbprint: RwLock<Option<String>>,
    status: Mutex<BTreeMap<String, CertificateStatus>>,
    failures: AtomicU64,
    /// Set when the thread should look at the names again.
    woken: Mutex<bool>,
    wake: Condvar,
    stopping: AtomicBool,
    /// Whether orders may start. Until then the thread only loads stored certificates.
    ordering: AtomicBool,
    /// The names that handshakes asked for, on frontends with `on_demand`.
    pub demand: demand::Demand,
    /// Makes the thread panic once, for the test of its supervisor.
    #[cfg(test)]
    panic_once: AtomicBool,
}

impl Shared {
    fn new(config: AutomaticHttps) -> Self {
        Self {
            demand: demand::Demand::new(config.options.on_demand.clone(), now_ms()),
            options: config.options,
            wanted: RwLock::new((by_name(config.names), config.plain_frontend)),
            certificates: RwLock::default(),
            alpn_answers: RwLock::default(),
            http_answers: RwLock::default(),
            thumbprint: RwLock::default(),
            status: Mutex::default(),
            failures: AtomicU64::new(0),
            woken: Mutex::new(false),
            wake: Condvar::new(),
            stopping: AtomicBool::new(false),
            ordering: AtomicBool::new(false),
            #[cfg(test)]
            panic_once: AtomicBool::new(false),
        }
    }

    /// The certificate of a managed name, for the resolver.
    pub fn certificate(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        read(&self.certificates).get(name).cloned()
    }

    /// The TLS-ALPN-01 answer for a name under validation, for the resolver.
    pub fn alpn_answer(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        read(&self.alpn_answers).get(name).cloned()
    }

    /// Every managed name: the listed ones, and the ones held on demand.
    fn names(&self) -> Vec<AutoName> {
        let wanted = read(&self.wanted);
        let mut names: Vec<AutoName> = wanted.0.values().cloned().collect();
        let held = self.demand.held_names();
        names.extend(held.into_iter().filter(|held| !wanted.0.contains_key(&held.name)));
        names
    }

    /// Whether `name` is managed only because a handshake asked for it.
    fn is_demanded(&self, name: &str) -> bool {
        self.demand.is_held(name) && !read(&self.wanted).0.contains_key(name)
    }

    /// The origin of a managed name, for `show certs`.
    fn origin(&self, name: &str) -> &'static str {
        if read(&self.wanted).0.contains_key(name) { LISTED } else { ON_DEMAND }
    }

    /// Whether a handshake that waits for `name` has its answer: the name is neither
    /// queued nor held without a certificate.
    fn is_settled(&self, name: &str) -> bool {
        let pending = self.demand.is_held(name) && self.certificate(name).is_none();
        !pending && !self.demand.is_queued(name)
    }

    /// A handshake asks for a certificate for `wanted`, which no listener serves and
    /// which passed the guards that read no state. Waits until the thread decided and
    /// served the name, at most `on_demand.wait` seconds. Returns at once when the name
    /// is denied or a table is full.
    pub async fn obtain(&self, wanted: AutoName) {
        let name = wanted.name.clone();
        if self.demand.request(wanted, now_ms()) == demand::Admission::Refused {
            return;
        }
        self.notify();
        self.demand.wait_until(|| self.is_settled(&name)).await;
    }

    /// Lets go of a name held on demand: it is no longer served or renewed. Its
    /// certificate stays in the storage.
    fn release(&self, name: &str) {
        self.demand.release(name);
        if !read(&self.wanted).0.contains_key(name) {
            write(&self.certificates).remove(name);
            self.status.lock().unwrap_or_else(PoisonError::into_inner).remove(name);
        }
    }

    /// Sleeps for `time` in short steps. Returns false when the daemon stops meanwhile.
    fn pause(&self, time: Duration) -> bool {
        let end = std::time::Instant::now() + time;
        loop {
            if self.stopping.load(Ordering::Acquire) {
                return false;
            }
            let left = end.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return true;
            }
            std::thread::sleep(left.min(Duration::from_millis(200)));
        }
    }

    fn has_plain_frontend(&self) -> bool {
        read(&self.wanted).1
    }

    /// Sets or removes the OCSP response that handshakes staple to the certificate of
    /// `name`. Handshakes that run keep the certificate they took.
    fn staple(&self, name: &str, response: Option<Vec<u8>>) {
        let mut all = write(&self.certificates);
        if let Some(served) = all.get_mut(name) {
            let mut next = CertifiedKey::clone(served);
            next.ocsp = response;
            *served = Arc::new(next);
        }
    }

    fn install(&self, name: &str, certificate: Arc<CertifiedKey>) {
        write(&self.certificates).insert(name.to_owned(), certificate);
    }

    /// Publishes the answer to a challenge.
    fn present(&self, challenge: &Challenge, now: u64) -> Result<(), AcmeError> {
        match challenge.kind {
            ChallengeKind::Http01 => {
                let answer = challenge.key_authorization.clone();
                write(&self.http_answers).insert(challenge.token.clone(), answer);
            }
            ChallengeKind::TlsAlpn01 => {
                let key = KeyPair::generate()?;
                let certificate = x509::challenge_certificate(
                    &key,
                    &challenge.name,
                    &challenge.key_authorization,
                    now,
                )?;
                let answer = driver::certified(vec![certificate], &key, false)?;
                write(&self.alpn_answers).insert(challenge.name.clone(), answer);
            }
            // The driver answers DNS-01 through the provider, not through a listener.
            ChallengeKind::Dns01 => {}
        }
        Ok(())
    }

    /// Removes every challenge answer. One order runs at a time, so all are its own.
    fn withdraw(&self) {
        write(&self.http_answers).clear();
        write(&self.alpn_answers).clear();
    }

    /// Drops the certificates and the status of names that are no longer managed.
    fn forget_except(&self, names: &[AutoName]) {
        let wanted = |name: &String| names.iter().any(|known| known.name == *name);
        write(&self.certificates).retain(|name, _| wanted(name));
        let mut all = self.status.lock().unwrap_or_else(PoisonError::into_inner);
        all.retain(|name, _| wanted(name));
    }

    fn set_status(&self, status: CertificateStatus) {
        let mut all = self.status.lock().unwrap_or_else(PoisonError::into_inner);
        all.insert(status.name.clone(), status);
    }

    /// Sleeps until `timeout` passed or somebody called [`Shared::notify`].
    fn sleep(&self, timeout: Duration) {
        let woken = self.woken.lock().unwrap_or_else(PoisonError::into_inner);
        let (mut woken, _) = self
            .wake
            .wait_timeout_while(woken, timeout, |woken| !*woken)
            .unwrap_or_else(PoisonError::into_inner);
        *woken = false;
    }

    fn notify(&self) {
        *self.woken.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.wake.notify_all();
    }
}

fn by_name(names: Vec<AutoName>) -> BTreeMap<String, AutoName> {
    names.into_iter().map(|name| (name.name.clone(), name)).collect()
}

/// The host of a `Host` header without its port, in lower case. An IPv6 address loses
/// its brackets.
fn host_name(host: &str) -> String {
    let name = match host.strip_prefix('[').and_then(|rest| rest.split_once(']')) {
        Some((address, _)) => address,
        None => host.rsplit_once(':').map_or(host, |(name, _)| name),
    };
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Automatic HTTPS of one daemon. Dropping it stops the thread after its current step.
pub struct Automatic {
    shared: Arc<Shared>,
    /// The ACME server of the local authority, when the configuration has one.
    server: Option<Arc<sibuna_acme::server::Server>>,
}

impl Automatic {
    /// Starts the thread `edge-acme`. It loads the stored certificates. After
    /// [`Automatic::allow_orders`] it orders and renews in the background. This call
    /// opens no socket and no file, and fails only when the thread cannot be spawned.
    ///
    /// The thread is supervised. When its work panics, `report` receives
    /// [`Event::Panicked`], the served certificates stay, and the work starts again
    /// after 5 seconds, then 10, up to 5 minutes, from what the storage holds.
    pub fn start(config: AutomaticHttps, report: Notify) -> io::Result<Self> {
        let shared = Arc::new(Shared::new(config));
        let thread = Arc::clone(&shared);
        let server = server::build(&shared);
        if let Some(server) = &server {
            let (shared, server, report) =
                (Arc::clone(&shared), Arc::clone(server), Arc::clone(&report));
            std::thread::Builder::new()
                .name("edge-acme-server".into())
                .spawn(move || server::run(&shared, &server, &report))?;
        }
        std::thread::Builder::new()
            .name("edge-acme".into())
            .spawn(move || supervise::run(&thread, &report))?;
        Ok(Self { shared, server })
    }

    /// The ACME server of the local authority and its configuration, when
    /// `global.acme.internal.server` is set. The server answers a request from memory
    /// and never blocks; its thread `edge-acme-server` validates and signs.
    pub fn acme_server(
        &self,
    ) -> Option<(&sibuna_acme::server::Server, &sibuna_lb::InternalServer)> {
        let config = self.shared.options.internal.server.as_ref()?;
        Some((self.server.as_deref()?, config))
    }

    pub(crate) fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }

    /// Lets the thread place orders. The daemon calls this once its listeners serve. A
    /// daemon that fails to start has then asked the authority for nothing, so a start
    /// that is tried again and again does not spend the limits of the authority.
    pub fn allow_orders(&self) {
        self.shared.ordering.store(true, Ordering::Release);
        self.shared.notify();
    }

    /// The `global.acme` options this instance runs with.
    pub fn options(&self) -> &AcmeOptions {
        &self.shared.options
    }

    /// Replaces the managed names after a reload. New names are ordered. Names that
    /// left are no longer renewed.
    pub fn set_names(&self, names: Vec<AutoName>, plain_frontend: bool) {
        *write(&self.shared.wanted) = (by_name(names), plain_frontend);
        self.shared.notify();
    }

    /// The body that answers `GET /.well-known/acme-challenge/TOKEN` for `host`.
    ///
    /// A token of a running order is answered for any host. Any other well-formed token
    /// is answered for a managed name, from the thumbprint of the account key: the node
    /// that placed the order may be another one that shares our storage.
    pub fn challenge_answer(&self, token: &[u8], host: &[u8]) -> Option<String> {
        let well_formed = !token.is_empty()
            && token.len() <= MAX_TOKEN
            && token.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_');
        let token = std::str::from_utf8(token).ok().filter(|_| well_formed)?;
        if let Some(answer) = read(&self.shared.http_answers).get(token) {
            return Some(answer.clone());
        }
        self.port_of(host)?;
        let thumbprint = read(&self.shared.thumbprint).clone()?;
        Some(format!("{token}.{thumbprint}"))
    }

    /// The port of the TLS frontend of `host`, when `host` is a managed name or a
    /// managed wildcard covers it. `host` is the value of a `Host` header and may carry
    /// a port.
    fn port_of(&self, host: &[u8]) -> Option<u16> {
        let name = host_name(std::str::from_utf8(host).ok()?);
        let wanted = read(&self.shared.wanted);
        let exact = wanted.0.get(&name);
        let covering = || {
            let (_, parent) = name.split_once('.')?;
            wanted.0.get(&format!("*.{parent}"))
        };
        let listed = exact.or_else(covering).map(|found| found.port);
        listed.or_else(|| self.shared.demand.held(&name).map(|held| held.port))
    }

    /// The root of the local authority, when the daemon manages a name that it issues
    /// for: the path of the file, the PEM text and the fields. Fails when the file
    /// cannot be read.
    pub fn local_root(&self) -> Result<Option<sibuna_acme::local::Root>, AcmeError> {
        if !self.shared.names().iter().any(|name| name.local) {
            return Ok(None);
        }
        sibuna_acme::local::read_root(std::path::Path::new(&self.shared.options.storage))
    }

    /// The port to redirect a plain HTTP request for `host` to, when `host` is a managed
    /// name and `global.acme.redirect` is on.
    pub fn redirect_port(&self, host: &[u8]) -> Option<u16> {
        self.shared.options.redirect.then(|| self.port_of(host)).flatten()
    }

    /// The state of every managed name, sorted by name.
    pub fn status(&self) -> Vec<CertificateStatus> {
        let known = self.shared.status.lock().unwrap_or_else(PoisonError::into_inner);
        let names = self.shared.names();
        names
            .iter()
            .map(|name| {
                let pending = || CertificateStatus::pending(&name.name);
                let status = known.get(&name.name).cloned().unwrap_or_else(pending);
                CertificateStatus { origin: self.shared.origin(&name.name), ..status }
            })
            .collect()
    }

    /// The failed attempts since the start, for a counter.
    pub fn failure_count(&self) -> u64 {
        self.shared.failures.load(Ordering::Relaxed)
    }
}

impl Drop for Automatic {
    fn drop(&mut self) {
        self.shared.stopping.store(true, Ordering::Release);
        self.shared.notify();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(name: &str, port: u16) -> AutoName {
        AutoName { name: name.to_owned(), port, local: false }
    }

    fn automatic(redirect: bool) -> Automatic {
        let guards = sibuna_lb::OnDemand {
            allow: vec!["apps.test".to_owned()],
            wait: 1,
            ..sibuna_lb::OnDemand::default()
        };
        let config = AutomaticHttps {
            options: AcmeOptions { redirect, on_demand: Some(guards), ..AcmeOptions::default() },
            names: vec![
                name("example.org", 443),
                name("alt.example.org", 8443),
                name("*.wild.example", 9443),
                name("::1", 7443),
            ],
            plain_frontend: true,
            on_demand: false,
        };
        // No thread: these tests read the tables only.
        Automatic { shared: Arc::new(Shared::new(config)), server: None }
    }

    #[test]
    fn a_token_of_the_running_order_is_answered_for_any_host() {
        let automatic = automatic(true);
        write(&automatic.shared.http_answers).insert("tok_1".to_owned(), "tok_1.print".to_owned());
        assert_eq!(
            automatic.challenge_answer(b"tok_1", b"other.example").as_deref(),
            Some("tok_1.print")
        );
        automatic.shared.withdraw();
        assert_eq!(automatic.challenge_answer(b"tok_1", b"other.example"), None);
    }

    #[test]
    fn another_node_s_token_is_answered_for_managed_names_only() {
        let automatic = automatic(true);
        assert_eq!(automatic.challenge_answer(b"abc", b"example.org"), None);
        *write(&automatic.shared.thumbprint) = Some("print".to_owned());
        assert_eq!(
            automatic.challenge_answer(b"abc", b"Example.org:80").as_deref(),
            Some("abc.print")
        );
        assert_eq!(automatic.challenge_answer(b"abc", b"unknown.example"), None);
        for bad in [&b""[..], b"a.b", b"a/b", b"a b", &[b'a'; 129]] {
            assert_eq!(automatic.challenge_answer(bad, b"example.org"), None);
        }
    }

    #[test]
    fn the_redirect_names_the_port_of_the_tls_frontend() {
        let on = automatic(true);
        assert_eq!(on.redirect_port(b"example.org"), Some(443));
        assert_eq!(on.redirect_port(b"ALT.example.org.:8080"), Some(8443));
        assert_eq!(on.redirect_port(b"unknown.example"), None);
        assert_eq!(automatic(false).redirect_port(b"example.org"), None);
        // A wildcard covers one label. An address is found with and without a port.
        assert_eq!(on.redirect_port(b"a.wild.example:80"), Some(9443));
        assert_eq!(on.redirect_port(b"a.b.wild.example"), None);
        assert_eq!(on.redirect_port(b"wild.example"), None);
        assert_eq!(on.redirect_port(b"[::1]:8080"), Some(7443));
        assert_eq!(on.redirect_port(b"[::1]"), Some(7443));
        assert!(on.local_root().is_ok_and(|root| root.is_none()));
        on.set_names(vec![name("new.example.org", 443)], false);
        assert_eq!(on.redirect_port(b"example.org"), None);
        assert_eq!(on.status().len(), 1);
        assert_eq!(on.status()[0].state, CertificateState::Pending);
    }

    #[test]
    fn a_name_on_demand_is_managed_while_it_is_held() {
        let automatic = automatic(true);
        let shared = &automatic.shared;
        assert!(shared.options.demanded("a.other.test", 9443, None).is_none());
        let Some(wanted) = shared.options.demanded("a.apps.test", 9443, None) else {
            panic!("the suffix allows the name");
        };
        assert_eq!(shared.demand.request(wanted.clone(), 1), demand::Admission::Pending);
        assert!(!shared.is_settled("a.apps.test") && !shared.is_demanded("a.apps.test"));
        assert_eq!(automatic.status().len(), 4);
        shared.demand.hold(wanted, 2);
        assert!(shared.is_demanded("a.apps.test") && !shared.is_settled("a.apps.test"));
        let origins: Vec<_> = automatic.status().iter().map(|line| line.origin).collect();
        assert_eq!(origins.iter().filter(|origin| **origin == "on-demand").count(), 1);
        assert_eq!(origins.len(), 5);
        assert_eq!(automatic.redirect_port(b"a.apps.test:80"), Some(9443));
        // With a certificate the waiting handshake has its answer.
        let Ok(key) = KeyPair::generate() else { panic!("no key") };
        let der = x509::challenge_certificate(&key, "a.apps.test", "a.b", 1_795_516_496);
        let certified = der.and_then(|der| driver::certified(vec![der], &key, false));
        let Ok(certified) = certified else { panic!("no certificate") };
        shared.install("a.apps.test", certified);
        assert!(shared.is_settled("a.apps.test"));
        shared.release("a.apps.test");
        assert!(shared.certificate("a.apps.test").is_none() && shared.is_settled("a.apps.test"));
        assert_eq!(automatic.status().len(), 4);
        assert_eq!(automatic.redirect_port(b"a.apps.test"), None);
        // A listed name is never a name on demand, and a release leaves it alone.
        assert!(!shared.is_demanded("example.org"));
        assert_eq!(shared.origin("example.org"), "listed");
    }

    #[tokio::test]
    async fn a_handshake_waits_for_a_pending_name_only() {
        let automatic = automatic(true);
        let shared = &automatic.shared;
        let name = |name: &str| AutoName { name: name.to_owned(), port: 443, local: true };
        shared.demand.deny("no.apps.test", u64::MAX, 0);
        let start = std::time::Instant::now();
        shared.obtain(name("no.apps.test")).await;
        assert!(start.elapsed() < Duration::from_millis(500));
        // Nobody decides the name: the wait ends after `wait`, one second here.
        shared.obtain(name("a.apps.test")).await;
        assert!(start.elapsed() >= Duration::from_secs(1));
        assert!(shared.demand.is_queued("a.apps.test"));
    }
}
