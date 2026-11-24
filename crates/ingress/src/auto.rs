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
//! ```
//!
//! A reader takes a read lock on a small map and nothing else. Only the thread talks to
//! the certificate authority.

mod client;
mod driver;

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError, RwLock};
use std::time::Duration;

use rustls::sign::CertifiedKey;
use sibuna_acme::{Challenge, ChallengeKind, Error as AcmeError, KeyPair, x509};
use sibuna_lb::{AcmeOptions, AutomaticHttps};

/// The ALPN protocol of the TLS-ALPN-01 challenge (RFC 8737).
pub(crate) const ACME_TLS: &[u8] = b"acme-tls/1";
/// The longest token we answer.
const MAX_TOKEN: usize = 128;

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
    /// An attempt failed. The served certificate, if any, stays.
    Failed {
        /// The name, or `None` for a failure of the storage or the account.
        name: Option<String>,
        /// What failed, with a hint.
        error: AcmeError,
        /// The time of the next attempt, in seconds since 1970.
        retry_at: u64,
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
    /// The managed names with the port of their TLS frontend, and whether the topology
    /// has a plain HTTP frontend. A reload replaces both.
    wanted: RwLock<(BTreeMap<String, u16>, bool)>,
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
}

impl Shared {
    fn new(config: AutomaticHttps) -> Self {
        Self {
            options: config.options,
            wanted: RwLock::new((config.names.into_iter().collect(), config.plain_frontend)),
            certificates: RwLock::default(),
            alpn_answers: RwLock::default(),
            http_answers: RwLock::default(),
            thumbprint: RwLock::default(),
            status: Mutex::default(),
            failures: AtomicU64::new(0),
            woken: Mutex::new(false),
            wake: Condvar::new(),
            stopping: AtomicBool::new(false),
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

    fn names(&self) -> Vec<String> {
        read(&self.wanted).0.keys().cloned().collect()
    }

    fn has_plain_frontend(&self) -> bool {
        read(&self.wanted).1
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
        }
        Ok(())
    }

    /// Removes every challenge answer. One order runs at a time, so all are its own.
    fn withdraw(&self) {
        write(&self.http_answers).clear();
        write(&self.alpn_answers).clear();
    }

    /// Drops the certificates and the status of names that are no longer managed.
    fn forget_except(&self, names: &[String]) {
        write(&self.certificates).retain(|name, _| names.contains(name));
        let mut all = self.status.lock().unwrap_or_else(PoisonError::into_inner);
        all.retain(|name, _| names.contains(name));
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

/// Automatic HTTPS of one daemon. Dropping it stops the thread after its current step.
pub struct Automatic {
    shared: Arc<Shared>,
}

impl Automatic {
    /// Starts the thread `edge-acme`. It loads the stored certificates, then orders and
    /// renews in the background. This call opens no socket and no file, and fails only
    /// when the thread cannot be spawned.
    pub fn start(config: AutomaticHttps, report: Notify) -> io::Result<Self> {
        let shared = Arc::new(Shared::new(config));
        let thread = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("edge-acme".into())
            .spawn(move || driver::Driver::new(thread, report).run())?;
        Ok(Self { shared })
    }

    pub(crate) fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }

    /// The `global.acme` options this instance runs with.
    pub fn options(&self) -> &AcmeOptions {
        &self.shared.options
    }

    /// Replaces the managed names after a reload: each name with the port of its TLS
    /// frontend. New names are ordered. Names that left are no longer renewed.
    pub fn set_names(&self, names: Vec<(String, u16)>, plain_frontend: bool) {
        *write(&self.shared.wanted) = (names.into_iter().collect(), plain_frontend);
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

    /// The port of the TLS frontend of `host`, when `host` is a managed name. `host` is
    /// the value of a `Host` header and may carry a port.
    fn port_of(&self, host: &[u8]) -> Option<u16> {
        let host = std::str::from_utf8(host).ok()?;
        let name = host.rsplit_once(':').map_or(host, |(name, _)| name);
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        read(&self.shared.wanted).0.get(&name).copied()
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
                known.get(name).cloned().unwrap_or_else(|| CertificateStatus::pending(name))
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

    fn automatic(redirect: bool) -> Automatic {
        let config = AutomaticHttps {
            options: AcmeOptions { redirect, ..AcmeOptions::default() },
            names: vec![("example.org".to_owned(), 443), ("alt.example.org".to_owned(), 8443)],
            plain_frontend: true,
        };
        // No thread: these tests read the tables only.
        Automatic { shared: Arc::new(Shared::new(config)) }
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
        on.set_names(vec![("new.example.org".to_owned(), 443)], false);
        assert_eq!(on.redirect_port(b"example.org"), None);
        assert_eq!(on.status().len(), 1);
        assert_eq!(on.status()[0].state, CertificateState::Pending);
    }
}
