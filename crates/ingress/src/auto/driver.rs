//! The thread `edge-acme`: it loads stored certificates, orders missing ones, renews the
//! ones that are due and retries failures, one name at a time (SID 0021).

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use sibuna_acme::store::{Retry, Store};
use sibuna_acme::{
    Account, Action, ChallengeKind, Error, Issued, KeyPair, Order, OrderOptions, pem, schedule,
    x509,
};
use sibuna_lb::AcmeChallenge;

use super::client::Client;
use super::{CertificateState, CertificateStatus, Event, Notify, Shared};

/// The longest time one order may take.
const ORDER_LIMIT: Duration = Duration::from_secs(300);
/// How long to wait for the lock of another node before looking again.
const LOCK_WAIT: u64 = 15;
/// The pause between two orders.
const PACE: Duration = Duration::from_secs(1);
/// The longest sleep. The names and the storage are looked at again after it.
const LONGEST_SLEEP: u64 = 3600;

/// Seconds since 1970.
fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())
}

/// Builds the key and chain that the TLS library serves. With `checked` the key must
/// belong to the leaf. The certificate of a TLS-ALPN-01 answer has a critical extension
/// that the check cannot read, so it is built without.
pub(super) fn certified(
    chain: Vec<Vec<u8>>,
    key: &KeyPair,
    checked: bool,
) -> Result<Arc<CertifiedKey>, Error> {
    let unusable = |error: rustls::Error| Error::rejected(format!("The certificate: {error}."));
    let chain: Vec<_> = chain.into_iter().map(CertificateDer::from).collect();
    let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.pkcs8().to_vec()));
    let provider = rustls::crypto::ring::default_provider();
    if checked {
        return CertifiedKey::from_der(chain, der, &provider).map(Arc::new).map_err(unusable);
    }
    let signer = provider.key_provider.load_private_key(der).map_err(unusable)?;
    Ok(Arc::new(CertifiedKey::new(chain, signer)))
}

/// A chain that passed the checks of SID 0021: it names the host, its key belongs to it,
/// and it has not expired.
struct Sound {
    certified: Arc<CertifiedKey>,
    fields: x509::Certificate,
}

fn sound(name: &str, chain_pem: &str, key: &KeyPair, now: u64) -> Result<Sound, Error> {
    let reject = |what: &str| Error::rejected(format!("The certificate for `{name}` {what}."));
    let chain = pem::decode("CERTIFICATE", chain_pem)
        .filter(|chain| !chain.is_empty())
        .ok_or_else(|| reject("is not a PEM chain"))?;
    let fields = chain.first().and_then(|leaf| x509::read(leaf));
    let fields = fields.ok_or_else(|| reject("cannot be read"))?;
    if !fields.names_host(name) {
        return Err(reject("does not name the host"));
    }
    if fields.not_after <= now {
        return Err(reject("has expired"));
    }
    Ok(Sound { certified: certified(chain, key, true)?, fields })
}

/// What the thread remembers of one name.
#[derive(Default)]
struct Entry {
    /// The validity and issuer of the served certificate.
    served: Option<x509::Certificate>,
    failures: u32,
    next_attempt: u64,
    error: Option<String>,
}

impl Entry {
    /// When the served certificate is due for renewal. Without one: at once.
    fn renew_at(&self) -> u64 {
        self.served.as_ref().map_or(0, |c| schedule::renew_at(c.not_before, c.not_after))
    }
}

/// What an order needs: the files, the account, the client and its runtime.
struct Ready {
    store: Store,
    account: Account,
    client: Client,
    runtime: tokio::runtime::Runtime,
}

/// The state of the thread.
pub(super) struct Driver {
    shared: Arc<Shared>,
    report: Notify,
    entries: BTreeMap<String, Entry>,
    /// Failures to open the store, the account or the client, and the next try.
    prepare_failures: u32,
    prepare_at: u64,
}

impl Driver {
    pub fn new(shared: Arc<Shared>, report: Notify) -> Self {
        Self { shared, report, entries: BTreeMap::new(), prepare_failures: 0, prepare_at: 0 }
    }

    fn stopping(&self) -> bool {
        self.shared.stopping.load(Ordering::Acquire)
    }

    /// Runs until the handle is dropped.
    pub fn run(mut self) {
        let mut ready = None;
        while !self.stopping() {
            if ready.is_none() && now() >= self.prepare_at {
                ready = self.prepare();
            }
            let sleep = match &mut ready {
                Some(ready) => self.round(ready),
                None => self.prepare_at.saturating_sub(now()),
            };
            self.shared.sleep(Duration::from_secs(sleep.clamp(1, LONGEST_SLEEP)));
        }
    }

    /// Opens the store, the account and the client. A failure is reported and tried
    /// again with the delay of a failed order.
    fn prepare(&mut self) -> Option<Ready> {
        match self.try_prepare() {
            Ok(ready) => {
                self.prepare_failures = 0;
                *super::write(&self.shared.thumbprint) = Some(ready.account.thumbprint());
                Some(ready)
            }
            Err(error) => {
                self.prepare_failures += 1;
                self.shared.failures.fetch_add(1, Ordering::Relaxed);
                self.prepare_at = now() + schedule::retry_delay(self.prepare_failures, None);
                (self.report)(&Event::Failed { name: None, error, retry_at: self.prepare_at });
                None
            }
        }
    }

    fn try_prepare(&self) -> Result<Ready, Error> {
        let options = &self.shared.options;
        let store = Store::open(Path::new(&options.storage), &options.directory)?;
        let account = Account::new(store.load_account()?);
        let client = Client::load(options.ca_file.as_deref())?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| Error::unreachable(format!("No runtime for the client: {error}.")))?;
        Ok(Ready { store, account, client, runtime })
    }

    /// Looks at every name once and returns the seconds until the next one is due.
    fn round(&mut self, ready: &mut Ready) -> u64 {
        let names = self.shared.names();
        self.entries.retain(|name, _| names.contains(name));
        self.shared.forget_except(&names);
        for name in &names {
            if self.stopping() {
                break;
            }
            let mut entry = match self.entries.remove(name) {
                Some(entry) => entry,
                None => self.adopt(ready, name),
            };
            let ordering = self.shared.ordering.load(Ordering::Acquire);
            if ordering && entry.next_attempt <= now() {
                self.attempt(ready, name, &mut entry);
                std::thread::sleep(PACE);
            }
            self.entries.insert(name.clone(), entry);
        }
        let next = self.entries.values().map(|entry| entry.next_attempt).min();
        next.unwrap_or(u64::MAX).saturating_sub(now())
    }

    /// The first look at a name: its stored certificate and the failures of an earlier
    /// run. A restart therefore orders nothing while the certificate is fresh, and waits
    /// as the stopped daemon would have waited.
    fn adopt(&self, ready: &Ready, name: &str) -> Entry {
        let mut entry = Entry::default();
        let now = now();
        self.look(ready, name, &mut entry, now);
        let retry = ready.store.load_retry(name);
        entry.failures = retry.map_or(0, |retry| retry.failures);
        entry.next_attempt = match retry {
            _ if entry.renew_at() > now => entry.renew_at(),
            Some(retry) => retry.next_attempt.min(now + schedule::LONGEST_DELAY),
            None => now,
        };
        self.publish(name, &entry, None);
        entry
    }

    /// Loads the stored certificate of a name and serves it when it is sound and does
    /// not expire earlier than the served one. Returns whether it was installed.
    fn look(&self, ready: &Ready, name: &str, entry: &mut Entry, now: u64) -> bool {
        let Ok(Some(stored)) = ready.store.load_certificate(name) else { return false };
        let Ok(found) = sound(name, &stored.chain_pem, &stored.key, now) else { return false };
        let served = entry.served.as_ref();
        if served.is_some_and(|served| found.fields.not_after <= served.not_after) {
            return false;
        }
        let not_after = found.fields.not_after;
        self.shared.install(name, found.certified);
        entry.served = Some(found.fields);
        (self.report)(&Event::Loaded { name: name.to_owned(), not_after });
        true
    }

    /// Writes the line of `show certs` for a name.
    fn publish(&self, name: &str, entry: &Entry, state: Option<CertificateState>) {
        let rest = match (&entry.served, &entry.error) {
            (_, Some(_)) => CertificateState::Retry,
            (Some(_), None) => CertificateState::Ready,
            (None, None) => CertificateState::Pending,
        };
        self.shared.set_status(CertificateStatus {
            name: name.to_owned(),
            issuer: entry.served.as_ref().map(|served| served.issuer.clone()),
            not_after: entry.served.as_ref().map(|served| served.not_after),
            next_attempt: Some(entry.next_attempt),
            state: state.unwrap_or(rest),
            error: entry.error.clone(),
        });
    }

    /// One attempt for a name that is due: look at the storage, take the lock, order.
    fn attempt(&self, ready: &mut Ready, name: &str, entry: &mut Entry) {
        let now = now();
        // Another node that shares the storage may have renewed already.
        if self.look(ready, name, entry, now) && entry.renew_at() > now {
            self.succeeded(ready, name, entry);
            return;
        }
        let _lock = match ready.store.lock(name) {
            Ok(Some(lock)) => lock,
            Ok(None) => {
                entry.next_attempt = now + LOCK_WAIT;
                self.publish(name, entry, Some(CertificateState::Waiting));
                return;
            }
            Err(error) => return self.failed(ready, name, entry, error),
        };
        self.publish(name, entry, Some(CertificateState::Ordering));
        let issued = self.order(ready, name, entry.failures);
        self.shared.withdraw();
        let installed = issued.and_then(|issued| {
            let found = sound(name, &issued.chain_pem, &issued.key, now)?;
            ready.store.save_certificate(name, &issued.chain_pem, &issued.key)?;
            Ok(found)
        });
        match installed {
            Ok(found) => {
                let renewed = entry.served.is_some();
                let not_after = found.fields.not_after;
                self.shared.install(name, found.certified);
                entry.served = Some(found.fields);
                self.succeeded(ready, name, entry);
                (self.report)(&Event::Obtained { name: name.to_owned(), not_after, renewed });
            }
            Err(error) => self.failed(ready, name, entry, error),
        }
    }

    fn succeeded(&self, ready: &Ready, name: &str, entry: &mut Entry) {
        ready.store.clear_retry(name);
        entry.failures = 0;
        entry.error = None;
        // A certificate that is due the moment it is issued has no life worth serving.
        // We look again after the first delay instead of ordering in a loop.
        let now = now();
        let due = entry.renew_at();
        entry.next_attempt = if due > now { due } else { now + schedule::FIRST_DELAY };
        self.publish(name, entry, None);
    }

    /// Schedules the next attempt after a failure and reports it. Nothing that is
    /// served changes.
    fn failed(&self, ready: &Ready, name: &str, entry: &mut Entry, error: Error) {
        entry.failures = entry.failures.saturating_add(1);
        entry.next_attempt = now() + schedule::retry_delay(entry.failures, error.retry_after);
        entry.error = Some(format!("{} ({})", error.title, error.code));
        let retry = Retry { failures: entry.failures, next_attempt: entry.next_attempt };
        let _ = ready.store.save_retry(name, retry);
        self.shared.failures.fetch_add(1, Ordering::Relaxed);
        self.publish(name, entry, None);
        let name = Some(name.to_owned());
        (self.report)(&Event::Failed { name, error, retry_at: entry.next_attempt });
    }

    /// The challenge of the next attempt. `auto` starts with HTTP-01 when the topology
    /// has a plain frontend, and takes the other type after each failure.
    fn challenge(&self, failures: u32) -> (ChallengeKind, bool) {
        match self.shared.options.challenge {
            AcmeChallenge::Http01 => (ChallengeKind::Http01, false),
            AcmeChallenge::TlsAlpn01 => (ChallengeKind::TlsAlpn01, false),
            AcmeChallenge::Auto => {
                let first = match self.shared.has_plain_frontend() {
                    true => ChallengeKind::Http01,
                    false => ChallengeKind::TlsAlpn01,
                };
                (if failures % 2 == 1 { first.other() } else { first }, true)
            }
        }
    }

    /// Runs one order to its end, within five minutes.
    fn order(&self, ready: &mut Ready, name: &str, failures: u32) -> Result<Issued, Error> {
        let (challenge, any_challenge) = self.challenge(failures);
        let options = OrderOptions {
            directory: self.shared.options.directory.clone(),
            name: name.to_owned(),
            email: self.shared.options.email.clone(),
            challenge,
            any_challenge,
        };
        let Ready { account, client, runtime, .. } = ready;
        let conversation = converse(account, client, &self.shared, options);
        // The timer needs the runtime, so it is made inside it.
        let limited = async { tokio::time::timeout(ORDER_LIMIT, conversation).await };
        match runtime.block_on(limited) {
            Ok(result) => result,
            Err(_) => Err(Error::unexpected(format!(
                "The order for `{name}` took longer than five minutes."
            ))),
        }
    }
}

/// Carries out the actions of one order: send, publish a challenge answer, wait.
async fn converse(
    account: &mut Account,
    client: &Client,
    shared: &Shared,
    options: OrderOptions,
) -> Result<Issued, Error> {
    let (mut order, mut action) = Order::begin(account, options);
    loop {
        action = match action {
            Action::Send(request) => order.advance(client.send(&request).await?),
            Action::Present(challenge) => {
                shared.present(&challenge, now())?;
                order.presented()
            }
            Action::Wait(seconds) => {
                tokio::time::sleep(Duration::from_secs(seconds)).await;
                order.resume()
            }
            Action::Done(issued) => return Ok(*issued),
            Action::Failed(error) => return Err(error),
        };
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    const NOW: u64 = 1_795_516_496;

    fn issue(name: &str, key: &KeyPair, not_after: u64) -> String {
        let authority = KeyPair::generate().unwrap();
        let template = x509::Template {
            issuer: "Test Authority",
            subject: name,
            names: &[name],
            not_before: NOW - 60,
            not_after,
            serial: 1,
            ..x509::Template::default()
        };
        let leaf = x509::write(&template, &key.subject_public_key_info(), &authority).unwrap();
        pem::encode("CERTIFICATE", &leaf)
    }

    #[test]
    fn only_a_sound_chain_is_served() {
        let key = KeyPair::generate().unwrap();
        let chain = issue("example.org", &key, NOW + 1000);
        let found = sound("example.org", &chain, &key, NOW).unwrap();
        assert_eq!(found.fields.not_after, NOW + 1000);
        assert_eq!(found.fields.issuer, "Test Authority");
        let code = |result: Result<Sound, Error>| result.err().unwrap().code;
        assert_eq!(code(sound("other.example", &chain, &key, NOW)), "ACME008");
        assert_eq!(code(sound("example.org", &chain, &key, NOW + 1000)), "ACME008");
        let other = KeyPair::generate().unwrap();
        assert_eq!(code(sound("example.org", &chain, &other, NOW)), "ACME008");
        assert_eq!(code(sound("example.org", "no pem", &key, NOW)), "ACME008");
    }

    #[test]
    fn a_challenge_certificate_is_served_without_the_key_check() {
        let key = KeyPair::generate().unwrap();
        let der = x509::challenge_certificate(&key, "example.org", "a.b", NOW).unwrap();
        assert!(certified(vec![der], &key, false).is_ok());
    }
}
