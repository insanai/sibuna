//! The thread `edge-acme`: it loads stored certificates, orders missing ones, renews the
//! ones that are due and retries failures, one name at a time (SID 0021).
//!
//! A name has one of two sources. The ACME authority issues after an order with a
//! challenge. The local authority issues at once, for internal names and addresses.
//! Storage, lock, schedule and retry are the same for both.

mod admit;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use sibuna_acme::dns::{DnsOptions, Solver};
use sibuna_acme::local::LocalAuthority;
use sibuna_acme::store::{Retry, Store};
use sibuna_acme::{
    Account, Action, ChallengeKind, Error, Issued, KeyPair, Order, OrderOptions, pem, schedule,
    x509,
};
use sibuna_lb::{AcmeChallenge, AutoName, is_address};

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
    /// How the served certificate was obtained, once an attempt of ours succeeded.
    via: Option<&'static str>,
}

impl Entry {
    /// When the served certificate is due for renewal. Without one: at once.
    fn renew_at(&self) -> u64 {
        self.served.as_ref().map_or(0, |c| schedule::renew_at(c.not_before, c.not_after))
    }
}

/// What an order needs: the files, the account, the client and its runtime, and the
/// settings of DNS-01 when the topology has them.
struct Ready {
    store: Store,
    account: Account,
    client: Client,
    runtime: tokio::runtime::Runtime,
    dns: Option<DnsOptions>,
}

/// The local authority and the files of its certificates.
struct Local {
    authority: LocalAuthority,
    store: Store,
}

/// Where the certificate of a name comes from.
enum Source<'a> {
    Acme(&'a mut Ready),
    Local(&'a Local),
}

impl Source<'_> {
    fn store(&self) -> &Store {
        match self {
            Self::Acme(ready) => &ready.store,
            Self::Local(local) => &local.store,
        }
    }
}

/// The failures to open a source, and the time of the next try.
#[derive(Default)]
struct Backoff {
    failures: u32,
    at: u64,
}

impl Backoff {
    /// Counts a failure and returns the time of the next try.
    fn fail(&mut self) -> u64 {
        self.failures += 1;
        self.at = now() + schedule::retry_delay(self.failures, None);
        self.at
    }
}

/// The state of the thread.
pub(super) struct Driver {
    shared: Arc<Shared>,
    report: Notify,
    entries: BTreeMap<String, Entry>,
    /// The ACME source, once it could be opened, and the failures to open it.
    ready: Option<Ready>,
    ready_backoff: Backoff,
    /// The local authority, once it could be opened, and the failures to open it.
    local: Option<Local>,
    local_backoff: Backoff,
    /// The client of the `ask` URL of issuance on demand, once it was needed.
    asker: Option<admit::Asker>,
}

impl Driver {
    pub fn new(shared: Arc<Shared>, report: Notify) -> Self {
        Self {
            shared,
            report,
            entries: BTreeMap::new(),
            ready: None,
            ready_backoff: Backoff::default(),
            local: None,
            local_backoff: Backoff::default(),
            asker: None,
        }
    }

    fn stopping(&self) -> bool {
        self.shared.stopping.load(Ordering::Acquire)
    }

    /// Runs until the handle is dropped.
    pub fn run(mut self) {
        while !self.stopping() {
            // The names that handshakes asked for are decided first. They stay queued
            // until then, so the handshakes know that they wait.
            let queued = self.shared.demand.queued();
            let mut names = self.shared.names();
            names.extend(queued.iter().cloned());
            self.prepare(&names);
            self.admit(&queued);
            let names = self.shared.names();
            let sleep = self.round(&names);
            self.shared.sleep(Duration::from_secs(sleep.clamp(1, LONGEST_SLEEP)));
        }
    }

    /// Opens the sources that the names need and that are not open: the store, the
    /// account and the client of the ACME authority, and the local authority. A node
    /// with internal names only never opens the first. A failure is reported and tried
    /// again with the delay of a failed order.
    fn prepare(&mut self, names: &[AutoName]) {
        let wants_acme = names.iter().any(|name| !name.local);
        if wants_acme && self.ready.is_none() && now() >= self.ready_backoff.at {
            match self.try_prepare() {
                Ok(ready) => {
                    self.ready_backoff = Backoff::default();
                    *super::write(&self.shared.thumbprint) = Some(ready.account.thumbprint());
                    self.ready = Some(ready);
                }
                Err(error) => {
                    let retry_at = self.ready_backoff.fail();
                    self.unprepared(error, retry_at);
                }
            }
        }
        let wants_local = names.iter().any(|name| name.local);
        if wants_local && self.local.is_none() && now() >= self.local_backoff.at {
            match self.try_local() {
                Ok(local) => {
                    self.local_backoff = Backoff::default();
                    self.local = Some(local);
                }
                Err(error) => {
                    let retry_at = self.local_backoff.fail();
                    self.unprepared(error, retry_at);
                }
            }
        }
    }

    fn unprepared(&self, error: Error, retry_at: u64) {
        self.shared.failures.fetch_add(1, Ordering::Relaxed);
        (self.report)(&Event::Failed { name: None, error, retry_at });
    }

    fn try_prepare(&self) -> Result<Ready, Error> {
        let options = &self.shared.options;
        let store = Store::open(Path::new(&options.storage), &options.directory)?;
        let account = Account::new(store.load_account()?);
        let client = Client::load(options.ca_file.as_deref())?;
        let dns = options.dns.as_ref().map(super::dns::options).transpose()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| Error::unreachable(format!("No runtime for the client: {error}.")))?;
        Ok(Ready { store, account, client, runtime, dns })
    }

    fn try_local(&self) -> Result<Local, Error> {
        let storage = Path::new(&self.shared.options.storage);
        let authority = LocalAuthority::open(storage, now())?;
        let store = Store::open_local(storage)?;
        Ok(Local { authority, store })
    }

    /// Looks at every name once and returns the seconds until the next one is due.
    fn round(&mut self, names: &[AutoName]) -> u64 {
        self.entries.retain(|known, _| names.iter().any(|name| name.name == *known));
        self.shared.forget_except(names);
        // The sources leave the driver for the round, so that the methods can borrow it.
        let (mut ready, local) = (self.ready.take(), self.local.take());
        for wanted in names {
            if self.stopping() {
                break;
            }
            let mut source = match (wanted.local, &mut ready, &local) {
                (true, _, Some(local)) => Source::Local(local),
                (false, Some(ready), _) => Source::Acme(ready),
                _ => continue,
            };
            let name = &wanted.name;
            let demanded = self.shared.is_demanded(name);
            let known = self.entries.remove(name);
            let before = known.as_ref().and_then(|entry| entry.served.as_ref());
            let before = before.map(|served| served.not_after);
            let mut entry = known.unwrap_or_else(|| self.adopt(&source, name));
            if entry.error.is_none() && self.is_stale(name, &entry) {
                entry.next_attempt = entry.next_attempt.min(now());
            }
            if demanded && self.leaves(name, &mut entry) {
                continue;
            }
            let ordering = self.shared.ordering.load(Ordering::Acquire);
            let attempted = ordering && entry.next_attempt <= now();
            if attempted {
                self.attempt(&mut source, name, &mut entry);
            }
            // The handshakes that wait for a name on demand are woken before the pause.
            let kept = !demanded || self.settle(name, &entry, before);
            if attempted {
                std::thread::sleep(PACE);
            }
            if kept {
                self.entries.insert(name.clone(), entry);
            }
        }
        (self.ready, self.local) = (ready, local);
        let waiting = |open: bool, backoff: &Backoff, local: bool| {
            (!open && names.iter().any(|name| name.local == local)).then_some(backoff.at)
        };
        let attempts = self.entries.values().map(|entry| entry.next_attempt);
        let next = attempts
            .chain(waiting(self.ready.is_some(), &self.ready_backoff, false))
            .chain(waiting(self.local.is_some(), &self.local_backoff, true))
            .min();
        next.unwrap_or(u64::MAX).saturating_sub(now())
    }

    /// Whether the served certificate of an address lacks an address that the daemon
    /// manages now. A client that connects to an address sends no server name, so one
    /// certificate lists all of them.
    fn is_stale(&self, name: &str, entry: &Entry) -> bool {
        let Some(served) = entry.served.as_ref().filter(|_| is_address(name)) else {
            return false;
        };
        let addresses = self.shared.names().into_iter().filter(|name| is_address(&name.name));
        addresses.filter(|name| name.local).any(|name| !served.names.contains(&name.name))
    }

    /// The first look at a name: its stored certificate and the failures of an earlier
    /// run. A restart therefore orders nothing while the certificate is fresh, and waits
    /// as the stopped daemon would have waited.
    fn adopt(&self, source: &Source<'_>, name: &str) -> Entry {
        let mut entry = Entry::default();
        let now = now();
        let store = source.store();
        self.look(store, name, &mut entry, now);
        if let Source::Acme(ready) = source {
            self.clean_leftover(ready, name);
        }
        let retry = store.load_retry(name);
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
    fn look(&self, store: &Store, name: &str, entry: &mut Entry, now: u64) -> bool {
        let Ok(Some(stored)) = store.load_certificate(name) else { return false };
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
        let via = entry.via.unwrap_or_else(|| self.planned(name));
        self.shared.set_status(CertificateStatus {
            name: name.to_owned(),
            origin: self.shared.origin(name),
            via,
            issuer: entry.served.as_ref().map(|served| served.issuer.clone()),
            not_after: entry.served.as_ref().map(|served| served.not_after),
            next_attempt: Some(entry.next_attempt),
            state: state.unwrap_or(rest),
            error: entry.error.clone(),
        });
    }

    /// How the next certificate of a name is obtained: `local`, or the challenge.
    fn planned(&self, name: &str) -> &'static str {
        let local = self.shared.names().iter().any(|known| known.name == name && known.local);
        if local { "local" } else { self.challenge(name, 0).0.word() }
    }

    /// Removes the DNS-01 record of an order that never cleaned up, because the daemon
    /// died. We take the lock of the name first: while another node holds it, the record
    /// belongs to its running order.
    fn clean_leftover(&self, ready: &Ready, name: &str) {
        if ready.store.load_presented(name).is_none() {
            return;
        }
        if let Ok(Some(_lock)) = ready.store.lock(name) {
            self.clean(ready, name);
        }
    }

    /// Removes the DNS-01 record of the order that just ended, if it presented one. A
    /// failure is reported. It does not fail the order, and the record stays remembered.
    fn clean(&self, ready: &Ready, name: &str) {
        let Some(options) = &ready.dns else { return };
        if let Err(error) = (Solver { options, store: &ready.store }).cleanup(name) {
            (self.report)(&Event::CleanupFailed { name: name.to_owned(), error });
        }
    }

    /// One attempt for a name that is due: look at the storage, take the lock, then
    /// order from the ACME authority or issue from the local one.
    fn attempt(&self, source: &mut Source<'_>, name: &str, entry: &mut Entry) {
        let now = now();
        // Another node that shares the storage may have renewed already.
        let found = self.look(source.store(), name, entry, now);
        if found && entry.renew_at() > now && !self.is_stale(name, entry) {
            self.succeeded(source.store(), name, entry);
            return;
        }
        let _lock = match source.store().lock(name) {
            Ok(Some(lock)) => lock,
            Ok(None) => {
                entry.next_attempt = now + LOCK_WAIT;
                self.publish(name, entry, Some(CertificateState::Waiting));
                return;
            }
            Err(error) => return self.failed(source.store(), name, entry, error),
        };
        self.publish(name, entry, Some(CertificateState::Ordering));
        let issued = match source {
            Source::Acme(ready) => {
                // A record whose cleanup failed last time goes first: the order below
                // remembers its own record in the same place.
                self.clean(ready, name);
                let issued = self.order(ready, name, entry.failures);
                self.shared.withdraw();
                self.clean(ready, name);
                issued
            }
            Source::Local(local) => self.issue(local, name).map(|issued| (issued, "local")),
        };
        let store = source.store();
        let installed = issued.and_then(|(issued, via)| {
            let found = sound(name, &issued.chain_pem, &issued.key, now)?;
            store.save_certificate(name, &issued.chain_pem, &issued.key)?;
            Ok((found, via))
        });
        match installed {
            Ok((found, via)) => {
                let renewed = entry.served.is_some();
                let not_after = found.fields.not_after;
                self.shared.install(name, found.certified);
                entry.served = Some(found.fields);
                entry.via = Some(via);
                self.succeeded(store, name, entry);
                (self.report)(&Event::Obtained { name: name.to_owned(), not_after, renewed });
            }
            Err(error) => self.failed(store, name, entry, error),
        }
    }

    /// Issues from the local authority. The certificate of an address lists every
    /// address that the daemon manages, with `name` first.
    fn issue(&self, local: &Local, name: &str) -> Result<Issued, Error> {
        let managed = self.shared.names();
        let mut names = vec![name];
        if is_address(name) {
            let others = managed.iter().filter(|other| other.local && other.name != name);
            names
                .extend(others.map(|other| other.name.as_str()).filter(|other| is_address(other)));
        }
        local.authority.issue(&names, self.shared.options.internal_lifetime, now())
    }

    fn succeeded(&self, store: &Store, name: &str, entry: &mut Entry) {
        store.clear_retry(name);
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
    fn failed(&self, store: &Store, name: &str, entry: &mut Entry, error: Error) {
        entry.failures = entry.failures.saturating_add(1);
        entry.next_attempt = now() + schedule::retry_delay(entry.failures, error.retry_after);
        entry.error = Some(format!("{} ({})", error.title, error.code));
        let retry = Retry { failures: entry.failures, next_attempt: entry.next_attempt };
        let _ = store.save_retry(name, retry);
        self.shared.failures.fetch_add(1, Ordering::Relaxed);
        self.publish(name, entry, None);
        let name = Some(name.to_owned());
        (self.report)(&Event::Failed { name, error, retry_at: entry.next_attempt });
    }

    /// The challenge of the next attempt. A wildcard takes DNS-01, which alone proves
    /// it. Else `auto` starts with HTTP-01 when the topology has a plain frontend, and
    /// takes the other type after each failure.
    fn challenge(&self, name: &str, failures: u32) -> (ChallengeKind, bool) {
        if name.starts_with("*.") {
            return (ChallengeKind::Dns01, false);
        }
        match self.shared.options.challenge {
            AcmeChallenge::Http01 => (ChallengeKind::Http01, false),
            AcmeChallenge::TlsAlpn01 => (ChallengeKind::TlsAlpn01, false),
            AcmeChallenge::Dns01 => (ChallengeKind::Dns01, false),
            AcmeChallenge::Auto => {
                let first = match self.shared.has_plain_frontend() {
                    true => ChallengeKind::Http01,
                    false => ChallengeKind::TlsAlpn01,
                };
                (if failures % 2 == 1 { first.other() } else { first }, true)
            }
        }
    }

    /// Runs one order to its end, within five minutes and the waits of DNS-01. Returns
    /// the certificate and the word of the challenge that was answered.
    fn order(
        &self,
        ready: &mut Ready,
        name: &str,
        failures: u32,
    ) -> Result<(Issued, &'static str), Error> {
        let (challenge, any_challenge) = self.challenge(name, failures);
        let options = OrderOptions {
            directory: self.shared.options.directory.clone(),
            name: name.to_owned(),
            email: self.shared.options.email.clone(),
            challenge,
            any_challenge,
        };
        let Ready { account, client, runtime, store, dns } = ready;
        let solver = dns.as_ref().map(|options| Solver { options, store });
        let mut limit = ORDER_LIMIT;
        if let (ChallengeKind::Dns01, Some(dns)) = (challenge, dns.as_ref()) {
            limit += dns.wait + dns.timeout + 2 * sibuna_acme::dns::HOOK_TIMEOUT;
        }
        let conversation = converse(account, client, &self.shared, options, solver.as_ref());
        // The timer needs the runtime, so it is made inside it.
        let limited = async { tokio::time::timeout(limit, conversation).await };
        match runtime.block_on(limited) {
            Ok(result) => result,
            Err(_) => Err(Error::unexpected(format!(
                "The order for `{name}` took longer than {} seconds.",
                limit.as_secs()
            ))),
        }
    }
}

/// Carries out the actions of one order: send, publish a challenge answer, wait.
///
/// DNS-01 runs a program and waits for name servers. It blocks this thread, which has
/// no other task: the runtime is a current-thread one of the certificate thread.
async fn converse(
    account: &mut Account,
    client: &Client,
    shared: &Shared,
    options: OrderOptions,
    solver: Option<&Solver<'_>>,
) -> Result<(Issued, &'static str), Error> {
    let mut via = options.challenge.word();
    let name = options.name.clone();
    let (mut order, mut action) = Order::begin(account, options);
    loop {
        action = match action {
            Action::Send(request) => order.advance(client.send(&request).await?),
            Action::Present(challenge) => {
                via = challenge.kind.word();
                match (challenge.kind, solver) {
                    (ChallengeKind::Dns01, Some(solver)) => {
                        solver.present(&name, &challenge, &mut |time| shared.pause(time))?;
                    }
                    (ChallengeKind::Dns01, None) => {
                        return Err(Error::provider("No DNS provider is configured."));
                    }
                    _ => shared.present(&challenge, now())?,
                }
                order.presented()
            }
            Action::Wait(seconds) => {
                tokio::time::sleep(Duration::from_secs(seconds)).await;
                order.resume()
            }
            Action::Done(issued) => return Ok((*issued, via)),
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
