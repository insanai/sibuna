//! The part of the certificate thread that decides the names of issuance on demand
//! (SID 0021): the guards that take time, the release of a name that nobody uses, and
//! the release of a name whose first order failed.

use std::time::Duration;

use sibuna_acme::store::Store;
use sibuna_acme::{Method, Request, schedule};
use sibuna_lb::AutoName;

use super::super::client::Client;
use super::super::demand::DENIAL_MS;
use super::super::{Event, now_ms};
use super::{Driver, Entry, now, sound};

/// The longest wait for the answer of the `ask` URL.
const ASK_LIMIT: Duration = Duration::from_secs(5);

/// Why a name was refused, for the log.
const NOT_READY: &str = "its certificate source is not open";
const NOT_ALLOWED: &str = "the ask URL did not allow it";
const NO_TOKEN: &str = "the rate of new certificates is spent";
/// Why a held name was released, for the log.
const UNUSED: &str = "no handshake named it since its certificate";
const WITHDRAWN: &str = "the ask URL no longer allows it";

/// What the `ask` URL said about a name.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Allowed,
    Refused,
    /// No answer within the limit, or no client.
    Silent,
}

/// The client that asks the `ask` URL, with a runtime of its own: a node whose names
/// all go to the local authority has no ACME client.
pub(super) struct Asker {
    client: Client,
    runtime: tokio::runtime::Runtime,
}

impl Asker {
    fn open(ca_file: Option<&str>) -> Option<Self> {
        let client = Client::load(ca_file).ok()?;
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().ok()?;
        Some(Self { client, runtime })
    }

    /// Sends `GET URL?domain=NAME` once. A status from 200 to 299 within five seconds
    /// allows the name, and any other status refuses it.
    fn ask(&self, url: &str, name: &str) -> Verdict {
        let request = Request {
            method: Method::Get,
            url: format!("{url}?domain={name}"),
            body: String::new(),
        };
        let exchange = async { tokio::time::timeout(ASK_LIMIT, self.client.send(&request)).await };
        match self.runtime.block_on(exchange) {
            Ok(Ok(response)) if (200..300).contains(&response.status) => Verdict::Allowed,
            Ok(Ok(_)) => Verdict::Refused,
            _ => Verdict::Silent,
        }
    }
}

/// Whether the storage has a certificate for `name` that is sound and not due. Such a
/// name costs no order, so it passes without `ask` and without a token.
fn has_fresh(store: &Store, name: &str) -> bool {
    let now = now();
    let Ok(Some(stored)) = store.load_certificate(name) else { return false };
    let Ok(found) = sound(name, &stored.chain_pem, &stored.key, now) else { return false };
    schedule::renew_at(found.fields.not_before, found.fields.not_after) > now
}

impl Driver {
    /// Decides every queued name: it becomes a held name, or it is denied for a while.
    /// A held name that a reload listed under `auto` is let go: the list manages it.
    pub(super) fn admit(&mut self, queued: &[AutoName]) {
        for held in self.shared.demand.held_names() {
            if !self.shared.is_demanded(&held.name) {
                self.shared.demand.release(&held.name);
            }
        }
        for wanted in queued {
            if self.stopping() {
                return;
            }
            let refusal = self.guard(wanted).err();
            let now = now_ms();
            match refusal {
                None => self.shared.demand.hold(wanted.clone(), now),
                Some((wait_ms, reason)) => {
                    self.shared.demand.deny(&wanted.name, now.saturating_add(wait_ms), now);
                    let seconds = wait_ms.div_ceil(1000);
                    (self.report)(&Event::Refused { name: wanted.name.clone(), reason, seconds });
                }
            }
        }
        if !queued.is_empty() {
            self.shared.demand.wake();
        }
    }

    /// The guards that take time, in the order of their cost: the storage, the `ask`
    /// URL, the token. A refusal names the milliseconds it lasts and its reason.
    fn guard(&mut self, wanted: &AutoName) -> Result<(), (u64, &'static str)> {
        let fresh = match (wanted.local, &self.ready, &self.local) {
            (true, _, Some(local)) => has_fresh(&local.store, &wanted.name),
            (false, Some(ready), _) => {
                ready.all().any(|authority| has_fresh(&authority.store, &wanted.name))
            }
            _ => return Err((DENIAL_MS, NOT_READY)),
        };
        if fresh {
            return Ok(());
        }
        // A new name needs a yes. Silence refuses it.
        if self.ask(&wanted.name) != Verdict::Allowed {
            return Err((DENIAL_MS, NOT_ALLOWED));
        }
        self.shared.demand.take_token(now_ms()).map_err(|wait_ms| (wait_ms, NO_TOKEN))
    }

    /// Asks the `ask` URL about `name`. Without a URL every name is allowed.
    fn ask(&mut self, name: &str) -> Verdict {
        let Some(url) = self.shared.demand.ask() else { return Verdict::Allowed };
        if self.asker.is_none() {
            self.asker = Asker::open(self.shared.options.ca_file.as_deref());
        }
        self.asker.as_ref().map_or(Verdict::Silent, |asker| asker.ask(url, name))
    }

    /// Looks at a name held on demand whose renewal is due. The name is released, and
    /// not renewed, when no handshake named it since its certificate was obtained, or
    /// when the `ask` URL no longer allows it. When the URL does not answer, the
    /// certificate stays and the renewal waits for the first retry delay. Returns
    /// whether the name was released.
    pub(super) fn leaves(&mut self, name: &str, entry: &mut Entry) -> bool {
        if entry.served.is_none() || entry.next_attempt > now() {
            return false;
        }
        let reason = match self.shared.demand.is_unused(name) {
            true => UNUSED,
            false => match self.ask(name) {
                Verdict::Allowed => return false,
                Verdict::Refused => WITHDRAWN,
                Verdict::Silent => {
                    entry.next_attempt = now() + schedule::FIRST_DELAY;
                    return false;
                }
            },
        };
        self.shared.release(name);
        (self.report)(&Event::Released { name: name.to_owned(), reason });
        true
    }

    /// Ends the look at a name held on demand. A new certificate is recorded. A name
    /// that has no certificate and whose next attempt lies ahead is released and denied
    /// until then: its order failed, in this run or in an earlier one, or another node
    /// holds its lock. The handshakes that wait are woken. Returns whether the name is
    /// still held.
    pub(super) fn settle(&self, name: &str, entry: &Entry, before: Option<u64>) -> bool {
        let now = now_ms();
        if entry.served.as_ref().map(|served| served.not_after) != before {
            self.shared.demand.obtained(name, now);
        }
        let failed = entry.served.is_none() && entry.next_attempt > super::now();
        if failed {
            self.shared.demand.deny(name, entry.next_attempt.saturating_mul(1000), now);
            self.shared.release(name);
        }
        self.shared.demand.wake();
        !failed
    }
}
