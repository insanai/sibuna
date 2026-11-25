//! The state of the ACME server: the nonces, the orders with their authorizations, and
//! the queue of work for the thread that validates and signs. Everything here is
//! memory, and everything has a bound.
//!
//! ```text
//! pending --all authorizations valid--> ready --finalize--> processing --issued--> valid
//!    |                                                           |
//!    +--an authorization invalid--> invalid <--not issued--------+
//! ```

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as _;

use super::{MAX_NONCES, MAX_ORDERS, MAX_TASKS, NONCE_LIFETIME, ORDER_LIFETIME, Task};
use crate::time::format_rfc3339;

/// The nonces that the server handed out and that no request used yet.
#[derive(Default)]
pub(super) struct Nonces {
    /// The nonces in the order of their making, each with the time of it.
    queue: VecDeque<(String, u64)>,
    known: HashSet<String>,
}

impl Nonces {
    /// Remembers a new nonce. At the bound the oldest nonce is dropped.
    pub fn add(&mut self, nonce: String, now: u64) {
        while self.queue.len() >= MAX_NONCES {
            if let Some((oldest, _)) = self.queue.pop_front() {
                self.known.remove(&oldest);
            }
        }
        self.known.insert(nonce.clone());
        self.queue.push_back((nonce, now));
    }

    /// Takes a nonce out and returns whether it was there and is not older than its
    /// lifetime. A nonce is accepted once: the second request with it finds nothing.
    pub fn take(&mut self, nonce: &str, now: u64) -> bool {
        while self.queue.front().is_some_and(|(_, made)| made + NONCE_LIFETIME < now) {
            if let Some((expired, _)) = self.queue.pop_front() {
                self.known.remove(&expired);
            }
        }
        self.known.remove(nonce)
    }

    /// How many nonces are remembered.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.known.len()
    }
}

/// The state of an authorization and of its one challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step {
    /// The client has not asked for the validation yet.
    Pending,
    /// The validation is queued or runs.
    Processing,
    /// The name is proved.
    Valid,
    /// The validation failed.
    Invalid,
}

/// The authorization of one name of an order.
pub(super) struct Authorization {
    pub name: String,
    pub token: String,
    pub step: Step,
    /// Why the validation failed.
    pub error: Option<String>,
}

/// The state of an order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Status {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

impl Status {
    fn word(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Processing => "processing",
            Self::Valid => "valid",
            Self::Invalid => "invalid",
        }
    }
}

/// One order.
pub(super) struct Order {
    /// The thumbprint of the account key that placed the order.
    pub owner: String,
    /// When the order was placed. It is removed [`ORDER_LIFETIME`] seconds later.
    pub created: u64,
    pub authorizations: Vec<Authorization>,
    pub status: Status,
    /// The chain as PEM, once the order is valid.
    pub certificate: Option<String>,
    /// Why the certificate was not issued.
    pub error: Option<String>,
}

impl Order {
    /// Moves a pending order on after a validation: to `invalid` when one failed, to
    /// `ready` when all names are proved.
    fn settle(&mut self) {
        if self.status != Status::Pending {
            return;
        }
        if self.authorizations.iter().any(|authz| authz.step == Step::Invalid) {
            self.status = Status::Invalid;
        } else if self.authorizations.iter().all(|authz| authz.step == Step::Valid) {
            self.status = Status::Ready;
        }
    }

    fn expires(&self) -> String {
        format_rfc3339(self.created + ORDER_LIFETIME)
    }
}

/// Everything the server remembers.
#[derive(Default)]
pub(super) struct State {
    pub nonces: Nonces,
    pub orders: HashMap<String, Order>,
    pub tasks: VecDeque<Task>,
    /// The revocation list that `GET /crl` answers with.
    pub crl: Vec<u8>,
}

impl State {
    /// Removes the orders that have reached the end of their hour.
    pub fn expire(&mut self, now: u64) {
        self.orders.retain(|_, order| order.created + ORDER_LIFETIME > now);
    }

    /// Whether one more order fits, for the account `owner`.
    pub fn has_room(&self, owner: &str) -> bool {
        let own = self.orders.values().filter(|order| order.owner == owner).count();
        self.orders.len() < MAX_ORDERS && own < super::MAX_ACCOUNT_ORDERS
    }

    /// Queues work. Returns whether the queue took it.
    pub fn queue(&mut self, task: Task) -> bool {
        if self.tasks.len() >= MAX_TASKS {
            return false;
        }
        self.tasks.push_back(task);
        true
    }

    /// Records the end of the validation of the authorization `index` of an order.
    /// An order that has left meanwhile is ignored.
    pub fn validated(&mut self, id: &str, index: usize, result: Result<(), String>) {
        let Some(order) = self.orders.get_mut(id) else { return };
        let Some(authz) = order.authorizations.get_mut(index) else { return };
        if authz.step != Step::Processing {
            return;
        }
        match result {
            Ok(()) => authz.step = Step::Valid,
            Err(reason) => {
                authz.step = Step::Invalid;
                authz.error = Some(reason);
            }
        }
        order.settle();
    }

    /// Records the end of the signing of an order: the chain, or why there is none.
    pub fn issued(&mut self, id: &str, result: Result<String, String>) {
        let Some(order) = self.orders.get_mut(id) else { return };
        if order.status != Status::Processing {
            return;
        }
        match result {
            Ok(chain) => {
                order.certificate = Some(chain);
                order.status = Status::Valid;
            }
            Err(reason) => {
                order.error = Some(reason);
                order.status = Status::Invalid;
            }
        }
    }
}

/// A problem document (RFC 7807) with an ACME error type.
pub(super) fn problem(kind: &str, detail: &str, status: u16) -> String {
    let mut text = format!(r#"{{"type":"urn:ietf:params:acme:error:{kind}","detail":"#);
    let _ = sibuna_json::write_string(&mut text, detail);
    let _ = write!(text, r#","status":{status}}}"#);
    text
}

/// The challenge object of the authorization `index` of the order `id`.
pub(super) fn challenge_json(base: &str, id: &str, index: usize, authz: &Authorization) -> String {
    let status = match authz.step {
        Step::Pending => "pending",
        Step::Processing => "processing",
        Step::Valid => "valid",
        Step::Invalid => "invalid",
    };
    let mut text = format!(
        r#"{{"type":"http-01","url":"{base}/chall/{id}.{index}","token":"{}","status":"{status}""#,
        authz.token
    );
    if let Some(reason) = &authz.error {
        let _ = write!(text, r#","error":{}"#, problem("incorrectResponse", reason, 403));
    }
    text.push('}');
    text
}

/// The authorization object `index` of the order `id`.
pub(super) fn authorization_json(base: &str, id: &str, index: usize, order: &Order) -> String {
    let Some(authz) = order.authorizations.get(index) else { return "{}".to_owned() };
    let status = match authz.step {
        Step::Pending | Step::Processing => "pending",
        Step::Valid => "valid",
        Step::Invalid => "invalid",
    };
    let (expires, name) = (order.expires(), &authz.name);
    let challenge = challenge_json(base, id, index, authz);
    let identifier = format!(r#"{{"type":"dns","value":"{name}"}}"#);
    let head = format!(r#""status":"{status}","expires":"{expires}""#);
    format!(r#"{{{head},"identifier":{identifier},"challenges":[{challenge}]}}"#)
}

/// The order object of the order `id`.
pub(super) fn order_json(base: &str, id: &str, order: &Order) -> String {
    let mut text =
        format!(r#"{{"status":"{}","expires":"{}","#, order.status.word(), order.expires());
    let names: Vec<String> = order
        .authorizations
        .iter()
        .map(|authz| format!(r#"{{"type":"dns","value":"{}"}}"#, authz.name))
        .collect();
    let urls: Vec<String> = (0..order.authorizations.len())
        .map(|index| format!(r#""{base}/authz/{id}.{index}""#))
        .collect();
    let _ = write!(
        text,
        r#""identifiers":[{}],"authorizations":[{}],"finalize":"{base}/finalize/{id}""#,
        names.join(","),
        urls.join(",")
    );
    if order.certificate.is_some() {
        let _ = write!(text, r#","certificate":"{base}/cert/{id}""#);
    }
    if let Some(reason) = &order.error {
        let _ = write!(text, r#","error":{}"#, problem("serverInternal", reason, 500));
    }
    text.push('}');
    text
}
