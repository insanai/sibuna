//! The ACME authorities of the certificate thread (SID 0021): the first one and those
//! of `fallback`. One attempt asks them in order and stops at the first certificate.
//!
//! ```text
//!   storage/
//!     AUTHORITY-1/   account key, certs/, locks/, retry state, DNS records
//!     AUTHORITY-2/   certs/ of the certificates that it issued
//! ```
//!
//! All authorities share the account key of the first one, so every node that shares
//! the storage answers an HTTP-01 challenge of any of them. The lock, the retry state
//! and the DNS record of a name live with the first authority.

use std::io::Read;
use std::path::Path;

use sibuna_acme::dns::{DnsOptions, Solver};
use sibuna_acme::store::Store;
use sibuna_acme::{Account, Binding, ChallengeKind, Error, Issued, OrderOptions};

use super::super::Event;
use super::super::client::Client;
use super::{Driver, Entry, ORDER_LIMIT, converse};

/// The largest file of a binding key that we read.
const MAX_KEY_FILE: u64 = 4096;

/// One authority: its files, its account and the client that reaches it.
pub(super) struct Authority {
    /// The URL of the directory.
    pub directory: String,
    email: Option<String>,
    pub store: Store,
    account: Account,
    pub client: Client,
    binding: Option<Binding>,
    /// The `renewalInfo` URL of the directory. `None`: not asked yet. `Some(None)`: the
    /// authority offers none.
    pub renewal_info: Option<Option<String>>,
}

/// Reads the binding of an authority from its key file. Fails with `ACME012` when the
/// file cannot be read or holds no base64url key. The key is in no message.
fn binding(eab: &sibuna_lb::Eab) -> Result<Binding, Error> {
    let file = &eab.key_file;
    let mut text = String::new();
    let read = std::fs::File::open(Path::new(file))
        .and_then(|opened| opened.take(MAX_KEY_FILE).read_to_string(&mut text));
    if let Err(error) = read {
        return Err(Error::binding(format!("The key file `{file}` cannot be read: {error}.")));
    }
    Binding::parse(&eab.kid, &text).ok_or_else(|| {
        Error::binding(format!("The key file `{file}` holds no key: expected base64url."))
    })
}

impl Authority {
    /// Opens the directory of `config` under `storage`. `keys` is the store that holds
    /// the account key: that of the first authority.
    fn open(
        storage: &Path,
        config: &sibuna_lb::Authority,
        keys: Option<&Store>,
    ) -> Result<Self, Error> {
        let store = Store::open(storage, &config.directory)?;
        let account = Account::new(keys.unwrap_or(&store).load_account()?);
        Ok(Self {
            directory: config.directory.clone(),
            email: config.email.clone(),
            account,
            client: Client::load(config.ca_file.as_deref())?,
            binding: config.eab.as_ref().map(binding).transpose()?,
            renewal_info: None,
            store,
        })
    }
}

/// What an order needs: the authorities, the runtime of their clients, and the
/// settings of DNS-01 when the topology has them.
pub(super) struct Ready {
    pub first: Authority,
    others: Vec<Authority>,
    pub runtime: tokio::runtime::Runtime,
    pub dns: Option<DnsOptions>,
}

impl Ready {
    /// Opens every authority of the options. Fails when one cannot be opened: a
    /// fallback that does not work is found at the start, not on the day it is needed.
    pub fn open(options: &sibuna_lb::AcmeOptions) -> Result<Self, Error> {
        let storage = Path::new(&options.storage);
        let mut listed = options.authorities().into_iter();
        let first = listed.next().ok_or_else(|| Error::storage("No authority is listed."))?;
        let first = Authority::open(storage, &first, None)?;
        let others = listed
            .map(|config| Authority::open(storage, &config, Some(&first.store)))
            .collect::<Result<Vec<_>, _>>()?;
        let dns = options.dns.as_ref().map(super::super::dns::options).transpose()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| Error::unreachable(format!("No runtime for the client: {error}.")))?;
        Ok(Self { first, others, runtime, dns })
    }

    /// The thumbprint of the account key, which all authorities share.
    pub fn thumbprint(&self) -> String {
        self.first.account.thumbprint()
    }

    /// The authorities in the order in which an attempt asks them.
    pub fn all(&self) -> impl Iterator<Item = &Authority> {
        std::iter::once(&self.first).chain(&self.others)
    }

    /// The authority at `index`, or the first one for an index that is not listed.
    pub fn at(&self, index: usize) -> &Authority {
        self.all().nth(index).unwrap_or(&self.first)
    }

    /// As [`Ready::at`], to change what the thread remembers of the authority.
    pub fn at_mut(&mut self, index: usize) -> &mut Authority {
        match index.checked_sub(1).and_then(|other| self.others.get_mut(other)) {
            Some(other) => other,
            None => &mut self.first,
        }
    }
}

impl Driver {
    /// One attempt at the authorities, in order. It stops at the first certificate and
    /// returns it with the word of its challenge and the index of its authority. A
    /// failure that is followed by another authority is reported. The last failure is
    /// returned.
    pub(super) fn order_any(
        &self,
        ready: &mut Ready,
        name: &str,
        entry: &Entry,
    ) -> Result<(Issued, &'static str, usize), Error> {
        let count = 1 + ready.others.len();
        let mut failure = Error::unexpected("No authority was asked.");
        for index in 0..count {
            // A record whose cleanup failed last time goes first: the order below
            // remembers its own record in the same place.
            self.clean(ready, name);
            let issued = self.order(ready, index, name, entry);
            self.shared.withdraw();
            self.clean(ready, name);
            match issued {
                Ok((issued, via)) => return Ok((issued, via, index)),
                Err(error) => failure = error,
            }
            if index + 1 == count || self.stopping() {
                break;
            }
            (self.report)(&Event::Fallback {
                name: name.to_owned(),
                authority: ready.at(index).directory.clone(),
                next: ready.at(index + 1).directory.clone(),
                error: failure.clone(),
            });
        }
        Err(failure)
    }

    /// The certificate that an order at the authority `index` replaces: the served
    /// one, when that authority issued it and renewal information is on.
    fn replaced(&self, entry: &Entry, index: usize) -> Option<String> {
        let served = entry.served.as_ref().filter(|_| entry.issued_by == index)?;
        self.shared.options.ari.then(|| sibuna_acme::ari::certificate_id(served)).flatten()
    }

    /// Runs one order at the authority `index` to its end, within five minutes and the
    /// waits of DNS-01. Returns the certificate and the word of the challenge that was
    /// answered.
    fn order(
        &self,
        ready: &mut Ready,
        index: usize,
        name: &str,
        entry: &Entry,
    ) -> Result<(Issued, &'static str), Error> {
        let (challenge, any_challenge) = self.challenge(name, entry.failures);
        let chosen = ready.at(index);
        let options = OrderOptions {
            directory: chosen.directory.clone(),
            name: name.to_owned(),
            email: chosen.email.clone(),
            challenge,
            any_challenge,
            binding: chosen.binding.clone(),
            replaces: self.replaced(entry, index),
        };
        let Ready { first, others, runtime, dns } = ready;
        // The DNS record of a name is remembered with the first authority.
        let records = &first.store;
        let (account, client) = match index.checked_sub(1).and_then(|at| others.get_mut(at)) {
            Some(other) => (&mut other.account, &other.client),
            None => (&mut first.account, &first.client),
        };
        self.conduct(Parts { account, client, records, runtime, dns: dns.as_ref() }, options)
    }

    fn conduct(
        &self,
        parts: Parts<'_>,
        options: OrderOptions,
    ) -> Result<(Issued, &'static str), Error> {
        let Parts { account, client, records, runtime, dns } = parts;
        let name = options.name.clone();
        let solver = dns.map(|options| Solver { options, store: records });
        let mut limit = ORDER_LIMIT;
        if let (ChallengeKind::Dns01, Some(dns)) = (options.challenge, dns) {
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

/// The borrowed parts of one order.
struct Parts<'a> {
    account: &'a mut Account,
    client: &'a Client,
    /// The store that remembers the DNS record: that of the first authority.
    records: &'a Store,
    runtime: &'a tokio::runtime::Runtime,
    dns: Option<&'a DnsOptions>,
}
