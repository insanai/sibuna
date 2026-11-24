//! The DNS-01 challenge (RFC 8555, section 8.4): write the TXT record through a
//! provider, wait until the authoritative servers show it, and remove it afterwards.
//!
//! Unlike the order machine, this module performs blocking I/O: it runs a program and
//! sends DNS messages. The caller runs it on a thread that may block.
//!
//! ```text
//! Solver::present                          Solver::cleanup
//!   store: save "dns" (owner, value)         store: load "dns"
//!   provider: present owner value            provider: cleanup owner value
//!   pause `wait` seconds                     store: clear "dns"
//!   check: every server shows the value
//! ```
//!
//! The file `dns` is written before the provider runs and removed after the cleanup
//! succeeded. A daemon that died in between finds the file and cleans up at its start.

pub mod hook;
pub mod lookup;
#[cfg(any(test, feature = "test-server"))]
pub mod server;
pub mod transport;
pub mod tsig;
pub mod update;
pub mod wire;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub use lookup::Lookup;
pub use tsig::TsigKey;

use crate::order::Challenge;
use crate::store::Store;
use crate::{Error, random_serial};

/// How long a hook program may run, in seconds.
pub const HOOK_TIMEOUT: Duration = Duration::from_secs(60);

/// The time in seconds since 1970.
pub(crate) fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs())
}

/// A random message identifier.
pub(crate) fn random_id() -> Result<u16, Error> {
    let bytes = random_serial()?.to_be_bytes();
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// How the TXT record is written and removed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Provider {
    /// A program of the operator. See [`hook`].
    Hook {
        /// The path of the program.
        program: PathBuf,
    },
    /// A dynamic update to the server of the zone. See [`update`].
    Rfc2136 {
        /// The server that takes the update.
        server: SocketAddr,
        /// The key that signs the update. Without one the update is unsigned.
        key: Option<TsigKey>,
        /// The zone to update. Without one it is found from the SOA record.
        zone: Option<String>,
    },
}

/// The settings of DNS-01. Fill the fields, or start from [`DnsOptions::hook`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsOptions {
    /// How the record is written.
    pub provider: Provider,
    /// Wait until the authoritative servers show the record.
    pub check: bool,
    /// The longest wait for the check.
    pub timeout: Duration,
    /// The pause after the provider returned and before the check.
    pub wait: Duration,
    /// Where the check asks.
    pub lookup: Lookup,
}

impl DnsOptions {
    /// The defaults with a hook program: the check for at most 120 seconds, no pause.
    pub fn hook(program: impl Into<PathBuf>) -> Self {
        Self {
            provider: Provider::Hook { program: program.into() },
            check: true,
            timeout: Duration::from_secs(120),
            wait: Duration::ZERO,
            lookup: Lookup::default(),
        }
    }
}

/// Presents and removes the record of one name.
#[derive(Debug)]
pub struct Solver<'a> {
    /// The settings.
    pub options: &'a DnsOptions,
    /// The store that remembers a presented record.
    pub store: &'a Store,
}

impl Solver<'_> {
    /// Runs the provider for the record `owner` with `value`.
    fn provide(&self, name: &str, owner: &str, value: &str, delete: bool) -> Result<(), Error> {
        match &self.options.provider {
            Provider::Hook { program } => hook::run(hook::Run {
                program,
                action: if delete { "cleanup" } else { "present" },
                owner,
                value,
                name,
                timeout: HOOK_TIMEOUT,
            }),
            Provider::Rfc2136 { server, key, zone } => {
                let found;
                let zone = match zone {
                    Some(zone) => zone.as_str(),
                    None => {
                        let deadline = Instant::now() + self.options.timeout;
                        found = self.options.lookup.zone_of(owner, deadline).map_err(|error| {
                            Error::provider(format!(
                                "The zone of `{owner}` is not known. {} Or set \
                                 `global.acme.dns.rfc2136.zone`.",
                                error.message
                            ))
                        })?;
                        found.as_str()
                    }
                };
                update::send(*server, key.as_ref(), update::Change { zone, owner, value, delete })
            }
        }
    }

    /// Writes the record that answers `challenge` for the `auto` name `name`, and
    /// returns when the authoritative servers show it. `pause` sleeps and returns false
    /// when the daemon stops. The record is remembered first, so [`Solver::cleanup`]
    /// removes it also after a failure here. Fails with `ACME001`, `ACME009` or
    /// `ACME010`.
    pub fn present(
        &self,
        name: &str,
        challenge: &Challenge,
        pause: &mut dyn FnMut(Duration) -> bool,
    ) -> Result<(), Error> {
        let (owner, value) = (challenge.dns_owner(), challenge.dns_value());
        self.store.save_presented(name, &owner, &value)?;
        self.provide(name, &owner, &value, false)?;
        let stopped = || Error::not_visible("The daemon stopped before the record was checked.");
        if !self.options.wait.is_zero() && !pause(self.options.wait) {
            return Err(stopped());
        }
        if !self.options.check {
            return Ok(());
        }
        lookup::wait_visible(&self.options.lookup, &owner, &value, self.options.timeout, pause)
    }

    /// Removes the record that an order of `name` presented, if one is remembered.
    /// Returns whether there was one. Fails with `ACME009`; the record then stays
    /// remembered, and a later call tries again.
    pub fn cleanup(&self, name: &str) -> Result<bool, Error> {
        let Some((owner, value)) = self.store.load_presented(name) else { return Ok(false) };
        self.provide(name, &owner, &value, true)?;
        self.store.clear_presented(name);
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
