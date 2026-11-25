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

pub mod cloudflare;
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
    /// The API of Cloudflare. See [`cloudflare`].
    Cloudflare {
        /// The file that holds the API token. It is read at each use.
        token_file: PathBuf,
        /// The zone of the record. Without one it is searched from the owner upwards.
        zone: Option<String>,
        /// The base URL of the API: [`cloudflare::DEFAULT_API`] outside tests.
        api: String,
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
    /// Write the record at the target of a CNAME delegation of `_acme-challenge.NAME`.
    pub follow_cname: bool,
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
            follow_cname: true,
        }
    }
}

/// Presents and removes the record of one name.
pub struct Solver<'a> {
    /// The settings.
    pub options: &'a DnsOptions,
    /// The store that remembers a presented record.
    pub store: &'a Store,
    /// Sends the calls of a provider that speaks HTTP. The Cloudflare provider needs
    /// it. The caller owns the sockets and the trust roots.
    pub http: Option<cloudflare::Send<'a>>,
}

impl std::fmt::Debug for Solver<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Solver")
            .field("options", self.options)
            .field("store", self.store)
            .field("http", &self.http.is_some())
            .finish()
    }
}

/// The largest token file that we read.
const MAX_TOKEN_FILE: u64 = 4096;

/// The owner that the authority asks for the `auto` name `name`: `_acme-challenge.` and
/// the name without its `*.`.
fn challenge_owner(name: &str) -> String {
    format!("_acme-challenge.{}", name.strip_prefix("*.").unwrap_or(name))
}

/// Whether `owner` may be handed to a provider: labels of letters, digits, `-` and
/// `_`, 253 bytes at most.
fn is_record_name(owner: &str) -> bool {
    let label = |label: &str| {
        (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    };
    owner.len() <= 253 && owner.split('.').all(label)
}

/// Reads the API token of a file. The token is in no message.
fn read_token(file: &std::path::Path) -> Result<String, Error> {
    use std::io::Read as _;
    let shown = file.display();
    let mut text = String::new();
    let read = std::fs::File::open(file)
        .and_then(|opened| opened.take(MAX_TOKEN_FILE).read_to_string(&mut text));
    if let Err(error) = read {
        return Err(Error::provider(format!("The token file `{shown}` cannot be read: {error}.")));
    }
    cloudflare::token(&text).map(str::to_owned).ok_or_else(|| {
        Error::provider(format!(
            "The token file `{shown}` holds no token: expected one word of printable text."
        ))
    })
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
                challenge: &challenge_owner(name),
                timeout: HOOK_TIMEOUT,
            }),
            Provider::Cloudflare { token_file, zone, api } => {
                let token = read_token(token_file)?;
                let send = self.http.ok_or_else(|| {
                    Error::provider("The Cloudflare provider has no HTTP client.")
                })?;
                let account = cloudflare::Cloudflare { api, token: &token, zone: zone.as_deref() };
                match delete {
                    true => account.cleanup(send, owner, value),
                    false => account.present(send, owner, value),
                }
            }
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
        let value = challenge.dns_value();
        // The record is written where a CNAME delegation of the challenge points. The
        // stored record names that place, so the cleanup removes what was written.
        let owner = match self.options.follow_cname {
            true => {
                let deadline = Instant::now() + self.options.timeout;
                self.options.lookup.final_owner(&challenge.dns_owner(), deadline)?
            }
            false => challenge.dns_owner(),
        };
        // The target comes out of a DNS answer, and a hook may hand it to a shell.
        if !is_record_name(&owner) {
            return Err(Error::provider(format!(
                "The CNAME records of `{}` lead to a name that is no host name.",
                challenge.dns_owner()
            )));
        }
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
