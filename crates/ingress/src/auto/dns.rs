//! Turns the `global.acme.dns` object into the settings of the DNS-01 solver: it reads
//! the TSIG key file and finds the resolver of the system.

use std::io::Read;
use std::path::Path;
use std::time::Duration;

use sibuna_acme::dns::{DnsOptions, Lookup, Provider, TsigKey, cloudflare, lookup};
use sibuna_acme::{Call, Error, Response};
use sibuna_lb::{DnsConfig, DnsProvider};

/// The largest key file and the largest `resolv.conf` we read.
const MAX_FILE: u64 = 64 * 1024;

fn read(path: &Path) -> std::io::Result<String> {
    let mut text = String::new();
    std::fs::File::open(path)?.take(MAX_FILE).read_to_string(&mut text)?;
    Ok(text)
}

/// The TSIG key `name` with the secret of `file`. Fails with `ACME009` when the file
/// cannot be read or holds no base64 secret. The secret is in no message.
fn key(name: &str, file: &str) -> Result<TsigKey, Error> {
    let text = read(Path::new(file)).map_err(|error| {
        Error::provider(format!("The TSIG key file `{file}` cannot be read: {error}."))
    })?;
    TsigKey::parse(name, &text).ok_or_else(|| {
        Error::provider(format!(
            "The TSIG key file `{file}` holds no secret: expected one line of base64."
        ))
    })
}

/// Sends the calls of a DNS provider that speaks HTTP, with the trust roots of the
/// system.
///
/// The provider runs inside an order, which itself runs on the current-thread runtime
/// of the certificate thread, and also outside of one, at a cleanup. A runtime cannot
/// block on a second future from inside itself. So each call gets a thread and a small
/// runtime of its own, and the caller waits for it. A call takes
/// [`cloudflare::CALL_LIMIT`] at most.
pub(super) struct Sender {
    client: super::client::Client,
}

impl Sender {
    /// Loads the trust roots of the system. Fails with `ACME009` when there are none.
    pub fn load() -> Result<Self, Error> {
        let client = super::client::Client::load(None).map_err(|error| {
            Error::provider(format!("The DNS provider has no HTTPS client. {}", error.message))
        })?;
        Ok(Self { client })
    }

    /// Sends one call and waits for the answer.
    pub fn send(&self, call: &Call) -> Result<Response, Error> {
        let exchange = || {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build();
            let runtime = runtime.map_err(|error| {
                Error::unreachable(format!("No runtime for the call: {error}."))
            })?;
            let limited = async {
                let exchange = self.client.call(call, cloudflare::MAX_RESPONSE);
                tokio::time::timeout(cloudflare::CALL_LIMIT, exchange).await
            };
            match runtime.block_on(limited) {
                Ok(result) => result,
                Err(_) => Err(Error::unreachable(format!("{}: no answer in time.", call.url))),
            }
        };
        let joined = std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name("edge-acme-dns".into())
                .spawn_scoped(scope, exchange)
                .map(|thread| thread.join())
        });
        match joined {
            Ok(Ok(result)) => result,
            _ => Err(Error::unreachable("The call of the DNS provider could not be run.")),
        }
    }
}

/// The sender that the provider of `config` needs: one for Cloudflare, none for a hook
/// and for a dynamic update.
pub(super) fn sender(config: &DnsConfig) -> Result<Option<Sender>, Error> {
    match config.provider {
        DnsProvider::Cloudflare { .. } => Sender::load().map(Some),
        DnsProvider::Hook(_) | DnsProvider::Rfc2136 { .. } => Ok(None),
    }
}

/// The settings of the solver for `config`. Without `resolver`, the first `nameserver`
/// of `/etc/resolv.conf` finds the zone and follows a delegation; when there is none, a
/// check that needs one fails later with its own message.
pub(super) fn options(config: &DnsConfig) -> Result<DnsOptions, Error> {
    let provider = match &config.provider {
        DnsProvider::Hook(program) => Provider::Hook { program: program.into() },
        DnsProvider::Cloudflare { token_file, zone, api } => Provider::Cloudflare {
            token_file: token_file.into(),
            zone: zone.clone(),
            api: api.clone().unwrap_or_else(|| cloudflare::DEFAULT_API.to_owned()),
        },
        DnsProvider::Rfc2136 { server, key: named, zone } => Provider::Rfc2136 {
            server: *server,
            key: named.as_ref().map(|(name, file)| key(name, file)).transpose()?,
            zone: zone.clone(),
        },
    };
    let system = || {
        read(Path::new("/etc/resolv.conf")).ok().and_then(|text| lookup::system_resolver(&text))
    };
    let lookup = Lookup {
        resolver: config.resolver.or_else(system),
        servers: config.servers.clone(),
        ..Lookup::default()
    };
    Ok(DnsOptions {
        provider,
        check: config.check,
        timeout: Duration::from_secs(config.timeout),
        wait: Duration::from_secs(config.wait),
        lookup,
        follow_cname: config.follow_cname,
    })
}
