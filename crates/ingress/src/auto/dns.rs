//! Turns the `global.acme.dns` object into the settings of the DNS-01 solver: it reads
//! the TSIG key file and finds the resolver of the system.

use std::io::Read;
use std::path::Path;
use std::time::Duration;

use sibuna_acme::Error;
use sibuna_acme::dns::{DnsOptions, Lookup, Provider, TsigKey, lookup};
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

/// The settings of the solver for `config`. Without `resolver`, the first `nameserver`
/// of `/etc/resolv.conf` finds the zone; when there is none, a check that needs one
/// fails later with its own message.
pub(super) fn options(config: &DnsConfig) -> Result<DnsOptions, Error> {
    let provider = match &config.provider {
        DnsProvider::Hook(program) => Provider::Hook { program: program.into() },
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
    })
}
