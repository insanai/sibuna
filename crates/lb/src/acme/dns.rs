//! The `global.acme.dns` object: how the daemon answers the DNS-01 challenge
//! (SID 0021). Nothing here opens a socket or a file.

use std::io;
use std::net::SocketAddr;

use sibuna_json::ObjectReader;

use crate::config::{field, invalid};

/// The longest wait of `timeout` and of `wait`, in seconds.
const MAX_WAIT: u64 = 3600;
/// The most servers of `servers`.
const MAX_SERVERS: usize = 8;

/// How the TXT record is written and removed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsProvider {
    /// A program of the operator, run as `PROGRAM present|cleanup RECORD VALUE`.
    Hook(String),
    /// A dynamic update (RFC 2136) to the server of the zone.
    Rfc2136 {
        /// The server that takes the update.
        server: SocketAddr,
        /// The name of the TSIG key, and the file that holds its secret in base64.
        key: Option<(String, String)>,
        /// The zone to update. Without one the daemon finds it from the SOA record.
        zone: Option<String>,
    },
}

/// The `global.acme.dns` object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsConfig {
    /// How the record is written.
    pub provider: DnsProvider,
    /// Wait until every authoritative server shows the record.
    pub check: bool,
    /// The longest wait for the check, in seconds.
    pub timeout: u64,
    /// Seconds to wait after the provider returned and before the check.
    pub wait: u64,
    /// The recursive resolver that finds the zone. `None`: the system's first one.
    pub resolver: Option<SocketAddr>,
    /// The authoritative servers to ask. Empty: the servers of the NS records.
    pub servers: Vec<SocketAddr>,
}

fn address(path: &str, text: &str) -> io::Result<SocketAddr> {
    text.parse().map_err(|_| invalid(format!("{path}: expected \"IP:PORT\", found `{text}`")))
}

fn seconds(r: &mut ObjectReader<'_, '_>, key: &str, least: u64, default: u64) -> io::Result<u64> {
    match field(r.take_u64(key))? {
        None => Ok(default),
        Some(value) if (least..=MAX_WAIT).contains(&value) => Ok(value),
        Some(_) => {
            let path = r.field_path(key);
            Err(invalid(format!("{path}: expected {least} to {MAX_WAIT} seconds")))
        }
    }
}

fn rfc2136(mut r: ObjectReader<'_, '_>) -> io::Result<DnsProvider> {
    let path = r.field_path("server");
    let Some(server) = field(r.take_str("server"))? else {
        return Err(invalid(format!("{path}: an update needs the \"IP:PORT\" of the server")));
    };
    let server = address(&path, server)?;
    let key_name = field(r.take_str("key_name"))?;
    let key_file = field(r.take_str("key_file"))?;
    let key = match (key_name, key_file) {
        (Some(name), Some(file)) if crate::hello::valid_host(name.trim_end_matches('.')) => {
            Some((name.to_owned(), file.to_owned()))
        }
        (None, None) => None,
        (Some(_), Some(_)) => {
            return Err(invalid(format!("{}: expected a DNS name", r.field_path("key_name"))));
        }
        _ => return Err(invalid(format!("{}: key_name and key_file go together", r.path()))),
    };
    let zone = match field(r.take_str("zone"))? {
        None => None,
        Some(zone) if crate::hello::valid_host(zone.trim_end_matches('.')) => {
            Some(zone.trim_end_matches('.').to_ascii_lowercase())
        }
        Some(_) => return Err(invalid(format!("{}: expected a DNS name", r.field_path("zone")))),
    };
    field(r.finish())?;
    Ok(DnsProvider::Rfc2136 { server, key, zone })
}

impl DnsConfig {
    pub(crate) fn parse(mut r: ObjectReader<'_, '_>) -> io::Result<Self> {
        let hook = field(r.take_str("hook"))?;
        let update = field(r.take_object("rfc2136"))?;
        let provider = match (hook, update) {
            (Some(program), None) if !program.is_empty() => DnsProvider::Hook(program.to_owned()),
            (None, Some(update)) => rfc2136(update)?,
            _ => {
                return Err(invalid(format!(
                    "{}: expected one provider, hook (a program) or rfc2136 (an object)",
                    r.path()
                )));
            }
        };
        let check = field(r.take_bool("check"))?.unwrap_or(true);
        let timeout = seconds(&mut r, "timeout", 1, 120)?;
        let wait = seconds(&mut r, "wait", 0, 0)?;
        let path = r.field_path("resolver");
        let resolver =
            field(r.take_str("resolver"))?.map(|text| address(&path, text)).transpose()?;
        let path = r.field_path("servers");
        let servers = match field(r.take_array("servers"))? {
            None => Vec::new(),
            Some(items) if (1..=MAX_SERVERS).contains(&items.len()) => items
                .iter()
                .map(|item| {
                    item.as_str().map_or_else(|| address(&path, "?"), |t| address(&path, t))
                })
                .collect::<io::Result<Vec<_>>>()?,
            Some(_) => {
                return Err(invalid(format!("{path}: expected 1 to {MAX_SERVERS} servers")));
            }
        };
        field(r.finish())?;
        Ok(Self { provider, check, timeout, wait, resolver, servers })
    }
}
