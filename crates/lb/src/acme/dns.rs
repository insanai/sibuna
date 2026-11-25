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
    /// The API of Cloudflare, with a token from a file.
    Cloudflare {
        /// The file that holds the API token.
        token_file: String,
        /// The zone of the record. Without one the daemon searches it at the API.
        zone: Option<String>,
        /// Another base URL of the API, for tests: `http` on a loopback address.
        api: Option<String>,
    },
    /// A dynamic update (RFC 2136) to the server of the zone. A server that is not on
    /// a loopback address needs a key, or `unsigned: true` in the file.
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
    /// Write the record at the target of a CNAME delegation of the challenge.
    pub follow_cname: bool,
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
    // Without a key the answer is trusted by its address and its identifier alone, and
    // anybody on the path may write the zone. That is fine on this host and a decision
    // elsewhere.
    let unsigned = field(r.take_bool("unsigned"))?.unwrap_or(false);
    if key.is_some() && unsigned {
        return Err(invalid(format!("{}: unsigned contradicts key_name and key_file", r.path())));
    }
    if key.is_none() && !unsigned && !server.ip().is_loopback() {
        return Err(invalid(format!(
            "{}: an update to {server} without a TSIG key is not signed; set key_name and \
             key_file, or unsigned: true",
            r.path()
        )));
    }
    let zone = zone(&mut r)?;
    field(r.finish())?;
    Ok(DnsProvider::Rfc2136 { server, key, zone })
}

/// Reads a zone name: a DNS name, stored in lower case without a final dot.
fn zone(r: &mut ObjectReader<'_, '_>) -> io::Result<Option<String>> {
    match field(r.take_str("zone"))? {
        None => Ok(None),
        Some(zone) if crate::hello::valid_host(zone.trim_end_matches('.')) => {
            Ok(Some(zone.trim_end_matches('.').to_ascii_lowercase()))
        }
        Some(_) => Err(invalid(format!("{}: expected a DNS name", r.field_path("zone")))),
    }
}

/// Whether `url` is an `http` URL on a loopback address. The API token goes to the
/// host of the URL, so no other host is accepted.
fn is_loopback_http(url: &str) -> bool {
    let printable = url.len() <= 512 && url.bytes().all(|byte| byte.is_ascii_graphic());
    let Some(rest) = url.strip_prefix("http://").filter(|_| printable) else { return false };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = match authority.strip_prefix('[') {
        Some(bracketed) => bracketed.split(']').next().unwrap_or_default(),
        None => authority.rsplit_once(':').map_or(authority, |(host, _)| host),
    };
    !authority.contains('@')
        && host.parse::<std::net::IpAddr>().is_ok_and(|address| address.is_loopback())
}

fn cloudflare(mut r: ObjectReader<'_, '_>) -> io::Result<DnsProvider> {
    let path = r.field_path("token_file");
    let token_file = match field(r.take_str("token_file"))? {
        Some(file) if !file.is_empty() => file.to_owned(),
        _ => return Err(invalid(format!("{path}: the provider needs the file of an API token"))),
    };
    let zone = zone(&mut r)?;
    let path = r.field_path("api");
    let api = match field(r.take_str("api"))? {
        None => None,
        Some(url) if is_loopback_http(url) => Some(url.to_owned()),
        Some(_) => {
            return Err(invalid(format!(
                "{path}: expected an http URL on a loopback address; this key is for tests, \
                 and the token is sent to the host that it names"
            )));
        }
    };
    field(r.finish())?;
    Ok(DnsProvider::Cloudflare { token_file, zone, api })
}

impl DnsConfig {
    pub(crate) fn parse(mut r: ObjectReader<'_, '_>) -> io::Result<Self> {
        let hook = field(r.take_str("hook"))?;
        let update = field(r.take_object("rfc2136"))?;
        let vendor = field(r.take_object("cloudflare"))?;
        let provider = match (hook, update, vendor) {
            (Some(program), None, None) if !program.is_empty() => {
                DnsProvider::Hook(program.to_owned())
            }
            (None, Some(update), None) => rfc2136(update)?,
            (None, None, Some(vendor)) => cloudflare(vendor)?,
            _ => {
                return Err(invalid(format!(
                    "{}: expected one provider: hook (a program), rfc2136 (an object) or \
                     cloudflare (an object)",
                    r.path()
                )));
            }
        };
        let follow_cname = field(r.take_bool("follow_cname"))?.unwrap_or(true);
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
        Ok(Self { provider, check, timeout, wait, resolver, servers, follow_cname })
    }
}
