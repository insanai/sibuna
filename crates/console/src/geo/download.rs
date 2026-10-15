//! GeoIP downloads (unit U6; Zig's `geoip_download.zig`): the provider's fixed URLs over
//! HTTPS with one redirect to an allowed asset host, bounded sizes, publisher and operator
//! checksums.
//!
//! Only the publisher URLs that `sibuna_geoip::Provider` builds are fetched; no destination,
//! credential or proxy field from a browser enters a download request. A redirect is
//! followed once, to an absolute `https://` URL on the provider's allowlisted asset host;
//! anything else fails closed. Every address a publisher name resolves to must be public.
//!
//! Changes from Zig: the publisher host is resolved under the public-only address policy
//! and the connection pinned to the checked address (Zig's HTTP client resolved without a
//! policy); the 120-second deadline bounds every network step, but not name resolution,
//! and a stopping console waits for a download in flight to end.

use std::fmt;
use std::time::{Duration, Instant};

use sibuna_geoip::Provider;
use sibuna_geoip::provider::{ChecksumError, ProviderError, parse_checksum_file};
use sibuna_net::outbound::{self, OutboundError, Policy};

use crate::client::{self, ClientError, Endpoint, Limits, Response, Scheme, split_url};
use crate::notify::delivery::SystemTrust;

/// The largest uncompressed source file.
pub const MAX_SOURCE_BYTES: usize = 32 * 1024 * 1024;
/// The largest publisher checksum file.
pub const CHECKSUM_BYTES: usize = 256;
/// The longest redirect target.
const MAX_LOCATION: usize = 1024;
/// The bound of one download, redirect included.
pub const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);

/// Why a download failed.
#[derive(Debug)]
pub enum DownloadError {
    /// The provider cannot name this file or version.
    Provider(ProviderError),
    /// The provider publishes no checksum file.
    NoChecksum,
    /// The URL is not an absolute `https://` URL.
    InvalidUrl,
    /// The host did not resolve, or resolved to an address that is not public.
    Address(OutboundError),
    /// The system trust store has no usable root.
    TlsUnavailable,
    /// The exchange failed (TLS, the connection, the deadline, a body over the bound).
    Client(ClientError),
    /// A redirect went to a host or scheme the provider does not allow, or a second one
    /// followed.
    RedirectRejected,
    /// The publisher answered with this status.
    PublisherUnavailable(u16),
    /// The publisher's checksum file is malformed or names another file.
    Checksum(ChecksumError),
}

impl fmt::Display for DownloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DownloadError::Provider(error) => error.fmt(f),
            DownloadError::NoChecksum => f.write_str("the provider publishes no checksum"),
            DownloadError::InvalidUrl => f.write_str("the download URL is not HTTPS"),
            DownloadError::Address(error) => error.fmt(f),
            DownloadError::TlsUnavailable => f.write_str("no usable system trust root"),
            DownloadError::Client(error) => error.fmt(f),
            DownloadError::RedirectRejected => f.write_str("the publisher redirect was refused"),
            DownloadError::PublisherUnavailable(status) => {
                write!(f, "the publisher answered {status}")
            }
            DownloadError::Checksum(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for DownloadError {}

impl From<ClientError> for DownloadError {
    fn from(error: ClientError) -> DownloadError {
        DownloadError::Client(error)
    }
}

impl From<ProviderError> for DownloadError {
    fn from(error: ProviderError) -> DownloadError {
        DownloadError::Provider(error)
    }
}

/// Downloads source file `file` of `provider` for `version`, at most `max_bytes` bytes.
///
/// Fails with [`DownloadError`].
pub fn fetch(
    trust: &SystemTrust,
    provider: Provider,
    file: u8,
    version: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, DownloadError> {
    let url = provider.url(file, version)?;
    fetch_url(trust, provider, &url, max_bytes)
}

/// Downloads and parses the publisher's SHA-256 file for source file `file`.
///
/// Fails with [`DownloadError::NoChecksum`] for a provider without checksum files,
/// [`DownloadError::Checksum`] for a malformed one, and like [`fetch`].
pub fn fetch_checksum(
    trust: &SystemTrust,
    provider: Provider,
    file: u8,
    version: &str,
) -> Result<[u8; 32], DownloadError> {
    let url = provider.checksum_url(file, version)?.ok_or(DownloadError::NoChecksum)?;
    let name = provider.file_name(file, version)?;
    let text = fetch_url(trust, provider, &url, CHECKSUM_BYTES)?;
    parse_checksum_file(&text, &name).map_err(DownloadError::Checksum)
}

/// Downloads `url` of `provider`, following at most one allowed redirect, within
/// [`DOWNLOAD_TIMEOUT`]; returns at most `max_bytes` body bytes.
///
/// Fails with [`DownloadError`].
pub fn fetch_url(
    trust: &SystemTrust,
    provider: Provider,
    url: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, DownloadError> {
    let deadline = Instant::now() + DOWNLOAD_TIMEOUT;
    follow(provider, url, |url| exchange(trust, url, max_bytes, deadline))
}

/// What a reply asks for: its body, or one redirect.
enum Next {
    Body(Vec<u8>),
    Redirect(String),
}

/// Runs the redirect policy over `get`, which performs one exchange.
fn follow(
    provider: Provider,
    url: &str,
    mut get: impl FnMut(&str) -> Result<Response, DownloadError>,
) -> Result<Vec<u8>, DownloadError> {
    let target = match next(get(url)?)? {
        Next::Body(body) => return Ok(body),
        Next::Redirect(target) => target,
    };
    let (origin, _) = split_url(&target).map_err(|_| DownloadError::RedirectRejected)?;
    if origin.scheme() != Scheme::Https || !provider.is_redirect_allowed(origin.host()) {
        return Err(DownloadError::RedirectRejected);
    }
    match next(get(&target)?)? {
        Next::Body(body) => Ok(body),
        Next::Redirect(_) => Err(DownloadError::RedirectRejected),
    }
}

/// Classifies a reply: 200 gives its body; a redirect status its `Location`.
fn next(mut response: Response) -> Result<Next, DownloadError> {
    match response.status {
        200 => Ok(Next::Body(std::mem::take(&mut response.body))),
        301 | 302 | 303 | 307 | 308 => {
            let location = response.header("Location").ok_or(DownloadError::RedirectRejected)?;
            if location.len() > MAX_LOCATION {
                return Err(DownloadError::RedirectRejected);
            }
            Ok(Next::Redirect(location.to_owned()))
        }
        status => Err(DownloadError::PublisherUnavailable(status)),
    }
}

/// One `GET` of an absolute `https://` URL, pinned to a checked public address.
fn exchange(
    trust: &SystemTrust,
    url: &str,
    max_bytes: usize,
    deadline: Instant,
) -> Result<Response, DownloadError> {
    let (origin, target) = split_url(url).map_err(|_| DownloadError::InvalidUrl)?;
    if origin.scheme() != Scheme::Https {
        return Err(DownloadError::InvalidUrl);
    }
    let host = origin.host().trim_start_matches('[').trim_end_matches(']');
    let addresses = outbound::resolve(host, origin.port(), Policy::PublicOnly)
        .map_err(DownloadError::Address)?;
    let address =
        addresses.iter().next().ok_or(DownloadError::Address(OutboundError::HostUnresolved))?;
    let connector = trust.connector().ok_or(DownloadError::TlsUnavailable)?;
    let endpoint =
        Endpoint { origin: &origin, address: Some(address), connector: Some(connector) };
    let limits = Limits { deadline, max_body: max_bytes };
    Ok(client::get(&endpoint, target, &[], &limits)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(status: u16, location: Option<&str>, body: &[u8]) -> Response {
        let mut head = format!("HTTP/1.1 {status} X");
        if let Some(location) = location {
            head.push_str(&format!("\r\nLocation: {location}"));
        }
        Response { status, head: head.into_bytes(), body: body.to_vec() }
    }

    #[test]
    fn one_redirect_to_an_allowed_asset_host_is_followed() {
        let provider = Provider::UserCountry;
        let asset = "https://release-assets.githubusercontent.com/a/b?sig=1";
        let mut asked = Vec::new();
        let body = follow(provider, "https://github.com/x", |url| {
            asked.push(url.to_owned());
            Ok(if asked.len() == 1 {
                reply(302, Some(asset), b"")
            } else {
                reply(200, None, b"rows")
            })
        })
        .unwrap();
        assert_eq!((body.as_slice(), asked.len()), (b"rows".as_slice(), 2));
        assert_eq!(asked[1], asset);
    }

    #[test]
    fn other_redirects_and_statuses_fail_closed() {
        let refused = [
            "http://release-assets.githubusercontent.com/a",
            "https://evil.example/a",
            "/relative/path",
            "https://user@release-assets.githubusercontent.com/a",
        ];
        for location in refused {
            let result = follow(Provider::UserCountry, "https://github.com/x", |_| {
                Ok(reply(302, Some(location), b""))
            });
            assert!(matches!(result, Err(DownloadError::RedirectRejected)), "{location}");
        }
        let long = format!("https://release-assets.githubusercontent.com/{}", "a".repeat(1100));
        let result = follow(Provider::UserCountry, "https://github.com/x", |_| {
            Ok(reply(302, Some(&long), b""))
        });
        assert!(matches!(result, Err(DownloadError::RedirectRejected)));
        // DB-IP allows no redirect at all.
        let asset = "https://release-assets.githubusercontent.com/a";
        let result = follow(Provider::Dbip, "https://download.db-ip.com/x", |_| {
            Ok(reply(301, Some(asset), b""))
        });
        assert!(matches!(result, Err(DownloadError::RedirectRejected)));
        // A second redirect is refused.
        let result = follow(Provider::UserCountry, "https://github.com/x", |_| {
            Ok(reply(302, Some(asset), b""))
        });
        assert!(matches!(result, Err(DownloadError::RedirectRejected)));
        let result =
            follow(Provider::UserCountry, "https://github.com/x", |_| Ok(reply(404, None, b"")));
        assert!(matches!(result, Err(DownloadError::PublisherUnavailable(404))));
        let result =
            follow(Provider::UserCountry, "https://github.com/x", |_| Ok(reply(302, None, b"")));
        assert!(matches!(result, Err(DownloadError::RedirectRejected)));
    }

    #[test]
    fn only_https_urls_to_public_hosts_are_fetched() {
        let trust = SystemTrust::default();
        let soon = Instant::now() + Duration::from_secs(1);
        assert!(matches!(
            exchange(&trust, "http://127.0.0.1:1/x", 10, soon),
            Err(DownloadError::InvalidUrl)
        ));
        assert!(matches!(
            exchange(&trust, "https://127.0.0.1/x", 10, soon),
            Err(DownloadError::Address(OutboundError::TargetRejected))
        ));
        assert!(matches!(
            exchange(&trust, "https://10.1.2.3/x", 10, soon),
            Err(DownloadError::Address(OutboundError::TargetRejected))
        ));
    }
}
