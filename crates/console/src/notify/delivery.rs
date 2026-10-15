//! Outbound delivery of one event to one destination (Zig's `notify_delivery.zig`): an
//! HTTPS webhook POST with an HMAC-SHA256 signature, or an RFC 5424 syslog line over UDP or
//! framed TCP. The target is checked again and its resolved addresses are checked against
//! the address policy just before each attempt; the outcome's detail never holds the
//! secret. Runs on the notifier thread, or on a request thread for a test delivery.
//!
//! Changes from Zig: Zig raced the attempt against a sleeping task and cancelled the loser.
//! Here every network step has the attempt's deadline (at most 10 seconds), but name
//! resolution waits for the system resolver, which its own configuration bounds, and a
//! stopping console waits for an attempt in flight to end. The webhook reply is read with
//! the console's HTTP client, its body bounded to 64 KiB, where Zig read only the status
//! line; a larger body fails the attempt.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use sibuna_console_protocol::CredentialKind;
use sibuna_console_protocol::codec::WireEnum;
use sibuna_console_protocol::notifications::{Destination, Kind, Pending, Read, Transport};
use sibuna_console_storage::access::Credential;
use sibuna_console_storage::notifications::{Reader, SealedSecret, read_secret};
use sibuna_crypto::{ct, hmac};
use sibuna_json::Writer;
use sibuna_net::connect::{Unreachable, connect_deadline, write_bounded};
use sibuna_net::outbound::{self, OutboundError, Policy};
use sibuna_tls::{Connector, Trust};

use super::target::{self, InvalidTarget, envelope_subject};
use super::{Delivery, syslog, wait_for};
use crate::auth::secrets::{MAX_SEALED, open_bytes};
use crate::client::{self, ClientError, Endpoint, Limits, Origin};
use crate::shared::Shared;
use crate::storage::StorageFailure;

/// The longest one attempt may take.
pub const DEADLINE: Duration = Duration::from_secs(10);
/// The largest webhook reply body read.
const MAX_REPLY_BODY: usize = 64 * 1024;
/// The detail of the event a test delivery sends.
pub const TEST_DETAIL: &str = "test delivery from the console";

/// The system trust store, loaded on the first HTTPS connection and kept.
#[derive(Debug, Default)]
pub struct SystemTrust {
    connector: OnceLock<Option<Connector>>,
}

impl SystemTrust {
    /// Returns the TLS configuration over the system roots, loading it on first use;
    /// `None` when the system store has no usable root (the failure is kept).
    pub fn connector(&self) -> Option<&Connector> {
        self.connector.get_or_init(|| Connector::load(&Trust::default()).ok()).as_ref()
    }
}

/// One delivery attempt.
#[derive(Clone, Copy, Debug)]
pub struct Attempt<'a> {
    /// Where it goes.
    pub destination: &'a Destination,
    /// What it reports; a test delivery has id 0 and sends no `Idempotency-Key`.
    pub event: &'a Pending,
    /// How the destination's sealed secret is read: under the notifier's lease, or with the
    /// administrator's credential of a test.
    pub read: &'a Read,
    /// The notifier's own budget; the attempt ends at this time at the latest.
    pub not_after: Option<Instant>,
}

/// Why an attempt failed; the names are Zig's error names, which the outcome's detail shows.
#[derive(Debug)]
pub enum DeliveryError {
    /// The deadline passed, or the console is stopping.
    Deadline,
    /// The target is not one the rule admits.
    Target(InvalidTarget),
    /// The destination has a secret but the console has no key to open it.
    KeyRequired,
    /// The secret could not be read or opened.
    SecretUnavailable,
    /// The host did not resolve, or resolved to an address the policy refuses.
    Address(OutboundError),
    /// The system trust store has no usable root.
    TlsUnavailable,
    /// The HTTP exchange failed.
    Client(ClientError),
    /// The syslog receiver could not be reached.
    Unreachable,
}

impl fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            DeliveryError::Deadline => "DeliveryDeadline",
            DeliveryError::Target(_) => "InvalidTarget",
            DeliveryError::KeyRequired => "ConsoleKeyRequired",
            DeliveryError::SecretUnavailable => "SecretUnavailable",
            DeliveryError::Address(OutboundError::InvalidHost) => "InvalidHost",
            DeliveryError::Address(OutboundError::TargetRejected) => "TargetRejected",
            DeliveryError::Address(OutboundError::TooManyAddresses) => "TooManyAddresses",
            DeliveryError::Address(_) => "HostUnresolved",
            DeliveryError::TlsUnavailable => "TlsUnavailable",
            DeliveryError::Client(ClientError::Deadline) => "DeliveryDeadline",
            DeliveryError::Client(ClientError::Tls(_)) => "TlsFailure",
            DeliveryError::Client(ClientError::TooLarge) => "ReplyTooLarge",
            DeliveryError::Client(ClientError::InvalidResponse) => "InvalidResponse",
            DeliveryError::Client(ClientError::Transport(_)) => "ConnectionFailed",
            DeliveryError::Client(_) => "InvalidTarget",
            DeliveryError::Unreachable => "ConnectionFailed",
        };
        f.write_str(name)
    }
}

impl std::error::Error for DeliveryError {}

impl From<InvalidTarget> for DeliveryError {
    fn from(error: InvalidTarget) -> DeliveryError {
        DeliveryError::Target(error)
    }
}

impl From<OutboundError> for DeliveryError {
    fn from(error: OutboundError) -> DeliveryError {
        DeliveryError::Address(error)
    }
}

impl From<ClientError> for DeliveryError {
    fn from(error: ClientError) -> DeliveryError {
        DeliveryError::Client(error)
    }
}

impl From<Unreachable> for DeliveryError {
    fn from(_: Unreachable) -> DeliveryError {
        DeliveryError::Unreachable
    }
}

/// Runs one attempt and returns its outcome: delivered for a 2xx webhook reply or a
/// written syslog line, with `status <code>` or the error's name as the detail.
pub fn deliver(shared: &Shared, trust: &SystemTrust, attempt: &Attempt<'_>) -> Delivery {
    match run(shared, trust, attempt) {
        Ok(status) => Delivery {
            delivered: (200..300).contains(&status),
            detail: format!("status {status}"),
        },
        Err(error) => Delivery { delivered: false, detail: error.to_string() },
    }
}

fn run(shared: &Shared, trust: &SystemTrust, attempt: &Attempt<'_>) -> Result<u16, DeliveryError> {
    let now = Instant::now();
    let limit = now + DEADLINE;
    let expires = attempt.not_after.map_or(limit, |not_after| not_after.min(limit));
    if expires <= now || shared.is_stopping() {
        return Err(DeliveryError::Deadline);
    }
    let destination = attempt.destination;
    let secret = if destination.kind == Kind::Webhook && destination.secret_set {
        Some(open_secret(shared, attempt.read)?)
    } else {
        None
    };
    if Instant::now() >= expires || shared.is_stopping() {
        return Err(DeliveryError::Deadline);
    }
    match destination.kind {
        Kind::Webhook => webhook(shared, trust, attempt, secret.as_ref(), expires),
        Kind::Syslog => send_syslog(destination, attempt.event, expires),
    }
}

/// A webhook secret in the clear, wiped on drop.
struct Secret {
    bytes: [u8; MAX_SEALED],
    length: usize,
}

impl Secret {
    fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..self.length).unwrap_or_default()
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        ct::zeroize(&mut self.bytes);
    }
}

/// Reads the destination's sealed secret (under the notifier's lease, or with the test's
/// administrator credential) and opens it under the console key, bound to the target.
fn open_secret(shared: &Shared, read: &Read) -> Result<Secret, DeliveryError> {
    let key = shared.keys.totp.as_ref().ok_or(DeliveryError::KeyRequired)?;
    let sealed = read_sealed(shared, read).map_err(|_| DeliveryError::SecretUnavailable)?;
    let envelope = sealed.envelope.ok_or(DeliveryError::SecretUnavailable)?;
    let subject = envelope_subject(&sealed.target);
    let mut secret = Secret { bytes: [0; MAX_SEALED], length: 0 };
    secret.length = open_bytes(&envelope, key.bytes(), subject, &mut secret.bytes)
        .map_err(|_| DeliveryError::SecretUnavailable)?;
    Ok(secret)
}

fn read_sealed(shared: &Shared, read: &Read) -> Result<SealedSecret, StorageFailure> {
    let (id, revision, now) = (read.id, read.revision, shared.now());
    match read.lease {
        Some(lease) => wait_for(&shared.storage, &|| shared.is_stopping(), move |tx| {
            Box::pin(
                async move { read_secret(tx, Reader::Notifier(&lease), id, revision, now).await },
            )
        }),
        None => {
            let credential = Credential::new(CredentialKind::Session, &read.auth);
            shared.storage.transact(move |tx| {
                Box::pin(async move {
                    read_secret(tx, Reader::Administrator(&credential), id, revision, now).await
                })
            })
        }
    }
}

/// Returns the webhook body: `{"event","node","at","detail","console"}`, as Zig wrote it.
pub fn webhook_body(event: &Pending, console: &str) -> String {
    let mut body = String::with_capacity(256);
    let mut json = Writer::new(&mut body);
    // Writing into a String cannot fail.
    let _ = (|| {
        json.begin_object()?;
        json.key("event")?;
        json.string(event.event.name())?;
        json.key("node")?;
        json.uint(u64::from(event.node))?;
        json.key("at")?;
        json.uint(event.raised_at)?;
        json.key("detail")?;
        json.string(event.detail.as_str())?;
        json.key("console")?;
        json.string(console)?;
        json.end_object()
    })();
    body
}

/// Returns `sha256=<hex>`, the HMAC-SHA256 of `body` under `secret`.
pub fn signature(secret: &[u8], body: &[u8]) -> String {
    let mut mac = hmac::hmac_sha256(secret, body);
    let value = format!("sha256={}", sibuna_encoding::hex::encode(&mac));
    ct::zeroize(&mut mac);
    value
}

fn webhook(
    shared: &Shared,
    trust: &SystemTrust,
    attempt: &Attempt<'_>,
    secret: Option<&Secret>,
    expires: Instant,
) -> Result<u16, DeliveryError> {
    let (destination, event) = (attempt.destination, attempt.event);
    let webhook = target::validate_webhook(destination.target.as_str())?;
    let addresses = outbound::resolve(&webhook.host, webhook.port, webhook.policy())?;
    let address = addresses.iter().next().ok_or(OutboundError::HostUnresolved)?;
    let origin = Origin::parse(&webhook.origin())?;
    let https = webhook.policy() == Policy::PublicOnly;
    let connector =
        if https { Some(trust.connector().ok_or(DeliveryError::TlsUnavailable)?) } else { None };
    let endpoint = Endpoint { origin: &origin, address: https.then_some(address), connector };
    let body = webhook_body(event, &shared.identity.origin);
    let key = format!("sibuna/{}/{}/{}", event.id, destination.id, destination.revision);
    let signed = secret.map(|secret| signature(secret.as_bytes(), body.as_bytes()));
    let mut fields = vec![("X-Sibuna-Event", event.event.name())];
    if event.id != 0 {
        fields.push(("Idempotency-Key", key.as_str()));
    }
    if let Some(signed) = &signed {
        fields.push(("X-Sibuna-Signature", signed.as_str()));
    }
    let limits = Limits { deadline: expires, max_body: MAX_REPLY_BODY };
    let response = client::post_json(&endpoint, webhook.path, &fields, body.as_bytes(), &limits)?;
    Ok(response.status)
}

fn send_syslog(
    destination: &Destination,
    event: &Pending,
    expires: Instant,
) -> Result<u16, DeliveryError> {
    let endpoint = target::validate_syslog(destination.target.as_str())?;
    let addresses = outbound::resolve(endpoint.host, endpoint.port, Policy::LoopbackAllowed)?;
    let address = addresses.iter().next().ok_or(OutboundError::HostUnresolved)?;
    let host = format!("node-{}", event.node);
    let line = syslog::format(
        syslog::Severity::Warning,
        event.raised_at,
        &host,
        event.event.name(),
        event.detail.as_str(),
    );
    match destination.transport {
        Transport::Tcp => {
            let stream = connect_deadline(address, expires)?;
            write_bounded(&stream, syslog::framed(&line).as_bytes(), expires)?;
        }
        Transport::Udp => {
            let local = match address.ip() {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            };
            let socket = UdpSocket::bind(SocketAddr::new(local, 0))
                .map_err(|_| DeliveryError::Unreachable)?;
            socket.send_to(line.as_bytes(), address).map_err(|_| DeliveryError::Unreachable)?;
        }
    }
    Ok(200)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_console_protocol::Text;
    use sibuna_console_protocol::notifications::Event;

    #[test]
    fn bodies_and_signatures_are_the_zig_ones() {
        let event = Pending {
            id: 7,
            node: 2,
            event: Event::Ban,
            raised_at: 100,
            detail: Text::new("2 local \"bans\"").unwrap(),
            attempts: 1,
        };
        let body = webhook_body(&event, "https://console.example");
        assert_eq!(
            body,
            "{\"event\":\"ban\",\"node\":2,\"at\":100,\"detail\":\"2 local \\\"bans\\\"\",\
             \"console\":\"https://console.example\"}"
        );
        // RFC 4231 test case 2.
        let mac = signature(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(mac, "sha256=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    #[test]
    fn errors_show_zig_names() {
        assert_eq!(DeliveryError::Deadline.to_string(), "DeliveryDeadline");
        assert_eq!(DeliveryError::from(ClientError::Deadline).to_string(), "DeliveryDeadline");
        assert_eq!(
            DeliveryError::from(OutboundError::TargetRejected).to_string(),
            "TargetRejected"
        );
        assert_eq!(DeliveryError::from(InvalidTarget).to_string(), "InvalidTarget");
    }
}
