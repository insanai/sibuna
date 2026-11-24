//! Dynamic update (RFC 2136): add or delete one TXT record on the server of a zone.

use std::net::SocketAddr;
use std::time::Duration;

use super::tsig::{self, TsigKey};
use super::wire::{self, CLASS_IN, CLASS_NONE, TYPE_SOA, TYPE_TXT};
use super::{random_id, transport, unix_now};
use crate::Error;

/// The opcode `UPDATE` in the flags of a header.
const OPCODE_UPDATE: u16 = 5 << 11;
/// The TTL of the record we add, in seconds.
const TTL: u32 = 60;
/// How long one try waits for the answer.
const TRY_TIMEOUT: Duration = Duration::from_secs(5);
/// How often an update is sent before it fails.
const TRIES: u32 = 3;

/// The update message that adds the TXT record `owner` with `value` to `zone`, or
/// deletes exactly that record. A delete names the value, so other values of the same
/// owner stay. Fails for a name that is no DNS name and for a value over 255 bytes.
pub fn message(
    id: u16,
    zone: &str,
    owner: &str,
    value: &str,
    delete: bool,
) -> Result<Vec<u8>, Error> {
    let Ok(length) = u8::try_from(value.len()) else {
        return Err(Error::unexpected("A TXT value has at most 255 bytes."));
    };
    let mut out = Vec::with_capacity(64 + zone.len() + owner.len() + value.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&OPCODE_UPDATE.to_be_bytes());
    // One zone, no prerequisite, one update, no additional record.
    out.extend_from_slice(&[0, 1, 0, 0, 0, 1, 0, 0]);
    wire::write_name(&mut out, zone)?;
    out.extend_from_slice(&TYPE_SOA.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    wire::write_name(&mut out, owner)?;
    out.extend_from_slice(&TYPE_TXT.to_be_bytes());
    let (class, ttl) = if delete { (CLASS_NONE, 0) } else { (CLASS_IN, TTL) };
    out.extend_from_slice(&class.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&(u16::from(length) + 1).to_be_bytes());
    out.push(length);
    out.extend_from_slice(value.as_bytes());
    Ok(out)
}

/// What an update changes.
#[derive(Clone, Copy, Debug)]
pub struct Change<'a> {
    /// The zone that holds the record.
    pub zone: &'a str,
    /// The owner of the TXT record.
    pub owner: &'a str,
    /// The text of the record.
    pub value: &'a str,
    /// Delete the record instead of adding it.
    pub delete: bool,
}

/// Sends one update to `server` and waits for its answer, three times at most. With a
/// key the update is signed and the signature of the answer is checked. Fails with
/// `ACME009` when no answer comes, the answer is not the server's, or it refuses.
pub fn send(server: SocketAddr, key: Option<&TsigKey>, change: Change<'_>) -> Result<(), Error> {
    let mut last = Error::provider(format!("The DNS server {server} did not answer."));
    for _ in 0..TRIES {
        let id = random_id()?;
        let mut request = message(id, change.zone, change.owner, change.value, change.delete)?;
        let mac = key.map(|key| tsig::sign(&mut request, key, unix_now())).transpose()?;
        let response = match transport::exchange(server, &request, TRY_TIMEOUT) {
            Ok(response) => response,
            Err(error) => {
                last =
                    Error::provider(format!("The DNS server {server} did not answer: {error}."));
                continue;
            }
        };
        let Some(answer) = wire::parse(&response).filter(|answer| answer.id == id) else {
            last = Error::provider(format!("The DNS server {server} sent no DNS answer."));
            continue;
        };
        if let (Some(key), Some(mac)) = (key, mac) {
            tsig::verify(&response, key, &mac, unix_now())?;
        }
        if answer.rcode != 0 {
            return Err(Error::provider(format!(
                "The DNS server {server} refused the update of `{}` in the zone `{}`: {}.",
                change.owner,
                change.zone,
                wire::rcode_name(answer.rcode)
            )));
        }
        return Ok(());
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn an_update_equals_the_one_of_miekg_dns() {
        // From miekg/dns 1.1.62: `SetUpdate("example.org.")`, then `Insert` or `Remove`
        // of one TXT record.
        let head = "123428000001000000010000076578616d706c65036f726700000600010f5f61636d652d\
            6368616c6c656e6765076578616d706c65036f72670000";
        let value = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0";
        let hex =
            |bytes: &[u8]| bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let text = hex(&[&[43][..], value.as_bytes()].concat());
        let squeeze = |text: &str| text.split_whitespace().collect::<String>();
        let add = message(0x1234, "example.org.", "_acme-challenge.example.org", value, false);
        assert_eq!(hex(&add.unwrap()), squeeze(&format!("{head}1000010000003c002c{text}")));
        let delete = message(0x1234, "example.org", "_acme-challenge.example.org.", value, true);
        assert_eq!(hex(&delete.unwrap()), squeeze(&format!("{head}1000fe00000000002c{text}")));
        assert!(message(1, "example.org", "a..b", value, false).is_err());
        assert!(message(1, "example.org", "a.b", &"x".repeat(256), false).is_err());
    }
}
