//! The Cloudflare provider of DNS-01 (SID 0021): the calls of the Cloudflare API,
//! version 4, that write and remove one TXT record.
//!
//! ```text
//!   present:  GET  /zones?name=Z            for the owner and each of its parents
//!             POST /zones/ID/dns_records    { type TXT, name, content, ttl 120 }
//!   cleanup:  GET  /zones?name=Z
//!             GET  /zones/ID/dns_records?type=TXT&name=OWNER
//!             DELETE /zones/ID/dns_records/RECORD   for each record with our value
//! ```
//!
//! The module builds each request and reads each answer. The caller sends them: it owns
//! the sockets and the trust roots. The token goes into the `Authorization` field and
//! into nothing else, and an answer that repeats it is not shown.

use sibuna_json::Value;

use crate::error::printable;
use crate::{Call, Error, Response};

/// The base URL of the API.
pub const DEFAULT_API: &str = "https://api.cloudflare.com/client/v4";
/// The largest answer that the caller reads.
pub const MAX_RESPONSE: usize = 256 * 1024;
/// The most zones that one search asks about. A deeper name needs `zone`.
pub const MAX_ZONE_QUESTIONS: usize = 8;
/// The longest wait for one answer. With the bound above, writing a record takes 90
/// seconds at most.
pub const CALL_LIMIT: std::time::Duration = std::time::Duration::from_secs(10);
/// The most records with our value that one cleanup deletes.
const MAX_DELETES: usize = 16;
/// The longest token.
const MAX_TOKEN: usize = 512;
/// The code of the API for a record that exists already.
const ALREADY_EXISTS: i64 = 81_058;

/// Bounds of the JSON documents of the API.
const LIMITS: sibuna_json::Limits = sibuna_json::Limits {
    max_input_bytes: MAX_RESPONSE,
    max_values: 16_384,
    max_string_bytes: 8192,
    max_depth: 16,
};

/// Sends one call and returns the answer.
pub type Send<'a> = &'a dyn Fn(&Call) -> Result<Response, Error>;

/// One account at the API.
#[derive(Clone, Copy)]
pub struct Cloudflare<'a> {
    /// The base URL, [`DEFAULT_API`] outside tests.
    pub api: &'a str,
    /// The API token. It needs the rights to read the zone and to edit its DNS.
    pub token: &'a str,
    /// The zone of the record. Without one it is searched from the owner upwards.
    pub zone: Option<&'a str>,
}

impl std::fmt::Debug for Cloudflare<'_> {
    /// Shows the URL and the zone. The token is not shown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cloudflare")
            .field("api", &self.api)
            .field("zone", &self.zone)
            .finish_non_exhaustive()
    }
}

/// The text of a token file as a token: one word of printable ASCII. `None` for
/// anything else.
pub fn token(text: &str) -> Option<&str> {
    let token = text.trim();
    let plain = !token.is_empty()
        && token.len() <= MAX_TOKEN
        && token.bytes().all(|byte| byte.is_ascii_graphic());
    plain.then_some(token)
}

/// The names that may be the zone of `owner`, longest first: the owner and its parents
/// down to two labels, [`MAX_ZONE_QUESTIONS`] at most.
pub fn zone_candidates(owner: &str) -> Vec<&str> {
    let mut candidates = Vec::new();
    let mut rest = owner.trim_end_matches('.');
    while rest.contains('.') && candidates.len() < MAX_ZONE_QUESTIONS {
        candidates.push(rest);
        rest = rest.split_once('.').map_or("", |(_, parent)| parent);
    }
    candidates
}

/// Whether `text` may stand in a URL of the API as it is: a DNS name or an identifier.
fn is_plain(text: &str) -> bool {
    let allowed = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_');
    !text.is_empty() && text.len() <= 255 && text.bytes().all(allowed)
}

impl Cloudflare<'_> {
    fn call(&self, method: &'static str, path: &str, body: Option<String>) -> Call {
        let mut headers = vec![("authorization", format!("Bearer {}", self.token))];
        if body.is_some() {
            headers.push(("content-type", "application/json".to_owned()));
        }
        let url = format!("{}{path}", self.api.trim_end_matches('/'));
        Call { method, url, headers, body: body.unwrap_or_default().into_bytes() }
    }

    /// A failure of the provider. Text of the API that repeats the token is not shown.
    fn failure(&self, what: &str, reason: &str) -> Error {
        let reason = reason.replace(self.token, "[token]");
        let mut error = Error::provider(format!("Cloudflare did not {what}: {reason}."));
        error.hint = "Check the token in `global.acme.dns.cloudflare.token_file`. It needs the \
                      rights Zone / Zone / Read and Zone / DNS / Edit for the zone of the name. \
                      Set `zone` when the search finds no zone."
            .to_owned();
        error
    }

    /// Sends a call and returns the `result` member of a successful answer. A failure
    /// carries the codes and messages of the `errors` member. `tolerated` is a code
    /// that counts as success, with an empty result.
    fn exchange<T>(
        &self,
        send: Send<'_>,
        call: &Call,
        what: &str,
        tolerated: Option<i64>,
        read: impl FnOnce(&Value<'_>) -> Option<T>,
    ) -> Result<Option<T>, Error> {
        let response = send(call).map_err(|error| self.failure(what, error.message.trim_end()))?;
        let unusable = || {
            let reason = format!("the API answered {} with a body we cannot use", response.status);
            self.failure(what, &reason)
        };
        let parsed =
            sibuna_json::parse_with_limits(&response.body, &LIMITS).map_err(|_| unusable())?;
        let members = parsed.as_object().ok_or_else(unusable)?;
        let success = members.get("success").and_then(Value::as_bool) == Some(true);
        if success && (200..300).contains(&response.status) {
            let result = members.get("result").ok_or_else(unusable)?;
            return read(result).map(Some).ok_or_else(unusable);
        }
        let errors = members.get("errors").and_then(Value::as_array).unwrap_or_default();
        let code = |error: &Value<'_>| {
            let code = error.as_object()?.get("code")?.as_number()?;
            code.as_i64().ok()
        };
        if tolerated.is_some() && errors.iter().any(|error| code(error) == tolerated) {
            return Ok(None);
        }
        let listed: Vec<String> = errors
            .iter()
            .take(4)
            .map(|error| {
                let message = error.as_object().and_then(|error| error.get("message"));
                let message = message.and_then(Value::as_str).unwrap_or("no message");
                format!("{} ({})", printable(message, 200), code(error).unwrap_or(0))
            })
            .collect();
        let reason = match listed.is_empty() {
            true => format!("the API answered {}", response.status),
            false => format!("the API answered {} with {}", response.status, listed.join("; ")),
        };
        Err(self.failure(what, &reason))
    }

    /// The identifier of the zone that holds `owner`: that of `zone`, or of the longest
    /// candidate that the account has.
    fn zone_id(&self, send: Send<'_>, owner: &str) -> Result<String, Error> {
        let candidates = match self.zone {
            Some(zone) => vec![zone.trim_end_matches('.')],
            None => zone_candidates(owner),
        };
        for candidate in candidates.iter().filter(|candidate| is_plain(candidate)) {
            let call = self.call("GET", &format!("/zones?name={candidate}"), None);
            let found = self.exchange(send, &call, "find the zone", None, |result| {
                let zones = result.as_array()?;
                let id = zones.iter().find_map(|zone| {
                    let zone = zone.as_object()?;
                    let name = zone.get("name")?.as_str()?;
                    let id = zone.get("id")?.as_str()?;
                    (name.eq_ignore_ascii_case(candidate) && is_plain(id)).then(|| id.to_owned())
                });
                Some(id)
            })?;
            if let Some(Some(id)) = found {
                return Ok(id);
            }
        }
        let reason = format!("the account has no zone for `{owner}`");
        Err(self.failure("find the zone", &reason))
    }

    /// Creates the TXT record `owner` with `value`. A record that exists already is
    /// success. Fails with `ACME009`.
    pub fn present(&self, send: Send<'_>, owner: &str, value: &str) -> Result<(), Error> {
        let owner = owner.trim_end_matches('.');
        if !is_plain(owner) || !is_plain(value) {
            return Err(self.failure("write the record", "the record has an unusual character"));
        }
        let zone = self.zone_id(send, owner)?;
        let body =
            format!(r#"{{"type":"TXT","name":"{owner}","content":"\"{value}\"","ttl":120}}"#);
        let call = self.call("POST", &format!("/zones/{zone}/dns_records"), Some(body));
        self.exchange(send, &call, "write the record", Some(ALREADY_EXISTS), |_| Some(()))?;
        Ok(())
    }

    /// Deletes every TXT record `owner` with `value`. No such record is success. Fails
    /// with `ACME009`.
    pub fn cleanup(&self, send: Send<'_>, owner: &str, value: &str) -> Result<(), Error> {
        let owner = owner.trim_end_matches('.');
        if !is_plain(owner) || !is_plain(value) {
            return Err(self.failure("remove the record", "the record has an unusual character"));
        }
        let zone = self.zone_id(send, owner)?;
        let path = format!("/zones/{zone}/dns_records?type=TXT&name={owner}");
        let call = self.call("GET", &path, None);
        let ours = |record: &Value<'_>| {
            let record = record.as_object()?;
            let name = record.get("name")?.as_str()?;
            let content = record.get("content")?.as_str()?;
            let id = record.get("id")?.as_str()?;
            let same = name.eq_ignore_ascii_case(owner) && content.trim_matches('"') == value;
            (same && is_plain(id)).then(|| id.to_owned())
        };
        let records = self.exchange(send, &call, "list the records", None, |result| {
            Some(result.as_array()?.iter().filter_map(ours).take(MAX_DELETES).collect::<Vec<_>>())
        })?;
        for record in records.unwrap_or_default() {
            let call = self.call("DELETE", &format!("/zones/{zone}/dns_records/{record}"), None);
            self.exchange(send, &call, "remove the record", None, |_| Some(()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
