//! ACME Renewal Information (RFC 9773): the authority says when a certificate should
//! be renewed. Nothing here opens a socket.
//!
//! ```text
//!   directory --renewalInfo--> URL
//!   GET URL/ID   ID = base64url(authority key id) "." base64url(serial)
//!   answer       { "suggestedWindow": { "start": T, "end": T } }, Retry-After
//!   pick         start + (hash(serial) mod (end - start))
//!   renewal      min(max(pick, floor), four fifths of the lifetime)
//! ```
//!
//! The pick depends on the certificate only, so a restart and another node choose the
//! same time.

use sibuna_crypto::sha256::Sha256;
use sibuna_json::Value;

use crate::order::{Method, Request, Response};
use crate::{Error, jws, time, x509};

/// The longest URL of the renewal information that we use.
const MAX_URL: usize = 2048;
/// The largest answer that we read.
const MAX_ANSWER: usize = 16 * 1024;
/// The shortest and the longest pause between two questions about one certificate.
const SHORTEST_POLL: u64 = 3600;
const LONGEST_POLL: u64 = 86_400;
/// The pause when the authority names none.
const DEFAULT_POLL: u64 = 6 * 3600;

const LIMITS: sibuna_json::Limits = sibuna_json::Limits {
    max_input_bytes: MAX_ANSWER,
    max_values: 64,
    max_string_bytes: MAX_URL,
    max_depth: 4,
};

/// The window in which the authority suggests the renewal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    /// The start, in seconds since 1970.
    pub start: u64,
    /// The end, in seconds since 1970. Not before the start.
    pub end: u64,
}

/// The answer of the authority about one certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    /// The suggested window.
    pub window: Window,
    /// The `Retry-After` of the answer, in seconds.
    pub retry_after: Option<u64>,
}

fn unusable(what: &str) -> Error {
    Error::unexpected(format!("The renewal information of the authority is unusable: {what}."))
}

/// The identifier of a certificate (RFC 9773, section 4.1): the key identifier of its
/// authority and its serial number, each in base64url, with a dot between them.
/// Returns `None` for a certificate without an authority key identifier.
pub fn certificate_id(certificate: &x509::Certificate) -> Option<String> {
    let (key_id, serial) = (&certificate.authority_key_id, &certificate.serial);
    (!key_id.is_empty() && !serial.is_empty())
        .then(|| format!("{}.{}", jws::base64url(key_id), jws::base64url(serial)))
}

/// The request for a directory. Pass its response to [`endpoint`].
pub fn directory_request(directory: &str) -> Request {
    Request { method: Method::Get, url: directory.to_owned(), body: String::new() }
}

/// The `renewalInfo` URL of a directory, or `None` when the authority has none. The
/// URL keeps the scheme of the directory. Fails for an answer that is no directory.
pub fn endpoint(directory: &str, response: &Response) -> Result<Option<String>, Error> {
    if response.status != 200 || response.body.len() > crate::order::MAX_BODY {
        return Err(unusable("the directory was not sent"));
    }
    let value = sibuna_json::parse_with_limits(&response.body, &crate::order::LIMITS)
        .map_err(|_| unusable("the directory is not JSON"))?;
    let members = value.as_object().ok_or_else(|| unusable("the directory is no object"))?;
    let Some(url) = members.get("renewalInfo").and_then(Value::as_str) else {
        return Ok(None);
    };
    let secure = directory.starts_with("https://");
    let scheme_ok = url.starts_with("https://") || (!secure && url.starts_with("http://"));
    let plain = url.bytes().all(|byte| byte.is_ascii_graphic());
    if !scheme_ok || !plain || url.len() > MAX_URL {
        return Err(unusable("its URL is malformed or leaves the scheme of the directory"));
    }
    Ok(Some(url.trim_end_matches('/').to_owned()))
}

/// The request for the renewal information of the certificate `id` at `endpoint`.
pub fn request(endpoint: &str, id: &str) -> Request {
    Request { method: Method::Get, url: format!("{endpoint}/{id}"), body: String::new() }
}

/// Reads the answer to [`request`]. Fails for another status than 200, for a body over
/// 16 KiB, and for a window that is missing, malformed or ends before it starts.
pub fn parse(response: &Response) -> Result<Info, Error> {
    if response.status != 200 {
        return Err(unusable(&format!("the status is {}", response.status)));
    }
    let value = sibuna_json::parse_with_limits(&response.body, &LIMITS)
        .map_err(|_| unusable("it is not a small JSON document"))?;
    let window = value
        .as_object()
        .and_then(|members| members.get("suggestedWindow"))
        .and_then(Value::as_object)
        .ok_or_else(|| unusable("it has no window"))?;
    let instant = |key: &str| {
        let text = window.get(key).and_then(Value::as_str);
        text.and_then(time::parse_rfc3339).ok_or_else(|| unusable("a time is malformed"))
    };
    let (start, end) = (instant("start")?, instant("end")?);
    if end < start {
        return Err(unusable("the window ends before it starts"));
    }
    Ok(Info { window: Window { start, end }, retry_after: response.retry_after })
}

/// The time in the window at which this certificate is renewed: the start plus a hash
/// of the serial number modulo the length. The result lies in `[start, end)`, or is
/// the start of an empty window.
pub fn pick(window: Window, serial: &[u8]) -> u64 {
    let digest = Sha256::digest(serial);
    let hash = digest.iter().take(8).fold(0u64, |hash, byte| (hash << 8) | u64::from(*byte));
    match window.end.saturating_sub(window.start) {
        0 => window.start,
        length => window.start + hash % length,
    }
}

/// The latest renewal time that an authority can ask for: four fifths of the lifetime.
pub fn latest(not_before: u64, not_after: u64) -> u64 {
    let lifetime = not_after.saturating_sub(not_before);
    not_before + lifetime / 5 * 4
}

/// The renewal time of a certificate with the pick `pick`. It is not before `floor`,
/// which keeps an authority from asking for a renewal the moment a certificate was
/// obtained, and never after [`latest`], which keeps it from parking a certificate
/// until it expires.
pub fn renew_at(not_before: u64, not_after: u64, pick: u64, floor: u64) -> u64 {
    pick.max(floor).min(latest(not_before, not_after))
}

/// The earliest renewal that the authority may ask for, for a certificate that this
/// process obtained at `obtained`: two minutes later, or a tenth of the lifetime when
/// that is shorter. A certificate that was loaded from the storage has no floor.
pub fn floor(obtained: Option<u64>, not_before: u64, not_after: u64) -> u64 {
    let tenth = (not_after.saturating_sub(not_before) / 10).max(1);
    obtained.map_or(0, |at| at + tenth.min(crate::schedule::FIRST_DELAY))
}

/// The seconds until the next question about a certificate: the `Retry-After` of the
/// answer, between one hour and one day, or six hours without it. A certificate that
/// lives less than ten hours is asked about every tenth of its lifetime at least, and
/// never more often than once a second.
pub fn poll_after(retry_after: Option<u64>, not_before: u64, not_after: u64) -> u64 {
    let tenth = (not_after.saturating_sub(not_before) / 10).max(1);
    let asked = retry_after.unwrap_or(DEFAULT_POLL).clamp(SHORTEST_POLL, LONGEST_POLL);
    asked.min(tenth)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    const NOW: u64 = 1_795_516_496;

    fn certificate(key_id: &[u8], serial: &[u8]) -> x509::Certificate {
        x509::Certificate {
            not_before: NOW,
            not_after: NOW + 1000,
            issuer: "Test".to_owned(),
            names: Vec::new(),
            serial: serial.to_vec(),
            authority_key_id: key_id.to_vec(),
        }
    }

    fn answer(body: &str) -> Response {
        Response { status: 200, body: body.as_bytes().to_vec(), ..Response::default() }
    }

    #[test]
    fn the_identifier_is_that_of_rfc_9773() {
        // RFC 9773, section 4.1: the example certificate.
        let key_id = [
            0x69, 0x88, 0x5b, 0x6b, 0x87, 0x46, 0x40, 0x41, 0xe1, 0xb3, 0x7b, 0x84, 0x7b, 0xa0,
            0xae, 0x2c, 0xde, 0x01, 0xc8, 0xd4,
        ];
        let serial = [0x00, 0x87, 0x65, 0x43, 0x21];
        assert_eq!(
            certificate_id(&certificate(&key_id, &serial)).as_deref(),
            Some("aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE")
        );
        assert_eq!(certificate_id(&certificate(&[], &serial)), None);
    }

    #[test]
    fn the_endpoint_is_read_from_the_directory() {
        let directory = "https://ca.example/dir";
        let with = answer(r#"{"newNonce":"x","renewalInfo":"https://ca.example/ari/"}"#);
        assert_eq!(endpoint(directory, &with).unwrap().as_deref(), Some("https://ca.example/ari"));
        assert_eq!(endpoint(directory, &answer(r#"{"newNonce":"x"}"#)).unwrap(), None);
        let plain = answer(r#"{"renewalInfo":"http://ca.example/ari"}"#);
        assert_eq!(endpoint(directory, &plain).unwrap_err().code, "ACME006");
        assert!(endpoint("http://127.0.0.1:1/dir", &plain).unwrap().is_some());
        assert!(endpoint(directory, &answer("[]")).is_err());
        assert!(endpoint(directory, &Response { status: 500, ..Response::default() }).is_err());
        let found = request("https://ca.example/ari", "a.b");
        assert_eq!(
            (found.method, found.url.as_str()),
            (Method::Get, "https://ca.example/ari/a.b")
        );
    }

    #[test]
    fn the_window_is_read_with_its_bounds() {
        // RFC 9773, section 4.2: the example answer.
        let body = r#"{
            "suggestedWindow": {
              "start": "2025-01-02T04:00:00Z",
              "end": "2025-01-03T04:00:00Z"
            },
            "explanationURL": "https://acme.example.com/docs/ari"
        }"#;
        let mut response = answer(body);
        response.retry_after = Some(21_600);
        let info = parse(&response).unwrap();
        assert_eq!(info.window, Window { start: 1_735_790_400, end: 1_735_876_800 });
        assert_eq!(info.retry_after, Some(21_600));
        let bad = [
            "",
            "{}",
            r#"{"suggestedWindow":{}}"#,
            r#"{"suggestedWindow":{"start":"2025-01-02T04:00:00Z"}}"#,
            r#"{"suggestedWindow":{"start":"2025-01-03T04:00:00Z","end":"2025-01-02T04:00:00Z"}}"#,
            r#"{"suggestedWindow":{"start":"soon","end":"later"}}"#,
        ];
        for body in bad {
            assert_eq!(parse(&answer(body)).unwrap_err().code, "ACME006", "{body}");
        }
        let large = format!(r#"{{"pad":"{}"}}"#, "x".repeat(MAX_ANSWER));
        assert!(parse(&answer(&large)).is_err());
        assert!(parse(&Response { status: 404, ..Response::default() }).is_err());
    }

    #[test]
    fn the_pick_lies_in_the_window_and_depends_on_the_serial_only() {
        let window = Window { start: NOW, end: NOW + 86_400 };
        let mut picks = std::collections::BTreeSet::new();
        for serial in 0u32..200 {
            let at = pick(window, &serial.to_be_bytes());
            assert!((window.start..window.end).contains(&at));
            assert_eq!(at, pick(window, &serial.to_be_bytes()));
            picks.insert(at);
        }
        // The picks spread: 200 serials do not share a handful of times.
        assert!(picks.len() > 190);
        assert_eq!(pick(Window { start: NOW, end: NOW }, b"1"), NOW);
        assert_eq!(pick(Window { start: NOW, end: NOW + 1 }, b"1"), NOW);
    }

    #[test]
    fn the_renewal_respects_the_floor_and_the_cap() {
        let (b, e) = (NOW, NOW + 1000);
        assert_eq!(latest(b, e), NOW + 800);
        assert_eq!(renew_at(b, e, NOW + 500, 0), NOW + 500);
        // The authority cannot park the certificate.
        assert_eq!(renew_at(b, e, NOW + 5000, 0), NOW + 800);
        assert_eq!(renew_at(b, e, u64::MAX, 0), NOW + 800);
        // A window in the past is due at once for a loaded certificate, and after the
        // floor for one that was just obtained.
        assert_eq!(renew_at(b, e, NOW - 10, 0), NOW - 10);
        assert_eq!(floor(None, b, e), 0);
        assert_eq!(floor(Some(NOW + 3), b, e), NOW + 103);
        assert_eq!(floor(Some(NOW), NOW, NOW + 90 * 86_400), NOW + 120);
        assert_eq!(renew_at(b, e, NOW - 10, floor(Some(NOW + 3), b, e)), NOW + 103);
        // The cap wins over the floor.
        assert_eq!(renew_at(b, e, 0, NOW + 900), NOW + 800);
    }

    #[test]
    fn the_poll_pause_is_clamped() {
        let long = (NOW, NOW + 90 * 86_400);
        assert_eq!(poll_after(None, long.0, long.1), 21_600);
        assert_eq!(poll_after(Some(1), long.0, long.1), 3600);
        assert_eq!(poll_after(Some(7200), long.0, long.1), 7200);
        assert_eq!(poll_after(Some(10 * 86_400), long.0, long.1), 86_400);
        // A certificate of a minute is asked about every six seconds.
        assert_eq!(poll_after(None, NOW, NOW + 60), 6);
        assert_eq!(poll_after(Some(1), NOW, NOW + 60), 6);
        assert_eq!(poll_after(None, NOW, NOW + 5), 1);
        assert_eq!(poll_after(None, NOW, NOW), 1);
    }
}
