//! What a frontend or a route does to a request besides choosing its pool (SID 0019):
//! the redirect to HTTPS, HSTS, edits of the header fields and a bound on the body.
//!
//! A frontend states a policy. A route states only what differs: each member it leaves
//! out is that of its frontend. Every member has a default that changes nothing.

use std::io;
use std::sync::Arc;

use sibuna_json::{ObjectReader, Value};

use crate::config::{field, invalid};

/// The most fields one edit sets, and the most it removes.
const MAX_FIELDS: usize = 32;
/// The longest value of a field that an edit sets.
const MAX_VALUE: usize = 1024;
/// The largest `max_body`: one tebibyte.
const MAX_BODY: u64 = 1 << 40;
/// The name of the HSTS field, in lower case.
const HSTS: &str = "strict-transport-security";
/// The `max-age` of `"hsts": true`: one year.
const HSTS_YEAR: u64 = 31_536_000;

/// Fields that frame a message or describe one hop. No edit may name them.
const FRAMING: [&str; 9] = [
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Request fields that Sibuna writes itself. A request edit may not name them.
const OWN_REQUEST: [&str; 10] = [
    "expect",
    "forwarded",
    "x-client-cert-sha256",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-proto",
    "x-real-ip",
    "x-sibuna-rule",
    "x-sibuna-status",
];

/// A redirect of cleartext requests to HTTPS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Redirect {
    /// The status of the answer: 308 keeps the method, 301 is for old clients.
    pub status: u16,
    /// The HTTPS port in the new location. 443 is left out of the location.
    pub port: u16,
}

/// A change to the header fields of a message: names to drop, then lines to add.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FieldEdit {
    /// Names of fields to drop, in lower case. A field that is set is dropped first.
    pub remove: Box<[Box<str>]>,
    /// The field lines to add, each ending in CRLF.
    pub append: Box<[u8]>,
}

/// The policy of one frontend or route. The default changes nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoutePolicy {
    /// Answer a cleartext request with a redirect to HTTPS.
    pub redirect_https: Option<Redirect>,
    /// The operator wrote `redirect_https: false`. The request stays on HTTP, and the
    /// automatic redirect of SID 0021 leaves it alone as well.
    pub keeps_http: bool,
    /// The `Strict-Transport-Security` line for responses on a TLS frontend, or empty.
    pub hsts: Box<[u8]>,
    /// The edit of the request that goes to the server.
    pub request_headers: FieldEdit,
    /// The edit of the response that goes to the client.
    pub response_headers: FieldEdit,
    /// The largest request body in bytes. A larger request is answered with 413.
    pub max_body: Option<u64>,
    /// The names dropped from a response: those of `response_headers`, and the HSTS
    /// field of the server when we write our own.
    response_remove: Box<[Box<str>]>,
}

impl RoutePolicy {
    /// A policy that only redirects to HTTPS on `port` with status 308: the automatic
    /// redirect of SID 0021, which then writes the answer of `redirect_https`.
    pub fn redirect_to(port: u16) -> Self {
        Self { redirect_https: Some(Redirect { status: 308, port }), ..Self::default() }
    }

    /// True when the policy changes nothing.
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// The names of the fields that are dropped from the response of a server. When the
    /// policy writes HSTS, the HSTS field of the server is among them, so that a client
    /// reads one policy.
    pub fn response_remove(&self) -> &[Box<str>] {
        &self.response_remove
    }

    /// Appends the location of the HTTPS redirect for a request to `host` (the `Host`
    /// field, validated by the caller), `path` and `query`.
    pub fn write_location(&self, out: &mut Vec<u8>, host: &[u8], path: &[u8], query: &[u8]) {
        out.extend_from_slice(b"https://");
        out.extend_from_slice(crate::http::bare_host(host));
        let port = self.redirect_https.map_or(443, |redirect| redirect.port);
        if port != 443 {
            out.extend_from_slice(format!(":{port}").as_bytes());
        }
        out.extend_from_slice(path);
        if !query.is_empty() {
            out.push(b'?');
            out.extend_from_slice(query);
        }
    }

    /// Reads the policy members of a frontend or route object. A member that is absent
    /// is that of `base`. `tls` says whether the frontend terminates TLS.
    ///
    /// # Errors
    ///
    /// A diagnostic for a malformed member, for `hsts` on a cleartext frontend and for
    /// `redirect_https` on a TLS frontend.
    pub(crate) fn parse(
        r: &mut ObjectReader<'_, '_>,
        base: &Arc<Self>,
        tls: bool,
    ) -> io::Result<Arc<Self>> {
        let mut policy = Self::clone(base);
        let mut stated = false;
        if let Some(value) = r.take("redirect_https") {
            let path = r.field_path("redirect_https");
            policy.redirect_https = redirect(value, &path)?;
            policy.keeps_http = policy.redirect_https.is_none();
            if tls && policy.redirect_https.is_some() {
                return Err(invalid(format!(
                    "{path}: this frontend already serves HTTPS. Hint: put the redirect on \
                     the cleartext frontend that listens on port 80."
                )));
            }
            stated = true;
        }
        if let Some(value) = r.take("hsts") {
            let path = r.field_path("hsts");
            policy.hsts = hsts(value, &path)?;
            if !tls && !policy.hsts.is_empty() {
                return Err(invalid(format!(
                    "{path}: browsers ignore HSTS on a cleartext response. Hint: put it on \
                     the frontend that has a tls section."
                )));
            }
            stated = true;
        }
        if let Some(value) = r.take("request_headers") {
            policy.request_headers = edit(value, &r.field_path("request_headers"), true)?;
            stated = true;
        }
        if let Some(value) = r.take("response_headers") {
            policy.response_headers = edit(value, &r.field_path("response_headers"), false)?;
            stated = true;
        }
        if let Some(value) = r.take("max_body") {
            policy.max_body = max_body(value, &r.field_path("max_body"))?;
            stated = true;
        }
        if !stated {
            return Ok(Arc::clone(base));
        }
        let mut remove = policy.response_headers.remove.to_vec();
        if !policy.hsts.is_empty() && !remove.iter().any(|name| **name == *HSTS) {
            remove.push(HSTS.into());
        }
        policy.response_remove = remove.into();
        Ok(Arc::new(policy))
    }
}

/// Reads `redirect_https`: `true` (308), `false`, 301, 308, or an object with `status`
/// and `port`.
fn redirect(value: &Value<'_>, path: &str) -> io::Result<Option<Redirect>> {
    let hint = "Hint: write true, 301 or 308, or {\"status\": 308, \"port\": 8443}.";
    let status = |code: u64| match code {
        301 | 308 => Ok(code as u16),
        _ => Err(invalid(format!("{path}: expected status 301 or 308, found {code}. {hint}"))),
    };
    if let Some(on) = value.as_bool() {
        return Ok(on.then_some(Redirect { status: 308, port: 443 }));
    }
    if let Some(number) = value.as_number() {
        let code = number.as_u64().map_err(|_| invalid(format!("{path}: {hint}")))?;
        return Ok(Some(Redirect { status: status(code)?, port: 443 }));
    }
    let mut rule = field(ObjectReader::with_path(value, path.to_owned())).map_err(|_| {
        invalid(format!("{path}: expected true, false, a status or an object. {hint}"))
    })?;
    let code = field(rule.take_u64("status"))?.unwrap_or(308);
    let port = field(rule.take_u64("port"))?.unwrap_or(443);
    field(rule.finish())?;
    if !(1..=65535).contains(&port) {
        return Err(invalid(format!("{path}.port: expected a port in 1..=65535, found {port}")));
    }
    Ok(Some(Redirect { status: status(code)?, port: port as u16 }))
}

/// Reads `hsts`: `true` (one year), `false`, or an object with `max_age` in seconds,
/// `include_subdomains` and `preload`. Returns the field line, or nothing.
fn hsts(value: &Value<'_>, path: &str) -> io::Result<Box<[u8]>> {
    let (age, subdomains, preload) = match value.as_bool() {
        Some(false) => return Ok(Box::default()),
        Some(true) => (HSTS_YEAR, false, false),
        None => {
            let mut rule =
                field(ObjectReader::with_path(value, path.to_owned())).map_err(|_| {
                    invalid(format!(
                        "{path}: expected true, false or an object. Hint: the members are \
                     max_age (seconds), include_subdomains and preload."
                    ))
                })?;
            let age = field(rule.take_u64("max_age"))?.unwrap_or(HSTS_YEAR);
            let subdomains = field(rule.take_bool("include_subdomains"))?.unwrap_or(false);
            let preload = field(rule.take_bool("preload"))?.unwrap_or(false);
            field(rule.finish())?;
            (age, subdomains, preload)
        }
    };
    if age > 10 * HSTS_YEAR {
        return Err(invalid(format!("{path}.max_age: expected at most ten years of seconds")));
    }
    let mut line = format!("Strict-Transport-Security: max-age={age}");
    if subdomains {
        line.push_str("; includeSubDomains");
    }
    if preload {
        line.push_str("; preload");
    }
    line.push_str("\r\n");
    Ok(line.into_bytes().into())
}

/// Reads `max_body`: a number of bytes, a text such as `"10m"` (k, m and g are powers
/// of 1024), or `"off"`.
fn max_body(value: &Value<'_>, path: &str) -> io::Result<Option<u64>> {
    let bytes = match (value.as_str(), value.as_number()) {
        (Some("off"), _) => return Ok(None),
        (Some(text), _) => size(text),
        (None, Some(number)) => number.as_u64().ok(),
        (None, None) => None,
    };
    match bytes {
        Some(bytes) if (1..=MAX_BODY).contains(&bytes) => Ok(Some(bytes)),
        _ => Err(invalid(format!(
            "{path}: expected a size from 1 byte to 1024g, such as 1048576 or \"10m\". \
             Hint: write \"off\" for no bound."
        ))),
    }
}

/// The bytes of a size text: digits and an optional `k`, `m` or `g`.
fn size(text: &str) -> Option<u64> {
    let (digits, shift) = match text.as_bytes().last()?.to_ascii_lowercase() {
        b'k' => (&text[..text.len() - 1], 10),
        b'm' => (&text[..text.len() - 1], 20),
        b'g' => (&text[..text.len() - 1], 30),
        _ => (text, 0),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u64>().ok()?.checked_mul(1 << shift)
}

/// Reads a field edit: `{"set": {"Name": "value"}, "remove": ["Name"]}`.
fn edit(value: &Value<'_>, path: &str, request: bool) -> io::Result<FieldEdit> {
    let mut rule = field(ObjectReader::with_path(value, path.to_owned())).map_err(|_| {
        invalid(format!(
            "{path}: expected an object. Hint: write {{\"set\": {{\"Name\": \"value\"}}, \
             \"remove\": [\"Name\"]}}; both members are optional."
        ))
    })?;
    let mut remove: Vec<Box<str>> = Vec::new();
    let mut append = Vec::new();
    if let Some(set) = rule.take("set") {
        let where_ = format!("{path}.set");
        let object =
            set.as_object().ok_or_else(|| invalid(format!("{where_}: expected an object")))?;
        for (name, value) in object.iter() {
            let name = field_name(name, &where_, request)?;
            let value = value.as_str().filter(|text| is_field_value(text)).ok_or_else(|| {
                invalid(format!(
                    "{where_}.{name}: expected a text of at most {MAX_VALUE} printable ASCII \
                     characters. Hint: a value holds no line break."
                ))
            })?;
            append.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
            remove.push(name.to_ascii_lowercase().into());
        }
    }
    for name in field(rule.take_array("remove"))?.unwrap_or_default() {
        let where_ = format!("{path}.remove");
        let name = name.as_str().ok_or_else(|| invalid(format!("{where_}: expected names")))?;
        let name = field_name(name, &where_, request)?.to_ascii_lowercase();
        if !remove.iter().any(|known| **known == *name) {
            remove.push(name.into());
        }
    }
    field(rule.finish())?;
    if remove.len() > MAX_FIELDS {
        return Err(invalid(format!("{path}: expected at most {MAX_FIELDS} fields")));
    }
    Ok(FieldEdit { remove: remove.into(), append: append.into() })
}

/// Checks the name of a field that an edit sets or removes.
fn field_name<'a>(name: &'a str, path: &str, request: bool) -> io::Result<&'a str> {
    let token = |b: u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b);
    if name.is_empty() || name.len() > 64 || !name.bytes().all(token) {
        return Err(invalid(format!(
            "{path}: {name:?} is not a field name. Hint: a name is 1 to 64 letters, digits \
             and `-`, such as X-Frame-Options."
        )));
    }
    let lower = name.to_ascii_lowercase().replace('_', "-");
    let own = request && OWN_REQUEST.contains(&lower.as_str());
    if FRAMING.contains(&lower.as_str()) || own {
        return Err(invalid(format!(
            "{path}: {name} is written by Sibuna and cannot be edited. Hint: the fields \
             that frame a message and the forwarding fields are not open to edits."
        )));
    }
    Ok(name)
}

fn is_field_value(text: &str) -> bool {
    text.len() <= MAX_VALUE
        && text.bytes().all(|b| b == b'\t' || (b' '..=b'~').contains(&b))
        && text.trim() == text
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn parse(source: &str, tls: bool) -> io::Result<Arc<RoutePolicy>> {
        parse_over(source, &Arc::default(), tls)
    }

    fn parse_over(
        source: &str,
        base: &Arc<RoutePolicy>,
        tls: bool,
    ) -> io::Result<Arc<RoutePolicy>> {
        let value = sibuna_json::parse(source.as_bytes()).unwrap();
        let mut r = ObjectReader::with_path(&value, "frontends.web".into()).unwrap();
        let policy = RoutePolicy::parse(&mut r, base, tls)?;
        r.finish().unwrap();
        Ok(policy)
    }

    #[test]
    fn a_policy_without_members_changes_nothing() {
        let policy = parse("{}", false).unwrap();
        assert!(policy.is_default());
        assert_eq!(policy.redirect_https, None);
        assert!(policy.hsts.is_empty());
        assert_eq!(policy.max_body, None);
        assert!(policy.request_headers.remove.is_empty());
        assert!(policy.response_headers.append.is_empty());
    }

    #[test]
    fn the_redirect_reads_a_switch_a_status_or_an_object() {
        let redirect = |source: &str| parse(source, false).map(|policy| policy.redirect_https);
        let to = |status, port| Some(Redirect { status, port });
        assert_eq!(redirect(r#"{"redirect_https":true}"#).unwrap(), to(308, 443));
        assert_eq!(redirect(r#"{"redirect_https":false}"#).unwrap(), None);
        let keeps = |source: &str| parse(source, false).unwrap().keeps_http;
        assert!(keeps(r#"{"redirect_https":false}"#));
        assert!(!keeps(r#"{"redirect_https":true}"#) && !keeps(r#"{"max_body":"1k"}"#));
        assert_eq!(RoutePolicy::redirect_to(8443).redirect_https, to(308, 8443));
        assert_eq!(redirect(r#"{"redirect_https":301}"#).unwrap(), to(301, 443));
        assert_eq!(redirect(r#"{"redirect_https":{"port":8443}}"#).unwrap(), to(308, 8443));
        let both = r#"{"redirect_https":{"status":301,"port":444}}"#;
        assert_eq!(redirect(both).unwrap(), to(301, 444));
        for bad in [
            r#"{"redirect_https":302}"#,
            r#"{"redirect_https":"yes"}"#,
            r#"{"redirect_https":{"port":0}}"#,
            r#"{"redirect_https":{"code":301}}"#,
        ] {
            assert!(redirect(bad).unwrap_err().to_string().contains("redirect_https"), "{bad}");
        }
        let error = parse(r#"{"redirect_https":true}"#, true).unwrap_err().to_string();
        assert!(error.contains("already serves HTTPS") && error.contains("Hint:"), "{error}");
        assert!(parse(r#"{"redirect_https":false}"#, true).is_ok());
    }

    #[test]
    fn the_location_keeps_host_path_and_query_and_names_an_odd_port() {
        let location = |source: &str, host: &[u8], query: &[u8]| {
            let mut out = Vec::new();
            parse(source, false).unwrap().write_location(&mut out, host, b"/a/b", query);
            String::from_utf8(out).unwrap()
        };
        let plain = r#"{"redirect_https":true}"#;
        assert_eq!(location(plain, b"example.org", b""), "https://example.org/a/b");
        assert_eq!(
            location(plain, b"example.org:8080", b"x=1&y"),
            "https://example.org/a/b?x=1&y"
        );
        assert_eq!(location(plain, b"[2001:db8::1]:80", b""), "https://[2001:db8::1]/a/b");
        let odd = r#"{"redirect_https":{"port":8443}}"#;
        assert_eq!(location(odd, b"example.org:80", b""), "https://example.org:8443/a/b");
    }

    #[test]
    fn hsts_needs_a_tls_frontend_and_writes_its_line() {
        let line =
            |source: &str| String::from_utf8(parse(source, true).unwrap().hsts.to_vec()).unwrap();
        assert_eq!(line(r#"{"hsts":true}"#), "Strict-Transport-Security: max-age=31536000\r\n");
        assert_eq!(line(r#"{"hsts":false}"#), "");
        // Our HSTS replaces that of the server. A route that turns it off keeps both out
        // of the edit.
        let on = parse(r#"{"hsts":true,"response_headers":{"remove":["Server"]}}"#, true).unwrap();
        let removed: Vec<&str> = on.response_remove().iter().map(|name| &**name).collect();
        assert_eq!(removed, ["server", "strict-transport-security"]);
        let off = parse_over(r#"{"hsts":false}"#, &on, true).unwrap();
        assert_eq!(off.response_remove().len(), 1);
        let full = r#"{"hsts":{"max_age":600,"include_subdomains":true,"preload":true}}"#;
        assert_eq!(
            line(full),
            "Strict-Transport-Security: max-age=600; includeSubDomains; preload\r\n"
        );
        let error = parse(r#"{"hsts":true}"#, false).unwrap_err().to_string();
        assert!(error.contains("cleartext") && error.contains("Hint:"), "{error}");
        assert!(parse(r#"{"hsts":"1y"}"#, true).is_err());
        assert!(parse(r#"{"hsts":{"max_age":99999999999}}"#, true).is_err());
    }

    #[test]
    fn an_edit_sets_and_removes_fields_and_refuses_framing() {
        let source = r#"{"request_headers":{"set":{"X-Tenant":"a b"},
                "remove":["X-Debug","x-tenant"]},
            "response_headers":{"set":{"X-Frame-Options":"DENY"},"remove":["Server"]}}"#;
        let policy = parse(source, false).unwrap();
        let names =
            |edit: &FieldEdit| edit.remove.iter().map(|n| n.to_string()).collect::<Vec<_>>();
        assert_eq!(names(&policy.request_headers), ["x-tenant", "x-debug"]);
        assert_eq!(&*policy.request_headers.append, b"X-Tenant: a b\r\n");
        assert_eq!(names(&policy.response_headers), ["x-frame-options", "server"]);
        assert_eq!(&*policy.response_headers.append, b"X-Frame-Options: DENY\r\n");
        for bad in [
            r#"{"request_headers":{"set":{"Host":"x"}}}"#,
            r#"{"request_headers":{"remove":["Content-Length"]}}"#,
            r#"{"request_headers":{"set":{"X_Forwarded_For":"1.2.3.4"}}}"#,
            r#"{"response_headers":{"set":{"Transfer-Encoding":"chunked"}}}"#,
            r#"{"response_headers":{"set":{"X-A":"a\r\nX-B: b"}}}"#,
            r#"{"response_headers":{"set":{"X A":"a"}}}"#,
            r#"{"response_headers":{"set":{"X-A":7}}}"#,
            r#"{"response_headers":{"add":{"X-A":"a"}}}"#,
            r#"{"response_headers":["X-A"]}"#,
        ] {
            assert!(parse(bad, false).is_err(), "{bad}");
        }
        // A response may set a field that only requests reserve.
        assert!(parse(r#"{"response_headers":{"set":{"X-Real-IP":"x"}}}"#, false).is_ok());
    }

    #[test]
    fn max_body_reads_bytes_and_suffixes() {
        let bound = |source: &str| parse(source, false).map(|policy| policy.max_body);
        assert_eq!(bound(r#"{"max_body":4096}"#).unwrap(), Some(4096));
        assert_eq!(bound(r#"{"max_body":"64k"}"#).unwrap(), Some(65536));
        assert_eq!(bound(r#"{"max_body":"10M"}"#).unwrap(), Some(10 << 20));
        assert_eq!(bound(r#"{"max_body":"1g"}"#).unwrap(), Some(1 << 30));
        assert_eq!(bound(r#"{"max_body":"off"}"#).unwrap(), None);
        for bad in [
            r#"{"max_body":0}"#,
            r#"{"max_body":"10x"}"#,
            r#"{"max_body":"2000g"}"#,
            r#"{"max_body":true}"#,
            r#"{"max_body":"k"}"#,
        ] {
            let error = bound(bad).unwrap_err().to_string();
            assert!(error.contains("max_body") && error.contains("Hint:"), "{error}");
        }
    }

    #[test]
    fn a_route_keeps_what_it_does_not_state() {
        let base =
            parse(r#"{"max_body":"1m","response_headers":{"remove":["Server"]}}"#, false).unwrap();
        let same = parse_over("{}", &base, false).unwrap();
        assert!(Arc::ptr_eq(&same, &base));
        let route =
            parse_over(r#"{"max_body":"off","redirect_https":true}"#, &base, false).unwrap();
        assert_eq!(route.max_body, None);
        assert_eq!(route.redirect_https, Some(Redirect { status: 308, port: 443 }));
        assert_eq!(route.response_headers, base.response_headers);
    }
}
