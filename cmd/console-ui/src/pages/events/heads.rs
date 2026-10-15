//! Redacted request and response heads of one incident (Zig `incident_heads.zig`): hex
//! decoded, drawn as UTF-8 (lossy) or Latin-1, and rebuilt as a cURL command whose values
//! stay redacted and which states what it lacks.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::codec::WireEnum;
use sibuna_console_protocol::incident_heads::{
    REQUEST_BYTES, REQUEST_HEX, RESPONSE_BYTES, RESPONSE_HEX, ResponseState,
};
use sibuna_html::write_value;
use sibuna_json::Value;

use super::wire::{self, boolean, counter, number, required, text};
use crate::error::UiError;
use crate::render::Html;

/// How the head bytes are drawn.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Charset {
    /// UTF-8; invalid sequences show as U+FFFD.
    #[default]
    Utf8,
    /// Latin-1: each byte is its own code point.
    Latin1,
}

/// The outcome of the last copy to the clipboard.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Copied {
    /// No copy since the command was drawn.
    #[default]
    None,
    /// The browser copied the command.
    Ok,
    /// The browser refused the copy.
    Failed,
}

/// The heads of the one incident whose heads the operator asked for.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct IncidentHeads {
    /// The incident; 0 for none.
    pub id: u64,
    /// Heads were captured for the incident.
    pub recorded: bool,
    /// The reply arrived and was valid.
    pub loaded: bool,
    /// The request is in flight.
    pub busy: bool,
    /// The request failed or the reply was invalid.
    pub failed: bool,
    /// The redacted request head, at most 2 KiB.
    pub request: Vec<u8>,
    /// The redacted response head, at most 1 KiB.
    pub response: Vec<u8>,
    /// The request head was truncated at capture.
    pub request_truncated: bool,
    /// The response head was truncated at capture.
    pub response_truncated: bool,
    /// What became of the origin response.
    pub response_state: ResponseState,
    /// How the bytes are drawn.
    pub charset: Charset,
    /// The last copy's outcome.
    pub copied: Copied,
}

impl IncidentHeads {
    /// Takes the heads reply for [`IncidentHeads::id`]. Nothing changes unless it is valid.
    ///
    /// # Errors
    ///
    /// [`UiError::InvalidResponse`] for a missing member, another version or incident, or
    /// hex that is odd, too long or not hex.
    pub fn set(&mut self, value: &Value<'_>) -> Result<(), UiError> {
        let value = wire::object(value)?;
        let version: u8 = required(value, "version", number)?;
        let id = required(value, "id", counter)?;
        let recorded = required(value, "recorded", boolean)?;
        let request = required(value, "request", text)?;
        let response = required(value, "response", text)?;
        let request_truncated = required(value, "request_truncated", boolean)?;
        let response_truncated = required(value, "response_truncated", boolean)?;
        let response_state = required(value, "response_state", |item| {
            item.as_str().and_then(ResponseState::from_name)
        })?;
        if version != 1 || id != self.id || request.len() > REQUEST_HEX {
            return Err(UiError::InvalidResponse);
        }
        if response.len() > RESPONSE_HEX {
            return Err(UiError::InvalidResponse);
        }
        let request = hex_bytes(request, REQUEST_BYTES)?;
        let response = hex_bytes(response, RESPONSE_BYTES)?;
        self.request = request;
        self.response = response;
        self.recorded = recorded;
        self.request_truncated = request_truncated;
        self.response_truncated = response_truncated;
        self.response_state = response_state;
        self.loaded = true;
        Ok(())
    }
}

/// Decodes hex digits (either case) into at most `max` bytes.
fn hex_bytes(text: &str, max: usize) -> Result<Vec<u8>, UiError> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() || pairs.len() > max {
        return Err(UiError::InvalidResponse);
    }
    let nibble = |digit: u8| char::from(digit).to_digit(16).and_then(|v| u8::try_from(v).ok());
    pairs
        .iter()
        .map(|[high, low]| Some(nibble(*high)? << 4 | nibble(*low)?))
        .collect::<Option<Vec<u8>>>()
        .ok_or(UiError::InvalidResponse)
}

/// Draws the heads area of the incident `id` (Zig `incident_heads.render`).
///
/// # Errors
///
/// The page exceeded the render bound.
pub fn render(model: &IncidentHeads, id: u64, out: &mut Html<'_>) -> fmt::Result {
    if model.id != id {
        out.write_str(
            "<p class=\"mt-3\"><button class=\"btn btn-sm\" data-action=\"events-heads-",
        )?;
        write_value(out, &id)?;
        return out.write_str("\">Show request and response heads</button></p>");
    }
    if model.busy {
        return out.write_str("<p role=\"status\">Loading heads\u{2026}</p>");
    }
    if model.failed {
        out.write_str(
            "<p class=\"sb-note\" role=\"status\">Heads unavailable. <button class=\"btn \
             btn-xs\" data-action=\"events-heads-",
        )?;
        write_value(out, &id)?;
        return out.write_str("\">Retry</button></p>");
    }
    if !model.loaded {
        return Ok(());
    }
    if !model.recorded {
        return out.write_str(
            "<p class=\"sb-note\">Request and response heads: Not recorded. Capture is off \
             (start with --console-capture-heads) or this incident predates it.</p>",
        );
    }
    out.write_str(
        "<section class=\"mt-3\" aria-label=\"Captured heads\"><h3>Request \u{b7} Response\
         </h3><p class=\"sb-note\">Redacted before capture: only listed header values are \
         kept, credential headers and every query value read [redacted]. Rendered as ",
    )?;
    out.write_str(match model.charset {
        Charset::Utf8 => "UTF-8 (invalid bytes shown as U+FFFD)",
        Charset::Latin1 => "Latin-1",
    })?;
    out.write_str(
        ". <button class=\"btn btn-xs\" data-action=\"events-heads-utf8\">UTF-8</button> \
         <button class=\"btn btn-xs\" data-action=\"events-heads-latin1\">Latin-1</button>\
         </p><h4>Request head",
    )?;
    if model.request_truncated {
        out.write_str(" (truncated at 2 KiB)")?;
    }
    out.write_str("</h4><pre class=\"whitespace-pre-wrap break-all\">")?;
    head_text(out, &model.request, model.charset)?;
    out.write_str("</pre><h4>Response head")?;
    if model.response_truncated {
        out.write_str(" (truncated at 1 KiB)")?;
    }
    out.write_str("</h4><pre class=\"whitespace-pre-wrap break-all\">")?;
    response_text(model, out)?;
    out.write_str("</pre>")?;
    curl_section(model, out)?;
    out.write_str("</section>")
}

/// Says what each response state observed; an empty head never implies a local answer.
fn response_text(model: &IncidentHeads, out: &mut impl fmt::Write) -> fmt::Result {
    if !model.response.is_empty() {
        return head_text(out, &model.response, model.charset);
    }
    out.write_str(match model.response_state {
        ResponseState::Captured => "Captured origin head is empty.",
        ResponseState::Local => {
            "Local response: Sibuna answered the client; there is no origin head. The \
             selected status is shown above."
        }
        ResponseState::Unobserved => {
            "Forward-auth mode: the ingress relayed the origin's response; Sibuna did not \
             observe it."
        }
        ResponseState::Unavailable => {
            "Origin unavailable: the relay ended before a response head arrived, so the \
             client received 502."
        }
        ResponseState::Unknown => {
            "Not recorded: this row predates response-state capture (before schema version \
             40), so whether the response was local is unknown."
        }
    })
}

fn curl_section(model: &IncidentHeads, out: &mut Html<'_>) -> fmt::Result {
    out.write_str("<h4>Copy as cURL</h4>")?;
    let Some(command) = curl(&model.request, model.request_truncated) else {
        return out.write_str(
            "<p class=\"sb-note\">Command unavailable: the captured request line or Host \
             header is incomplete, so no usable URL exists.</p>",
        );
    };
    out.write_str(
        "<p><button class=\"btn btn-sm\" data-action=\"events-heads-copy\">Copy command\
         </button> <span role=\"status\">",
    )?;
    out.write_str(match model.copied {
        Copied::None => "",
        Copied::Ok => "Copied to the clipboard.",
        Copied::Failed => "Copy failed; select the text below and copy it.",
    })?;
    out.write_str(
        "</span></p><textarea readonly class=\"textarea font-mono w-full\" rows=\"5\" \
         aria-label=\"cURL command\">",
    )?;
    out.escaped(&command)?;
    out.write_str("</textarea>")
}

/// Writes head bytes as text without inventing content: carriage returns are dropped,
/// other control bytes show as U+2400, UTF-8 decoding replaces each invalid byte with
/// U+FFFD, and Latin-1 maps each byte to its code point. Text is escaped for HTML.
///
/// # Errors
///
/// The sink's error.
pub fn head_text(out: &mut impl fmt::Write, bytes: &[u8], charset: Charset) -> fmt::Result {
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        index += 1;
        match byte {
            b'\r' => {}
            b'\n' => out.write_char('\n')?,
            0..0x20 | 0x7f => out.write_char('\u{2400}')?,
            0x20..0x7f => sibuna_html::escape(out, char::from(byte).encode_utf8(&mut [0; 4]))?,
            _ if charset == Charset::Latin1 => out.write_char(char::from(byte))?,
            _ => {
                let start = index - 1;
                let decoded = sequence_length(byte)
                    .and_then(|length| bytes.get(start..start + length))
                    .and_then(|sequence| std::str::from_utf8(sequence).ok());
                match decoded {
                    Some(text) => {
                        out.write_str(text)?;
                        index = start + text.len();
                    }
                    None => out.write_char('\u{fffd}')?,
                }
            }
        }
    }
    Ok(())
}

/// The length a UTF-8 lead byte announces (Zig's `utf8ByteSequenceLength`).
fn sequence_length(byte: u8) -> Option<usize> {
    match byte {
        0..0x80 => Some(1),
        0xc0..0xe0 => Some(2),
        0xe0..0xf0 => Some(3),
        0xf0..0xf8 => Some(4),
        _ => None,
    }
}

/// Headers cURL must not replay: framing and hop-by-hop fields, and the Host cURL derives
/// from the URL. A value that is wholly `[redacted]` is a credential placeholder and is
/// omitted rather than sent.
const SKIPPED_HEADERS: [&[u8]; 11] = [
    b"host",
    b"content-length",
    b"transfer-encoding",
    b"connection",
    b"keep-alive",
    b"upgrade",
    b"proxy-connection",
    b"te",
    b"trailer",
    b"expect",
    b"proxy-authorization",
];

/// A header line split at its first colon, the value trimmed of spaces.
fn header_line(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let colon = line.iter().position(|&byte| byte == b':')?;
    let (name, rest) = line.split_at(colon);
    Some((name, trim_spaces(rest.get(1..).unwrap_or_default())))
}

fn trim_spaces(mut bytes: &[u8]) -> &[u8] {
    while let [b' ', rest @ ..] = bytes {
        bytes = rest;
    }
    while let [rest @ .., b' '] = bytes {
        bytes = rest;
    }
    bytes
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

/// Splits `bytes` at every CRLF, as Zig's `splitSequence` does.
fn crlf_lines(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = Some(bytes);
    std::iter::from_fn(move || {
        let current = rest?;
        match current.windows(2).position(|pair| pair == b"\r\n") {
            Some(end) => {
                rest = current.get(end + 2..);
                current.get(..end)
            }
            None => {
                rest = None;
                Some(current)
            }
        }
    })
}

/// Builds `curl --globoff -X 'METHOD' 'scheme://host/target' -H '...'` as plain text with
/// single quotes escaped, or returns `None` when the request line or Host is incomplete:
/// no usable URL is ever fabricated. The trailing comment names what the command lacks:
/// redacted or omitted values, the uncaptured body and an assumed scheme.
///
/// Head bytes that are not UTF-8 are replaced with U+FFFD in the text.
pub fn curl(head: &[u8], truncated: bool) -> Option<String> {
    let line_end = head.windows(2).position(|pair| pair == b"\r\n")?;
    let (line, rest) = head.split_at(line_end);
    let rest = rest.get(2..).unwrap_or_default();
    let mut words = line.split(|&byte| byte == b' ').filter(|word| !word.is_empty());
    let (method, target) = (words.next()?, words.next()?);
    if words.next().is_none() || words.next().is_some() {
        return None;
    }
    let absolute = contains(target, b"://");
    if !absolute && target.first() != Some(&b'/') {
        return None;
    }
    let (mut host, mut scheme, mut redactions) = (None, None, 0_usize);
    for (name, value) in crlf_lines(rest).filter_map(header_line) {
        if name.eq_ignore_ascii_case(b"host") {
            host = Some(value);
        }
        if name.eq_ignore_ascii_case(b"x-forwarded-proto") && matches!(value, b"https" | b"http") {
            scheme = Some(value);
        }
        if contains(value, b"[redacted]") {
            redactions += 1;
        }
    }
    if contains(target, b"[redacted]") {
        redactions += 1;
    }
    // A truncated head may have lost the Host line; only a complete one names the URL.
    let authority = host?;
    if truncated && !head.ends_with(b"\r\n") {
        return None;
    }
    let mut command = b"curl --globoff -X ".to_vec();
    quoted(&mut command, method);
    command.extend_from_slice(b" '");
    if !absolute {
        escape_quoted(&mut command, scheme.unwrap_or(b"http"));
        command.extend_from_slice(b"://");
        escape_quoted(&mut command, authority);
    }
    escape_quoted(&mut command, target);
    command.push(b'\'');
    for line in crlf_lines(rest) {
        let Some((name, value)) = header_line(line) else { continue };
        let skipped = SKIPPED_HEADERS.iter().any(|entry| name.eq_ignore_ascii_case(entry));
        if skipped || value == b"[redacted]" {
            continue;
        }
        command.extend_from_slice(b" \\\n  -H ");
        quoted(&mut command, line);
    }
    let mut command = String::from_utf8_lossy(&command).into_owned();
    let observed = if scheme.is_some() || absolute { "observed" } else { "assumed" };
    // Writing into a String cannot fail.
    let _ = write!(
        command,
        "\n# incomplete: {redactions} values redacted or omitted; body not captured; \
         scheme {observed}\n"
    );
    Some(command)
}

fn quoted(out: &mut Vec<u8>, value: &[u8]) {
    out.push(b'\'');
    escape_quoted(out, value);
    out.push(b'\'');
}

/// Escapes single quotes for a shell and drops control bytes.
fn escape_quoted(out: &mut Vec<u8>, value: &[u8]) {
    for &byte in value {
        if byte == b'\'' {
            out.extend_from_slice(b"'\\''");
        } else if byte >= 0x20 && byte != 0x7f {
            out.push(byte);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(bytes: &[u8], charset: Charset) -> String {
        let mut out = String::new();
        head_text(&mut out, bytes, charset).unwrap();
        out
    }

    /// Ported from `incident_heads.zig`.
    #[test]
    fn heads_render_under_both_charsets_and_become_an_escaped_marked_curl_command() {
        assert_eq!(text(b"caf\xe9 <b>\r\n\x01", Charset::Latin1), "caf\u{e9} &lt;b&gt;\n\u{2400}");
        assert_eq!(text(b"caf\xe9", Charset::Utf8), "caf\u{fffd}");
        let out = curl(
            b"GET /a?x=[redacted] HTTP/1.1\r\nHost: app.example\r\nCookie: [redacted]\r\n\
              X-Forwarded-Proto: https\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\
              X-Q: it's\r\nReferer: /r?k=[redacted]\r\n",
            false,
        )
        .unwrap();
        assert!(out.starts_with("curl --globoff -X 'GET' 'https://app.example/a?x=[redacted]'"));
        assert!(out.contains("-H 'X-Q: it'\\''s'"));
        assert!(!out.contains("Cookie"));
        assert!(!out.contains("Connection"));
        assert!(!out.contains("Content-Length"));
        assert!(out.contains("-H 'Referer: /r?k=[redacted]'"));
        assert!(out.contains(
            "# incomplete: 3 values redacted or omitted; body not captured; scheme observed"
        ));
        // No Host, an incomplete request line or a cut first line yields no command at all.
        assert_eq!(curl(b"GET /a HTTP/1.1\r\nX-Q: 1\r\n", false), None);
        assert_eq!(curl(b"GET /a\r\nHost: h\r\n", false), None);
        assert_eq!(curl(b"GET /a HTTP/1.1", true), None);
        assert_eq!(curl(b"GET * HTTP/1.1\r\nHost: h\r\n", false), None);
        assert!(
            curl(b"GET /a HTTP/1.1\r\nHost: h\r\n", false).unwrap().contains("scheme assumed")
        );
    }

    /// Ported from `incident_heads.zig`.
    #[test]
    fn response_states_are_stated_and_an_empty_head_never_claims_a_local_answer() {
        let mut model = IncidentHeads { recorded: true, loaded: true, ..Default::default() };
        let state = |model: &IncidentHeads| {
            let mut out = String::new();
            response_text(model, &mut out).unwrap();
            out
        };
        assert!(state(&model).contains("Not recorded"));
        model.response_state = ResponseState::Unobserved;
        assert!(state(&model).contains("Forward-auth"));
        model.response_state = ResponseState::Unavailable;
        assert!(state(&model).contains("502"));
    }

    #[test]
    fn a_truncated_head_needs_its_last_line_complete() {
        assert!(curl(b"GET /a HTTP/1.1\r\nHost: h\r\nX-A: 1", true).is_none());
        assert!(curl(b"GET /a HTTP/1.1\r\nHost: h\r\nX-A: 1", false).is_some());
        assert!(curl(b"GET /a HTTP/1.1\r\nHost: h\r\n", true).is_some());
        let absolute = curl(b"GET http://x/y HTTP/1.1\r\nHost: h\r\n", false).unwrap();
        assert!(absolute.starts_with("curl --globoff -X 'GET' 'http://x/y'"));
        assert!(absolute.ends_with("scheme observed\n"));
    }

    #[test]
    fn utf8_heads_keep_valid_sequences_and_replace_each_invalid_byte() {
        assert_eq!(text("\u{e9}\u{1f600}".as_bytes(), Charset::Utf8), "\u{e9}\u{1f600}");
        assert_eq!(text(b"\xf0\x9f\x98", Charset::Utf8), "\u{fffd}\u{fffd}\u{fffd}");
        assert_eq!(text(b"\xed\xa0\x80", Charset::Utf8), "\u{fffd}\u{fffd}\u{fffd}");
        assert_eq!(text(b"\x7f\"'&", Charset::Utf8), "\u{2400}&quot;&#39;&amp;");
    }

    #[test]
    fn replies_decode_hex_for_the_requested_incident_only() {
        let mut model = IncidentHeads { id: 5, busy: true, ..Default::default() };
        let reply = |id: &str, request: &str| {
            format!(
                "{{\"version\":1,\"id\":{id},\"recorded\":true,\"request\":\"{request}\",\
                 \"response\":\"\",\"request_truncated\":false,\"response_truncated\":false,\
                 \"response_state\":\"local\"}}"
            )
        };
        let set = |model: &mut IncidentHeads, text: String| {
            model.set(&sibuna_json::parse(text.as_bytes()).unwrap())
        };
        assert_eq!(set(&mut model, reply("6", "4745")), Err(UiError::InvalidResponse));
        assert_eq!(set(&mut model, reply("5", "474")), Err(UiError::InvalidResponse));
        assert_eq!(set(&mut model, reply("5", "47zz")), Err(UiError::InvalidResponse));
        assert!(!model.loaded);
        set(&mut model, reply("\"5\"", "4a4B")).unwrap();
        assert_eq!(model.request, b"JK");
        assert_eq!(model.response_state, ResponseState::Local);
        assert!(model.loaded && model.recorded);
        let long = "00".repeat(REQUEST_BYTES + 1);
        assert_eq!(set(&mut model, reply("5", &long)), Err(UiError::InvalidResponse));
    }

    /// Random heads: the command builder never panics and only ever names a complete URL.
    #[test]
    fn random_heads_never_panic() {
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let alphabet = b"GET /:\r\n Host'x[redacted]\x01\xff\xe9";
        for _ in 0..20_000 {
            let length = (next() % 64) as usize;
            let head: Vec<u8> =
                (0..length).map(|_| alphabet[(next() % alphabet.len() as u64) as usize]).collect();
            if let Some(command) = curl(&head, next() % 2 == 0) {
                assert!(command.starts_with("curl --globoff -X '"));
            }
            let _ = text(&head, Charset::Utf8);
            let _ = text(&head, Charset::Latin1);
        }
    }
}
