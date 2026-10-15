//! Plays one scenario against one daemon: binds the scenario's source address, fills the
//! placeholders from the daemon's own answers, sends each request, and records what came
//! back.

use std::io::Write;
use std::net::{Shutdown, SocketAddrV4};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sibuna_encoding::base64::{self, URL_SAFE_NO_PAD};
use sibuna_pow::{hashcash, posw};

use crate::configs::COOKIE_NAME;
use crate::corpus::{COOKIE, Case, ID, ID_TAMPERED, LEN, SOLUTION, TICKET, WRONG};
use crate::response::{Event, Reader, Response, find};
use crate::socket::connect_from;

/// The hardest hashcash challenge the client solves; harder ones get a wrong nonce.
pub const MAX_HASHCASH_BITS: u32 = 16;
/// The deepest PoSW challenge the client solves; deeper ones get a wrong proof.
pub const MAX_POSW_DEPTH: u32 = 14;
/// How long a daemon may stay silent before the read counts as stalled.
pub const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// One request as sent and what the daemon answered to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exchange {
    /// The request bytes after the placeholders were filled.
    pub request: Vec<u8>,
    /// The events read after it: interim and final responses, the end of the connection.
    pub events: Vec<Event>,
}

/// Everything one daemon answered to one scenario, per connection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Transcript {
    /// The exchanges of each connection, in order.
    pub connections: Vec<Vec<Exchange>>,
    /// A connection that could not be opened, with the error.
    pub connect_error: Option<String>,
}

/// Keeps challenge issuance below the daemon's load-adaptive baseline of 50 per second
/// (SID 0006, Part H): above it the daemon adds difficulty bits that depend on how fast
/// the run goes, which would differ between the daemons for reasons of timing alone.
#[derive(Debug)]
pub struct Pacer {
    limit: u32,
    window: Mutex<(u64, u32)>,
}

impl Pacer {
    /// A pacer that admits at most `limit` issues per wall-clock second.
    pub fn new(limit: u32) -> Pacer {
        Pacer { limit, window: Mutex::new((0, 0)) }
    }

    /// Waits until `count` more issues fit into the current second, then counts them. A
    /// count above the limit waits for a second of its own.
    pub fn acquire(&self, count: u32) {
        let count = count.min(self.limit);
        loop {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
            {
                let mut window = self.window.lock().unwrap_or_else(|poison| poison.into_inner());
                if window.0 != now.as_secs() {
                    *window = (now.as_secs(), 0);
                }
                if window.1 + count <= self.limit {
                    window.1 += count;
                    return;
                }
            }
            let rest = Duration::from_secs(1)
                .saturating_sub(Duration::from_nanos(u64::from(now.subsec_nanos())));
            std::thread::sleep(rest + Duration::from_millis(2));
        }
    }
}

/// An issued challenge as the client reads it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Challenge {
    /// The identifier, which is also the statement to solve.
    pub id: String,
    /// `hashcash` or `posw`.
    pub algorithm: String,
    /// Bits (hashcash) or tree depth (PoSW).
    pub difficulty: u32,
    /// PoSW openings.
    pub challenges: u8,
}

/// What a scenario has learned from one daemon so far.
#[derive(Clone, Debug, Default)]
pub struct State {
    /// The last challenge issued.
    pub challenge: Option<Challenge>,
    /// The last session cookie, as `name=value`.
    pub cookie: Option<String>,
    /// The last requirement ticket.
    pub ticket: Option<String>,
}

impl State {
    /// Learns from `response`: a challenge in its body, a cookie, a ticket.
    pub fn observe(&mut self, response: &Response) {
        let body = &response.body;
        if let (Some(id), Some(algorithm)) =
            (json_field(body, "id"), json_field(body, "algorithm"))
        {
            self.challenge = Some(Challenge {
                id,
                algorithm,
                difficulty: json_field(body, "difficulty")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0),
                challenges: json_field(body, "challenges")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0),
            });
        }
        for (name, value) in &response.headers {
            let prefix = format!("{COOKIE_NAME}=");
            if name.eq_ignore_ascii_case("set-cookie") && value.starts_with(&prefix) {
                self.cookie = Some(value.split(';').next().unwrap_or_default().to_owned());
            }
        }
        let ticket = text_after(body, b"data-ticket=\"", b"\"")
            .or_else(|| text_after(body, b"need=", b"\"&"));
        if let Some(ticket) = ticket {
            self.ticket = Some(ticket);
        }
    }

    /// Fills the placeholders of `template` from what has been learned.
    pub fn fill(&self, template: &[u8]) -> Vec<u8> {
        if find(template, b"@@").is_none() {
            return template.to_vec();
        }
        let mut text = template.to_vec();
        let challenge = self.challenge.clone().unwrap_or_default();
        let id = if challenge.id.is_empty() { "none".to_owned() } else { challenge.id.clone() };
        let replacements = [
            (ID_TAMPERED, tamper(&id)),
            (ID, id),
            (SOLUTION, solution(&challenge, true)),
            (WRONG, solution(&challenge, false)),
            (COOKIE, self.cookie.clone().unwrap_or_else(|| format!("{COOKIE_NAME}=none"))),
            (TICKET, self.ticket.clone().unwrap_or_else(|| "none".to_owned())),
        ];
        for (placeholder, value) in &replacements {
            text = replace(&text, placeholder.as_bytes(), value.as_bytes());
        }
        let body_length = find(&text, b"\r\n\r\n").map_or(0, |at| text.len() - at - 4);
        replace(&text, LEN.as_bytes(), body_length.to_string().as_bytes())
    }
}

/// `id` with its third character from the end changed. That character lies inside the
/// identifier's authentication tag and encodes six full bits, so the result is still
/// canonical base64url and fails only the tag check; changing the last character could
/// instead make the encoding non-canonical, depending on the random identifier.
fn tamper(id: &str) -> String {
    let mut chars: Vec<char> = id.chars().collect();
    if let Some(index) = chars.len().checked_sub(3) {
        chars[index] = if chars[index] == 'A' { 'B' } else { 'A' };
    }
    chars.into_iter().collect()
}

/// The JSON solution field for `challenge`: a solving one when `solved` and the challenge is
/// within the solver's limits, else a well-formed wrong one.
pub fn solution(challenge: &Challenge, solved: bool) -> String {
    let id = challenge.id.as_bytes();
    if challenge.algorithm == "posw" {
        let params = posw::Params {
            depth: u8::try_from(challenge.difficulty).unwrap_or(0),
            challenges: challenge.challenges,
        };
        let mut workspace = Box::new(posw::Workspace::new());
        if solved
            && challenge.difficulty <= MAX_POSW_DEPTH
            && let Ok(proof) = posw::solve(id, params, &mut workspace)
        {
            return format!("\"proof\":\"{}\"", base64::encode(URL_SAFE_NO_PAD, proof));
        }
        let size = if params.is_valid() { params.proof_size() } else { 33 };
        return format!("\"proof\":\"{}\"", base64::encode(URL_SAFE_NO_PAD, &vec![0u8; size]));
    }
    let bits = challenge.difficulty;
    if solved
        && bits <= MAX_HASHCASH_BITS
        && let Some(nonce) = hashcash::solve_bits(id, bits, 1 << 24)
    {
        return format!("\"nonce\":\"{nonce}\"");
    }
    let wrong = (0..u64::MAX).find(|&nonce| !hashcash::verify_bits(id, nonce, bits.max(1)));
    format!("\"nonce\":\"{}\"", wrong.unwrap_or(0))
}

/// Replaces every `from` in `text` by `to`.
pub fn replace(text: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = find(rest, from) {
        out.extend_from_slice(&rest[..at]);
        out.extend_from_slice(to);
        rest = &rest[at + from.len()..];
    }
    out.extend_from_slice(rest);
    out
}

/// The text after `marker` up to the first byte in `ends`.
fn text_after(body: &[u8], marker: &[u8], ends: &[u8]) -> Option<String> {
    let start = find(body, marker)? + marker.len();
    let rest = body.get(start..)?;
    let end = rest.iter().position(|byte| ends.contains(byte)).unwrap_or(rest.len());
    Some(String::from_utf8_lossy(&rest[..end]).into_owned())
}

/// The value of a top-level JSON field `"key":` as text, without quotes.
fn json_field(body: &[u8], key: &str) -> Option<String> {
    let marker = format!("\"{key}\":");
    let start = find(body, marker.as_bytes())? + marker.len();
    let rest = body.get(start..)?;
    let rest = rest.strip_prefix(b"\"").unwrap_or(rest);
    let end = rest.iter().position(|byte| b"\",}".contains(byte)).unwrap_or(rest.len());
    Some(String::from_utf8_lossy(&rest[..end]).into_owned())
}

/// True when the request is a `HEAD`, whose answer has no body.
fn is_head(request: &[u8]) -> bool {
    request.starts_with(b"HEAD ")
}

/// True when the request issues a challenge, which the pacer must admit.
fn issues_challenge(request: &[u8]) -> bool {
    find(request, b"/__sibuna/challenge.json").is_some()
}

/// Plays `case` against the daemon at `daemon`.
pub fn run_case(case: &Case, daemon: SocketAddrV4, pacer: &Pacer) -> Transcript {
    let mut transcript = Transcript::default();
    let mut state = State::default();
    // All issues of a scenario fall into one second: a scenario that tests the challenge
    // budget must not be spread over seconds, or the budget's bucket would refill.
    let issues = case.connections.iter().flatten().filter(|request| issues_challenge(request));
    let issues = issues.count();
    if issues > 0 {
        pacer.acquire(u32::try_from(issues).unwrap_or(u32::MAX));
    }
    for steps in &case.connections {
        let stream = match connect_from(case.source, daemon) {
            Ok(stream) => stream,
            Err(error) => {
                transcript.connect_error = Some(error.to_string());
                return transcript;
            }
        };
        let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
        let _ = stream.set_nodelay(true);
        let mut reader = Reader::new(stream);
        let mut exchanges = Vec::with_capacity(steps.len());
        for (index, template) in steps.iter().enumerate() {
            let last = index + 1 == steps.len();
            let request = state.fill(template);
            let events = send_and_read(&mut reader, &request, last, &mut state);
            let ended = !matches!(events.last(), Some(Event::Response(_)));
            exchanges.push(Exchange { request, events });
            if ended {
                break;
            }
        }
        transcript.connections.push(exchanges);
    }
    transcript
}

/// Sends one request and reads its answer: one final response (after any interim ones),
/// or after the last request of a connection, everything until the connection ends.
fn send_and_read(
    reader: &mut Reader,
    request: &[u8],
    last: bool,
    state: &mut State,
) -> Vec<Event> {
    let mut stream = reader.stream();
    // A daemon may close before it read everything; what it answered is still readable.
    let _ = stream.write_all(request);
    let _ = stream.flush();
    if last {
        let _ = stream.shutdown(Shutdown::Write);
    }
    let mut events = Vec::new();
    loop {
        let event = reader.next_event(is_head(request));
        let Event::Response(response) = &event else {
            events.push(event);
            return events;
        };
        state.observe(response);
        let interim = (100..200).contains(&response.status);
        events.push(event);
        if !interim && !last {
            return events;
        }
    }
}

#[cfg(test)]
mod tests;
