use super::*;

#[test]
fn response_head_parsing_decides_the_body_framing() {
    let sized =
        parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n", false).unwrap();
    assert_eq!(sized.status, 200);
    assert_eq!(sized.framing, Framing::Length(12));
    assert!(sized.keep_alive);
    let closing = parse_response_head(
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n",
        false,
    )
    .unwrap();
    assert!(!closing.keep_alive);
    let old_keep = parse_response_head(
        b"HTTP/1.0 200 OK\r\nContent-Length: 1\r\nConnection: Keep-Alive\r\n\r\n",
        false,
    )
    .unwrap();
    assert!(old_keep.keep_alive);
    let chunked = parse_response_head(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: gzip, Chunked\r\n\r\n",
        false,
    )
    .unwrap();
    assert_eq!(chunked.framing, Framing::Chunked);
    let not_modified = b"HTTP/1.1 304 Not Modified\r\nContent-Length: 9\r\n\r\n";
    assert_eq!(parse_response_head(not_modified, false).unwrap().framing, Framing::None);
    let head_only = parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n", true);
    assert_eq!(head_only.unwrap().framing, Framing::None);
    let legacy = parse_response_head(b"HTTP/1.0 200 OK\r\nServer: old\r\n\r\n", false).unwrap();
    assert_eq!(legacy.framing, Framing::UntilClose);
    assert!(!legacy.keep_alive);
    assert!(parse_response_head(b"HTTP/1.1 20x\r\n\r\n", false).is_none());
    let bad_length = b"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n";
    assert!(parse_response_head(bad_length, false).is_none());
}

#[test]
fn zig_integer_syntax_and_status_bounds() {
    let plus = parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: +3\r\n\r\n", false);
    assert_eq!(plus.unwrap().framing, Framing::Length(3));
    let underscore = parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 1_0\r\n\r\n", false);
    assert_eq!(underscore.unwrap().framing, Framing::Length(10));
    assert!(parse_response_head(b"HTTP/1.1 099 Low\r\n\r\n", false).is_none());
    assert!(parse_response_head(b"HTTP/1.1 +99 Low\r\n\r\n", false).is_none());
    assert_eq!(parse_response_head(b"HTTP/1.1 999 \r\n\r\n", false).unwrap().status, 999);
    assert!(parse_response_head(b"HTTP/1.2 200 OK\r\n\r\n", false).is_none());
    assert!(parse_response_head(b"HTTP/1.1 200OK\r\n\r\n", false).is_none());
    assert!(parse_response_head(b"HTTP/1.1 200 ", false).is_some());
    assert_eq!(chunk_size(b"1_0 ;x\r\n"), Some(16));
    assert_eq!(chunk_size(b" -0 \r\n"), Some(0));
    assert_eq!(chunk_size(b"\r\n"), None);
}

#[test]
fn client_heads_replace_connection_fields() {
    let head = b"HTTP/1.1 200 OK\r\nKeep-Alive: t\r\nProxy-Authenticate: x\r\nUpgrade: h2\r\n\
        Connection: X-Hop\r\nX-Hop: 1\r\nX-App: 2\r\n\r\n";
    let mut out = Vec::new();
    write_client_head(&mut out, head, false).unwrap();
    assert_eq!(out, b"HTTP/1.1 200 OK\r\nX-App: 2\r\nConnection: close\r\n\r\n");
}

/// A deliberately plain reading of the same rules, line by line with owned strings, to
/// check the parser against.
fn reference(head: &[u8], head_request: bool) -> Option<ResponseHead> {
    if head.len() < 13 || &head[..7] != b"HTTP/1." || !b"01".contains(&head[7]) {
        return None;
    }
    if head[8] != b' ' || head[12] != b' ' {
        return None;
    }
    let status = naive_zig_decimal(std::str::from_utf8(&head[9..12]).ok()?)?;
    if !(100..=u64::from(u16::MAX)).contains(&status) {
        return None;
    }
    let lines = naive_lines(head);
    let (mut length, mut chunked, mut encoded) = (None::<u64>, false, false);
    let (mut keep, mut closing) = (head[7] == b'1', false);
    let mut nominated = Vec::new();
    for line in lines.iter().skip(1) {
        if line.is_empty() {
            break;
        }
        let colon = line.iter().position(|&b| b == b':')?;
        let name = &line[..colon];
        let token = |b: &u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b);
        if name.is_empty() || !name.iter().all(token) {
            return None;
        }
        let raw = &line[colon + 1..];
        if raw.iter().any(|&b| (b < 32 && b != b'\t') || b == 127) {
            return None;
        }
        let value = String::from_utf8_lossy(raw).trim_matches([' ', '\t']).to_string();
        let lower = String::from_utf8_lossy(name).to_ascii_lowercase();
        let list: Vec<String> =
            value.split(',').map(|t| t.trim_matches([' ', '\t']).to_ascii_lowercase()).collect();
        match lower.as_str() {
            "transfer-encoding" => {
                if chunked {
                    return None;
                }
                encoded = true;
                for coding in &list {
                    if chunked || coding.is_empty() {
                        return None;
                    }
                    chunked = coding == "chunked";
                }
            }
            "content-length" => {
                let n = naive_zig_decimal(&value)?;
                if length.is_some_and(|previous| previous != n) {
                    return None;
                }
                length = Some(n);
            }
            "connection" => {
                closing |= list.iter().any(|t| t == "close");
                keep |= list.iter().any(|t| t == "keep-alive");
                nominated.extend(list.clone());
            }
            _ => {}
        }
    }
    if nominated.iter().any(|t| t == "content-length" || t == "transfer-encoding") {
        return None;
    }
    let framing = naive_framing(status, head_request, length, encoded, chunked);
    let keep_alive = keep && framing != Framing::UntilClose && !closing;
    Some(ResponseHead { status: status as u16, framing, keep_alive })
}

fn naive_framing(
    status: u64,
    head_request: bool,
    length: Option<u64>,
    encoded: bool,
    chunked: bool,
) -> Framing {
    if head_request || status / 100 == 1 || status == 204 || status == 304 {
        Framing::None
    } else if encoded {
        if chunked { Framing::Chunked } else { Framing::UntilClose }
    } else {
        length.map_or(Framing::UntilClose, Framing::Length)
    }
}

/// Splits at every CRLF by walking the bytes one at a time.
fn naive_lines(head: &[u8]) -> Vec<Vec<u8>> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index + 1 < head.len() {
        if head[index] == b'\r' && head[index + 1] == b'\n' {
            lines.push(head[start..index].to_vec());
            start = index + 2;
            index += 2;
        } else {
            index += 1;
        }
    }
    lines.push(head[start..].to_vec());
    lines
}

/// Zig's `parseInt(u64, text, 10)` with 128-bit arithmetic.
fn naive_zig_decimal(text: &str) -> Option<u64> {
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'+') => (false, &text[1..]),
        Some(b'-') => (true, &text[1..]),
        _ => (false, text),
    };
    if digits.is_empty() || digits.starts_with('_') || digits.ends_with('_') {
        return None;
    }
    let mut value: u128 = 0;
    for c in digits.chars().filter(|&c| c != '_') {
        value = value * 10 + u128::from(c.to_digit(10)?);
        if value > u128::from(u64::MAX) {
            return None;
        }
    }
    if negative && value != 0 {
        return None;
    }
    Some(value as u64)
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound.max(1) as u64) as usize
    }
}

const SEEDS: [&[u8]; 8] = [
    b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nContent-Type: text/plain\r\n\r\n",
    b"HTTP/1.0 200 OK\r\nConnection: Keep-Alive\r\nContent-Length: 1\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\nContent-Length: 5\r\n\r\n",
    b"HTTP/1.1 304 Not Modified\r\nETag: \"x\"\r\nConnection: close, X-Hop\r\n\r\n",
    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
    b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: +1_0\r\nConnection: content-length\r\n\r\n",
    b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n\r\n",
];

const ALPHABET: &[u8] = b"\r\n:, \t_+-019AaZzckeplosdtrnug\x00\x7f\x80\xff";

fn mutate(rng: &mut Rng) -> Vec<u8> {
    let mut input = SEEDS[rng.below(SEEDS.len())].to_vec();
    for _ in 0..1 + rng.below(4) {
        let at = rng.below(input.len() + 1);
        match rng.below(6) {
            0 if !input.is_empty() => {
                let index = at.min(input.len() - 1);
                input[index] ^= 1 << rng.below(8);
            }
            1 => input.insert(at, ALPHABET[rng.below(ALPHABET.len())]),
            2 => input.truncate(at),
            3 => {
                let end = (at + rng.below(24)).min(input.len());
                let piece = input[at..end].to_vec();
                input.splice(at..at, piece);
            }
            4 => {
                let other = SEEDS[rng.below(SEEDS.len())];
                let from = rng.below(other.len());
                input.truncate(at);
                input.extend_from_slice(&other[from..]);
            }
            _ => {
                if at < input.len() {
                    input.remove(at);
                }
            }
        }
    }
    input
}

#[test]
fn fuzz_response_heads_agree_with_a_reference() {
    let mut rng = Rng(0x5851_f42d_4c95_7f2d);
    let mut accepted = 0;
    for _ in 0..200_000 {
        let input = mutate(&mut rng);
        let head_request = rng.below(5) == 0;
        let parsed = parse_response_head(&input, head_request);
        assert_eq!(
            parsed,
            reference(&input, head_request),
            "{:?}",
            String::from_utf8_lossy(&input)
        );
        if parsed.is_some() {
            accepted += 1;
            let mut out = Vec::new();
            write_client_head(&mut out, &input, true).unwrap();
            // The connection field, plus a CRLF the head may lack on its last line.
            assert!(out.len() <= input.len() + 28);
        }
    }
    // The mutations must exercise both verdicts.
    assert!(accepted > 20_000, "{accepted}");
}
