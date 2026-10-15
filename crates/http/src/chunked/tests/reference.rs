//! A whole-input reference decoder written from the grammar of RFC 9112 section 7.1 and the
//! rules R5 to R7 of SID 0009, independently of the incremental decoder.

use super::{ChunkError, MAX_LINE, MAX_TRAILER};

/// The lexical items of a chunk extension.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Item {
    Space,
    Semicolon,
    Equals,
    Token,
    Quoted,
}

fn tchar(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

/// Splits extension text into items, or `None` on a byte no item may hold or an unclosed
/// quoted string.
fn lex(text: &[u8]) -> Option<Vec<Item>> {
    let mut items = Vec::new();
    let mut i = 0;
    while i < text.len() {
        let c = text[i];
        if c == b' ' || c == b'\t' {
            while i < text.len() && (text[i] == b' ' || text[i] == b'\t') {
                i += 1;
            }
            items.push(Item::Space);
        } else if c == b';' {
            items.push(Item::Semicolon);
            i += 1;
        } else if c == b'=' {
            items.push(Item::Equals);
            i += 1;
        } else if tchar(c) {
            while i < text.len() && tchar(text[i]) {
                i += 1;
            }
            items.push(Item::Token);
        } else if c == b'"' {
            i += 1;
            loop {
                if i >= text.len() {
                    return None;
                }
                if text[i] == b'"' {
                    i += 1;
                    break;
                }
                // A quoted pair: the backslash and the byte it escapes.
                i += if text[i] == b'\\' { 2 } else { 1 };
            }
            items.push(Item::Quoted);
        } else {
            return None;
        }
    }
    Some(items)
}

/// `*( [Space] ";" [Space] Token [ [Space] "=" [Space] ( Token / Quoted ) ] )`
fn valid_extensions(text: &[u8]) -> bool {
    let Some(items) = lex(text) else { return false };
    let mut i = 0;
    let at = |i: usize| items.get(i).copied();
    while i < items.len() {
        if at(i) == Some(Item::Space) {
            i += 1;
        }
        if at(i) != Some(Item::Semicolon) {
            return false;
        }
        i += 1;
        if at(i) == Some(Item::Space) {
            i += 1;
        }
        if at(i) != Some(Item::Token) {
            return false;
        }
        i += 1;
        let mut j = i;
        if at(j) == Some(Item::Space) {
            j += 1;
        }
        if at(j) != Some(Item::Equals) {
            continue;
        }
        j += 1;
        if at(j) == Some(Item::Space) {
            j += 1;
        }
        if !matches!(at(j), Some(Item::Token | Item::Quoted)) {
            return false;
        }
        i = j + 1;
    }
    true
}

/// The next line as (text, length with CRLF); `Ok(None)` while incomplete.
fn line(input: &[u8]) -> Result<Option<(&[u8], usize)>, ChunkError> {
    let limit = input.len().min(MAX_LINE);
    let Some(lf) = input[..limit].iter().position(|&c| c == b'\n') else {
        return if input.len() >= MAX_LINE { Err(ChunkError::Malformed) } else { Ok(None) };
    };
    if lf == 0 || input[lf - 1] != b'\r' {
        return Err(ChunkError::Malformed);
    }
    let text = &input[..lf - 1];
    if text.iter().any(|&c| (c < 32 && c != b'\t') || c == 127) {
        return Err(ChunkError::Malformed);
    }
    Ok(Some((text, lf + 1)))
}

fn size(text: &[u8]) -> Result<u64, ChunkError> {
    let digits = text.iter().take_while(|c| c.is_ascii_hexdigit()).count();
    if digits == 0 || digits > 16 || !valid_extensions(&text[digits..]) {
        return Err(ChunkError::Malformed);
    }
    let hex = std::str::from_utf8(&text[..digits]).map_err(|_| ChunkError::Malformed)?;
    u64::from_str_radix(hex, 16).map_err(|_| ChunkError::Malformed)
}

/// Decodes the whole of `input`: the body bytes recovered, the bytes consumed, and whether
/// the body ended.
pub(super) fn decode(input: &[u8]) -> Result<(Vec<u8>, usize, bool), ChunkError> {
    let mut body = Vec::new();
    let mut pos = 0;
    loop {
        let Some((text, length)) = line(&input[pos..])? else {
            return Ok((body, pos, false));
        };
        let chunk = size(text)?;
        pos += length;
        if chunk == 0 {
            break;
        }
        let available = (input.len() - pos) as u64;
        let take = chunk.min(available) as usize;
        body.extend_from_slice(&input[pos..pos + take]);
        pos += take;
        if take as u64 != chunk {
            return Ok((body, pos, false));
        }
        match &input[pos..] {
            [] | [b'\r'] => return Ok((body, pos, false)),
            [b'\r', b'\n', ..] => pos += 2,
            _ => return Err(ChunkError::Malformed),
        }
    }
    let mut trailer = 0;
    loop {
        let Some((text, length)) = line(&input[pos..])? else {
            return Ok((body, pos, false));
        };
        pos += length;
        if text.is_empty() {
            return Ok((body, pos, true));
        }
        trailer += length;
        let colon = text.iter().position(|&c| c == b':');
        let name_ok =
            colon.is_some_and(|colon| colon > 0 && text[..colon].iter().all(|&c| tchar(c)));
        if trailer > MAX_TRAILER || !name_ok {
            return Err(ChunkError::Malformed);
        }
    }
}
