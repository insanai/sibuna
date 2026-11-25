//! Bounded TLS record reassembly for passthrough routing.

use std::io::{self, Read};
use std::net::TcpStream;

/// The most bytes any inspection may hold (`inspect_bytes` is at most this).
pub(crate) const LIMIT: usize = 32768;

/// What an inspection knows after it took more bytes (SID 0032).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// The ClientHello is not whole yet and there is room for more bytes.
    More,
    /// A whole ClientHello handshake message is assembled.
    Whole,
    /// The byte bound is reached and the ClientHello is not whole.
    Over,
    /// The bytes are not TLS handshake records that hold a ClientHello.
    Invalid,
}

#[derive(Default)]
pub(crate) struct Inspection {
    pub wire: Vec<u8>,
    handshake: Vec<u8>,
    consumed: usize,
}

pub(crate) struct Hello<'a> {
    pub ja4: std::cell::OnceCell<Option<[u8; sibuna_policy::ja4::LEN]>>,
    pub version: u16,
    pub ciphers: &'a [u8],
    pub extensions: &'a [u8],
    pub signatures: &'a [u8],
    pub sni: Option<&'a str>,
    pub alpn: &'a [u8],
    /// The hello carries the `encrypted_client_hello` extension, real or greased.
    pub ech: bool,
}

impl Inspection {
    /// Reads the socket once and never holds more than `limit` bytes. An error is the
    /// error of the socket, and a closed socket reports `UnexpectedEof`.
    pub fn read(
        &mut self,
        socket: &mut TcpStream,
        scratch: &mut [u8],
        limit: usize,
    ) -> io::Result<Step> {
        let available = limit.min(LIMIT).saturating_sub(self.wire.len()).min(scratch.len());
        if available == 0 {
            return Ok(Step::Over);
        }
        let n = socket.read(&mut scratch[..available])?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(self.feed(&scratch[..n], limit))
    }

    /// Takes `bytes` as the next bytes of the client. The caller gives at most the
    /// room that is left under `limit`.
    pub fn feed(&mut self, bytes: &[u8], limit: usize) -> Step {
        self.wire.extend_from_slice(bytes);
        match self.reassemble() {
            None => Step::Invalid,
            Some(true) => Step::Whole,
            Some(false) if self.wire.len() >= limit.min(LIMIT) => Step::Over,
            Some(false) => Step::More,
        }
    }

    /// Moves whole records into the handshake buffer. `None` says the bytes are not a
    /// ClientHello, `Some(true)` that the handshake message is whole.
    fn reassemble(&mut self) -> Option<bool> {
        while let Some(header) = self.wire.get(self.consumed..)?.first_chunk::<5>() {
            let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
            if header[0] != 22 || header[1] != 3 || !(1..=16384).contains(&len) {
                return None;
            }
            let start = self.consumed + 5;
            let Some(record) = self.wire.get(start..start + len) else { break };
            self.handshake.extend_from_slice(record);
            self.consumed = start + len;
            if let Some([kind, high, a, b]) = self.handshake.first_chunk::<4>().copied() {
                let size = usize::from(u16::from_be_bytes([a, b]));
                if kind != 1 || high != 0 || size > LIMIT - 4 {
                    return None;
                }
                if self.handshake.len() >= 4 + size {
                    self.handshake.truncate(4 + size);
                    return Some(true);
                }
            }
        }
        // A record header that is not whole yet can already show another protocol.
        let rest = self.wire.get(self.consumed..)?;
        let foreign = rest.first().is_some_and(|kind| *kind != 22)
            || rest.get(1).is_some_and(|major| *major != 3);
        if foreign { None } else { Some(false) }
    }

    pub fn hello(&self) -> Option<Hello<'_>> {
        let mut body = self.handshake.get(4 + 34..)?;
        let session = vector8(&mut body)?;
        let ciphers = vector16(&mut body)?;
        if session.len() > 32
            || ciphers.is_empty()
            || ciphers.len() % 2 != 0
            || vector8(&mut body)?.is_empty()
        {
            return None;
        }
        let mut hello = Hello {
            ja4: Default::default(),
            version: u16::from_be_bytes(*self.handshake.get(4..6)?.first_chunk()?),
            ciphers,
            extensions: &[],
            signatures: &[],
            sni: None,
            alpn: &[],
            ech: false,
        };
        if body.is_empty() {
            return Some(hello);
        }
        let extensions = vector16(&mut body)?;
        if !body.is_empty() {
            return None;
        }
        hello.read_extensions(extensions)?;
        Some(hello)
    }
}

impl<'a> Hello<'a> {
    fn read_extensions(&mut self, mut extensions: &'a [u8]) -> Option<()> {
        self.extensions = extensions;
        let mut seen = [0u64; 1024];
        while !extensions.is_empty() {
            let kind = u16::from_be_bytes(*extensions.split_off(..2)?.first_chunk()?);
            let slot = &mut seen[usize::from(kind / 64)];
            let mask = 1u64 << (kind % 64);
            if *slot & mask != 0 {
                return None;
            }
            *slot |= mask;
            let mut data = vector16(&mut extensions)?;
            match kind {
                0 => {
                    let mut list = vector16(&mut data)?;
                    if !data.is_empty() || list.split_off_first()? != &0 {
                        return None;
                    }
                    let host = std::str::from_utf8(vector16(&mut list)?).ok()?;
                    if !list.is_empty() || !valid_host(host) {
                        return None;
                    }
                    self.sni = Some(host);
                }
                16 => {
                    let mut list = vector16(&mut data)?;
                    if !data.is_empty() || list.is_empty() {
                        return None;
                    }
                    self.alpn = list;
                    while !list.is_empty() {
                        if vector8(&mut list)?.is_empty() {
                            return None;
                        }
                    }
                }
                13 => {
                    self.signatures = vector16(&mut data)?;
                    if !data.is_empty() || !pairs(self.signatures) {
                        return None;
                    }
                }
                43 => {
                    let offered = vector8(&mut data)?;
                    if !data.is_empty() || !pairs(offered) {
                        return None;
                    }
                    self.version = crate::ja4::codes(offered).max().unwrap_or(0);
                }
                ENCRYPTED_CLIENT_HELLO => self.ech = true,
                _ => {}
            }
        }
        Some(())
    }
}

/// The extension of RFC 9849. A client sends it with a real inner hello or as grease,
/// and the two look alike by design.
const ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

fn pairs(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.len().is_multiple_of(2)
}

pub(super) fn vector8<'a>(bytes: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = usize::from(*bytes.split_off_first()?);
    bytes.split_off(..len)
}

pub(super) fn vector16<'a>(bytes: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = u16::from_be_bytes(*bytes.split_off(..2)?.first_chunk()?);
    bytes.split_off(..usize::from(len))
}

pub(crate) fn valid_host(host: &str) -> bool {
    host.len() <= 253
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

impl Hello<'_> {
    pub fn offers(&self, protocol: &[u8]) -> bool {
        let mut list = self.alpn;
        while let Some(item) = vector8(&mut list) {
            if item == protocol {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn extension(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
    }

    /// A TLS 1.3 ClientHello in one record: two ciphers, ALPN `h2` and `http/1.1`,
    /// signature algorithms, the server name when given, and `extra` extension bytes.
    pub(crate) fn hello(sni: Option<&[u8]>, extra: &[u8]) -> Vec<u8> {
        let mut extensions = Vec::new();
        if let Some(host) = sni {
            let mut name = vec![0, (host.len() + 3) as u8, 0, 0, host.len() as u8];
            name.extend_from_slice(host);
            extension(&mut extensions, 0, &name);
        }
        extension(&mut extensions, 16, b"\x00\x0c\x02h2\x08http/1.1");
        extension(&mut extensions, 43, &[2, 3, 4]);
        extension(&mut extensions, 13, &[0, 4, 4, 3, 8, 4]);
        extensions.extend_from_slice(extra);
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7; 32]);
        body.extend_from_slice(&[0, 0, 4, 0x13, 1, 0x13, 2, 1, 0]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut wire = vec![22, 3, 1];
        wire.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        wire.extend_from_slice(&[1, 0]);
        wire.extend_from_slice(&(body.len() as u16).to_be_bytes());
        wire.extend_from_slice(&body);
        wire
    }

    /// An inspection that took `bytes` in one piece.
    pub(crate) fn parsed(bytes: &[u8]) -> Inspection {
        let mut inspection = Inspection::default();
        inspection.feed(bytes, LIMIT);
        inspection
    }

    /// Runs every reader over what the inspection holds. The readers must not panic.
    fn exercise(inspection: &Inspection) {
        if let Some(hello) = inspection.hello() {
            let _ = crate::ja4::fingerprint(&hello);
            let _ = hello.offers(b"h2");
        }
    }

    /// A small deterministic generator, so a failure can be repeated.
    fn next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn a_whole_hello_shows_its_name_protocols_and_fingerprint() {
        let inspection = parsed(&hello(Some(b"api.test"), &[]));
        let hello = inspection.hello().unwrap();
        assert_eq!(hello.sni, Some("api.test"));
        assert!(hello.offers(b"h2") && hello.offers(b"http/1.1") && !hello.offers(b"h3"));
        assert_eq!(hello.version, 0x0304);
        assert!(!hello.ech);
        let ja4 = crate::ja4::fingerprint(&hello).unwrap();
        assert!(ja4.starts_with(b"t13d0204h2_"), "{}", String::from_utf8_lossy(&ja4));
    }

    #[test]
    fn every_truncation_of_a_hello_is_incomplete_and_never_invalid() {
        let wire = hello(Some(b"api.test"), &[0xfe, 0x0d, 0, 2, 0, 0]);
        for cut in 0..wire.len() {
            let mut inspection = Inspection::default();
            assert_eq!(inspection.feed(&wire[..cut], LIMIT), Step::More, "cut {cut}");
            assert!(inspection.hello().is_none());
        }
        assert_eq!(Inspection::default().feed(&wire, LIMIT), Step::Whole);
    }

    #[test]
    fn every_split_of_a_hello_gives_the_same_answer_as_one_piece() {
        let wire = hello(Some(b"api.test"), &[]);
        for cut in 1..wire.len() {
            let mut inspection = Inspection::default();
            assert_eq!(inspection.feed(&wire[..cut], LIMIT), Step::More);
            assert_eq!(inspection.feed(&wire[cut..], LIMIT), Step::Whole);
            assert_eq!(inspection.wire, wire);
            assert_eq!(inspection.hello().unwrap().sni, Some("api.test"));
        }
    }

    #[test]
    fn a_hello_across_many_small_records_is_reassembled() {
        let wire = hello(Some(b"api.test"), &[]);
        let mut records = Vec::new();
        for piece in wire[5..].chunks(7) {
            records.extend_from_slice(&[22, 3, 3, 0, piece.len() as u8]);
            records.extend_from_slice(piece);
        }
        let inspection = parsed(&records);
        assert_eq!(inspection.hello().unwrap().sni, Some("api.test"));
    }

    #[test]
    fn the_byte_bound_ends_an_unfinished_hello() {
        let wire = hello(Some(b"api.test"), &[]);
        let mut inspection = Inspection::default();
        let limit = wire.len() - 1;
        assert_eq!(inspection.feed(&wire[..limit - 1], limit), Step::More);
        assert_eq!(inspection.feed(&wire[limit - 1..limit], limit), Step::Over);
        assert_eq!(inspection.wire.len(), limit);
    }

    #[test]
    fn another_protocol_is_invalid_from_its_first_bytes() {
        let foreign: [&[u8]; 5] =
            [b"G", b"GET / HTTP/1.1\r\n", b"SSH-2.0-x\r\n", &[22, 2], &[22, 3, 1, 0, 0]];
        for bytes in foreign {
            assert_eq!(Inspection::default().feed(bytes, LIMIT), Step::Invalid, "{bytes:?}");
        }
        // A handshake record that holds another message than a ClientHello.
        let other = [22, 3, 3, 0, 4, 2, 0, 0, 0];
        assert_eq!(Inspection::default().feed(&other, LIMIT), Step::Invalid);
        // A handshake message that claims more than any inspection may hold.
        let huge = [22, 3, 3, 0, 4, 1, 0, 0xff, 0xff];
        assert_eq!(Inspection::default().feed(&huge, LIMIT), Step::Invalid);
    }

    #[test]
    fn hostile_hellos_are_refused_without_a_panic() {
        let good = hello(Some(b"api.test"), &[]);
        // The same extension twice.
        let twice = hello(Some(b"api.test"), &[0, 43, 0, 3, 2, 3, 4]);
        assert!(parsed(&twice).hello().is_none());
        // A server name with a byte that no host name has.
        assert!(parsed(&hello(Some(b"a b.test"), &[])).hello().is_none());
        // An extension that claims more bytes than the hello has.
        assert!(parsed(&hello(None, &[0, 99, 0xff, 0xff])).hello().is_none());
        // Every single-byte change of a good hello, to three other values.
        for index in 0..good.len() {
            for flip in [0x01, 0x80, 0xff] {
                let mut bytes = good.clone();
                bytes[index] ^= flip;
                let mut inspection = Inspection::default();
                let _ = inspection.feed(&bytes, LIMIT);
                exercise(&inspection);
            }
        }
    }

    #[test]
    fn random_bytes_never_panic_and_never_exceed_the_bound() {
        let mut state = 0x9e37_79b9_7f4a_7c15;
        let good = hello(Some(b"api.test"), &[]);
        for round in 0..20_000 {
            let limit = 1024 + (next(&mut state) % 4096) as usize;
            let mut inspection = Inspection::default();
            // Half of the rounds start as a real hello and then go wrong.
            let keep = if round % 2 == 0 { (next(&mut state) as usize) % good.len() } else { 0 };
            let mut step = inspection.feed(&good[..keep], limit);
            while step == Step::More {
                let room = limit - inspection.wire.len();
                let size = 1 + (next(&mut state) as usize) % room.min(300);
                let chunk: Vec<u8> = (0..size).map(|_| next(&mut state) as u8).collect();
                step = inspection.feed(&chunk, limit);
            }
            assert!(inspection.wire.len() <= limit);
            exercise(&inspection);
        }
    }

    #[test]
    fn random_records_with_valid_headers_never_panic() {
        let mut state = 0x2545_f491_4f6c_dd1d;
        for _ in 0..20_000 {
            let size = 4 + (next(&mut state) as usize) % 600;
            let mut body: Vec<u8> = (0..size).map(|_| next(&mut state) as u8).collect();
            // A ClientHello header whose length is right, over random content.
            body[..4].copy_from_slice(&[1, 0, ((size - 4) >> 8) as u8, (size - 4) as u8]);
            let mut wire = vec![22, 3, 1, (size >> 8) as u8, size as u8];
            wire.extend_from_slice(&body);
            let mut inspection = Inspection::default();
            assert_eq!(inspection.feed(&wire, LIMIT), Step::Whole);
            exercise(&inspection);
        }
    }
}
