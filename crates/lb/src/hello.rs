//! Bounded TLS record reassembly for passthrough routing.

use std::io::{self, Read};
use std::net::TcpStream;

use crate::config::invalid;

const LIMIT: usize = 32768;

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
}

impl Inspection {
    pub fn read(&mut self, socket: &mut TcpStream, scratch: &mut [u8]) -> io::Result<bool> {
        let available = (LIMIT - self.wire.len()).min(scratch.len());
        if available == 0 {
            return Err(invalid("ClientHello exceeds inspection budget"));
        }
        let n = socket.read(&mut scratch[..available])?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.wire.extend_from_slice(&scratch[..n]);
        self.reassemble()
    }

    fn reassemble(&mut self) -> io::Result<bool> {
        while let Some(header) = self.wire[self.consumed..].first_chunk::<5>() {
            let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
            if header[0] != 22 || header[1] != 3 || !(1..=16384).contains(&len) {
                return Err(invalid("expected TLS handshake record"));
            }
            let start = self.consumed + 5;
            let Some(record) = self.wire.get(start..start + len) else { break };
            self.handshake.extend_from_slice(record);
            self.consumed = start + len;
            if let Some([kind, high, a, b]) = self.handshake.first_chunk::<4>().copied() {
                let size = usize::from(u16::from_be_bytes([a, b]));
                if kind != 1 || high != 0 || size > LIMIT - 4 {
                    return Err(invalid("invalid ClientHello handshake size or type"));
                }
                if self.handshake.len() >= 4 + size {
                    self.handshake.truncate(4 + size);
                    return Ok(true);
                }
            }
        }
        Ok(false)
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
                _ => {}
            }
        }
        Some(())
    }
}

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
