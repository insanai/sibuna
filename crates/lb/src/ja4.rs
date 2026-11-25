//! JA4 over a bounded TCP ClientHello. Only a rule that requests JA4 pays for hashing.

use sibuna_crypto::sha256::Sha256;
use sibuna_encoding::hex;
use sibuna_policy::ja4::LEN;

use crate::hello::{Hello, vector8, vector16};

fn grease(code: u16) -> bool {
    let [hi, lo] = code.to_be_bytes();
    hi == lo && lo & 15 == 10
}

pub(super) fn codes(bytes: &[u8]) -> impl Iterator<Item = u16> + '_ {
    bytes.as_chunks::<2>().0.iter().copied().map(u16::from_be_bytes).filter(|&n| !grease(n))
}

fn version(code: u16) -> &'static [u8; 2] {
    match code {
        2 => b"s2",
        0x0300 => b"s3",
        0x0301 => b"10",
        0x0302 => b"11",
        0x0303 => b"12",
        0x0304 => b"13",
        _ => b"00",
    }
}

fn alpn_code(mut wire: &[u8]) -> [u8; 2] {
    let Some(protocol) = vector8(&mut wire) else { return *b"00" };
    let (Some(&first), Some(&last)) = (protocol.first(), protocol.last()) else { return *b"00" };
    if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() {
        return [first, last];
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    [HEX[usize::from(first >> 4)], HEX[usize::from(last & 15)]]
}

fn count(n: usize) -> [u8; 2] {
    let n = n.min(99) as u8;
    [b'0' + n / 10, b'0' + n % 10]
}

fn feed(hash: &mut Sha256, list: impl Iterator<Item = u16>) -> Option<()> {
    let mut hex_code = [0; 4];
    for (i, code) in list.enumerate() {
        if i != 0 {
            hash.update(b",");
        }
        hex::encode_to_slice(&code.to_be_bytes(), &mut hex_code).ok()?;
        hash.update(&hex_code);
    }
    Some(())
}

fn hash_list(out: &mut [u8], codes: &mut [u16], signatures: &[u8]) -> Option<()> {
    if codes.is_empty() {
        out.fill(b'0');
        return Some(());
    }
    codes.sort_unstable();
    let mut hash = Sha256::new();
    feed(&mut hash, codes.iter().copied())?;
    let mut signatures = self::codes(signatures).peekable();
    if signatures.peek().is_some() {
        hash.update(b"_");
        feed(&mut hash, signatures)?;
    }
    hex::encode_to_slice(&hash.finalize()[..6], out).ok()
}

pub(super) fn fingerprint(hello: &Hello<'_>) -> Option<[u8; LEN]> {
    let mut ciphers: Vec<u16> = codes(hello.ciphers).collect();
    let mut extensions = Vec::new();
    let mut total = 0;
    let mut wire = hello.extensions;
    while !wire.is_empty() {
        let kind = u16::from_be_bytes(*wire.split_off(..2)?.first_chunk()?);
        vector16(&mut wire)?;
        if !grease(kind) {
            total += 1;
            if !matches!(kind, 0 | 16) {
                extensions.push(kind);
            }
        }
    }
    let mut out = [b'_'; LEN];
    out[0] = b't';
    out[1..3].copy_from_slice(version(hello.version));
    out[3] = if hello.sni.is_some() { b'd' } else { b'i' };
    out[4..6].copy_from_slice(&count(ciphers.len()));
    out[6..8].copy_from_slice(&count(total));
    out[8..10].copy_from_slice(&alpn_code(hello.alpn));
    hash_list(&mut out[11..23], &mut ciphers, &[])?;
    hash_list(&mut out[24..36], &mut extensions, hello.signatures)?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_client_hello_ignores_grease_and_retains_signature_order() {
        let be =
            |codes: &[u16]| codes.iter().flat_map(|code| code.to_be_bytes()).collect::<Vec<_>>();
        let ciphers = be(&[
            0x7a7a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
            0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ]);
        let kinds = [
            0x1b, 0, 0x33, 16, 0x4469, 0x17, 0x2d, 13, 5, 0x23, 0x12, 43, 0xff01, 11, 10, 0x15,
            0x2a2a,
        ];
        let extensions = be(&kinds.into_iter().flat_map(|kind| [kind, 0]).collect::<Vec<_>>());
        let signatures = be(&[0x403, 0x804, 0x401, 0x503, 0x805, 0x501, 0x806, 0x601]);
        let hello = Hello {
            version: 0x0304,
            sni: Some("example.test"),
            alpn: b"\x02h2",
            ciphers: &ciphers,
            signatures: &signatures,
            extensions: &extensions,
            ja4: Default::default(),
            ech: false,
        };
        assert_eq!(fingerprint(&hello), Some(*b"t13d1516h2_8daaf6152771_e5627efa2ab1"));
        assert_eq!(alpn_code(b"\x02\xab\xcd"), *b"ad");
    }
}
