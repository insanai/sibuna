//! The name constraints of the root of the local authority (SID 0021).
//!
//! The configuration lists DNS suffixes and address ranges. This module writes them as
//! the value of the X.509 name constraints extension (RFC 5280, section 4.2.1.10).
//!
//! ```text
//! list                          extension
//! ----                          ---------
//! corp.internal, 10.0.0.0/8     permitted: dNSName corp.internal, iPAddress 10.0.0.0/8
//! corp.internal                 permitted: dNSName corp.internal
//!                               excluded:  iPAddress 0.0.0.0/0 and ::/0
//! 10.0.0.0/8                    permitted: dNSName invalid, iPAddress 10.0.0.0/8
//! ```
//!
//! X.509 constrains each kind of name by itself: a root with DNS subtrees only may
//! still sign any address. Our list means "these and nothing else", so a kind without
//! an entry is closed. Addresses are closed by excluding all of them. DNS names are
//! closed by permitting only the top-level name `invalid`, which RFC 6761 reserves and
//! which no host has. Every verifier reads that the same way, which an excluded empty
//! name does not promise.

use std::net::IpAddr;

use crate::der;

/// The type of the extension: 2.5.29.30.
pub(crate) const NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];
/// The most entries of a list.
pub const MAX_ENTRIES: usize = 32;
/// The `dNSName` choice of a general name.
const DNS_NAME: u8 = 0x82;
/// The `iPAddress` choice of a general name.
const IP_ADDRESS: u8 = 0x87;

/// One subtree: `SEQUENCE { base GeneralName }`.
fn subtree(tag: u8, base: &[u8]) -> Vec<u8> {
    der::sequence(&[&der::element(tag, base)])
}

/// The address and the mask of `ADDRESS/PREFIX`, as the extension holds them. Returns
/// `None` when the text is no range.
fn range(text: &str) -> Option<Vec<u8>> {
    let (address, prefix) = text.split_once('/')?;
    let prefix: u32 = prefix.parse().ok()?;
    let mut bytes = match address.parse::<IpAddr>().ok()? {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    };
    let length = bytes.len();
    if prefix as usize > length * 8 {
        return None;
    }
    let mask = (0..length).map(|index| {
        let bits = prefix.saturating_sub(index as u32 * 8).min(8);
        // `bits` is at most 8, so the shift is at most 8 and the cast keeps the byte.
        (0xff00u32 >> bits) as u8
    });
    let mask: Vec<u8> = mask.collect();
    for (byte, mask) in bytes.iter_mut().zip(&mask) {
        *byte &= mask;
    }
    bytes.extend(mask);
    Some(bytes)
}

/// The DER value of the name constraints extension for `list`. An entry with a slash is
/// an address range `ADDRESS/PREFIX`, any other entry a DNS suffix without a leading
/// dot. Returns `Ok(None)` for the empty list, which constrains nothing, and the entry
/// as the error when it is no suffix and no range or the list is too long.
pub fn value(list: &[String]) -> Result<Option<Vec<u8>>, String> {
    if list.is_empty() {
        return Ok(None);
    }
    if list.len() > MAX_ENTRIES {
        return Err(format!("{} entries", list.len()));
    }
    let (mut permitted, mut names, mut ranges) = (Vec::new(), 0, 0);
    for entry in list {
        if entry.contains('/') {
            let range = range(entry).ok_or_else(|| entry.clone())?;
            permitted.extend(subtree(IP_ADDRESS, &range));
            ranges += 1;
        } else {
            let plain = !entry.is_empty()
                && entry.len() <= 253
                && !entry.starts_with('.')
                && entry.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
            if !plain {
                return Err(entry.clone());
            }
            permitted.extend(subtree(DNS_NAME, entry.to_ascii_lowercase().as_bytes()));
            names += 1;
        }
    }
    if names == 0 {
        permitted.extend(subtree(DNS_NAME, b"invalid"));
    }
    let mut parts = der::element(0xa0, &permitted);
    if ranges == 0 {
        let mut excluded = subtree(IP_ADDRESS, &[0; 8]);
        excluded.extend(subtree(IP_ADDRESS, &[0; 32]));
        parts.extend(der::element(0xa1, &excluded));
    }
    Ok(Some(der::element(der::SEQUENCE, &parts)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn list(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|entry| (*entry).to_owned()).collect()
    }

    #[test]
    fn ranges_carry_the_address_and_the_mask() {
        assert_eq!(range("10.0.0.0/8").unwrap(), [10, 0, 0, 0, 255, 0, 0, 0]);
        assert_eq!(range("10.1.2.3/12").unwrap(), [10, 0, 0, 0, 255, 240, 0, 0]);
        assert_eq!(range("127.0.0.1/32").unwrap(), [127, 0, 0, 1, 255, 255, 255, 255]);
        assert_eq!(range("0.0.0.0/0").unwrap(), [0; 8]);
        let v6 = range("fd00::/8").unwrap();
        assert_eq!((v6.len(), v6[0], v6[16], v6[17]), (32, 0xfd, 0xff, 0));
        for bad in ["10.0.0.0", "10.0.0.0/33", "::/129", "host/8", "10.0.0.0/x", "/8"] {
            assert_eq!(range(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_empty_list_constrains_nothing_and_bad_entries_are_named() {
        assert_eq!(value(&[]), Ok(None));
        assert_eq!(value(&list(&["a b"])), Err("a b".to_owned()));
        assert_eq!(value(&list(&[".corp"])), Err(".corp".to_owned()));
        assert_eq!(value(&list(&["10.0.0.0/40"])), Err("10.0.0.0/40".to_owned()));
        assert!(value(&vec!["a.test".to_owned(); 33]).is_err());
    }

    #[test]
    fn a_kind_without_an_entry_is_closed() {
        let names = value(&list(&["corp.internal"])).unwrap().unwrap();
        // permitted: one dNSName; excluded: all of IPv4 and all of IPv6.
        let (der::SEQUENCE, body, rest) = der::read(&names).unwrap() else { panic!() };
        assert!(rest.is_empty());
        let parts: Vec<_> = der::children(body).collect();
        assert_eq!(parts.iter().map(|part| part.0).collect::<Vec<_>>(), [0xa0, 0xa1]);
        assert_eq!(der::children(parts[0].1).count(), 1);
        assert_eq!(der::children(parts[1].1).count(), 2);
        let ranges = value(&list(&["10.0.0.0/8"])).unwrap().unwrap();
        let (_, body, _) = der::read(&ranges).unwrap();
        let parts: Vec<_> = der::children(body).collect();
        assert_eq!(parts.len(), 1);
        assert!(parts[0].1.windows(7).any(|window| window == b"invalid"));
        let both = value(&list(&["Corp.Internal", "10.0.0.0/8"])).unwrap().unwrap();
        let (_, body, _) = der::read(&both).unwrap();
        assert_eq!(der::children(body).count(), 1);
        assert!(both.windows(13).any(|window| window == b"corp.internal"));
    }
}
