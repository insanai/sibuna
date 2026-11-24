//! TSIG with HMAC-SHA256 (RFC 8945): signing a request and checking the signed answer.
//!
//! ```text
//! request MAC  = HMAC(key, request || variables)
//! response MAC = HMAC(key, length || request MAC || response without TSIG || variables)
//! variables    = key name, class ANY, TTL 0, algorithm, time, fudge, error, other data
//! ```

use std::fmt;

use sibuna_crypto::hmac::HmacSha256;
use sibuna_encoding::base64::{self, STANDARD};

use super::wire::{self, CLASS_ANY, Data, HEADER, TYPE_TSIG};
use crate::Error;

/// The name of the algorithm in a TSIG record.
const ALGORITHM: &str = "hmac-sha256";
/// The seconds that the clocks of the two sides may differ.
const FUDGE: u16 = 300;
/// The length of the MAC.
const MAC: usize = 32;
/// The longest secret read from a key file, in bytes of base64.
const MAX_SECRET: usize = 1024;

/// A TSIG key: its name and its secret. `Debug` shows the name only.
#[derive(Clone, PartialEq, Eq)]
pub struct TsigKey {
    /// The name of the key, as the server knows it.
    pub name: String,
    /// The shared secret.
    pub secret: Vec<u8>,
}

impl fmt::Debug for TsigKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TsigKey").field("name", &self.name).finish_non_exhaustive()
    }
}

impl TsigKey {
    /// A key from its name and the text of its file: the secret in base64, alone on the
    /// first line that is not empty and does not start with `#` or `;`. Returns `None`
    /// when there is no such line, it is no base64, or the name is no DNS name.
    pub fn parse(name: &str, file: &str) -> Option<Self> {
        let line = file
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with(';'))?;
        if line.len() > MAX_SECRET {
            return None;
        }
        let secret = base64::decode(STANDARD, line.as_bytes()).ok().filter(|s| !s.is_empty())?;
        let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
        wire::write_name(&mut Vec::new(), &name).ok()?;
        Some(Self { name, secret })
    }
}

/// The fields of a TSIG record that enter the MAC after the message.
struct Variables<'a> {
    key: &'a TsigKey,
    time: u64,
    fudge: u16,
    error: u16,
    other: &'a [u8],
}

impl Variables<'_> {
    fn feed(&self, mac: &mut HmacSha256) -> Result<(), Error> {
        let mut bytes = Vec::with_capacity(64);
        wire::write_name(&mut bytes, &self.key.name)?;
        bytes.extend_from_slice(&CLASS_ANY.to_be_bytes());
        bytes.extend_from_slice(&[0; 4]);
        wire::write_name(&mut bytes, ALGORITHM)?;
        bytes.extend_from_slice(&self.time.to_be_bytes()[2..]);
        bytes.extend_from_slice(&self.fudge.to_be_bytes());
        bytes.extend_from_slice(&self.error.to_be_bytes());
        bytes.extend_from_slice(&(self.other.len() as u16).to_be_bytes());
        bytes.extend_from_slice(self.other);
        mac.update(&bytes);
        Ok(())
    }
}

/// Signs `message` in place: appends the TSIG record and counts it in the header.
/// `time` is in seconds since 1970. Returns the MAC, which [`verify`] needs for the
/// answer. Fails for a message without a header.
pub fn sign(message: &mut Vec<u8>, key: &TsigKey, time: u64) -> Result<[u8; MAC], Error> {
    sign_after(message, key, time, None)
}

/// Signs the answer to a request whose MAC is `request_mac`, as a server does.
pub fn sign_answer(
    message: &mut Vec<u8>,
    key: &TsigKey,
    time: u64,
    request_mac: &[u8; MAC],
) -> Result<[u8; MAC], Error> {
    sign_after(message, key, time, Some(request_mac))
}

fn sign_after(
    message: &mut Vec<u8>,
    key: &TsigKey,
    time: u64,
    request_mac: Option<&[u8; MAC]>,
) -> Result<[u8; MAC], Error> {
    if message.len() < HEADER {
        return Err(Error::unexpected("A DNS message has a header."));
    }
    let mut mac = HmacSha256::new(&key.secret);
    if let Some(request_mac) = request_mac {
        mac.update(&(MAC as u16).to_be_bytes());
        mac.update(request_mac);
    }
    mac.update(message);
    Variables { key, time, fudge: FUDGE, error: 0, other: &[] }.feed(&mut mac)?;
    let mac = mac.finalize();
    let id = [message[0], message[1]];
    let mut data = Vec::with_capacity(64);
    wire::write_name(&mut data, ALGORITHM)?;
    data.extend_from_slice(&time.to_be_bytes()[2..]);
    data.extend_from_slice(&FUDGE.to_be_bytes());
    data.extend_from_slice(&(MAC as u16).to_be_bytes());
    data.extend_from_slice(&mac);
    data.extend_from_slice(&id);
    data.extend_from_slice(&[0; 4]);
    wire::write_name(message, &key.name)?;
    message.extend_from_slice(&TYPE_TSIG.to_be_bytes());
    message.extend_from_slice(&CLASS_ANY.to_be_bytes());
    message.extend_from_slice(&[0; 4]);
    message.extend_from_slice(&(data.len() as u16).to_be_bytes());
    message.extend_from_slice(&data);
    let additional = u16::from_be_bytes([message[10], message[11]]).wrapping_add(1);
    message[10..12].copy_from_slice(&additional.to_be_bytes());
    Ok(mac)
}

/// The data of a TSIG record, split into its fields.
struct Signature<'a> {
    time: u64,
    fudge: u16,
    mac: &'a [u8],
    original_id: [u8; 2],
    error: u16,
    other: &'a [u8],
}

fn signature(data: &[u8]) -> Option<Signature<'_>> {
    let (algorithm, at) = wire::read_name(data, 0)?;
    if algorithm != ALGORITHM {
        return None;
    }
    let rest = data.get(at..)?;
    let u16_at = |at: usize| rest.get(at..at + 2).map(|b| u16::from_be_bytes([b[0], b[1]]));
    let mut time = [0; 8];
    time[2..].copy_from_slice(rest.get(..6)?);
    let mac_end = 10 + usize::from(u16_at(8)?);
    let other_length = usize::from(u16_at(mac_end + 4)?);
    let other = rest.get(mac_end + 6..mac_end + 6 + other_length)?;
    (rest.len() == mac_end + 6 + other_length).then_some(Signature {
        time: u64::from_be_bytes(time),
        fudge: u16_at(6)?,
        mac: rest.get(10..mac_end)?,
        original_id: [*rest.get(mac_end)?, *rest.get(mac_end + 1)?],
        error: u16_at(mac_end + 2)?,
        other,
    })
}

/// The name of a TSIG error code.
fn error_name(code: u16) -> String {
    match code {
        16 => "BADSIG: the secret differs".to_owned(),
        17 => "BADKEY: the server does not know the key name".to_owned(),
        18 => "BADTIME: the clocks differ by more than five minutes".to_owned(),
        other => format!("code {other}"),
    }
}

/// Whether two byte strings are equal, in a time that depends on their length only.
fn equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).fold(0, |difference, (a, b)| difference | (a ^ b)) == 0
}

/// Checks the TSIG record of `response` against the MAC of our request. `now` is in
/// seconds since 1970. Fails with `ACME009` when the answer is unsigned, signed with
/// another key, signed at another time, or reports a TSIG error.
pub fn verify(
    response: &[u8],
    key: &TsigKey,
    request_mac: &[u8; MAC],
    now: u64,
) -> Result<(), Error> {
    let refuse = |what: &str| Error::provider(format!("The answer of the DNS server {what}."));
    let message = wire::parse(response).ok_or_else(|| refuse("cannot be read"))?;
    let additional = u16::from_be_bytes([response[10], response[11]]);
    let record = message
        .records
        .last()
        .filter(|record| record.kind == TYPE_TSIG && additional > 0)
        .ok_or_else(|| refuse("is not signed"))?;
    let Data::Other(data) = &record.data else { return Err(refuse("is not signed")) };
    let found = signature(data).ok_or_else(|| refuse("has a TSIG record we cannot read"))?;
    if found.error != 0 {
        return Err(refuse(&format!("reports the TSIG error {}", error_name(found.error))));
    }
    if record.name != key.name {
        return Err(refuse("is signed with another key"));
    }
    let mut mac = HmacSha256::new(&key.secret);
    mac.update(&(MAC as u16).to_be_bytes());
    mac.update(request_mac);
    mac.update(&found.original_id);
    mac.update(&response[2..10]);
    mac.update(&(additional - 1).to_be_bytes());
    mac.update(&response[HEADER..record.start]);
    let variables = Variables {
        key,
        time: found.time,
        fudge: found.fudge,
        error: found.error,
        other: found.other,
    };
    variables.feed(&mut mac)?;
    if !equal(&mac.finalize(), found.mac) {
        return Err(refuse("has a wrong signature"));
    }
    if now.abs_diff(found.time) > u64::from(found.fudge.min(FUDGE)) {
        return Err(refuse("was signed at another time; check the clocks"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::super::update;
    use super::*;

    // The vectors below come from miekg/dns 1.1.62, the DNS library of CoreDNS and of
    // Pebble: an update of `example.org.` built with `Msg.SetUpdate` and `Insert`,
    // signed with `TsigGenerate`, and the answer of `SetReply` signed with the MAC of
    // the request. RFC 8945 has no test vector.
    const SECRET: &str = "c2lidW5hLXRzaWctdGVzdC1zZWNyZXQtMDEyMzQ1Njc=";
    const VALUE: &str = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0";
    const TIME: u64 = 1_795_516_496;
    const TSIG_HEAD: &str =
        "0a736962756e612d6b65790000fa00ff00000000003d0b686d61632d736861323536000000";
    const ADD_MAC: &str = "d7d4fe1f7d7b2cc489c6776f07582b59662d43055b5c13cd4e822b3df1077769";
    const DELETE_MAC: &str = "54fddc605fd71d48f067ee331f1965946093357281849c3029669367e0d071aa";
    const REPLY: &str = "1234a8000001000000000001076578616d706c65036f72670000060001\
        0a736962756e612d6b65790000fa00ff00000000003d0b686d61632d7368613235360000006b056851012c0020\
        4321e9d3bbaac3288c2c3767002b41ba58aff03f36a9648ce268723ccceb3906123400000000";

    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text
            .bytes()
            .filter_map(|byte| char::from(byte).to_digit(16))
            .map(|d| d as u8)
            .collect();
        digits.chunks(2).map(|pair| pair[0] << 4 | pair[1]).collect()
    }

    fn key() -> TsigKey {
        TsigKey::parse("Sibuna-Key.", &format!("# the secret\n{SECRET}\n")).unwrap()
    }

    #[test]
    fn a_signed_update_equals_the_one_of_miekg_dns() {
        for (delete, mac) in [(false, ADD_MAC), (true, DELETE_MAC)] {
            let owner = "_acme-challenge.example.org";
            let mut message =
                update::message(0x1234, "example.org", owner, VALUE, delete).unwrap();
            let unsigned = message.len();
            let made = sign(&mut message, &key(), TIME).unwrap();
            assert_eq!(made.to_vec(), hex(mac));
            let tail = format!("{TSIG_HEAD}6b056850012c0020{mac}123400000000");
            assert_eq!(message[unsigned..], hex(&tail));
            assert_eq!(message[10..12], [0, 1]);
        }
    }

    #[test]
    fn the_signed_answer_of_miekg_dns_verifies() {
        let reply = hex(REPLY);
        let request: [u8; 32] = hex(ADD_MAC).try_into().unwrap();
        verify(&reply, &key(), &request, TIME + 1).unwrap();
        verify(&reply, &key(), &request, TIME + 301).unwrap();
        let fails = |reply: &[u8], key: &TsigKey, request: &[u8; 32], now: u64| {
            let error = verify(reply, key, request, now).unwrap_err();
            assert_eq!(error.code, "ACME009");
            error.message
        };
        assert!(fails(&reply, &key(), &request, TIME + 302).contains("another time"));
        let other: [u8; 32] = hex(DELETE_MAC).try_into().unwrap();
        assert!(fails(&reply, &key(), &other, TIME).contains("wrong signature"));
        let mut wrong = key();
        wrong.secret[0] ^= 1;
        assert!(fails(&reply, &wrong, &request, TIME).contains("wrong signature"));
        wrong = TsigKey { name: "other-key".to_owned(), ..key() };
        assert!(fails(&reply, &wrong, &request, TIME).contains("another key"));
        // A changed response code breaks the signature.
        let mut changed = reply.clone();
        changed[3] = 5;
        assert!(fails(&changed, &key(), &request, TIME).contains("wrong signature"));
        // An answer without the record, and one cut short.
        let mut unsigned = reply[..29].to_vec();
        unsigned[11] = 0;
        assert!(fails(&unsigned, &key(), &request, TIME).contains("not signed"));
        assert!(fails(&reply[..60], &key(), &request, TIME).contains("cannot be read"));
        assert!(fails(&[], &key(), &request, TIME).contains("cannot be read"));
    }

    #[test]
    fn our_signed_answer_equals_the_one_of_miekg_dns() {
        let reply = hex(REPLY);
        let mut answer = reply[..29].to_vec();
        answer[11] = 0;
        let request: [u8; 32] = hex(ADD_MAC).try_into().unwrap();
        sign_answer(&mut answer, &key(), TIME + 1, &request).unwrap();
        assert_eq!(answer, reply);
    }

    #[test]
    fn a_tsig_error_of_the_server_is_named() {
        // An unsigned TSIG record with the error BADKEY, as a server sends it.
        let mut reply = hex(REPLY)[..29].to_vec();
        reply[3] = 9;
        let mut data = Vec::new();
        wire::write_name(&mut data, ALGORITHM).unwrap();
        data.extend_from_slice(&[0, 0, 0, 0, 0, 1, 1, 44, 0, 0, 0x12, 0x34, 0, 17, 0, 0]);
        wire::write_name(&mut reply, "sibuna-key").unwrap();
        reply.extend_from_slice(&[0, 250, 0, 255, 0, 0, 0, 0, 0, data.len() as u8]);
        reply.extend_from_slice(&data);
        let error = verify(&reply, &key(), &[0; 32], TIME).unwrap_err();
        assert!(error.message.contains("BADKEY"), "{}", error.message);
    }

    #[test]
    fn a_key_file_holds_base64_and_the_key_is_not_printed() {
        assert_eq!(key().name, "sibuna-key");
        assert_eq!(key().secret, b"sibuna-tsig-test-secret-01234567");
        for (name, file) in
            [("k", ""), ("k", "# only a comment\n"), ("k", "not base64!"), ("a..b", SECRET)]
        {
            assert_eq!(TsigKey::parse(name, file), None, "{name} {file}");
        }
        let printed = format!("{:?}", key());
        assert!(printed.contains("sibuna-key") && !printed.contains("115"), "{printed}");
    }
}
