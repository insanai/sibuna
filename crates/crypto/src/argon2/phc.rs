//! The PHC string format of Zig's `std.crypto.pwhash.argon2.strHash` and `strVerify`:
//!
//! ```text
//! $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
//! ```
//!
//! Salt and hash are standard base64 without padding. The parser accepts exactly the
//! strings Zig's `phc_format.deserialize` accepts for Argon2, quirks included: parameters
//! may come in any order and repeat, a parameter list may end in an item without `=`,
//! numbers may contain `_` between digits, and fields after the hash are ignored. A
//! string whose parameter list contains `alg_version=...` made Zig panic; we reject it.
//!
//! Verification checks the cost parameters against the caller's [`Limits`] before it
//! touches memory, so a stored string cannot make the server work harder than intended.

#[cfg(test)]
mod tests;

use core::fmt;

use super::{
    Block, Error, HASH_LEN, MAX_PARALLELISM, MAX_PHC_BINARY_LEN, Mode, Params, VERSION, derive_key,
};
use crate::ct;

/// The longest string [`hash_phc`] writes: `$argon2id$v=19`, the largest parameters, a
/// 64-byte salt and a 32-byte hash.
pub const PHC_MAX_LEN: usize = "$argon2id$v=19$m=4294967295,t=4294967295,p=16777215$".len()
    + encoded_len(MAX_PHC_BINARY_LEN)
    + 1
    + encoded_len(HASH_LEN);

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The largest costs a stored PHC string may ask for. Verification fails with
/// [`Error::LimitExceeded`] before any memory is used when a string exceeds them.
///
/// The default admits exactly the default [`Params`]: `m = 19456`, `t = 2`, `p = 1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The largest memory cost `m`, in KiB.
    pub max_memory_kib: u32,
    /// The largest number of passes `t`.
    pub max_time_cost: u32,
    /// The largest number of lanes `p`.
    pub max_parallelism: u32,
}

impl Default for Limits {
    fn default() -> Self {
        let params = Params::default();
        Limits {
            max_memory_kib: params.memory_kib,
            max_time_cost: params.time_cost,
            max_parallelism: params.parallelism,
        }
    }
}

/// A byte string of at most 64 bytes decoded from base64.
#[derive(Clone, Copy)]
struct Binary {
    bytes: [u8; MAX_PHC_BINARY_LEN],
    len: usize,
}

impl Binary {
    const EMPTY: Binary = Binary { bytes: [0; MAX_PHC_BINARY_LEN], len: 0 };

    fn as_slice(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or(&[])
    }
}

/// A parsed Argon2 PHC string.
///
/// ```
/// use sibuna_crypto::argon2::{Mode, PhcHash};
/// let text = b"$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaGhhc2g";
/// let parsed = PhcHash::parse(text).unwrap();
/// assert_eq!(parsed.params.mode, Mode::Argon2id);
/// assert_eq!(parsed.salt(), b"somesalt");
/// ```
#[derive(Clone)]
pub struct PhcHash {
    /// The variant and cost parameters. Parameters missing from a string that Zig
    /// accepts anyway (through repeated parameters) are zero.
    pub params: Params,
    /// The `v=` field, if present. Verification requires 19 (0x13) when present.
    pub version: Option<u32>,
    salt: Binary,
    hash: Binary,
}

impl PhcHash {
    /// Parses `text`, which is borrowed for the call.
    ///
    /// Fails with [`Error::InvalidEncoding`] when the string is malformed and with
    /// [`Error::UnsupportedAlgorithm`] when it names no Argon2 variant. Parameter values
    /// are not checked here; [`verify_phc`] checks them.
    pub fn parse(text: &[u8]) -> Result<PhcHash, Error> {
        let fields = parse_fields(text)?;
        let mode = Mode::from_name(fields.algorithm).ok_or(Error::UnsupportedAlgorithm)?;
        Ok(PhcHash {
            params: Params {
                mode,
                time_cost: fields.time_cost,
                memory_kib: fields.memory_kib,
                parallelism: fields.parallelism,
            },
            version: fields.version,
            salt: fields.salt,
            hash: fields.hash,
        })
    }

    /// The decoded salt, at most 64 bytes.
    pub fn salt(&self) -> &[u8] {
        self.salt.as_slice()
    }

    /// The decoded hash, at most 64 bytes.
    pub fn hash(&self) -> &[u8] {
        self.hash.as_slice()
    }
}

impl fmt::Debug for PhcHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PhcHash")
            .field("params", &self.params)
            .field("version", &self.version)
            .field("salt_len", &self.salt.len)
            .field("hash_len", &self.hash.len)
            .finish()
    }
}

/// Hashes `password` with `params` and the caller's random `salt` (Zig draws
/// [`SALT_LEN`](super::SALT_LEN) = 32 bytes), and writes the PHC string to `out`.
///
/// Returns the string, which borrows `out`. The hash is [`HASH_LEN`] = 32 bytes, as in
/// Zig. Fails with [`Error::BufferTooSmall`] when `out` cannot hold the string (checked
/// before hashing; [`PHC_MAX_LEN`] bytes always suffice), with [`Error::InvalidEncoding`]
/// for a salt longer than 64 bytes, and otherwise as [`derive_key`] does.
pub fn hash_phc<'o>(
    params: &Params,
    password: &[u8],
    salt: &[u8],
    workspace: &mut [Block],
    out: &'o mut [u8],
) -> Result<&'o str, Error> {
    if salt.len() > MAX_PHC_BINARY_LEN {
        return Err(Error::InvalidEncoding);
    }
    let zero_hash = [0u8; HASH_LEN];
    // A dry run with a placeholder hash sizes the string without touching `out`.
    let len = write_phc(&mut Writer { out: &mut [], len: 0 }, params, salt, &zero_hash);
    if len > out.len() {
        return Err(Error::BufferTooSmall);
    }
    let mut hash = [0u8; HASH_LEN];
    derive_key(params, password, salt, workspace, &mut hash)?;
    let len = write_phc(&mut Writer { out, len: 0 }, params, salt, &hash);
    let text = out.get(..len).ok_or(Error::BufferTooSmall)?;
    core::str::from_utf8(text).map_err(|_| Error::InvalidEncoding)
}

/// Checks `password` against the PHC string `text`, using `workspace` as memory.
///
/// Borrows everything for the call. The order of checks is Zig's, with the limits added
/// before any memory is used: [`Error::InvalidEncoding`] or
/// [`Error::UnsupportedAlgorithm`] for a malformed string or a version other than 19,
/// [`Error::LimitExceeded`] for costs above `limits`, [`Error::WeakParameters`] for
/// invalid costs, a salt under 8 bytes or a hash under 4 bytes,
/// [`Error::WorkspaceTooSmall`], and finally [`Error::VerificationFailed`] when the
/// password does not match. The hashes are compared in constant time.
pub fn verify_phc(
    text: &[u8],
    password: &[u8],
    limits: &Limits,
    workspace: &mut [Block],
) -> Result<(), Error> {
    let parsed = PhcHash::parse(text)?;
    if parsed.version.is_some_and(|version| version != VERSION) {
        return Err(Error::InvalidEncoding);
    }
    let params = &parsed.params;
    if params.memory_kib > limits.max_memory_kib
        || params.time_cost > limits.max_time_cost
        || params.parallelism > limits.max_parallelism
    {
        return Err(Error::LimitExceeded);
    }
    let expected = parsed.hash();
    let mut computed = [0u8; MAX_PHC_BINARY_LEN];
    let computed = computed.get_mut(..expected.len()).ok_or(Error::InvalidEncoding)?;
    derive_key(params, password, parsed.salt(), workspace, computed)?;
    let matches = ct::eq(computed, expected);
    ct::zeroize(computed);
    if matches { Ok(()) } else { Err(Error::VerificationFailed) }
}

/// The fields of a PHC string before the algorithm name is interpreted.
struct Fields<'a> {
    algorithm: &'a [u8],
    version: Option<u32>,
    memory_kib: u32,
    time_cost: u32,
    parallelism: u32,
    salt: Binary,
    hash: Binary,
}

/// Number of fields Zig's `deserialize` requires for Argon2: the algorithm, `m`, `t`, `p`,
/// salt and hash. The version is optional.
const REQUIRED_FIELDS: usize = 6;

/// Splits and decodes a PHC string as Zig's `phc_format.deserialize` does for Argon2's
/// result type.
fn parse_fields(text: &[u8]) -> Result<Fields<'_>, Error> {
    let mut pieces = text.split(|&byte| byte == b'$');
    // The string must start with `$`.
    if pieces.next() != Some(&[][..]) {
        return Err(Error::InvalidEncoding);
    }
    let algorithm = pieces.next().ok_or(Error::InvalidEncoding)?;
    let mut fields = Fields {
        algorithm,
        version: None,
        memory_kib: 0,
        time_cost: 0,
        parallelism: 0,
        salt: Binary::EMPTY,
        hash: Binary::EMPTY,
    };
    // Zig counts every field it sets, repeated parameters included, and requires six.
    let set = 1 + parse_after_algorithm(&mut pieces, &mut fields)?;
    if set < REQUIRED_FIELDS {
        return Err(Error::InvalidEncoding);
    }
    Ok(fields)
}

/// Parses the optional version, the parameters, the salt and the hash. Returns the number
/// of fields set. The string may end after any of them.
fn parse_after_algorithm<'a>(
    pieces: &mut impl Iterator<Item = &'a [u8]>,
    fields: &mut Fields<'a>,
) -> Result<usize, Error> {
    let mut set = 0;
    let Some(mut piece) = pieces.next() else { return Ok(set) };
    if let Some((b"v", value)) = split_key_value(piece) {
        fields.version = Some(parse_decimal(value, u32::MAX)?);
        set += 1;
        let Some(next) = pieces.next() else { return Ok(set) };
        piece = next;
    }
    let mut has_params = false;
    for item in piece.split(|&byte| byte == b',') {
        // An item without `=` ends the list, and the rest of the field is ignored.
        let Some((key, value)) = split_key_value(item) else { break };
        set_parameter(fields, key, value)?;
        set += 1;
        has_params = true;
    }
    // Without parameters, the field just read is the salt.
    if has_params {
        let Some(next) = pieces.next() else { return Ok(set) };
        piece = next;
    }
    fields.salt = decode_base64(piece)?;
    set += 1;
    let Some(piece) = pieces.next() else { return Ok(set) };
    fields.hash = decode_base64(piece)?;
    Ok(set + 1)
}

/// Stores one `key=value` parameter. Zig matches keys against every field of its result
/// type, so `alg_id`, `salt` and `hash` are parameters too.
fn set_parameter<'a>(fields: &mut Fields<'a>, key: &[u8], value: &'a [u8]) -> Result<(), Error> {
    match key {
        b"alg_id" => fields.algorithm = value,
        b"m" => fields.memory_kib = parse_decimal(value, u32::MAX)?,
        b"t" => fields.time_cost = parse_decimal(value, u32::MAX)?,
        b"p" => fields.parallelism = parse_decimal(value, MAX_PARALLELISM)?,
        b"salt" => fields.salt = decode_base64(value)?,
        b"hash" => fields.hash = decode_base64(value)?,
        // Zig panics on `alg_version` (an optional field it cannot parse here) and
        // rejects every other key.
        _ => return Err(Error::InvalidEncoding),
    }
    Ok(())
}

/// Splits `key=value` at the first `=`; the value ends at the next `=`, as in Zig's
/// `kvSplit`. Returns `None` without `=`.
fn split_key_value(text: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut parts = text.split(|&byte| byte == b'=');
    let key = parts.next()?;
    let value = parts.next()?;
    Some((key, value))
}

/// Parses an unsigned decimal number as Zig's `fmt.parseUnsigned(T, text, 10)` does for a
/// type whose largest value is `max`: at least one character, digits with `_` allowed
/// between them (not first or last), leading zeros allowed, no sign.
fn parse_decimal(text: &[u8], max: u32) -> Result<u32, Error> {
    match (text.first(), text.last()) {
        (Some(b'_'), _) | (_, Some(b'_')) | (None, _) => return Err(Error::InvalidEncoding),
        _ => {}
    }
    let mut value: u32 = 0;
    for &byte in text {
        if byte == b'_' {
            continue;
        }
        if !byte.is_ascii_digit() {
            return Err(Error::InvalidEncoding);
        }
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(byte - b'0')))
            .filter(|&value| value <= max)
            .ok_or(Error::InvalidEncoding)?;
    }
    Ok(value)
}

/// Length of the unpadded base64 encoding of `len` bytes.
const fn encoded_len(len: usize) -> usize {
    len / 3 * 4 + (len % 3 * 4).div_ceil(3)
}

/// The 6-bit value of a base64 character of the standard alphabet.
fn sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decodes standard base64 without padding, strictly, as Zig's
/// `std.base64.standard_no_pad.Decoder` does: a length of 1 modulo 4, a character outside
/// the alphabet (`=` included) or non-zero unused bits in the last character are errors,
/// and so is a result longer than 64 bytes.
fn decode_base64(text: &[u8]) -> Result<Binary, Error> {
    let tail = text.len() % 4;
    if tail == 1 {
        return Err(Error::InvalidEncoding);
    }
    let len = text.len() / 4 * 3 + tail * 3 / 4;
    if len > MAX_PHC_BINARY_LEN {
        return Err(Error::InvalidEncoding);
    }
    let mut binary = Binary { bytes: [0; MAX_PHC_BINARY_LEN], len };
    let mut accumulator: u32 = 0;
    let mut bits = 0;
    let mut written = 0;
    for &byte in text {
        let value = sextet(byte).ok_or(Error::InvalidEncoding)?;
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            let slot = binary.bytes.get_mut(written).ok_or(Error::InvalidEncoding)?;
            *slot = (accumulator >> bits) as u8;
            written += 1;
            accumulator &= (1 << bits) - 1;
        }
    }
    // The bits left over from the last character must be zero.
    if accumulator != 0 {
        return Err(Error::InvalidEncoding);
    }
    Ok(binary)
}

/// Appends to a byte buffer and counts the bytes. Bytes that do not fit are counted but
/// not written, so a writer over an empty buffer sizes a string.
struct Writer<'a> {
    out: &'a mut [u8],
    len: usize,
}

impl Writer<'_> {
    fn push(&mut self, bytes: &[u8]) {
        let end = self.len + bytes.len();
        if let Some(target) = self.out.get_mut(self.len..end) {
            target.copy_from_slice(bytes);
        }
        self.len = end;
    }

    fn push_decimal(&mut self, value: u32) {
        let mut digits = [0u8; 10];
        let mut start = digits.len();
        let mut rest = value;
        loop {
            start -= 1;
            digits[start] = b'0' + (rest % 10) as u8;
            rest /= 10;
            if rest == 0 {
                break;
            }
        }
        self.push(&digits[start..]);
    }

    fn push_base64(&mut self, bytes: &[u8]) {
        let (groups, tail) = bytes.as_chunks::<3>();
        for group in groups {
            let n = u32::from_be_bytes([0, group[0], group[1], group[2]]);
            self.push(&[18, 12, 6, 0].map(|shift| ALPHABET[(n >> shift) as usize & 63]));
        }
        match *tail {
            [a] => {
                let n = u32::from(a) << 16;
                self.push(&[18, 12].map(|shift| ALPHABET[(n >> shift) as usize & 63]));
            }
            [a, b] => {
                let n = (u32::from(a) << 16) | (u32::from(b) << 8);
                self.push(&[18, 12, 6].map(|shift| ALPHABET[(n >> shift) as usize & 63]));
            }
            _ => {}
        }
    }
}

/// Writes `$<mode>$v=19$m=<m>,t=<t>,p=<p>$<salt>$<hash>` and returns its length.
fn write_phc(writer: &mut Writer<'_>, params: &Params, salt: &[u8], hash: &[u8]) -> usize {
    writer.push(b"$");
    writer.push(params.mode.name().as_bytes());
    writer.push(b"$v=");
    writer.push_decimal(VERSION);
    writer.push(b"$m=");
    writer.push_decimal(params.memory_kib);
    writer.push(b",t=");
    writer.push_decimal(params.time_cost);
    writer.push(b",p=");
    writer.push_decimal(params.parallelism);
    writer.push(b"$");
    writer.push_base64(salt);
    writer.push(b"$");
    writer.push_base64(hash);
    writer.len
}
