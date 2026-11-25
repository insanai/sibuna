//! Reading the WebAssembly binary format: bytes, LEB128 integers, names and vectors.
//! Every read checks the remaining input and returns an error at the end.

use std::fmt;

/// Why a module did not load.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoadError {
    /// The bytes are not a well-formed module, or the module does not validate.
    Malformed(&'static str),
    /// The module is well formed and uses something this interpreter does not run.
    Unsupported(&'static str),
    /// The module passes one of the bounds of SID 0030.
    Limit(&'static str),
    /// The module imports something that the host does not offer.
    Import(String),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Malformed(what) => write!(f, "malformed module: {what}"),
            LoadError::Unsupported(what) => write!(f, "unsupported: {what}"),
            LoadError::Limit(what) => write!(f, "limit exceeded: {what}"),
            LoadError::Import(name) => write!(f, "forbidden import `{name}`"),
        }
    }
}

impl std::error::Error for LoadError {}

/// The result of a step of loading.
pub(crate) type Load<T> = Result<T, LoadError>;

/// A cursor over the bytes of a module or of one of its sections.
#[derive(Clone, Copy)]
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    /// A reader over `bytes`.
    pub fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes }
    }

    /// True when nothing is left.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The bytes that are left.
    pub fn rest(&self) -> usize {
        self.bytes.len()
    }

    /// Takes one byte.
    pub fn byte(&mut self) -> Load<u8> {
        let (&first, rest) =
            self.bytes.split_first().ok_or(LoadError::Malformed("unexpected end"))?;
        self.bytes = rest;
        Ok(first)
    }

    /// Takes `count` bytes.
    pub fn take(&mut self, count: usize) -> Load<&'a [u8]> {
        let (front, rest) =
            self.bytes.split_at_checked(count).ok_or(LoadError::Malformed("unexpected end"))?;
        self.bytes = rest;
        Ok(front)
    }

    /// Takes a reader over the next `count` bytes.
    pub fn sub(&mut self, count: usize) -> Load<Reader<'a>> {
        self.take(count).map(Reader::new)
    }

    /// Reads a LEB128 integer of at most `bits` bits into the low bits of a `u64`.
    /// With `signed` the value is sign-extended to 64 bits. Bits beyond `bits` in the
    /// last byte must agree with the sign, as the specification demands.
    fn leb(&mut self, bits: u32, signed: bool) -> Load<u64> {
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = self.byte()?;
            let low = u64::from(byte & 0x7f);
            let left = bits - shift;
            if left < 7 {
                // The last byte: the unused bits must be all zero, or all one for a
                // negative number, and no further byte may follow.
                let unused = low >> left;
                let ones = (1u64 << (7 - left)) - 1;
                let negative = signed && (low >> (left - 1)) & 1 == 1;
                let fits = if negative { unused == ones } else { unused == 0 };
                if byte & 0x80 != 0 || !fits {
                    return Err(LoadError::Malformed("integer too long"));
                }
            }
            value |= low << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                if signed && shift < 64 && byte & 0x40 != 0 {
                    value |= u64::MAX << shift;
                }
                return Ok(value);
            }
            if shift >= bits {
                return Err(LoadError::Malformed("integer too long"));
            }
        }
    }

    /// Reads an unsigned 32-bit integer.
    pub fn u32(&mut self) -> Load<u32> {
        self.leb(32, false).map(|value| value as u32)
    }

    /// Reads a signed 32-bit integer.
    pub fn i32(&mut self) -> Load<i32> {
        self.leb(32, true).map(|value| value as i64 as i32)
    }

    /// Reads a signed 64-bit integer.
    pub fn i64(&mut self) -> Load<i64> {
        self.leb(64, true).map(|value| value as i64)
    }

    /// Reads a count that must not exceed `limit`; `what` names it in the error.
    pub fn count(&mut self, limit: usize, what: &'static str) -> Load<usize> {
        let count = self.u32()? as usize;
        if count > limit { Err(LoadError::Limit(what)) } else { Ok(count) }
    }

    /// Reads a name: a length and that many bytes of UTF-8.
    pub fn name(&mut self) -> Load<&'a str> {
        let length = self.u32()? as usize;
        let bytes = self.take(length)?;
        std::str::from_utf8(bytes).map_err(|_| LoadError::Malformed("name is not UTF-8"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leb128_reads_the_examples_of_the_specification() {
        assert_eq!(Reader::new(&[0xe5, 0x8e, 0x26]).u32().unwrap(), 624_485);
        assert_eq!(Reader::new(&[0xc0, 0xbb, 0x78]).i32().unwrap(), -123_456);
        assert_eq!(Reader::new(&[0x7f]).i32().unwrap(), -1);
        assert_eq!(Reader::new(&[0x7f]).i64().unwrap(), -1);
        assert_eq!(Reader::new(&[0xff, 0xff, 0xff, 0xff, 0x0f]).u32().unwrap(), u32::MAX);
        assert_eq!(Reader::new(&[0x80, 0x80, 0x80, 0x80, 0x78]).i32().unwrap(), i32::MIN);
        let min = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f];
        assert_eq!(Reader::new(&min).i64().unwrap(), i64::MIN);
        // A redundant encoding of zero is allowed while it stays within the length.
        assert_eq!(Reader::new(&[0x80, 0x00]).u32().unwrap(), 0);
    }

    #[test]
    fn leb128_refuses_overlong_and_overflowing_integers() {
        assert!(Reader::new(&[0xff, 0xff, 0xff, 0xff, 0x1f]).u32().is_err());
        assert!(Reader::new(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x00]).u32().is_err());
        assert!(Reader::new(&[0xff, 0xff, 0xff, 0xff, 0x4f]).i32().is_err());
        assert!(Reader::new(&[0x80]).u32().is_err());
        assert!(Reader::new(&[]).u32().is_err());
    }

    #[test]
    fn a_count_above_its_limit_is_a_limit_error() {
        assert_eq!(Reader::new(&[5]).count(4, "things"), Err(LoadError::Limit("things")));
        assert_eq!(Reader::new(&[4]).count(4, "things"), Ok(4));
    }
}
