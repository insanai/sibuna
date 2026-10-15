//! The gzip container (RFC 1952): member header, footer and the boundary between members.
//!
//! A member is a header, DEFLATE data and an eight-byte footer holding the CRC-32 and the
//! size modulo 2^32 of the member's output. The header is ten fixed bytes plus optional
//! fields selected by flags:
//!
//! ```text
//! +----+----+----+-----+-----+-----+-----+-----+-----+----+
//! | 1f | 8b | CM | FLG |        MTIME          | XFL | OS |
//! +----+----+----+-----+-----+-----+-----+-----+-----+----+
//! FEXTRA: XLEN (2 bytes) and XLEN bytes;  FNAME: bytes up to a zero;
//! FCOMMENT: bytes up to a zero;  FHCRC: low 16 bits of the CRC-32 of the header so far.
//! ```
//!
//! We skip the optional fields without keeping them, so a long name costs no memory, and
//! check the header CRC when present.

use crate::bits::Input;
use crate::crc32::Crc32;
use crate::decoder::{Decoder, Flow, State, need_input};
use crate::error::Error;

const FLAG_HCRC: u8 = 1 << 1;
const FLAG_EXTRA: u8 = 1 << 2;
const FLAG_NAME: u8 = 1 << 3;
const FLAG_COMMENT: u8 = 1 << 4;
/// Flag bits RFC 1952 reserves; a decoder must reject them.
const FLAGS_RESERVED: u8 = 0xe0;
/// The first byte of every gzip member.
const MAGIC_FIRST: u8 = 0x1f;

/// Which part of the header comes next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Field {
    /// Byte `n` of the ten fixed bytes.
    Fixed(u8),
    /// Byte `n` of XLEN.
    ExtraLength(u8),
    /// The extra field, with this many bytes left.
    Extra(u16),
    Name,
    Comment,
    /// Byte `n` of the header CRC.
    HeaderCrc(u8),
    /// The header has been read completely.
    Complete,
}

/// A gzip header read so far.
pub(crate) struct HeaderParser {
    field: Field,
    flags: u8,
    /// XLEN, then the stored header CRC, assembled byte by byte.
    value: u16,
    /// The CRC-32 of the header bytes so far, for FHCRC.
    crc: Crc32,
}

impl HeaderParser {
    /// Returns a parser at the first header byte.
    pub(crate) fn new() -> Self {
        Self { field: Field::Fixed(0), flags: 0, value: 0, crc: Crc32::new() }
    }

    /// Accepts one header byte. Returns `Ok(true)` when the header is complete.
    fn accept(&mut self, byte: u8) -> Result<bool, Error> {
        if !matches!(self.field, Field::HeaderCrc(_)) {
            self.crc.update(&[byte]);
        }
        self.field = match self.field {
            Field::Fixed(index) => {
                match (index, byte) {
                    (0, MAGIC_FIRST) | (1, 0x8b) => {}
                    (0 | 1, _) => return Err(Error::NotGzip),
                    (2, 8) => {}
                    (2, _) => return Err(Error::UnsupportedMethod),
                    (3, flags) if flags & FLAGS_RESERVED != 0 => return Err(Error::ReservedFlags),
                    (3, flags) => self.flags = flags,
                    _ => {}
                }
                if index < 9 { Field::Fixed(index + 1) } else { self.next_field(FLAG_EXTRA) }
            }
            Field::ExtraLength(0) => {
                self.value = u16::from(byte);
                Field::ExtraLength(1)
            }
            Field::ExtraLength(_) => {
                let length = self.value | u16::from(byte) << 8;
                if length == 0 { self.next_field(FLAG_NAME) } else { Field::Extra(length) }
            }
            Field::Extra(1) => self.next_field(FLAG_NAME),
            Field::Extra(left) => Field::Extra(left - 1),
            Field::Name if byte == 0 => self.next_field(FLAG_COMMENT),
            Field::Comment if byte == 0 => self.next_field(FLAG_HCRC),
            field @ (Field::Name | Field::Comment) => field,
            Field::HeaderCrc(0) => {
                self.value = u16::from(byte);
                Field::HeaderCrc(1)
            }
            Field::HeaderCrc(_) => {
                let stored = self.value | u16::from(byte) << 8;
                if stored != (self.crc.value() & 0xffff) as u16 {
                    return Err(Error::HeaderCrcMismatch);
                }
                Field::Complete
            }
            // The decoder stops feeding bytes once the header is complete.
            Field::Complete => Field::Complete,
        };
        Ok(self.field == Field::Complete)
    }

    /// Returns the first optional field at or after `flag` that the flags select, or the
    /// end of the header.
    fn next_field(&self, flag: u8) -> Field {
        let order = [
            (FLAG_EXTRA, Field::ExtraLength(0)),
            (FLAG_NAME, Field::Name),
            (FLAG_COMMENT, Field::Comment),
            (FLAG_HCRC, Field::HeaderCrc(0)),
        ];
        let start = order.iter().position(|&(f, _)| f == flag).unwrap_or(order.len());
        order[start..]
            .iter()
            .find(|&&(f, _)| self.flags & f != 0)
            .map_or(Field::Complete, |&(_, field)| field)
    }
}

impl Decoder {
    /// Reads the member header up to the first DEFLATE block.
    pub(crate) fn step_gzip_header(
        &mut self,
        input: &mut Input<'_>,
        is_last: bool,
    ) -> Result<Flow, Error> {
        loop {
            let Some(byte) = self.bits.take_byte(input) else { return need_input(is_last) };
            if self.header.accept(byte)? {
                self.state = State::BlockHeader;
                return Ok(Flow::Continue);
            }
        }
    }

    /// Reads the footer and checks the CRC-32 and size of the member's output.
    pub(crate) fn step_gzip_footer(
        &mut self,
        input: &mut Input<'_>,
        is_last: bool,
    ) -> Result<Flow, Error> {
        // `footer_len < 8` inside the loop.
        while self.footer_len < self.footer.len() {
            let Some(byte) = self.bits.take_byte(input) else { return need_input(is_last) };
            self.footer[self.footer_len] = byte;
            self.footer_len += 1;
        }
        let [c0, c1, c2, c3, s0, s1, s2, s3] = self.footer;
        if u32::from_le_bytes([c0, c1, c2, c3]) != self.crc.value() {
            return Err(Error::CrcMismatch);
        }
        if u32::from_le_bytes([s0, s1, s2, s3]) != self.member_size {
            return Err(Error::SizeMismatch);
        }
        self.member_count += 1;
        self.state = State::MemberEnd;
        Ok(Flow::Continue)
    }

    /// Decides what follows a member: the end of the stream, or another member.
    ///
    /// After the last member the limits allow, the stream is done and any further bytes are
    /// left unconsumed. Otherwise, a further byte must start a new member.
    pub(crate) fn step_member_end(
        &mut self,
        input: &mut Input<'_>,
        is_last: bool,
    ) -> Result<Flow, Error> {
        if self.member_count >= self.limits.max_members.max(1) {
            self.state = State::Done;
            return Ok(Flow::Continue);
        }
        match self.bits.peek_byte(input) {
            None if is_last => self.state = State::Done,
            None => return Ok(Flow::NeedInput),
            Some(MAGIC_FIRST) => self.begin_member(),
            Some(_) => return Err(Error::TrailingData),
        }
        Ok(Flow::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(header: &[u8]) -> Result<bool, Error> {
        let mut parser = HeaderParser::new();
        for &byte in header {
            if parser.accept(byte)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[test]
    fn minimal_header() {
        assert_eq!(parse(&[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3]), Ok(true));
        assert_eq!(parse(&[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0]), Ok(false));
    }

    #[test]
    fn rejects_bad_fixed_fields() {
        assert_eq!(parse(&[0x1f, 0x8c]), Err(Error::NotGzip));
        assert_eq!(parse(&[0x50, 0x4b]), Err(Error::NotGzip));
        assert_eq!(parse(&[0x1f, 0x8b, 9]), Err(Error::UnsupportedMethod));
        assert_eq!(parse(&[0x1f, 0x8b, 8, 0x20]), Err(Error::ReservedFlags));
    }

    #[test]
    fn optional_fields_in_order() {
        let mut header =
            vec![0x1f, 0x8b, 8, FLAG_EXTRA | FLAG_NAME | FLAG_COMMENT, 0, 0, 0, 0, 0, 3];
        header.extend_from_slice(&[3, 0, b'a', 0, b'b']); // XLEN 3 and an extra field
        header.extend_from_slice(b"name\0comment\0");
        assert_eq!(parse(&header), Ok(true));
        assert_eq!(parse(&header[..header.len() - 1]), Ok(false));
        // An empty extra field is followed directly by the name.
        let mut header = vec![0x1f, 0x8b, 8, FLAG_EXTRA | FLAG_NAME, 0, 0, 0, 0, 0, 3, 0, 0];
        header.extend_from_slice(b"x\0");
        assert_eq!(parse(&header), Ok(true));
    }

    // From Zig 0.16 std.compress.flate.Decompress test "gzip header": FLG has FNAME and
    // FHCRC, and 0xd699 is the CRC-32 of the header bytes before it, low 16 bits.
    #[test]
    fn header_crc_is_checked() {
        let header = [
            0x1f, 0x8b, 0x08, 0x12, 0x00, 0x09, 0x6e, 0x88, 0x00, 0xff, 0x48, 0x65, 0x6c, 0x6c,
            0x6f, 0x00, 0x99, 0xd6,
        ];
        assert_eq!(parse(&header), Ok(true));
        let mut corrupt = header;
        corrupt[16] ^= 1;
        assert_eq!(parse(&corrupt), Err(Error::HeaderCrcMismatch));
    }
}
