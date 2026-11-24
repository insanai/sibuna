//! The DNS message format (RFC 1035, section 4): writing a query and reading an answer.
//!
//! An answer is untrusted. Reading follows at most [`MAX_POINTERS`] compression pointers
//! in one name, keeps at most [`MAX_RECORDS`] records, and returns `None` for anything
//! that breaks the format. It never panics and never loops.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::Error;

/// The record type `A`.
pub const TYPE_A: u16 = 1;
/// The record type `NS`.
pub const TYPE_NS: u16 = 2;
/// The record type `CNAME`.
pub const TYPE_CNAME: u16 = 5;
/// The record type `SOA`.
pub const TYPE_SOA: u16 = 6;
/// The record type `TXT`.
pub const TYPE_TXT: u16 = 16;
/// The record type `AAAA`.
pub const TYPE_AAAA: u16 = 28;
/// The record type `TSIG` (RFC 8945).
pub const TYPE_TSIG: u16 = 250;
/// The class `IN`.
pub const CLASS_IN: u16 = 1;
/// The class `NONE`, which deletes one record in an update (RFC 2136).
pub const CLASS_NONE: u16 = 254;
/// The class `ANY`.
pub const CLASS_ANY: u16 = 255;
/// The most records kept from one message.
pub const MAX_RECORDS: usize = 64;
/// The most compression pointers followed in one name.
pub const MAX_POINTERS: usize = 16;
/// The longest name in wire form, in bytes.
pub const MAX_NAME: usize = 255;
/// The length of the header.
pub const HEADER: usize = 12;
/// The flag bit `TC`: the answer was cut to fit.
const FLAG_TRUNCATED: u16 = 0x0200;

/// Appends `name` in wire form, without compression. A final dot is allowed, and the
/// empty name is the root. Fails for an empty label, a label over 63 bytes, and a name
/// over 255 bytes.
pub fn write_name(out: &mut Vec<u8>, name: &str) -> Result<(), Error> {
    let start = out.len();
    if push_name(out, name.strip_suffix('.').unwrap_or(name)).is_none() {
        out.truncate(start);
        let shown = crate::error::printable(name, 80);
        return Err(Error::unexpected(format!("`{shown}` is no DNS name.")));
    }
    Ok(())
}

/// Appends the labels of `name` and the root label. Returns `None` for a bad name,
/// with a part of it appended.
fn push_name(out: &mut Vec<u8>, name: &str) -> Option<()> {
    let start = out.len();
    if !name.is_empty() {
        for label in name.split('.') {
            let length = u8::try_from(label.len()).ok()?;
            (1..=63).contains(&length).then_some(())?;
            out.push(length);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    (out.len() - start <= MAX_NAME).then_some(())
}

/// A query for the records of type `kind` at `name`, class `IN`, with one question.
/// `recurse` sets the flag that asks a resolver to find the answer elsewhere.
pub fn query(id: u16, name: &str, kind: u16, recurse: bool) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(HEADER + name.len() + 6);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(u16::from(recurse) << 8).to_be_bytes());
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    write_name(&mut out, name)?;
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

/// Whether the message has the flag `TC`. A message shorter than a header has not.
pub fn is_truncated(packet: &[u8]) -> bool {
    packet
        .get(2..4)
        .is_some_and(|flags| u16::from_be_bytes([flags[0], flags[1]]) & FLAG_TRUNCATED != 0)
}

/// The data of a record, for the types that the client reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Data {
    /// An IPv4 address.
    A(Ipv4Addr),
    /// An IPv6 address.
    Aaaa(Ipv6Addr),
    /// The name in an `NS` or a `CNAME` record.
    Name(String),
    /// The strings of a `TXT` record, joined.
    Txt(Vec<u8>),
    /// The raw data of any other type.
    Other(Vec<u8>),
}

/// One resource record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The owner, in lower case, without a final dot.
    pub name: String,
    /// The type.
    pub kind: u16,
    /// The class.
    pub class: u16,
    /// The data.
    pub data: Data,
    /// Where the record starts in the message.
    pub start: usize,
}

/// A message, as far as the client reads one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    /// The identifier.
    pub id: u16,
    /// The response code, 0 for no error. The four bits of the header.
    pub rcode: u8,
    /// The flag `TC`.
    pub truncated: bool,
    /// The operation: 0 for a question, 5 for an update.
    pub opcode: u8,
    /// The name and the type of the first question.
    pub question: Option<(String, u16)>,
    /// The records of the answer, authority and additional sections, in this order.
    pub records: Vec<Record>,
    /// How many of `records` belong to the answer section.
    pub answer_count: usize,
}

impl Message {
    /// The records of the answer section.
    pub fn answers(&self) -> &[Record] {
        &self.records[..self.answer_count.min(self.records.len())]
    }
}

/// A reader over the bytes of a message.
struct Reader<'a> {
    packet: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(count)?;
        let bytes = self.packet.get(self.at..end)?;
        self.at = end;
        Some(bytes)
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn name(&mut self) -> Option<String> {
        let (name, end) = read_name(self.packet, self.at)?;
        self.at = end;
        Some(name)
    }
}

/// Reads the name at `at`. Returns the name in lower case without a final dot, and the
/// offset after the name in the record that holds it. A pointer must point backwards.
/// Returns `None` for a name that leaves the message, has more than [`MAX_POINTERS`]
/// pointers or [`MAX_NAME`] bytes, or has a label that is not printable ASCII.
pub fn read_name(packet: &[u8], at: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut at = at;
    let mut end = None;
    let mut pointers = 0;
    let mut length = 1;
    loop {
        let first = *packet.get(at)?;
        match first >> 6 {
            0b11 => {
                let second = *packet.get(at + 1)?;
                let target = usize::from(first & 0x3f) << 8 | usize::from(second);
                pointers += 1;
                if pointers > MAX_POINTERS || target >= at {
                    return None;
                }
                end.get_or_insert(at + 2);
                at = target;
            }
            0b00 if first == 0 => return Some((name, end.unwrap_or(at + 1))),
            0b00 => {
                let label = packet.get(at + 1..at + 1 + usize::from(first))?;
                length += 1 + label.len();
                let printable = label.iter().all(|byte| byte.is_ascii_graphic() && *byte != b'.');
                if length > MAX_NAME || !printable {
                    return None;
                }
                if !name.is_empty() {
                    name.push('.');
                }
                name.extend(label.iter().map(|byte| char::from(byte.to_ascii_lowercase())));
                at += 1 + label.len();
            }
            _ => return None,
        }
    }
}

/// The strings of the data of a `TXT` record, joined.
fn text(data: &[u8]) -> Option<Vec<u8>> {
    let mut joined = Vec::with_capacity(data.len());
    let mut rest = data;
    while let Some((length, tail)) = rest.split_first() {
        let string = tail.get(..usize::from(*length))?;
        joined.extend_from_slice(string);
        rest = &tail[string.len()..];
    }
    Some(joined)
}

fn record(reader: &mut Reader<'_>) -> Option<Record> {
    let start = reader.at;
    let name = reader.name()?;
    let kind = reader.u16()?;
    let class = reader.u16()?;
    let _ttl = reader.take(4)?;
    let length = usize::from(reader.u16()?);
    let data_at = reader.at;
    let raw = reader.take(length)?;
    let data = match kind {
        TYPE_A => Data::A(Ipv4Addr::from(<[u8; 4]>::try_from(raw).ok()?)),
        TYPE_AAAA => Data::Aaaa(Ipv6Addr::from(<[u8; 16]>::try_from(raw).ok()?)),
        TYPE_NS | TYPE_CNAME => {
            let (target, end) = read_name(reader.packet, data_at)?;
            if end != data_at + length {
                return None;
            }
            Data::Name(target)
        }
        TYPE_TXT => Data::Txt(text(raw)?),
        _ => Data::Other(raw.to_vec()),
    };
    Some(Record { name, kind, class, data, start })
}

/// Reads a message. Returns `None` when it breaks the format. Records after the first
/// [`MAX_RECORDS`] are not read.
pub fn parse(packet: &[u8]) -> Option<Message> {
    let mut reader = Reader { packet, at: 0 };
    let id = reader.u16()?;
    let flags = reader.u16()?;
    let counts = [reader.u16()?, reader.u16()?, reader.u16()?, reader.u16()?];
    let mut message = Message {
        id,
        rcode: (flags & 0x000f) as u8,
        truncated: flags & FLAG_TRUNCATED != 0,
        opcode: ((flags >> 11) & 0x0f) as u8,
        ..Message::default()
    };
    for index in 0..counts[0] {
        let name = reader.name()?;
        let kind = reader.u16()?;
        let _class = reader.u16()?;
        if index == 0 {
            message.question = Some((name, kind));
        }
    }
    let answers = usize::from(counts[1]);
    let total = answers + usize::from(counts[2]) + usize::from(counts[3]);
    for _ in 0..total.min(MAX_RECORDS) {
        message.records.push(record(&mut reader)?);
    }
    message.answer_count = answers.min(message.records.len());
    Some(message)
}

/// The usual name of a response code, for a diagnostic.
pub fn rcode_name(rcode: u8) -> String {
    let name = match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        other => return format!("code {other}"),
    };
    name.to_owned()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// An answer to `a.example.org TXT` with two answers: the second owner is a pointer
    /// to the question, the first is a CNAME whose target ends in a pointer.
    fn answer() -> Vec<u8> {
        let mut packet = query(7, "a.Example.org", TYPE_TXT, true).unwrap();
        packet[2] = 0x81;
        packet[7] = 2;
        // a.example.org CNAME b.example.org (b + pointer to "example.org" at 14).
        packet.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 4, 1, b'b', 0xc0, 14]);
        // b.example.org (pointer to the CNAME data at 43) TXT "he" "llo".
        packet.extend_from_slice(&[0xc0, 43, 0, 16, 0, 1, 0, 0, 0, 60, 0, 7]);
        packet.extend_from_slice(&[2, b'h', b'e', 3, b'l', b'l', b'o']);
        packet
    }

    #[test]
    fn a_query_has_one_question_and_the_recursion_flag() {
        let packet = query(0x1234, "example.org.", TYPE_SOA, true).unwrap();
        let head = [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7];
        assert_eq!(packet[..13], head);
        assert_eq!(packet[packet.len() - 5..], [0, 0, 6, 0, 1]);
        assert_eq!(
            query(1, "", TYPE_NS, false).unwrap()[2..],
            [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1]
        );
        let parsed = parse(&packet).unwrap();
        assert_eq!(parsed.question, Some(("example.org".to_owned(), TYPE_SOA)));
        assert!(parsed.records.is_empty() && !parsed.truncated);
    }

    #[test]
    fn names_have_bounded_labels_and_length() {
        let mut out = vec![9];
        for bad in ["a..b", ".a", &"a".repeat(64), &["abcdefg"; 32].join(".")] {
            assert!(write_name(&mut out, bad).is_err(), "{bad}");
            assert_eq!(out, [9]);
        }
        let longest = [&"a".repeat(63)[..]; 3].join(".") + "." + &"b".repeat(61);
        write_name(&mut out, &longest).unwrap();
        assert_eq!(out.len(), 1 + 255);
        assert_eq!(read_name(&out, 1).unwrap(), (longest, 256));
    }

    #[test]
    fn an_answer_with_compression_is_read() {
        let message = parse(&answer()).unwrap();
        assert_eq!((message.id, message.rcode, message.answer_count), (7, 0, 2));
        assert_eq!(message.question, Some(("a.example.org".to_owned(), TYPE_TXT)));
        let [alias, text] = message.answers() else { panic!("two answers") };
        assert_eq!((alias.name.as_str(), alias.kind), ("a.example.org", TYPE_CNAME));
        assert_eq!(alias.data, Data::Name("b.example.org".to_owned()));
        assert_eq!((text.name.as_str(), text.kind), ("b.example.org", TYPE_TXT));
        assert_eq!(text.data, Data::Txt(b"hello".to_vec()));
        assert_eq!(text.start, 47);
    }

    #[test]
    fn addresses_and_truncation_are_read() {
        let mut packet = query(1, "ns.example.org", TYPE_A, false).unwrap();
        packet[2] = 0x86;
        packet[3] = 0x03;
        packet[7] = 1;
        packet[11] = 1;
        packet.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 192, 0, 2, 1]);
        packet.extend_from_slice(&[0xc0, 12, 0, 28, 0, 1, 0, 0, 0, 1, 0, 16]);
        packet.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        let message = parse(&packet).unwrap();
        assert!(message.truncated && is_truncated(&packet) && !is_truncated(&[1, 2]));
        assert_eq!((message.rcode, rcode_name(message.rcode).as_str()), (3, "NXDOMAIN"));
        assert_eq!(message.answers().len(), 1);
        assert_eq!(message.records[0].data, Data::A(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(message.records[1].data, Data::Aaaa(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn every_prefix_and_every_flipped_byte_is_read_without_a_panic() {
        let packet = answer();
        for length in 0..packet.len() {
            assert_eq!(parse(&packet[..length]), None, "prefix of {length}");
        }
        for index in 0..packet.len() {
            for value in [0x00, 0x3f, 0x40, 0x80, 0xc0, 0xff] {
                let mut changed = packet.clone();
                changed[index] = value;
                let _ = parse(&changed);
            }
        }
    }

    #[test]
    fn hostile_names_end() {
        let header = |answers: u8| vec![0, 1, 0x80, 0, 0, 0, 0, answers, 0, 0, 0, 0];
        // A pointer to itself, and a pointer forwards.
        for target in [12, 14] {
            let mut packet = header(1);
            packet.extend_from_slice(&[0xc0, target, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 1, 2, 3, 4]);
            assert_eq!(parse(&packet), None);
        }
        // A chain of backward pointers longer than the bound.
        let mut packet = header(1);
        packet.push(0);
        for index in 0..=MAX_POINTERS {
            let target = if index == 0 { 12 } else { 13 + 2 * (index - 1) };
            packet.extend_from_slice(&[0xc0, target as u8]);
        }
        let last = packet.len() - 2;
        assert_eq!(read_name(&packet, last), None);
        assert_eq!(read_name(&packet, last - 2).unwrap().0, "");
        // Reserved label types, a label with a dot, a label that is not ASCII.
        for label in [&[0x40, b'a'][..], &[0x80, b'a'], &[1, b'.'], &[1, 0xe4], &[1, b' ']] {
            let mut packet = header(0);
            packet.extend_from_slice(label);
            packet.push(0);
            assert_eq!(read_name(&packet, 12), None, "{label:?}");
        }
        // A name over 255 bytes is refused.
        let mut long = header(0);
        for _ in 0..5 {
            long.push(63);
            long.extend_from_slice(&[b'a'; 63]);
        }
        long.push(0);
        assert_eq!(read_name(&long, 12), None);
    }

    #[test]
    fn a_message_that_claims_many_records_is_read_up_to_the_bound() {
        let mut packet = vec![0, 1, 0x80, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(parse(&packet), None);
        for _ in 0..100 {
            packet.extend_from_slice(&[0, 0, 16, 0, 1, 0, 0, 0, 0, 0, 2, 1, b'x']);
        }
        let message = parse(&packet).unwrap();
        assert_eq!((message.records.len(), message.answer_count), (MAX_RECORDS, MAX_RECORDS));
        // A text string that runs past its record, and an address of the wrong size.
        let bad_text =
            [0, 1, 0x80, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 16, 0, 1, 0, 0, 0, 0, 0, 2, 5, b'x'];
        assert_eq!(parse(&bad_text), None);
        let bad_address =
            [0, 1, 0x80, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 2, 5, 5];
        assert_eq!(parse(&bad_address), None);
    }
}
