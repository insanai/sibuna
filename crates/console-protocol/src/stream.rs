//! Typed reading straight from the pull reader, for the one decoder on a hot path: peer
//! snapshots arrive every second from every peer. Building the value tree first costs
//! more than the decoding itself, so [`crate::StatsSnapshot::from_json`] reads events
//! directly, with exactly the rules of [`crate::codec`]; the tests compare the two paths
//! on the golden, differential and fuzz corpora.
//!
//! Every reader takes the value's first event, already read, so that optional values and
//! array ends are recognised without peeking ahead.

use sibuna_json::{Event, EventKind, Limits, PullReader};

use crate::codec::{
    DecodeError, DecodeErrorKind, Path, WireEnum, enum_from_text, zig_parse_f64, zig_slice_to_int,
};

/// A pull reader whose errors are decode errors.
pub(crate) struct Stream<'a> {
    reader: PullReader<'a>,
}

impl<'a> Stream<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Stream<'a> {
        Stream { reader: PullReader::with_limits(input, &Limits::default()) }
    }

    /// Reads the next event; the end of the document where a value is due is an error.
    pub(crate) fn event(&mut self, path: Path<'_>) -> Result<Event<'a>, DecodeError> {
        match self.reader.next() {
            Ok(Some(event)) => Ok(event),
            Ok(None) => Err(DecodeError::new(path, DecodeErrorKind::Missing)),
            Err(error) => Err(DecodeError::new(Path::Root, DecodeErrorKind::Syntax(error))),
        }
    }

    /// Checks that nothing but whitespace follows the document.
    pub(crate) fn finish(mut self) -> Result<(), DecodeError> {
        match self.reader.next() {
            Ok(None) => Ok(()),
            Ok(Some(_)) => {
                Err(DecodeError::new(Path::Root, DecodeErrorKind::Invalid("trailing data")))
            }
            Err(error) => Err(DecodeError::new(Path::Root, DecodeErrorKind::Syntax(error))),
        }
    }

    /// Reads the object that `first` opens, whose keys are `names`, calling `field` with
    /// each member's index; returns the set of members read as bits. Unknown and repeated
    /// keys are refused.
    pub(crate) fn object(
        &mut self,
        first: Event<'a>,
        path: Path<'_>,
        names: &[&str],
        mut field: impl FnMut(&mut Stream<'a>, usize, Path<'_>) -> Result<(), DecodeError>,
    ) -> Result<u64, DecodeError> {
        if first != Event::BeginObject {
            return Err(wrong_type(path, "an object", &first));
        }
        let mut seen = 0u64;
        let mut hint = 0;
        loop {
            let key = match self.event(path)? {
                Event::EndObject => return Ok(seen),
                Event::Key(key) => key,
                _ => {
                    return Err(DecodeError::new(
                        path,
                        DecodeErrorKind::Invalid("expected a key"),
                    ));
                }
            };
            let index = match names.get(hint) {
                Some(name) if *name == key => hint,
                _ => names.iter().position(|name| *name == key).ok_or_else(|| {
                    DecodeError::new(path.key(&key), DecodeErrorKind::UnknownKey)
                })?,
            };
            if seen & (1 << index) != 0 {
                let rule = DecodeErrorKind::Invalid("repeated key");
                return Err(DecodeError::new(path.key(&key), rule));
            }
            seen |= 1 << index;
            hint = index + 1;
            field(self, index, path.key(&key))?;
        }
    }

    /// Reads the array that `first` opens, of exactly `N` elements read by `element`.
    pub(crate) fn array<T: Default, const N: usize>(
        &mut self,
        first: Event<'a>,
        path: Path<'_>,
        mut element: impl FnMut(&mut Stream<'a>, Event<'a>, Path<'_>) -> Result<T, DecodeError>,
    ) -> Result<[T; N], DecodeError> {
        if first != Event::BeginArray {
            return Err(wrong_type(path, "an array", &first));
        }
        let wrong_length = || DecodeError::new(path, DecodeErrorKind::WrongLength { expected: N });
        let mut result: [T; N] = std::array::from_fn(|_| T::default());
        for (index, slot) in result.iter_mut().enumerate() {
            match self.event(path)? {
                Event::EndArray => return Err(wrong_length()),
                event => *slot = element(self, event, path.index(index))?,
            }
        }
        match self.event(path)? {
            Event::EndArray => Ok(result),
            _ => Err(wrong_length()),
        }
    }

    /// Reads a text value that `first` starts, as Zig read a `[]const u8`: a string, or an
    /// array of byte values that must form UTF-8.
    pub(crate) fn text(
        &mut self,
        first: Event<'a>,
        path: Path<'_>,
    ) -> Result<String, DecodeError> {
        match first {
            Event::String(text) => Ok(text.into_owned()),
            Event::BeginArray => {
                let mut bytes = Vec::new();
                loop {
                    match self.event(path)? {
                        Event::EndArray => break,
                        event => bytes.push(int::<u8>(&event, path.index(bytes.len()))?),
                    }
                }
                String::from_utf8(bytes).map_err(|_| {
                    DecodeError::new(path, DecodeErrorKind::Invalid("the bytes are not UTF-8"))
                })
            }
            other => Err(wrong_type(path, "a string", &other)),
        }
    }

    /// Reads `N` bytes that `first` starts: an array of byte values or a string of exactly
    /// `N` bytes.
    pub(crate) fn byte_array<const N: usize>(
        &mut self,
        first: Event<'a>,
        path: Path<'_>,
    ) -> Result<[u8; N], DecodeError> {
        if let Event::String(text) = &first {
            return <[u8; N]>::try_from(text.as_bytes()).map_err(|_| {
                DecodeError::new(path, DecodeErrorKind::WrongLength { expected: N })
            });
        }
        self.array(first, path, |_, event, path| int::<u8>(&event, path))
    }
}

/// Reads an integer: a number or a string holding one, with Zig's `sliceToInt` rules.
pub(crate) fn int<T: TryFrom<i128>>(event: &Event<'_>, path: Path<'_>) -> Result<T, DecodeError> {
    let value = match event {
        Event::Number(number) => zig_slice_to_int(number.as_str()),
        Event::String(text) => zig_slice_to_int(text),
        other => return Err(wrong_type(path, "an integer", other)),
    };
    value
        .and_then(|value| T::try_from(value).ok())
        .ok_or_else(|| DecodeError::new(path, DecodeErrorKind::InvalidNumber))
}

/// Reads an integer or `null`.
pub(crate) fn optional_int<T: TryFrom<i128>>(
    event: &Event<'_>,
    path: Path<'_>,
) -> Result<Option<T>, DecodeError> {
    if *event == Event::Null { Ok(None) } else { int(event, path).map(Some) }
}

/// Reads a finite number: a number or a string, with Zig's `parseFloat` syntax.
pub(crate) fn float(event: &Event<'_>, path: Path<'_>) -> Result<f64, DecodeError> {
    let value = match event {
        Event::Number(number) => number.as_f64().ok(),
        Event::String(text) => zig_parse_f64(text),
        other => return Err(wrong_type(path, "a number", other)),
    };
    value.ok_or_else(|| DecodeError::new(path, DecodeErrorKind::InvalidNumber))
}

/// Reads `true` or `false`.
pub(crate) fn boolean(event: &Event<'_>, path: Path<'_>) -> Result<bool, DecodeError> {
    match event {
        Event::Bool(flag) => Ok(*flag),
        other => Err(wrong_type(path, "a boolean", other)),
    }
}

/// Reads an enumeration by name or ordinal, or `null`.
pub(crate) fn optional_enum<T: WireEnum>(
    event: &Event<'_>,
    path: Path<'_>,
) -> Result<Option<T>, DecodeError> {
    let text = match event {
        Event::Null => return Ok(None),
        Event::Number(number) => number.as_str(),
        Event::String(text) => text,
        other => return Err(wrong_type(path, "a name", other)),
    };
    enum_from_text::<T>(text)
        .map(Some)
        .ok_or_else(|| DecodeError::new(path, DecodeErrorKind::UnknownName))
}

fn wrong_type(path: Path<'_>, expected: &'static str, found: &Event<'_>) -> DecodeError {
    let found = match found.kind() {
        EventKind::BeginObject => "an object",
        EventKind::BeginArray => "an array",
        EventKind::String => "a string",
        EventKind::Number => "a number",
        EventKind::Bool => "a boolean",
        EventKind::Null => "null",
        EventKind::EndObject | EventKind::EndArray | EventKind::Key => "the end of a container",
    };
    DecodeError::new(path, DecodeErrorKind::WrongType { expected, found })
}
