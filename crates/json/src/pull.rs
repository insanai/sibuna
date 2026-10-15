//! The streaming pull reader, which holds the crate's one implementation of the grammar.
//!
//! A [`PullReader`] hands out one [`Event`] per call to [`PullReader::next`], in document
//! order, and checks every byte as it passes it. A typed reader can therefore check a key
//! or a value the moment it arrives and stop at the first problem in document order: an
//! unknown key early in a file is reported before a syntax error later in it. The tree
//! parser ([`parse`](crate::parse)) is a loop over these events, so both report the same
//! errors at the same offsets.
//!
//! The reader keeps one flag per open container instead of recursing, so its stack is
//! bounded by [`Limits::max_depth`] and deep input cannot overflow the thread's stack.

mod string;

use std::borrow::Cow;

use crate::error::{Error, ErrorKind};
use crate::limits::Limits;
use crate::number::{self, Number};
use crate::swar;

/// One step through a JSON document.
///
/// An object is `BeginObject`, then a `Key` and the events of its value for each member,
/// then `EndObject`. An array is `BeginArray`, the events of its elements, then
/// `EndArray`. Strings without escapes and all numbers borrow the input.
#[derive(Clone, Debug, PartialEq)]
pub enum Event<'a> {
    /// `{`.
    BeginObject,
    /// `}`.
    EndObject,
    /// `[`.
    BeginArray,
    /// `]`.
    EndArray,
    /// An object key, decoded.
    Key(Cow<'a, str>),
    /// A string value, decoded.
    String(Cow<'a, str>),
    /// A number, as its source text.
    Number(Number<'a>),
    /// `true` or `false`.
    Bool(bool),
    /// `null`.
    Null,
}

/// The kind of an [`Event`], as [`PullReader::peek`] reports it before reading the event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EventKind {
    /// `{`.
    BeginObject,
    /// `}`.
    EndObject,
    /// `[`.
    BeginArray,
    /// `]`.
    EndArray,
    /// An object key.
    Key,
    /// A string value.
    String,
    /// A number.
    Number,
    /// `true` or `false`.
    Bool,
    /// `null`.
    Null,
}

impl Event<'_> {
    /// Returns the kind of this event.
    pub fn kind(&self) -> EventKind {
        match self {
            Event::BeginObject => EventKind::BeginObject,
            Event::EndObject => EventKind::EndObject,
            Event::BeginArray => EventKind::BeginArray,
            Event::EndArray => EventKind::EndArray,
            Event::Key(_) => EventKind::Key,
            Event::String(_) => EventKind::String,
            Event::Number(_) => EventKind::Number,
            Event::Bool(_) => EventKind::Bool,
            Event::Null => EventKind::Null,
        }
    }
}

/// What the grammar allows next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// A value: at the start, after `:`, or after `,` in an array.
    Value,
    /// A key was read, so `:` comes next.
    AfterKey,
    /// A value was read, so `,`, a closing bracket or the end of the document comes next.
    AfterValue,
    /// `{` was read, so a key or `}` comes next.
    ObjectStart,
    /// `,` was read inside an object, so a key comes next.
    ObjectNext,
    /// `[` was read, so a value or `]` comes next.
    ArrayStart,
}

/// What [`PullReader::step`] read. The text of a key, string or number waits in the
/// reader until it is taken; an error waits in its failure slot.
///
/// Returning one byte keeps the per-event result in a register. An `Event` with its error
/// is 40 bytes, which goes back through memory and costs a store-forwarding stall on
/// every event of the tree parser's loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    BeginObject,
    EndObject,
    BeginArray,
    EndArray,
    Key,
    String,
    Number,
    True,
    False,
    Null,
    /// The document is complete.
    End,
    /// The reader failed; the error is in `PullReader::failure`.
    Failed,
}

/// Where the next event starts, once whitespace and separators are behind the reader.
enum Position {
    /// A value starts here.
    Value,
    /// A key should start here.
    Key,
    /// This closing bracket ends a container.
    Close(u8),
    /// The document is complete and only whitespace followed it.
    End,
}

/// Reads a JSON document one event at a time.
///
/// The grammar, the limits and the error kinds are those of [`parse`](crate::parse), with
/// one exception: duplicate keys are not detected, because that needs every key of an
/// object at once; callers that keep keys check them. After an error every call returns
/// the same error again.
///
/// ```
/// use sibuna_json::{Event, PullReader};
///
/// let mut reader = PullReader::new(br#"{"name": "office", "tags": [1, 2]}"#);
/// assert_eq!(reader.next().unwrap(), Some(Event::BeginObject));
/// assert_eq!(reader.next().unwrap(), Some(Event::Key("name".into())));
/// assert_eq!(reader.next().unwrap(), Some(Event::String("office".into())));
/// assert_eq!(reader.next().unwrap(), Some(Event::Key("tags".into())));
/// assert!(reader.skip_value().unwrap());
/// assert_eq!(reader.next().unwrap(), Some(Event::EndObject));
/// assert_eq!(reader.next().unwrap(), None);
/// ```
#[derive(Debug)]
pub struct PullReader<'a> {
    input: &'a [u8],
    /// The input as text when all of it is valid UTF-8, checked once up front; `None`
    /// sends every string run through its own check, so that the first invalid sequence
    /// is reported where the reader meets it.
    valid_text: Option<&'a str>,
    /// The offset of the next unread byte.
    pos: usize,
    state: State,
    /// One flag per open container, innermost last: true for an object.
    containers: Vec<bool>,
    limits: Limits,
    value_count: usize,
    /// The offset of the first byte of the last event read.
    event_offset: usize,
    /// The text of the last key or string read, until it is taken.
    text: Cow<'a, str>,
    /// The text of the last number read.
    number: &'a str,
    /// The error that stopped the reader, returned again by every later call.
    failure: Option<Error>,
}

impl<'a> PullReader<'a> {
    /// Starts reading `input` with the default [`Limits`]. Nothing is read yet.
    pub fn new(input: &'a [u8]) -> PullReader<'a> {
        PullReader::with_limits(input, &Limits::default())
    }

    /// Starts reading `input` with `limits`. An input longer than
    /// [`Limits::max_input_bytes`] makes the first call fail with
    /// [`ErrorKind::InputTooLarge`].
    pub fn with_limits(input: &'a [u8], limits: &Limits) -> PullReader<'a> {
        let failure = (input.len() > limits.max_input_bytes)
            .then(|| Error::at(ErrorKind::InputTooLarge, input, limits.max_input_bytes));
        PullReader {
            input,
            valid_text: std::str::from_utf8(input).ok(),
            pos: 0,
            state: State::Value,
            containers: Vec::new(),
            limits: *limits,
            value_count: 0,
            event_offset: 0,
            text: Cow::Borrowed(""),
            number: "",
            failure,
        }
    }

    /// Reads the next event; `None` once the document is complete and only whitespace
    /// follows it. Strings borrow the input unless they hold escapes.
    ///
    /// # Errors
    ///
    /// The first problem in document order, with its location; then the same error on
    /// every later call.
    #[expect(
        clippy::should_implement_trait,
        reason = "Zig's `Scanner.next`; `Result<Option<_>>` lets callers use `?`"
    )]
    pub fn next(&mut self) -> Result<Option<Event<'a>>, Error> {
        Ok(Some(match self.step(true) {
            Step::BeginObject => Event::BeginObject,
            Step::EndObject => Event::EndObject,
            Step::BeginArray => Event::BeginArray,
            Step::EndArray => Event::EndArray,
            Step::Key => Event::Key(self.take_text()),
            Step::String => Event::String(self.take_text()),
            Step::Number => Event::Number(self.take_number()),
            Step::True => Event::Bool(true),
            Step::False => Event::Bool(false),
            Step::Null => Event::Null,
            Step::End => return Ok(None),
            Step::Failed => return Err(self.failure()),
        }))
    }

    /// Returns the kind of the next event without reading it; `None` at the end of the
    /// document.
    ///
    /// Like Zig's `peekNextTokenType`, it reads the whitespace, `,` and `:` before the
    /// event and then decides from the event's first byte alone: a malformed token, or a
    /// closing bracket that does not match the open container, is reported by the
    /// following [`PullReader::next`]. [`PullReader::offset`] then points at the event.
    ///
    /// # Errors
    ///
    /// The first problem before the event, or at its first byte.
    pub fn peek(&mut self) -> Result<Option<EventKind>, Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        let result = self.peek_kind();
        if let Err(error) = result {
            self.failure = Some(error);
        }
        result
    }

    /// Reads and discards the next value: a scalar, or an array or object with everything
    /// in it, checked as strictly as [`PullReader::next`] checks it but without decoding
    /// strings. Returns false, reading nothing but whitespace and separators, when no
    /// value comes next (a key, a closing bracket or the end of the document).
    ///
    /// # Errors
    ///
    /// The first problem in the skipped value, or before it.
    pub fn skip_value(&mut self) -> Result<bool, Error> {
        if let Some(EventKind::Key | EventKind::EndObject | EventKind::EndArray) | None =
            self.peek()?
        {
            return Ok(false);
        }
        let depth = self.containers.len();
        // Every event takes at least one byte, so this ends within the input.
        loop {
            if self.step(false) == Step::Failed {
                return Err(self.failure());
            }
            if self.containers.len() <= depth {
                return Ok(true);
            }
        }
    }

    /// Returns the offset of the next unread byte: just past the last event read, or at
    /// the next event after [`PullReader::peek`].
    pub fn offset(&self) -> usize {
        self.pos
    }

    /// Returns the offset of the first byte of the last event read (its quote, digit,
    /// letter or bracket); 0 before the first.
    pub fn event_offset(&self) -> usize {
        self.event_offset
    }

    /// Returns the number of arrays and objects open at the current position.
    pub fn depth(&self) -> usize {
        self.containers.len()
    }

    /// Reads the next event and returns its kind, leaving its text for `take_text` or
    /// `take_number` and an error for `failure`; `decode` false skips building the text of
    /// strings with escapes (they come back empty).
    #[inline(always)]
    pub(crate) fn step(&mut self, decode: bool) -> Step {
        if self.failure.is_some() {
            return Step::Failed;
        }
        let result = match self.settle() {
            Ok(Position::Value) => self.value(decode),
            Ok(Position::Key) => self.key(decode),
            Ok(Position::Close(bracket)) => self.close(bracket),
            Ok(Position::End) => return Step::End,
            Err(error) => Err(error),
        };
        result.unwrap_or_else(|error| {
            self.failure = Some(error);
            Step::Failed
        })
    }

    /// Takes the text of the key or string `step` just read.
    pub(crate) fn take_text(&mut self) -> Cow<'a, str> {
        std::mem::take(&mut self.text)
    }

    /// Returns the number `step` just read.
    pub(crate) fn take_number(&self) -> Number<'a> {
        Number::from_scanned(self.number)
    }

    /// Returns the error that stopped the reader, after `step` returned `Step::Failed`.
    pub(crate) fn failure(&self) -> Error {
        // `step` stores the error before it returns `Step::Failed`, so the default is never
        // used; it keeps this path free of panics all the same.
        self.failure.unwrap_or_else(|| Error::at(ErrorKind::UnexpectedEnd, self.input, self.pos))
    }

    fn peek_kind(&mut self) -> Result<Option<EventKind>, Error> {
        let kind = match self.settle()? {
            Position::End => return Ok(None),
            Position::Close(b'}') => EventKind::EndObject,
            Position::Close(_) => EventKind::EndArray,
            Position::Key if self.byte() == Some(b'"') => EventKind::Key,
            Position::Key => return Err(self.error_or_end(ErrorKind::ExpectedKey, self.pos)),
            Position::Value => {
                self.check_value_limit()?;
                match self.byte() {
                    Some(b'{') => EventKind::BeginObject,
                    Some(b'[') => EventKind::BeginArray,
                    Some(b'"') => EventKind::String,
                    Some(b'-' | b'0'..=b'9') => EventKind::Number,
                    Some(b't' | b'f') => EventKind::Bool,
                    Some(b'n') => EventKind::Null,
                    _ => return Err(self.error_or_end(ErrorKind::ExpectedValue, self.pos)),
                }
            }
        };
        Ok(Some(kind))
    }

    /// Reads whitespace and separators up to the start of the next event.
    #[inline(always)]
    fn settle(&mut self) -> Result<Position, Error> {
        loop {
            self.skip_whitespace();
            match self.state {
                State::Value => return Ok(Position::Value),
                State::ObjectNext => return Ok(Position::Key),
                State::ObjectStart if self.byte() == Some(b'}') => {
                    return Ok(Position::Close(b'}'));
                }
                State::ObjectStart => return Ok(Position::Key),
                State::ArrayStart if self.byte() == Some(b']') => {
                    return Ok(Position::Close(b']'));
                }
                State::ArrayStart => self.state = State::Value,
                State::AfterKey if self.byte() == Some(b':') => {
                    self.pos += 1;
                    self.state = State::Value;
                }
                State::AfterKey => {
                    return Err(self.error_or_end(ErrorKind::ExpectedColon, self.pos));
                }
                State::AfterValue => match (self.byte(), self.containers.last()) {
                    (None, None) => return Ok(Position::End),
                    (Some(_), None) => {
                        return Err(self.error(ErrorKind::TrailingCharacters, self.pos));
                    }
                    (Some(b','), Some(&object)) => {
                        self.pos += 1;
                        self.state = if object { State::ObjectNext } else { State::Value };
                    }
                    (Some(bracket @ (b']' | b'}')), Some(_)) => {
                        return Ok(Position::Close(bracket));
                    }
                    (_, Some(&object)) => {
                        let kind = if object {
                            ErrorKind::ExpectedCommaOrBrace
                        } else {
                            ErrorKind::ExpectedCommaOrBracket
                        };
                        return Err(self.error_or_end(kind, self.pos));
                    }
                },
            }
        }
    }

    /// Reads the value that starts at the current position.
    #[inline(always)]
    fn value(&mut self, decode: bool) -> Result<Step, Error> {
        let start = self.pos;
        self.check_value_limit()?;
        self.value_count += 1;
        self.event_offset = start;
        let Some(byte) = self.byte() else {
            return Err(self.error(ErrorKind::UnexpectedEnd, start));
        };
        let event = match byte {
            b'{' | b'[' => {
                if self.containers.len() >= self.limits.max_depth {
                    return Err(self.error(ErrorKind::DepthLimit, start));
                }
                let object = byte == b'{';
                self.containers.push(object);
                self.pos += 1;
                self.state = if object { State::ObjectStart } else { State::ArrayStart };
                return Ok(if object { Step::BeginObject } else { Step::BeginArray });
            }
            b'"' => {
                self.text = self.string(decode)?;
                Step::String
            }
            b'-' | b'0'..=b'9' => {
                self.number = self.number()?;
                Step::Number
            }
            b't' => self.literal("true", Step::True)?,
            b'f' => self.literal("false", Step::False)?,
            b'n' => self.literal("null", Step::Null)?,
            _ => return Err(self.error(ErrorKind::ExpectedValue, start)),
        };
        self.state = State::AfterValue;
        Ok(event)
    }

    /// Reads the key that should start at the current position.
    #[inline(always)]
    fn key(&mut self, decode: bool) -> Result<Step, Error> {
        let start = self.pos;
        if self.byte() != Some(b'"') {
            return Err(self.error_or_end(ErrorKind::ExpectedKey, start));
        }
        self.event_offset = start;
        self.text = self.string(decode)?;
        self.state = State::AfterKey;
        Ok(Step::Key)
    }

    /// Reads the closing bracket at the current position, which must match the innermost
    /// open container.
    fn close(&mut self, bracket: u8) -> Result<Step, Error> {
        let object = bracket == b'}';
        if self.containers.last() != Some(&object) {
            let kind = if object {
                ErrorKind::ExpectedCommaOrBracket
            } else {
                ErrorKind::ExpectedCommaOrBrace
            };
            return Err(self.error(kind, self.pos));
        }
        self.containers.pop();
        self.event_offset = self.pos;
        self.pos += 1;
        self.state = State::AfterValue;
        Ok(if object { Step::EndObject } else { Step::EndArray })
    }

    fn check_value_limit(&self) -> Result<(), Error> {
        if self.value_count >= self.limits.max_values {
            return Err(self.error(ErrorKind::ValueLimit, self.pos));
        }
        Ok(())
    }

    /// Reads `word`, whose first byte is known to match, and returns `step`.
    fn literal(&mut self, word: &str, step: Step) -> Result<Step, Error> {
        let rest = self.input.get(self.pos..).unwrap_or_default();
        let matched = rest.iter().zip(word.as_bytes()).take_while(|(a, b)| a == b).count();
        if matched < word.len() {
            return Err(self.error_or_end(ErrorKind::InvalidLiteral, self.pos + matched));
        }
        self.pos += word.len();
        Ok(step)
    }

    /// Reads the number at the current position and returns its text.
    fn number(&mut self) -> Result<&'a str, Error> {
        let start = self.pos;
        let end = number::scan(self.input, start)
            .map_err(|offset| self.error_or_end(ErrorKind::InvalidNumber, offset))?;
        self.pos = end;
        // The number grammar admits only ASCII, so the text is always valid UTF-8.
        let text = match self.valid_text {
            Some(text) => text.get(start..end),
            None => self.input.get(start..end).and_then(|bytes| std::str::from_utf8(bytes).ok()),
        };
        Ok(text.unwrap_or_default())
    }

    #[inline(always)]
    fn skip_whitespace(&mut self) {
        self.pos += swar::whitespace_len(self.input.get(self.pos..).unwrap_or_default());
    }

    /// Returns the byte at the current position.
    fn byte(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn error(&self, kind: ErrorKind, offset: usize) -> Error {
        Error::at(kind, self.input, offset)
    }

    /// Returns the error for input that stops at `offset`: the end of input if that is
    /// where `offset` is, `kind` otherwise.
    fn error_or_end(&self, kind: ErrorKind, offset: usize) -> Error {
        let kind = if offset >= self.input.len() { ErrorKind::UnexpectedEnd } else { kind };
        self.error(kind, offset)
    }
}

#[cfg(test)]
mod tests;
