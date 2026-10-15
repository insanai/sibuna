//! A bounded JSON parser, a streaming pull reader and a compact writer for Sibuna.
//!
//! The parser reads a whole document into a [`Value`] tree that borrows the input: strings
//! without escapes and all numbers are slices of it. It follows RFC 8259 as strictly as
//! Zig 0.16's `std.json` scanner does (no comments, trailing commas, leading zeros, lone
//! surrogates, raw control characters or invalid UTF-8) and rejects duplicate object keys,
//! as Zig's default parse options do. It never recurses, and every resource it uses is
//! bounded by [`Limits`]; exceeding a limit is an [`Error`] that carries the byte offset,
//! line and column.
//!
//! [`PullReader`] reads the same grammar one [`Event`] at a time, so a typed reader can
//! check each key and value as it arrives and stop at the first problem in document order.
//! It holds the crate's only implementation of the grammar: the tree parser is a loop over
//! its events, so the two cannot disagree.
//!
//! ```
//! use sibuna_json::{Event, PullReader};
//!
//! // An unknown key is seen before the syntax error that follows it.
//! let mut reader = PullReader::new(br#"{"actoin": "DENY", "rules": [}"#);
//! assert_eq!(reader.next().unwrap(), Some(Event::BeginObject));
//! assert_eq!(reader.next().unwrap(), Some(Event::Key("actoin".into())));
//! ```
//!
//! Plain text inside strings and runs of whitespace are scanned eight bytes at a time in
//! safe, portable integer code (`swar`), which behaves the same on x86-64, AArch64 and
//! wasm32. The input is checked for UTF-8 once up front so that strings can borrow it;
//! only when that check fails are strings checked run by run, so that the first invalid
//! sequence is reported where the reader meets it.
//!
//! [`ObjectReader`] takes typed fields from an object and rejects keys nobody took, naming
//! the field by its path (`rules[2].challenge.difficulty`). [`Writer`] emits compact JSON
//! into any `fmt::Write` sink with the escaping of Zig's `std.json.Stringify`.
//!
//! ```
//! use sibuna_json::{parse, Value};
//!
//! let value = parse(b"{\"name\":\"caf\\u00e9\",\"sizes\":[1,2.5]}").unwrap();
//! let object = value.as_object().unwrap();
//! assert_eq!(object.get("name").and_then(Value::as_str), Some("caf\u{e9}"));
//! assert_eq!(value.to_string(), "{\"name\":\"caf\u{e9}\",\"sizes\":[1,2.5]}");
//! ```
//!
//! Deliberate changes from Zig's `std.json`:
//!
//! - Numbers keep their source text ([`Number`]) instead of becoming `integer`, `float` or
//!   `number_string`. [`Number::as_i64`] and [`Number::as_u64`] convert exactly; like
//!   Zig's typed parsing they accept integral values written with a fraction or exponent
//!   (`8.0`, `1e3`), but they decide integrality exactly where Zig rounded through `f128`.
//!   [`Number::is_integer_literal`] is Zig's `isNumberFormattedLikeAnInteger`.
//! - Duplicate keys are always an error; the `use_first` and `use_last` options are not
//!   ported, because no Sibuna caller used them and unique keys make [`Object::get`]
//!   unambiguous.
//! - Typed parsing into structs (`parseFromSlice(T, ..)`) is replaced by
//!   [`ObjectReader`], which reports the path of the offending field where Zig reported
//!   only `error.UnknownField`.
//! - Explicit limits replace allocator failure as the bound on hostile input.
//! - [`PullReader`] replaces Zig's `Scanner` and `Token`: keys are their own event, strings
//!   come whole (borrowed or decoded) instead of in partial tokens, and `skip_value`
//!   checks what it skips. Its `peek` keeps Zig's `peekNextTokenType` behaviour of
//!   deciding from one byte.
//! - Invalid UTF-8 is reported where the reader meets it, inside a string, as Zig does; a
//!   non-ASCII byte outside a string is the structural error of its position, and a
//!   sequence cut short by the end of the input is [`ErrorKind::UnexpectedEnd`]. Offsets
//!   follow Zig's scanner (an invalid escape at the byte after the backslash, a lone low
//!   surrogate after its four digits), except that invalid UTF-8 is located at the start
//!   of its sequence rather than at the first byte Zig refused.
//! - [`Writer::float`] writes `null` for NaN and infinities, as JavaScript does, where
//!   Zig wrote `"nan"` and the invalid token `inf`.

mod error;
mod limits;
mod number;
mod parse;
mod pull;
mod reader;
mod swar;
mod value;
mod write;

pub use error::{Error, ErrorKind};
pub use limits::Limits;
pub use number::{Number, NumberError};
pub use parse::{parse, parse_with_limits};
pub use pull::{Event, EventKind, PullReader};
pub use reader::{FieldError, FieldErrorKind, ObjectReader};
pub use value::{Object, ObjectIter, Value};
pub use write::{Writer, escape_str, write_string};
