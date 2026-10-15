//! A bounded JSON parser and a compact writer for Sibuna.
//!
//! The parser reads a whole document into a [`Value`] tree that borrows the input: strings
//! without escapes and all numbers are slices of it. It follows RFC 8259 as strictly as
//! Zig 0.16's `std.json` scanner does (no comments, trailing commas, leading zeros, lone
//! surrogates, raw control characters or invalid UTF-8) and rejects duplicate object keys,
//! as Zig's default parse options do. It never recurses, and every resource it uses is
//! bounded by [`Limits`]; exceeding a limit is an [`Error`] that carries the byte offset,
//! line and column.
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
//! - [`Writer::float`] writes `null` for NaN and infinities, as JavaScript does, where
//!   Zig wrote `"nan"` and the invalid token `inf`.

mod error;
mod number;
mod parse;
mod reader;
mod value;
mod write;

pub use error::{Error, ErrorKind};
pub use number::{Number, NumberError};
pub use parse::{Limits, parse, parse_with_limits};
pub use reader::{FieldError, FieldErrorKind, ObjectReader};
pub use value::{Object, ObjectIter, Value};
pub use write::{Writer, escape_str, write_string};
