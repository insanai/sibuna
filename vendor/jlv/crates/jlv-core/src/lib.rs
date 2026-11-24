//! The small shared vocabulary of jlavideploy (JDD 0002, tier `core`).
//!
//! Every other crate uses these types: typed UUIDv7 identifiers ([`Id`]), wall-clock
//! milliseconds ([`Millis`]), source spans ([`Span`]), evaluation and protocol limits
//! ([`Limits`]) and the structured diagnostic every surface renders ([`Problem`]).
//! Domain records and their states stay in the libraries that own them.

#![forbid(unsafe_code)]

mod diagnostic;
mod fields;
mod id;
mod limits;
mod problem;
mod random;
mod span;
mod time;

pub use diagnostic::{Diagnostic, Sources};
pub use fields::Fields;
pub use gd_json::{Object, Value};
pub use id::{Id, IdError};
pub use limits::Limits;
pub use problem::{Action, Location, Problem, RetryClass};
pub use random::fill_random;
pub use span::{SourceId, Span};
pub use time::Millis;
