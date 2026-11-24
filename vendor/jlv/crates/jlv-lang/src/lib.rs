//! The JLV semantic kernel (JDD 0004; tier `kernel` of JDD 0002).
//!
//! The kernel defines immutable [`Value`]s and [`Type`]s with assignability, the checked
//! core [`program`] that the compiler lowers source to, the reference evaluator
//! [`eval::run`] with its normalized step budget, the [`signature`] registry format that
//! libraries publish, the interface of [`native`] functions, and the canonical
//! encoding and domain-separated digests of [`canonical`] and [`digest`].
//!
//! It has no cloud, SSH, package manager, database, account or HTTP primitive, and no
//! clock, randomness or file access during evaluation: preparation is a pure function
//! of its explicit inputs and budget.

#![forbid(unsafe_code)]

pub mod base64;
pub mod canonical;
mod code;
pub mod codes;
pub mod digest;
pub mod eval;
pub mod native;
mod ops;
pub mod program;
pub mod signature;
pub mod types;
pub mod value;

pub use digest::Digest;
pub use types::Type;
pub use value::Value;
