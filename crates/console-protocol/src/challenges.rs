//! The boot-local challenge funnel and one bounded timing partition, shared with the
//! browser.

use std::fmt::{self, Write};

use sibuna_json::{Value, Writer};

use crate::codec::{Decode, DecodeError, Encode, Fields, Path, WireEnum, field};

/// Rejection causes counted separately.
pub const CAUSE_COUNT: usize = 13;
/// Parameter partitions (one per authenticated parameter byte).
pub const BIN_COUNT: usize = 256;
/// Solve-time histogram buckets.
pub const BUCKET_COUNT: usize = 16;

/// A proof-of-work algorithm.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// Hashcash over SHA-256.
    #[default]
    Hashcash,
    /// The Cohen-Pietrzak proof of sequential work.
    Posw,
}

impl WireEnum for Algorithm {
    const ALL: &'static [Algorithm] = &[Algorithm::Hashcash, Algorithm::Posw];

    fn name(self) -> &'static str {
        match self {
            Algorithm::Hashcash => "hashcash",
            Algorithm::Posw => "posw",
        }
    }
}

/// The challenge parameters in force or last issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Defaults {
    /// The algorithm.
    pub algorithm: Algorithm,
    /// Hashcash difficulty in bits.
    pub difficulty: u32,
    /// The proof-of-work parameter.
    pub parameter: u8,
    /// Proof openings, for the sequential-work proof.
    pub openings: u8,
}

impl Default for Defaults {
    fn default() -> Defaults {
        Defaults { algorithm: Algorithm::Hashcash, difficulty: 16, parameter: 16, openings: 0 }
    }
}

impl Encode for Defaults {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "algorithm", &self.algorithm)?;
        field(json, "difficulty", &self.difficulty)?;
        field(json, "parameter", &self.parameter)?;
        field(json, "openings", &self.openings)?;
        json.end_object()
    }
}

impl Decode for Defaults {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Defaults, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let defaults = Defaults {
            algorithm: fields.or_default("algorithm")?,
            difficulty: fields.or("difficulty", 16)?,
            parameter: fields.or("parameter", 16)?,
            openings: fields.or_default("openings")?,
        };
        fields.finish()?;
        Ok(defaults)
    }
}

/// The challenge funnel: issuance, submissions, outcomes, rejection causes, and the
/// selected partition's solve-time histogram and solver split. Counters are written as
/// plain JSON numbers, as Zig's default serializer did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Snapshot {
    /// When it was observed, in Unix seconds.
    pub timestamp: u64,
    /// The configured parameters.
    pub configured: Defaults,
    /// The parameters of the last challenge issued.
    pub last_issued: Option<Defaults>,
    /// Challenges issued.
    pub issued: u64,
    /// Solutions submitted.
    pub submitted: u64,
    /// Solutions accepted.
    pub accepted: u64,
    /// Solutions rejected.
    pub rejected: u64,
    /// Rejections by cause.
    pub causes: [u64; CAUSE_COUNT],
    /// The partition the histogram describes.
    pub selected: u8,
    /// Acceptances by partition.
    pub bin_accepted: [u64; BIN_COUNT],
    /// The selected partition's solve-time histogram.
    pub buckets: [u64; BUCKET_COUNT],
    /// Acceptances without a reported solve time.
    pub missing: u64,
    /// Acceptances with an invalid solve time.
    pub invalid: u64,
    /// Acceptances solved by WebAssembly.
    pub wasm: u64,
    /// Acceptances solved by the JavaScript fallback.
    pub javascript: u64,
    /// Acceptances whose solver is unknown.
    pub unknown_solver: u64,
}

impl Default for Snapshot {
    fn default() -> Snapshot {
        Snapshot {
            timestamp: 0,
            configured: Defaults::default(),
            last_issued: None,
            issued: 0,
            submitted: 0,
            accepted: 0,
            rejected: 0,
            causes: [0; CAUSE_COUNT],
            selected: 0,
            bin_accepted: [0; BIN_COUNT],
            buckets: [0; BUCKET_COUNT],
            missing: 0,
            invalid: 0,
            wasm: 0,
            javascript: 0,
            unknown_solver: 0,
        }
    }
}

impl Encode for Snapshot {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "timestamp", &self.timestamp)?;
        field(json, "configured", &self.configured)?;
        field(json, "last_issued", &self.last_issued)?;
        field(json, "issued", &self.issued)?;
        field(json, "submitted", &self.submitted)?;
        field(json, "accepted", &self.accepted)?;
        field(json, "rejected", &self.rejected)?;
        field(json, "causes", &self.causes)?;
        field(json, "selected", &self.selected)?;
        field(json, "bin_accepted", &self.bin_accepted)?;
        field(json, "buckets", &self.buckets)?;
        field(json, "missing", &self.missing)?;
        field(json, "invalid", &self.invalid)?;
        field(json, "wasm", &self.wasm)?;
        field(json, "javascript", &self.javascript)?;
        field(json, "unknown_solver", &self.unknown_solver)?;
        json.end_object()
    }
}

impl Decode for Snapshot {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Snapshot, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let snapshot = Snapshot {
            timestamp: fields.or_default("timestamp")?,
            configured: fields.or_default("configured")?,
            last_issued: fields.or_default("last_issued")?,
            issued: fields.or_default("issued")?,
            submitted: fields.or_default("submitted")?,
            accepted: fields.or_default("accepted")?,
            rejected: fields.or_default("rejected")?,
            causes: fields.or("causes", [0; CAUSE_COUNT])?,
            selected: fields.or_default("selected")?,
            bin_accepted: fields.or("bin_accepted", [0; BIN_COUNT])?,
            buckets: fields.or("buckets", [0; BUCKET_COUNT])?,
            missing: fields.or_default("missing")?,
            invalid: fields.or_default("invalid")?,
            wasm: fields.or_default("wasm")?,
            javascript: fields.or_default("javascript")?,
            unknown_solver: fields.or_default("unknown_solver")?,
        };
        fields.finish()?;
        Ok(snapshot)
    }
}
