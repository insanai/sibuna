//! Collector minutes and the internal archive-write requests. No HTTP route accepts
//! archive writes from a browser.

use std::fmt::{self, Write};

use sibuna_json::{Value, Writer};

use crate::client_family::STATUS_SLOTS;
use crate::codec::{Decode, DecodeError, Encode, Fields, Path, field};
use crate::space_saving::{Sketch, Summary};

/// Bytes per stored archive chunk.
pub const CHUNK_BYTES: usize = 2048;
/// The largest archive accepted for storage (see [`crate::rankings_archive::MAX_BYTES`]).
pub const MAX_BYTES: usize = crate::rankings_archive::MAX_BYTES;
/// The charged retention quota for archives.
pub const QUOTA_BYTES: u64 = 512 * 1024 * 1024;

/// Referring hosts share the Space-Saving bound with paths; host keys are 24 bytes.
pub type Referrers = Sketch<256, 24>;

/// Starts storing an archive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Begin {
    /// SHA-256 of the archive.
    pub digest: [u8; 32],
    /// The archive's length.
    pub total_bytes: u32,
    /// The writer's clock, in Unix seconds.
    pub now: u64,
}

/// One chunk of an archive.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Chunk {
    /// SHA-256 of the archive.
    pub digest: [u8; 32],
    /// The chunk number.
    pub ordinal: u8,
    /// At most [`CHUNK_BYTES`] bytes.
    pub bytes: Vec<u8>,
}

/// Publishes a fully stored archive after checksum and semantic validation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Finish {
    /// SHA-256 of the archive.
    pub digest: [u8; 32],
    /// The writer's clock, in Unix seconds.
    pub now: u64,
}

/// Returns the conservative retention charge of an archive of `bytes` bytes, with room
/// for chunk keys and indexes. This bounds archive reservations, not the database's
/// physical size.
pub fn charge(bytes: u32) -> u64 {
    u64::from(bytes).div_ceil(CHUNK_BYTES as u64) * 8192 + 1024
}

/// Exact sampled histograms over bounded label sets (SID 0007): no sketch is needed when
/// the key space is small. `status` counts the selected or observed response status.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Families {
    /// Samples by [`crate::client_family::Os`] ordinal.
    pub os: [u64; 8],
    /// Samples by [`crate::client_family::Browser`] ordinal.
    pub browser: [u64; 8],
    /// Samples by [`crate::client_family::status_slot`].
    pub status: [u64; STATUS_SLOTS],
}

impl Encode for Families {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "os", &self.os)?;
        field(json, "browser", &self.browser)?;
        field(json, "status", &self.status)?;
        json.end_object()
    }
}

impl Decode for Families {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Families, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let families = Families {
            os: fields.or_default("os")?,
            browser: fields.or_default("browser")?,
            status: fields.or("status", [0; STATUS_SLOTS])?,
        };
        fields.finish()?;
        Ok(families)
    }
}

/// One collector minute: complete sketches and histograms of the sampled traffic.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Minute {
    /// The UTC minute index; `None` before the first sample.
    pub minute: Option<u64>,
    /// The first sampled second.
    pub first_second: u64,
    /// The last sampled second.
    pub last_second: u64,
    /// Samples whose key was truncated.
    pub truncated_records: u64,
    /// Samples refused.
    pub rejected_records: u64,
    /// Path prefixes.
    pub paths: Summary,
    /// Referring hosts.
    pub referrers: Referrers,
    /// Client families and statuses.
    pub families: Families,
    /// False for archives written before referrers and families were retained.
    pub extended: bool,
}

impl Default for Minute {
    fn default() -> Minute {
        Minute {
            minute: None,
            first_second: 0,
            last_second: 0,
            truncated_records: 0,
            rejected_records: 0,
            paths: Summary::new(),
            referrers: Referrers::new(),
            families: Families::default(),
            extended: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charges_round_up_to_chunks() {
        assert_eq!(charge(0), 1024);
        assert_eq!(charge(1), 8192 + 1024);
        assert_eq!(charge(2048), 8192 + 1024);
        assert_eq!(charge(2049), 2 * 8192 + 1024);
    }
}
