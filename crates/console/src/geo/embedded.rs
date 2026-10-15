//! The embedded GeoIP snapshot (unit U6; Zig's `geoip_embedded.zig`): validated at build
//! time from `SIBUNA_GEOIP_DATA` (decision 7), served at revision 0 until the first durable
//! import replaces it.
//!
//! The daemon passes the snapshot's bytes as `Inputs::geoip_embedded` (`None`, or empty
//! bytes, when the build embeds none); the importer decodes them once at start, and only
//! when storage holds no generation. Zig embedded the file with `@embedFile` in the
//! console library; here the library takes the bytes, so it builds without one.

use sibuna_console_protocol::Text;
use sibuna_console_protocol::geo::Metadata;
use sibuna_geoip::Database;
use sibuna_geoip::snapshot::{self, SnapshotError};

use super::import::source_digests;

/// Decodes the embedded snapshot `bytes`; `Ok(None)` when they are empty.
///
/// Fails with the [`SnapshotError`] of a snapshot that does not decode, which a build that
/// validated it cannot produce.
pub fn load(bytes: &[u8]) -> Result<Option<Database>, SnapshotError> {
    snapshot::load_embedded(bytes)
}

/// Returns the metadata the GeoIP page shows for the embedded `database` at storage's
/// `revision`: no activation time, because no import activated it.
pub fn metadata(database: &Database, revision: u64) -> Metadata {
    let digest = sibuna_encoding::hex::encode(database.digest());
    Metadata {
        revision,
        digest: Text::from_string(digest).unwrap_or_default(),
        provider: Text::new(database.provider().name()).unwrap_or_default(),
        source_version: Text::new(database.version().as_str()).unwrap_or_default(),
        source_digests: Text::from_string(source_digests(database)).unwrap_or_default(),
        ranges: u32::try_from(database.range_count()).unwrap_or(u32::MAX),
        loaded_at: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_geoip::Provider;

    // geoip_embedded.zig: "an embedded snapshot, when present, decodes into a usable
    // generation".
    #[test]
    fn an_embedded_snapshot_when_present_decodes_into_a_usable_generation() {
        assert_eq!(load(b""), Ok(None));
        let csv = b"8.8.8.0,8.8.8.255,US\n";
        let database = Database::from_csv(Provider::Dbip, "2026-09", csv).unwrap();
        let bytes = snapshot::encode(&database).unwrap();
        let loaded = load(&bytes).unwrap().unwrap();
        assert_ne!(loaded.range_count(), 0);
        assert_eq!(loaded.lookup_text("8.8.8.8").unwrap().as_str(), "US");
        let shown = metadata(&loaded, 0);
        assert_eq!((shown.revision, shown.ranges, shown.loaded_at), (0, 1, 0));
        assert_eq!(shown.provider.as_str(), "dbip");
        assert_eq!(shown.digest.len(), 64);
        assert!(load(&bytes[..bytes.len() - 1]).is_err());
    }
}
