//! The active GeoIP generation (Zig's `geoip_generation.zig`), shared by the console and
//! the storage thread's incident hook.
//!
//! A generation is immutable and reference-counted: readers clone an `Arc` under a short
//! read lock and look up without it, so an import that swaps the generation never waits for
//! readers and never frees memory a reader still uses. Zig held its registry mutex for
//! every lookup and freed the old generation under it; the `Arc` replaces both. At most one
//! import runs at a time ([`GeoSlot::begin_import`]); a refused import never touches the
//! active generation.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

use sibuna_console_storage::sidecars::{CountryLookup, CountryMapping};
use sibuna_geoip::{Database, address};

/// The generation lookups use, with its activation revision.
#[derive(Debug)]
pub struct Active {
    /// The ranges.
    pub database: Database,
    /// The revision under which it was activated; 0 for an embedded snapshot.
    pub revision: u64,
    /// True for the snapshot built into the binary, before any durable import.
    pub embedded: bool,
}

/// Why an import step was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SlotError {
    /// Another import is running.
    Busy,
    /// The active revision is not the one the import expected.
    Conflict,
}

impl fmt::Display for SlotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SlotError::Busy => "a GeoIP import is already running",
            SlotError::Conflict => "the active GeoIP generation changed",
        })
    }
}

impl std::error::Error for SlotError {}

/// The active generation, if any, and the import claim.
#[derive(Debug, Default)]
pub struct GeoSlot {
    active: RwLock<Option<Arc<Active>>>,
    /// Set while an import holds its claim. Acquire on claim and Release on release, so the
    /// next import sees everything the previous one did.
    importing: AtomicBool,
}

/// The right to activate a generation, held by the one running import; dropping it ends
/// the import.
#[derive(Debug)]
pub struct ImportClaim {
    slot: Arc<GeoSlot>,
}

impl Drop for ImportClaim {
    fn drop(&mut self) {
        self.slot.importing.store(false, Ordering::Release);
    }
}

impl GeoSlot {
    /// Returns an empty slot: no generation, no import.
    pub fn new() -> GeoSlot {
        GeoSlot::default()
    }

    /// Installs `database` as the active generation at `revision` (startup: the durable
    /// generation, or the embedded snapshot with `embedded`).
    pub fn restore(&self, database: Database, revision: u64, embedded: bool) {
        let active = Arc::new(Active { database, revision, embedded });
        *self.active.write().unwrap_or_else(PoisonError::into_inner) = Some(active);
    }

    /// Returns the active generation, or `None` before one is loaded.
    pub fn active(&self) -> Option<Arc<Active>> {
        self.active.read().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// Returns true once a generation is loaded.
    pub fn is_loaded(&self) -> bool {
        self.active().is_some()
    }

    /// Returns the active revision; 0 when none is loaded.
    pub fn revision(&self) -> u64 {
        self.active().map_or(0, |active| active.revision)
    }

    /// Returns true while the embedded snapshot serves lookups.
    pub fn is_embedded(&self) -> bool {
        self.active().is_some_and(|active| active.embedded)
    }

    /// Maps the client address `text` for an incident: `None` without a generation; the
    /// generation digest with no country when the address does not parse or maps to none.
    pub fn lookup(&self, text: &str) -> Option<CountryMapping> {
        let active = self.active()?;
        let generation = *active.database.digest();
        let country = address::parse(text)
            .ok()
            .and_then(|ip| active.database.lookup(ip))
            .map(|country| country.to_bytes());
        Some(CountryMapping { country, generation })
    }

    /// Returns the incident hook's country lookup over this slot.
    pub fn country_lookup(self: &Arc<Self>) -> CountryLookup {
        let slot = Arc::clone(self);
        Box::new(move |text| slot.lookup(text))
    }

    /// Returns true while an import holds its claim.
    pub fn is_importing(&self) -> bool {
        self.importing.load(Ordering::Acquire)
    }

    /// Claims the one import.
    ///
    /// Fails with [`SlotError::Busy`] while another claim is held.
    pub fn begin_import(self: &Arc<Self>) -> Result<ImportClaim, SlotError> {
        self.importing
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| SlotError::Busy)?;
        Ok(ImportClaim { slot: Arc::clone(self) })
    }

    /// Makes `database` the active generation when the active revision is still
    /// `expected_revision`, and returns the new revision (one more). Call it only after the
    /// storage commit of the same generation; readers holding the old one keep it until they
    /// drop it.
    ///
    /// Fails with [`SlotError::Conflict`] (dropping `database`, the old generation stays
    /// active) when the revision moved, and with [`SlotError::Busy`] when `claim` belongs
    /// to another slot.
    pub fn activate(
        &self,
        claim: &ImportClaim,
        database: Database,
        expected_revision: u64,
    ) -> Result<u64, SlotError> {
        if !std::ptr::eq(Arc::as_ptr(&claim.slot), self) {
            return Err(SlotError::Busy);
        }
        let mut active = self.active.write().unwrap_or_else(PoisonError::into_inner);
        let revision = active.as_ref().map_or(0, |current| current.revision);
        if revision != expected_revision {
            return Err(SlotError::Conflict);
        }
        let next = revision.checked_add(1).ok_or(SlotError::Conflict)?;
        *active = Some(Arc::new(Active { database, revision: next, embedded: false }));
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_geoip::Provider;

    // geoip_generation.zig: "failed import and revision conflict retain the previous
    // immutable generation".
    #[test]
    fn a_failed_import_or_a_conflict_keeps_the_previous_generation() {
        let slot = Arc::new(GeoSlot::new());
        assert_eq!(slot.lookup("8.8.8.8"), None);
        let claim = slot.begin_import().unwrap();
        assert_eq!(slot.begin_import().map(drop), Err(SlotError::Busy));
        let first = Database::from_csv(Provider::Dbip, "2026-09", b"8.8.8.0,8.8.8.255,US\n");
        assert_eq!(slot.activate(&claim, first.unwrap(), 0), Ok(1));
        let overlap = b"8.8.8.0,8.8.8.255,US\n8.8.8.255,8.8.9.0,DE";
        assert!(Database::from_csv(Provider::Dbip, "2026-09", overlap).is_err());
        let csv = b"8.8.8.0,8.8.8.255,DE\n";
        let second = Database::from_csv(Provider::UserCountry, "2026-09-09", csv).unwrap();
        assert_eq!(slot.activate(&claim, second, 0), Err(SlotError::Conflict));
        let mapping = slot.lookup("8.8.8.8").unwrap();
        assert_eq!(mapping.country, Some(*b"US"));
        assert!(slot.active().unwrap().database.provider().attribution().is_some());
        let third = Database::from_csv(Provider::UserCountry, "2026-09-09", csv).unwrap();
        assert_eq!(slot.activate(&claim, third, 1), Ok(2));
        assert_eq!(slot.lookup("8.8.8.8").unwrap().country, Some(*b"DE"));
        assert!(slot.active().unwrap().database.provider().attribution().is_none());
        drop(claim);
        assert!(!slot.is_importing());
        assert!(slot.begin_import().is_ok());
    }

    #[test]
    fn lookups_report_the_generation_also_for_unmapped_addresses() {
        let slot = Arc::new(GeoSlot::new());
        let database = Database::from_csv(Provider::Dbip, "2026-09", b"8.8.8.0,8.8.8.255,US\n");
        slot.restore(database.unwrap(), 0, true);
        assert!(slot.is_embedded() && slot.is_loaded());
        let digest = *slot.active().unwrap().database.digest();
        let unparsed = slot.lookup("not an address").unwrap();
        assert_eq!(unparsed, CountryMapping { country: None, generation: digest });
        assert_eq!(slot.lookup("10.0.0.1").unwrap().country, None);
        let hook = slot.country_lookup();
        assert_eq!(hook("8.8.8.8").and_then(|mapping| mapping.country), Some(*b"US"));
        let other = Arc::new(GeoSlot::new());
        let claim = other.begin_import().unwrap();
        let again = Database::from_csv(Provider::Dbip, "2026-09", b"8.8.8.0,8.8.8.255,US\n");
        assert_eq!(slot.activate(&claim, again.unwrap(), 0), Err(SlotError::Busy));
    }
}
