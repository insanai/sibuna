//! Maintenance commands: fenced leases for pruning and notification delivery. They carry
//! only owned identity and fencing values.

use std::fmt;

use crate::error::MAX_I64;

/// How long incidents are kept, in days.
pub const INCIDENT_DAYS: u64 = 30;
/// How long audit rows are kept, in days.
pub const AUDIT_DAYS: u64 = 365;
/// Rows one prune step deletes.
pub const BATCH_ROWS: usize = 16;
/// How long a lease lasts, in seconds.
pub const LEASE_SECONDS: u64 = 30;

/// A lease that names no boot or carries an out-of-range fence or expiry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InvalidLease;

impl fmt::Display for InvalidLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the lease names no boot or has an out-of-range fence or expiry")
    }
}

impl std::error::Error for InvalidLease {}

/// The node and boot that hold (or ask for) a lease.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Holder {
    /// The node id.
    pub node: u32,
    /// The holder's boot id; never all zeros.
    pub boot: [u8; 16],
}

impl Holder {
    /// Checks that the holder names a boot.
    ///
    /// # Errors
    ///
    /// [`InvalidLease`] for an all-zero boot.
    pub fn validate(&self) -> Result<(), InvalidLease> {
        if self.boot == [0; 16] { Err(InvalidLease) } else { Ok(()) }
    }
}

/// A granted lease; its fence orders every write made under it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Lease {
    /// Who holds it.
    pub holder: Holder,
    /// The fencing token, 1 to `i64::MAX`.
    pub fence: u64,
    /// When it expires, in Unix seconds.
    pub expires: u64,
}

impl Lease {
    /// Checks the holder, fence and expiry.
    ///
    /// # Errors
    ///
    /// [`InvalidLease`] when any is out of range.
    pub fn validate(&self) -> Result<(), InvalidLease> {
        self.holder.validate()?;
        if self.fence == 0 || self.fence > MAX_I64 || self.expires > MAX_I64 {
            return Err(InvalidLease);
        }
        Ok(())
    }
}

/// What a prune step deletes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Kind {
    /// Incidents older than their retention.
    #[default]
    Incidents,
    /// Audit rows older than their retention.
    Audit,
    /// Expired sessions.
    Sessions,
    /// Expired kiosk grants.
    KioskGrants,
    /// Abandoned GeoIP stages.
    Stages,
    /// Abandoned policy import stages.
    ImportStages,
    /// Old notification deliveries.
    NotificationHistory,
}

/// One prune step under a lease.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Prune {
    /// The lease the step runs under.
    pub lease: Lease,
    /// What to delete.
    pub kind: Kind,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leases_need_a_boot_and_a_bounded_fence() {
        let holder = Holder { node: 1, boot: [1; 16] };
        assert_eq!(Holder::default().validate(), Err(InvalidLease));
        assert_eq!(Lease { holder, fence: 1, expires: 0 }.validate(), Ok(()));
        assert_eq!(Lease { holder, fence: 0, expires: 0 }.validate(), Err(InvalidLease));
        assert_eq!(Lease { holder, fence: 1, expires: u64::MAX }.validate(), Err(InvalidLease));
    }
}
