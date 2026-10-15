//! Listener-owned connection accounting by class.
//!
//! Every connection is admitted as [`Class::Http`]. A WebSocket upgrade transfers it to
//! [`Class::Browser`] or [`Class::Peer`] in one step. Browser and peer connections have
//! quotas of their own, and the two quotas together leave `http_reserved` slots that only
//! HTTP connections can take, so long-lived streams never lock out logins and API calls.

use std::fmt;

/// The class a connection is counted under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Class {
    /// An HTTP request; every connection starts here.
    Http,
    /// A browser's WebSocket subscription.
    Browser,
    /// A management peer's WebSocket stream.
    Peer,
}

/// The limits of an [`Admission`]. The defaults are the console's: 96 slots, 16 of them
/// reserved for HTTP, 64 browser subscriptions and 16 peer streams.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Capacity {
    /// Connections of every class together; 16 to 256.
    pub max_slots: u16,
    /// Slots that browser and peer streams can never take; 16 to `max_slots`.
    pub http_reserved: u16,
    /// Browser subscriptions; at most 64.
    pub max_browsers: u16,
    /// Peer streams; at most 64.
    pub max_peers: u16,
}

impl Default for Capacity {
    fn default() -> Self {
        Capacity { max_slots: 96, http_reserved: 16, max_browsers: 64, max_peers: 16 }
    }
}

impl Capacity {
    /// Checks the limits: 16 to 256 slots, a reserve of at least 16 that fits the slots, at
    /// most 64 browsers and 64 peers, and browsers plus peers within the unreserved slots.
    /// A larger listener therefore cannot raise the browser quota.
    ///
    /// # Errors
    ///
    /// [`AdmissionError::InvalidCapacity`] when any rule fails.
    pub fn validate(&self) -> Result<(), AdmissionError> {
        let slots_ok = (16..=256).contains(&self.max_slots);
        let reserve_ok = self.http_reserved >= 16 && self.http_reserved <= self.max_slots;
        if !slots_ok || !reserve_ok {
            return Err(AdmissionError::InvalidCapacity);
        }
        let streams = u32::from(self.max_browsers) + u32::from(self.max_peers);
        let unreserved = u32::from(self.max_slots - self.http_reserved);
        if self.max_browsers > 64 || self.max_peers > 64 || streams > unreserved {
            return Err(AdmissionError::InvalidCapacity);
        }
        Ok(())
    }
}

/// Why a connection was not admitted, or a capacity refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdmissionError {
    /// The limits break a rule of [`Capacity::validate`].
    InvalidCapacity,
    /// The class's quota or the slot table is full.
    Full,
    /// The listener is stopping and admits nothing more.
    Stopping,
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AdmissionError::InvalidCapacity => "invalid listener capacity",
            AdmissionError::Full => "listener capacity exhausted",
            AdmissionError::Stopping => "listener is stopping",
        })
    }
}

impl std::error::Error for AdmissionError {}

/// Counts of admitted connections by class, under a validated [`Capacity`].
///
/// The listener serialises every call behind its slot-table lock, so the counts need no
/// atomics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admission {
    capacity: Capacity,
    http: u16,
    browsers: u16,
    peers: u16,
    stopping: bool,
}

impl Admission {
    /// An empty admission under `capacity`.
    ///
    /// # Errors
    ///
    /// [`AdmissionError::InvalidCapacity`] when `capacity` fails [`Capacity::validate`].
    pub fn new(capacity: Capacity) -> Result<Admission, AdmissionError> {
        capacity.validate()?;
        Ok(Admission { capacity, http: 0, browsers: 0, peers: 0, stopping: false })
    }

    /// The limits this admission enforces.
    pub fn capacity(&self) -> Capacity {
        self.capacity
    }

    /// Admits one connection of `class`.
    ///
    /// # Errors
    ///
    /// [`AdmissionError::Stopping`] after [`Admission::stop`], and [`AdmissionError::Full`]
    /// when every slot is taken or the class's quota is reached.
    pub fn acquire(&mut self, class: Class) -> Result<(), AdmissionError> {
        if self.stopping {
            return Err(AdmissionError::Stopping);
        }
        if self.total() >= u32::from(self.capacity.max_slots) {
            return Err(AdmissionError::Full);
        }
        match class {
            Class::Http => self.http += 1,
            Class::Browser if self.browsers < self.capacity.max_browsers => self.browsers += 1,
            Class::Peer if self.peers < self.capacity.max_peers => self.peers += 1,
            Class::Browser | Class::Peer => return Err(AdmissionError::Full),
        }
        Ok(())
    }

    /// Transfers one admitted HTTP connection to `class` in one step: on failure it stays
    /// counted as HTTP. Transferring to [`Class::Http`] changes nothing.
    ///
    /// # Errors
    ///
    /// As [`Admission::acquire`] for `class`.
    pub fn upgrade(&mut self, class: Class) -> Result<(), AdmissionError> {
        if class == Class::Http {
            return Ok(());
        }
        // The caller holds an HTTP admission; a zero count means it released it already.
        debug_assert!(self.http > 0, "upgrade without an admitted HTTP connection");
        self.http = self.http.saturating_sub(1);
        self.acquire(class).inspect_err(|_| self.http += 1)
    }

    /// Releases one connection of `class`.
    pub fn release(&mut self, class: Class) {
        let count = match class {
            Class::Http => &mut self.http,
            Class::Browser => &mut self.browsers,
            Class::Peer => &mut self.peers,
        };
        debug_assert!(*count > 0, "release without an admitted connection");
        *count = count.saturating_sub(1);
    }

    /// Refuses every later [`Admission::acquire`] and [`Admission::upgrade`].
    pub fn stop(&mut self) {
        self.stopping = true;
    }

    /// True after [`Admission::stop`].
    pub fn is_stopping(&self) -> bool {
        self.stopping
    }

    /// The admitted connections of `class`.
    pub fn count(&self, class: Class) -> u16 {
        match class {
            Class::Http => self.http,
            Class::Browser => self.browsers,
            Class::Peer => self.peers,
        }
    }

    fn total(&self) -> u32 {
        u32::from(self.http) + u32::from(self.browsers) + u32::from(self.peers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_and_peer_saturation_retain_reserved_http_capacity() {
        let mut admission = Admission::new(Capacity::default()).unwrap();
        for _ in 0..64 {
            admission.acquire(Class::Browser).unwrap();
        }
        for _ in 0..16 {
            admission.acquire(Class::Peer).unwrap();
        }
        assert_eq!(admission.acquire(Class::Browser), Err(AdmissionError::Full));
        assert_eq!(admission.acquire(Class::Peer), Err(AdmissionError::Full));
        for _ in 0..16 {
            admission.acquire(Class::Http).unwrap();
        }
        assert_eq!(admission.acquire(Class::Http), Err(AdmissionError::Full));
        assert_eq!(admission.upgrade(Class::Browser), Err(AdmissionError::Full));
        assert_eq!(admission.count(Class::Http), 16);
        admission.release(Class::Browser);
        admission.upgrade(Class::Browser).unwrap();
        assert_eq!(admission.count(Class::Http), 15);
        admission.stop();
        assert_eq!(admission.acquire(Class::Http), Err(AdmissionError::Stopping));
    }

    #[test]
    fn larger_listener_cannot_expand_browser_subscription_quota() {
        let capacity = Capacity { max_slots: 256, max_browsers: 65, ..Capacity::default() };
        assert_eq!(capacity.validate(), Err(AdmissionError::InvalidCapacity));
        assert_eq!(Admission::new(capacity), Err(AdmissionError::InvalidCapacity));
    }

    #[test]
    fn capacity_rules_bound_every_limit() {
        let valid = Capacity::default();
        assert_eq!(valid.validate(), Ok(()));
        let invalid = [
            Capacity { max_slots: 15, ..valid },
            Capacity { max_slots: 257, ..valid },
            Capacity { http_reserved: 15, ..valid },
            Capacity { http_reserved: 97, ..valid },
            Capacity { max_peers: 17, ..valid },
            Capacity { max_slots: 256, max_peers: 65, ..valid },
        ];
        for capacity in invalid {
            assert_eq!(capacity.validate(), Err(AdmissionError::InvalidCapacity), "{capacity:?}");
        }
    }

    #[test]
    fn upgrade_stopping_keeps_the_http_admission() {
        let mut admission = Admission::new(Capacity::default()).unwrap();
        admission.acquire(Class::Http).unwrap();
        admission.stop();
        assert_eq!(admission.upgrade(Class::Peer), Err(AdmissionError::Stopping));
        assert_eq!(admission.count(Class::Http), 1);
        assert_eq!(admission.count(Class::Peer), 0);
        assert_eq!(admission.upgrade(Class::Http), Ok(()));
    }
}
