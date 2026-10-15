//! Country activity of the selected globe mode (`globe_data.zig`).
//!
//! Both modes borrow one accepted snapshot. Changing modes neither opens another stream
//! nor mixes sampled requests with locally persisted incident findings.

use sibuna_console_protocol::CountryCount;

use crate::state::State;

/// The country activity the globe shows.
#[derive(Clone, Copy, Debug)]
pub(super) struct Activity<'a> {
    /// The largest countries, largest first; empty slots have no samples.
    pub countries: &'a [CountryCount],
    /// Activity whose country is unknown.
    pub unknown: u64,
    /// Activity from countries beyond the slots.
    pub other: u64,
    /// What one count is: `samples` or `findings`.
    pub unit: &'static str,
}

/// Returns the activity of the mode `state` selects: sampled traffic, or recorded
/// findings (incident geography of format version 1). `None` without statistics, or in
/// Attacks mode without incident geography of a known format.
pub(super) fn activity(state: &State) -> Option<Activity<'_>> {
    let stats = state.stats.as_ref()?;
    if state.globe_attacks {
        let incidents = stats.incident_geo.as_ref().filter(|incidents| incidents.version == 1)?;
        return Some(Activity {
            countries: &incidents.countries,
            unknown: incidents.unknown,
            other: incidents.other,
            unit: "findings",
        });
    }
    Some(Activity {
        countries: &stats.countries,
        unknown: stats.unknown_samples,
        other: stats.other_country_samples,
        unit: "samples",
    })
}

#[cfg(test)]
mod tests {
    use sibuna_console_protocol::{StatsSnapshot, incident_geo};

    use super::*;

    // Port of globe_data.zig "globe modes borrow independent observations and reject
    // absent or future incident formats".
    #[test]
    fn globe_modes_borrow_independent_observations_and_reject_absent_or_future_formats() {
        let mut state = State::new();
        assert!(activity(&state).is_none());
        let mut stats = StatsSnapshot::default();
        stats.countries[0] = CountryCount { code: 0x5553, samples: 9 };
        state.stats = Some(stats);
        assert_eq!(activity(&state).unwrap().countries[0].samples, 9);
        state.globe_attacks = true;
        assert!(activity(&state).is_none());
        let mut incidents = incident_geo::Snapshot { unknown: 3, ..Default::default() };
        incidents.countries[0] = CountryCount { code: 0x494e, samples: 2 };
        state.stats.as_mut().unwrap().incident_geo = Some(incidents);
        assert_eq!(activity(&state).unwrap().countries[0].samples, 2);
        assert_eq!(activity(&state).unwrap().unknown, 3);
        state.stats.as_mut().unwrap().incident_geo.as_mut().unwrap().version = 2;
        assert!(activity(&state).is_none());
        state.reset();
        assert!(!state.globe_attacks);
    }
}
