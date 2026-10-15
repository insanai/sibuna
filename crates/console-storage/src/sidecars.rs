//! The writer of the incident sidecars (SID 0013, "Incident sidecars"): evidence metadata,
//! redacted heads and the country at persistence, written by the incident hook in the
//! transaction of the core's incident batch (SID 0013, "Changes to the core storage",
//! item 2).
//!
//! | Sidecar                     | Written when                                         |
//! |-----------------------------|------------------------------------------------------|
//! | `console_incident_evidence` | the evidence has a version (the console captures)    |
//! | `console_incident_heads`    | a request or response head was captured              |
//! | `console_incident_country`  | a GeoIP generation is loaded and maps the address    |
//!
//! The daemon registers [`incident_hook`] as `Hooks::on_incidents` only when the console is
//! enabled. Every insert is guarded twice: it writes only for an incident row the batch
//! really inserted (a replayed batch whose first commit succeeded inserts none), and it does
//! nothing when the sidecar exists. The hook never fails on a value it cannot store: such a
//! value is left out or made storable, because a failing hook rolls the batch back and the
//! storage thread would retry it for ever. Deleting an incident deletes its sidecars through
//! the foreign keys' `ON DELETE CASCADE` (S36, with `Database::delete_incidents`).
//!
//! # Changes from the Zig version
//!
//! - Heads are bytes, not hex text; the evidence row has no `version` column.
//! - Zig asserted that the evidence was of version 1 and that the country code was two
//!   upper-case letters, and its SQL failed for a status outside 100 to 599 or truncation
//!   bits beyond 255. Here an unusable status leaves the evidence out, truncation keeps its
//!   low eight bits (the seven Zig defined and one spare), a code that is not two upper-case
//!   letters is stored as Unknown, and heads with the unrecordable state `unknown` are left
//!   out, so one bad value cannot stall the incident writer.

use sibuna_core::incident_heads::ResponseState;
use sibuna_storage::{BatchIncident, IncidentHook, Param, Sql, StorageError, Transaction};

/// Where an address lies in the loaded GeoIP generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CountryMapping {
    /// The ISO 3166-1 alpha-2 code; `None` when the address maps to no country (Unknown).
    pub country: Option<[u8; 2]>,
    /// The SHA-256 digest of the generation that mapped it.
    pub generation: [u8; 32],
}

/// Maps a client address to its country in the loaded GeoIP generation; returns `None`
/// while no generation is loaded. It runs on the storage thread for every incident.
pub type CountryLookup = Box<dyn Fn(&str) -> Option<CountryMapping> + Send>;

const INSERT_EVIDENCE: Sql = Sql::both(
    "INSERT INTO console_incident_evidence (incident_id, selected_status, query_bytes, \
     body_bytes, declared_body_bytes, truncated) \
     SELECT $1, $2, $3, $4, $5, $6 WHERE EXISTS (SELECT 1 FROM security_incidents WHERE id = $1) \
     ON CONFLICT (incident_id) DO NOTHING",
);
const INSERT_HEADS: Sql = Sql::both(
    "INSERT INTO console_incident_heads (incident_id, request_head, response_head, \
     request_truncated, response_truncated, response_state) \
     SELECT $1, $2, $3, ($4 <> 0), ($5 <> 0), $6 \
     WHERE EXISTS (SELECT 1 FROM security_incidents WHERE id = $1) \
     ON CONFLICT (incident_id) DO NOTHING",
);
const INSERT_COUNTRY: Sql = Sql::both(
    "INSERT INTO console_incident_country (incident_id, country, generation) \
     SELECT $1, $2, $3 WHERE EXISTS (SELECT 1 FROM security_incidents WHERE id = $1) \
     ON CONFLICT (incident_id) DO NOTHING",
);

/// Returns the incident hook that writes the sidecars of each batch, mapping addresses with
/// `country` when one is given. The hook borrows the batch's transaction and incidents; it
/// fails only with the driver's error.
///
/// An incident keeps the country it was first mapped with: when a batch rolls back and is
/// retried, the mappings of the failed attempt are reused, so a GeoIP generation activated
/// in between does not change them (as in Zig, which fixed them when it prepared the batch).
/// Only the last attempt's mappings are kept.
pub fn incident_hook(country: Option<CountryLookup>) -> IncidentHook {
    let mut previous: Vec<(i64, Option<CountryMapping>)> = Vec::new();
    Box::new(move |tx, incidents| {
        let mappings: Vec<Option<CountryMapping>> = incidents
            .iter()
            .enumerate()
            .map(|(index, incident)| {
                // A retry presents the batch in the same order; search only if it does not.
                let same = previous.get(index).filter(|(id, _)| *id == incident.id);
                match same.or_else(|| previous.iter().find(|(id, _)| *id == incident.id)) {
                    Some(&(_, mapping)) => mapping,
                    None => country.as_ref().and_then(|lookup| lookup(incident.client_ip)),
                }
            })
            .collect();
        previous.clear();
        previous
            .extend(incidents.iter().map(|incident| incident.id).zip(mappings.iter().copied()));
        Box::pin(async move {
            for (incident, mapping) in incidents.iter().zip(mappings) {
                write_sidecars(tx, incident, mapping).await?;
            }
            Ok(())
        })
    })
}

/// Writes the sidecars of one incident. Fails with the driver's error.
pub async fn write_sidecars(
    tx: &mut Transaction,
    incident: &BatchIncident<'_>,
    country: Option<CountryMapping>,
) -> Result<(), StorageError> {
    let evidence = incident.evidence;
    if evidence.version != 0 && (100..=599).contains(&evidence.selected_status) {
        let params: [Param<'_>; 6] = [
            incident.id.into(),
            i64::from(evidence.selected_status).into(),
            i64::from(evidence.query_bytes).into(),
            i64::from(evidence.body_bytes).into(),
            i64::from(evidence.declared_body_bytes).into(),
            i64::from(evidence.truncated & 0xff).into(),
        ];
        tx.execute(INSERT_EVIDENCE, &params).await?;
    }
    let captured = !incident.request_head.is_empty() || !incident.response_head.is_empty();
    if let Some(state) = state_name(incident.response_state).filter(|_| captured) {
        // Only a captured response keeps its head; the schema refuses one for other states.
        let keep = incident.response_state == ResponseState::Captured;
        let response: &[u8] = if keep { incident.response_head } else { &[] };
        let params: [Param<'_>; 6] = [
            incident.id.into(),
            incident.request_head.into(),
            response.into(),
            i64::from(incident.request_truncated).into(),
            i64::from(keep && incident.response_truncated).into(),
            state.into(),
        ];
        tx.execute(INSERT_HEADS, &params).await?;
    }
    if let Some(mapping) = country {
        let code = mapping.country.filter(|code| code.iter().all(u8::is_ascii_uppercase));
        let code = code.as_ref().and_then(|code| std::str::from_utf8(code).ok());
        let params: [Param<'_>; 3] =
            [incident.id.into(), code.into(), mapping.generation.as_slice().into()];
        tx.execute(INSERT_COUNTRY, &params).await?;
    }
    Ok(())
}

/// The stored name of a response state; `None` for `Unknown`, which only old Zig rows had.
pub fn state_name(state: ResponseState) -> Option<&'static str> {
    match state {
        ResponseState::Unknown => None,
        ResponseState::Captured => Some("captured"),
        ResponseState::Local => Some("local"),
        ResponseState::Unobserved => Some("unobserved"),
        ResponseState::Unavailable => Some("unavailable"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_recordable_state_has_the_name_its_check_lists() {
        let names: Vec<_> = [
            ResponseState::Unknown,
            ResponseState::Captured,
            ResponseState::Local,
            ResponseState::Unobserved,
            ResponseState::Unavailable,
        ]
        .into_iter()
        .map(state_name)
        .collect();
        assert_eq!(
            names,
            [None, Some("captured"), Some("local"), Some("unobserved"), Some("unavailable")]
        );
    }
}
