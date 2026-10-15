//! Private candidate engines composed from the stored policy, the way the next rebuild would
//! compose them, so a workflow is refused before it commits a policy that cannot publish.
//!
//! The caller passes the daemon's composition [`Options`] (its default difficulty, WAF
//! switch and policy file); storage adds the stored rules (as management documents), the
//! decisive unexpired reputation rows and the stored inspection override. Zig's
//! `console_policy_candidate.zig` read the same rows in pages of eight and 64 with a
//! two-megabyte arena; here the reads are bounded by row limits one past each capacity.

use sibuna_policy::candidate::{self, CandidateError, MAX_REPUTATIONS, Options, Reputation};
use sibuna_policy::{Action, Engine, MAX_RULES, Mode, Modes};
use sibuna_storage::{Sql, Transaction};

use super::rules::{self, StoredRule};
use crate::error::ConsoleStorageError;
use crate::row::{self, Fields};

const REPUTATION: Sql = Sql::both(
    "SELECT r.ip_or_cidr, r.reputation_score FROM ip_reputation r \
     WHERE (r.banned_until IS NULL OR r.banned_until > $1) \
     AND (r.reputation_score <= -50 OR r.reputation_score >= 50) \
     AND ($2 IS NULL OR NOT EXISTS (SELECT 1 FROM console_reputation_sources s \
     WHERE s.ip_or_cidr = r.ip_or_cidr AND s.country = $2)) LIMIT $3",
);

const INSPECTION: Sql =
    Sql::both("SELECT path_traversal, sqli, xss, rce FROM policy_inspection WHERE id = 1");

/// The stored inputs of a candidate, read in the caller's transaction.
#[derive(Debug, Default)]
pub(crate) struct Inputs {
    /// Each rule's id and management document, by id.
    pub(crate) documents: Vec<(String, String)>,
    /// Decisive reputation prefixes with their action.
    pub(crate) reputation: Vec<(String, Action)>,
    /// The stored inspection override.
    pub(crate) inspection: Option<Modes>,
}

impl Inputs {
    /// Reads every stored rule, the reputation rows decisive at `now` (without the prefixes
    /// a country action of `omit_country` owns), and the inspection override.
    ///
    /// Fails with [`ConsoleStorageError::InvalidInput`] naming Zig's error when the rows
    /// exceed an engine (`TooManyDocuments`, `TooManyReputations`), with
    /// [`sibuna_storage::StorageError::InvalidRow`] for a row the types cannot hold, and
    /// with the driver's error.
    pub(crate) async fn load(
        tx: &mut Transaction,
        now: u64,
        omit_country: Option<&str>,
    ) -> Result<Inputs, ConsoleStorageError> {
        let documents = load_documents(tx).await?;
        let reputation = load_reputation(tx, now, omit_country).await?;
        let inspection = load_inspection(tx).await?;
        Ok(Inputs { documents, reputation, inspection })
    }

    /// Replaces the document whose id is `id` by `source`, or adds `source` when no stored
    /// rule has the id, and returns the replaced document.
    pub(crate) fn replace(&mut self, id: &str, source: &str) -> Option<String> {
        match self.documents.iter_mut().find(|(stored, _)| stored == id) {
            Some((_, document)) => Some(std::mem::replace(document, source.to_owned())),
            None => {
                self.documents.push((id.to_owned(), source.to_owned()));
                None
            }
        }
    }

    /// Composes the candidate engine on `base`, then applies the inspection override.
    pub(crate) fn compose(&self, base: &Options<'_>) -> Result<Engine, CandidateError> {
        let sources: Vec<&[u8]> =
            self.documents.iter().map(|(_, document)| document.as_bytes()).collect();
        self.compose_sources(base, &sources)
    }

    /// Composes a candidate from `sources` instead of the stored rules (an import).
    pub(crate) fn compose_sources(
        &self,
        base: &Options<'_>,
        sources: &[&[u8]],
    ) -> Result<Engine, CandidateError> {
        let reputation: Vec<Reputation<'_>> = self
            .reputation
            .iter()
            .map(|(cidr, action)| Reputation { cidr: cidr.as_bytes(), action: *action })
            .collect();
        let mut engine = candidate::compose(base, sources, &reputation)?;
        if let Some(modes) = self.inspection {
            engine.inspection_modes = modes;
        }
        Ok(engine)
    }
}

/// Returns the refusal of a candidate that does not compose: Zig answered every candidate
/// error with `invalid_input` (`draftFailure`); the text is Zig's error name.
pub(crate) fn refusal(error: CandidateError) -> ConsoleStorageError {
    ConsoleStorageError::InvalidInput(error.name())
}

async fn load_documents(
    tx: &mut Transaction,
) -> Result<Vec<(String, String)>, ConsoleStorageError> {
    let limit = row::int(MAX_RULES as u64 + 1)?;
    let rows = tx.fetch_all(rules::ALL, &[limit.into()]).await?;
    if rows.len() > MAX_RULES {
        return Err(refusal(CandidateError::TooManyDocuments));
    }
    rows.into_iter()
        .map(|cells| {
            let rule = StoredRule::decode(Fields::new(cells, "policies"))?;
            let document = rule.document();
            Ok((rule.id, document))
        })
        .collect()
}

async fn load_reputation(
    tx: &mut Transaction,
    now: u64,
    omit_country: Option<&str>,
) -> Result<Vec<(String, Action)>, ConsoleStorageError> {
    let limit = row::int(MAX_REPUTATIONS as u64 + 1)?;
    let params = [row::int(now)?.into(), omit_country.into(), limit.into()];
    let rows = tx.fetch_all(REPUTATION, &params).await?;
    if rows.len() > MAX_REPUTATIONS {
        return Err(refusal(CandidateError::TooManyReputations));
    }
    rows.into_iter()
        .map(|cells| {
            let mut fields = Fields::new(cells, "ip_reputation");
            let cidr = fields.text("ip_or_cidr")?;
            let score: i32 = fields.integer("reputation_score")?;
            Ok((cidr, if score < 0 { Action::Deny } else { Action::Allow }))
        })
        .collect()
}

/// Returns the stored inspection override, if any.
pub(crate) async fn load_inspection(
    tx: &mut Transaction,
) -> Result<Option<Modes>, ConsoleStorageError> {
    let Some(cells) = row::first(tx.fetch_all(INSPECTION, &[]).await?) else {
        return Ok(None);
    };
    let mut fields = Fields::new(cells, "policy_inspection");
    let mode = |text: &str| Mode::parse(text.as_bytes());
    Ok(Some(Modes {
        path_traversal: fields.parsed("path_traversal", mode)?,
        sqli: fields.parsed("sqli", mode)?,
        xss: fields.parsed("xss", mode)?,
        rce: fields.parsed("rce", mode)?,
    }))
}
