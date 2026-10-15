//! S16: replacing every rule with the set of one import request.
//!
//! The accepted review of SID 0013 made an import one bounded request: at most 128
//! documents (the engine's rule capacity) within the policy crate's file bound of 256 KiB.
//! The set is validated by composing the candidate it would publish and is applied in one
//! transaction, so nothing is staged. Zig staged documents in chunks under a client-chosen
//! digest; here the digest the audit names is computed from the request.

use sibuna_policy::MAX_RULES;
use sibuna_policy::candidate::{MAX_FILE_BYTES, Options};
use sibuna_policy::management::{self, MAX_DOCUMENT};
use sibuna_storage::{Sql, Transaction};

use super::summary::SummaryWriter;
use super::{HistoryKind, Inputs, POLICY_WRITE, insert_history, policy_audit, refusal};
use crate::access::{self, Credential};
use crate::audit::{self, AuditAction};
use crate::error::ConsoleStorageError;
use crate::revision;
use crate::row;

/// One import request: the complete rule set that replaces every stored rule.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Import {
    /// The revision the operator saw.
    pub expected_revision: u64,
    /// 1 to 128 management documents of at most 4,096 bytes each, at most 256 KiB in all.
    pub documents: Vec<String>,
}

impl Import {
    /// Checks the request's bounds. Fails with [`ConsoleStorageError::InvalidInput`].
    fn validate(&self) -> Result<(), ConsoleStorageError> {
        let count = self.documents.len();
        if count == 0 || count > MAX_RULES {
            return Err(ConsoleStorageError::InvalidInput("import document count"));
        }
        let mut total: usize = 0;
        for document in &self.documents {
            if document.is_empty() || document.len() > MAX_DOCUMENT {
                return Err(ConsoleStorageError::InvalidInput("import document size"));
            }
            total = total.saturating_add(document.len());
        }
        if total > MAX_FILE_BYTES {
            return Err(ConsoleStorageError::InvalidInput("import size"));
        }
        if self.expected_revision >= row::MAX_INTEGER {
            return Err(ConsoleStorageError::InvalidInput("expected revision"));
        }
        Ok(())
    }
}

/// Returns the lowercase hex SHA-256 of an import's documents, each followed by a line
/// feed (the set as JSON lines): the digest `policy.import` names.
pub fn import_digest(documents: &[String]) -> String {
    let mut hasher = sibuna_crypto::sha256::Sha256::new();
    for document in documents {
        hasher.update(document.as_bytes());
        hasher.update(b"\n");
    }
    sibuna_encoding::hex::encode(&hasher.finalize())
}

const DELETE_ALL: Sql = Sql::both("DELETE FROM policies");

/// Replaces every stored rule with `import.documents` at `import.expected_revision` (S16):
/// parses every document, composes the candidate engine of exactly this set on `base`
/// (with the stored reputation and inspection), deletes every rule, inserts the set, writes
/// one edit history row per rule, advances the policy revision to the expected revision
/// plus one, and audits `policy.import` with the set's digest and count. Returns the
/// committed revision. The credential is `credential`.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a request outside its bounds or a
/// set that does not validate (the text names Zig's error, such as `DuplicateId`), like
/// [`access::authorize_in`] for policy writers, with [`ConsoleStorageError::Conflict`] for
/// a stale revision, and with the driver's error.
pub async fn import_rules(
    tx: &mut Transaction,
    credential: &Credential,
    base: &Options<'_>,
    import: &Import,
    now: u64,
) -> Result<u64, ConsoleStorageError> {
    import.validate()?;
    let documents = import
        .documents
        .iter()
        .map(|source| management::parse(source.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| ConsoleStorageError::InvalidInput(error.name()))?;
    let principal = access::authorize_in(tx, credential, POLICY_WRITE, now).await?;
    let lock = revision::lock(tx, import.expected_revision).await?;
    let sources: Vec<&[u8]> = import.documents.iter().map(|text| text.as_bytes()).collect();
    Inputs::load(tx, now, None).await?.compose_sources(base, &sources).map_err(refusal)?;
    let committed = lock.expected().checked_add(1).ok_or(ConsoleStorageError::Capacity)?;
    tx.execute(DELETE_ALL, &[]).await?;
    let edited = (HistoryKind::Edit, Some(principal.actor));
    for (document, source) in documents.iter().zip(&import.documents) {
        super::rules::store(tx, document, now).await?;
        insert_history(tx, &document.id, committed, edited, now, source).await?;
    }
    let revision = revision::advance(tx, lock).await?;
    let digest = import_digest(&import.documents);
    let after = SummaryWriter::new()
        .int("count", i64::try_from(documents.len()).unwrap_or(i64::MAX))
        .text("sha256", &digest)
        .finish();
    let row = audit::AuditRow {
        target: Some(digest),
        after: Some(after),
        ..policy_audit(&principal, credential, AuditAction::PolicyImport, revision, now)
    };
    audit::append_audit(tx, &row).await?;
    Ok(revision)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_are_bounded() {
        let document = r#"{"id":"a","name":"A","action":"deny"}"#.to_owned();
        let import = Import { expected_revision: 0, documents: vec![document.clone()] };
        assert!(import.validate().is_ok());
        let empty = Import { documents: Vec::new(), ..import.clone() };
        assert!(empty.validate().is_err());
        let many = Import { documents: vec![document.clone(); MAX_RULES + 1], ..import.clone() };
        assert!(many.validate().is_err());
        let large = Import { documents: vec!["x".repeat(MAX_DOCUMENT + 1)], ..import.clone() };
        assert!(large.validate().is_err());
        let total = Import { documents: vec!["x".repeat(MAX_DOCUMENT); 65], ..import.clone() };
        assert!(total.validate().is_err());
        let stale = Import { expected_revision: row::MAX_INTEGER, ..import };
        assert!(stale.validate().is_err());
    }

    #[test]
    fn the_digest_covers_the_documents_as_json_lines() {
        let digest = import_digest(&["{}".to_owned(), "[]".to_owned()]);
        let expected = sibuna_crypto::sha256::Sha256::digest(b"{}\n[]\n");
        assert_eq!(digest, sibuna_encoding::hex::encode(&expected));
        assert_eq!(digest.len(), 64);
    }
}
