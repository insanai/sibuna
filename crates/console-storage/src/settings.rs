//! Operator settings: S20, the settings read, and the typed catalogue other jobs read.
//!
//! | Id  | Invariant                                                      | Function           |
//! |-----|----------------------------------------------------------------|--------------------|
//! | S20 | a setting change is within the catalogue's bounds, matches the | [`change_setting`] |
//! |     | expected revision, and writes `setting.change` with the old    |                    |
//! |     | and new value                                                  |                    |
//!
//! The catalogue is the protocol's ([`sibuna_console_protocol::settings::CATALOG`]): six
//! integer settings, each from 1 to its maximum; a missing row means the default. The
//! `CHECK` of `console_settings.value` states the same bounds. No other function writes
//! `console_settings`.

use sibuna_console_protocol::notifications::{self, Setting, SettingChange, SettingsPage};
use sibuna_console_protocol::settings::{self, Definition, Group};
use sibuna_console_protocol::{Action, Text};
use sibuna_storage::{Param, Sql, Transaction};

use crate::access::{self, Credential, Need};
use crate::audit::summary::Summary;
use crate::audit::{self, AuditAction, AuditRow};
use crate::error::ConsoleStorageError;
use crate::row::{self, Fields};

/// What settings require: an administrator's browser session with its CSRF digest, for the
/// read too (Zig's settings authority). Tokens are refused.
pub const SETTINGS_NEED: Need = Need::mutation(Action::ManageSettings, None);

/// One key of the catalogue, in catalogue order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SettingKey {
    /// `notify.spike_factor`: the denial-spike multiplier, 1 to 1,000,000 (default 3).
    SpikeFactor,
    /// `notify.spike_minimum`: the fewest denials a spike needs, 1 to 1,000,000 (100).
    SpikeMinimum,
    /// `retention.minutes`: days of minute history, 1 to 90 (90).
    RetentionMinutes,
    /// `retention.rankings`: days of ranking archives, 1 to 7 (7).
    RetentionRankings,
    /// `retention.incidents`: days of incidents, 1 to 30 (30).
    RetentionIncidents,
    /// `retention.audit`: days of audit and policy history, 1 to 365 (365).
    RetentionAudit,
}

impl SettingKey {
    /// Every key, in catalogue order.
    pub const ALL: [SettingKey; 6] = [
        SettingKey::SpikeFactor,
        SettingKey::SpikeMinimum,
        SettingKey::RetentionMinutes,
        SettingKey::RetentionRankings,
        SettingKey::RetentionIncidents,
        SettingKey::RetentionAudit,
    ];

    /// Returns the protocol's definition of the key.
    pub fn definition(self) -> &'static Definition {
        // `ALL` lists the catalogue's keys in its order; the unit tests check it.
        &settings::CATALOG[self as usize]
    }

    /// Returns the stored key, such as `retention.audit`.
    pub fn as_str(self) -> &'static str {
        self.definition().key
    }

    /// Returns the key stored as `name`, if any.
    pub fn parse(name: &str) -> Option<SettingKey> {
        SettingKey::ALL.into_iter().find(|key| key.as_str() == name)
    }

    /// Returns the largest value; the smallest is 1.
    pub fn maximum(self) -> u32 {
        self.definition().maximum
    }

    /// Returns the value a missing row means.
    pub fn default_value(self) -> u32 {
        // The catalogue's defaults are decimal constants within their bounds (unit tests).
        self.definition().default.parse().unwrap_or(1)
    }

    /// Returns true for a retention period, whose change needs the operator's confirmation.
    pub fn is_retention(self) -> bool {
        self.definition().group == Group::Retention
    }
}

const READ: Sql = Sql {
    sqlite: "SELECT value, revision FROM console_settings WHERE key = $1",
    postgres: "SELECT value, revision FROM console_settings WHERE key = $1 FOR UPDATE",
};
const INSERT: Sql = Sql::both(
    "INSERT INTO console_settings (key, value, revision, updated_at, updated_by) \
     VALUES ($1, $2, 1, $3, $4) ON CONFLICT (key) DO NOTHING",
);
const UPDATE: Sql = Sql::both(
    "UPDATE console_settings SET value = $2, revision = revision + 1, updated_at = $3, \
     updated_by = $4 WHERE key = $1 AND revision = $5",
);

/// Returns the value and revision of the row of `key`, locking it on PostgreSQL.
async fn stored(
    tx: &mut Transaction,
    key: SettingKey,
) -> Result<Option<(u32, u64)>, ConsoleStorageError> {
    let Some(cells) = row::first(tx.fetch_all(READ, &[key.as_str().into()]).await?) else {
        return Ok(None);
    };
    let mut fields = Fields::new(cells, "console_settings");
    Ok(Some((fields.integer("value")?, fields.integer("revision")?)))
}

/// Returns the value of `key`: the stored one, or the catalogue's default. Jobs such as
/// retention read their periods with it in their own transaction. Reads only.
///
/// Fails with [`sibuna_storage::StorageError::InvalidRow`] for a stored value outside the
/// key's bounds, and with the driver's error.
pub async fn current(tx: &mut Transaction, key: SettingKey) -> Result<u32, ConsoleStorageError> {
    const VALUE: Sql = Sql::both("SELECT value FROM console_settings WHERE key = $1");
    let Some(cells) = row::first(tx.fetch_all(VALUE, &[key.as_str().into()]).await?) else {
        return Ok(key.default_value());
    };
    let mut fields = Fields::new(cells, "console_settings");
    let value: u32 = fields.integer("value")?;
    if !(1..=key.maximum()).contains(&value) {
        return Err(fields.invalid("value"));
    }
    Ok(value)
}

/// Changes one setting at its expected revision and audits it (S20): `change.value` must
/// be 1 to 7 decimal digits within the key's bounds, a retention period needs
/// `change.confirmed`, and an expected revision of 0 creates the row (revision 1) only when
/// none exists, while any other updates it only at that revision. Writes `setting.change`
/// with the old value (on an update) and the new one, as text as Zig wrote them. Returns
/// the new revision. The credential is `credential`; `change.auth` is not read.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for an unknown key, a value outside the
/// catalogue, an unconfirmed retention change or a revision of 2^63 - 1, like
/// [`access::authorize_in`] for an administrator's browser session, with
/// [`ConsoleStorageError::Conflict`] for a stale revision, and with the driver's error.
pub async fn change_setting(
    tx: &mut Transaction,
    credential: &Credential,
    change: &SettingChange,
    now: u64,
) -> Result<u64, ConsoleStorageError> {
    let key = SettingKey::parse(change.key.as_str())
        .ok_or(ConsoleStorageError::InvalidInput("setting key"))?;
    let valid = settings::is_valid(key.as_str(), change.value.as_str());
    let value: u32 = change.value.as_str().parse().unwrap_or(0);
    if !valid || value == 0 || change.expected_revision >= row::MAX_INTEGER {
        return Err(ConsoleStorageError::InvalidInput("setting value"));
    }
    if key.is_retention() && !change.confirmed {
        return Err(ConsoleStorageError::InvalidInput("an unconfirmed retention change"));
    }
    let principal = access::authorize_in(tx, credential, SETTINGS_NEED, now).await?;
    let before = stored(tx, key).await?;
    let shared: [Param<'_>; 4] = [
        key.as_str().into(),
        i64::from(value).into(),
        row::int(now)?.into(),
        row::int(principal.actor)?.into(),
    ];
    let revision = match before {
        None if change.expected_revision == 0 => {
            if tx.execute(INSERT, &shared).await? != 1 {
                return Err(ConsoleStorageError::Conflict);
            }
            1
        }
        Some((_, revision)) if revision == change.expected_revision => {
            let mut params = shared.to_vec();
            params.push(row::int(revision)?.into());
            if tx.execute(UPDATE, &params).await? != 1 {
                return Err(ConsoleStorageError::Conflict);
            }
            revision.checked_add(1).ok_or(ConsoleStorageError::Capacity)?
        }
        _ => return Err(ConsoleStorageError::Conflict),
    };
    let summary = |value: u32| Summary::new().text("value", &value.to_string()).finish();
    let row = AuditRow {
        subject: Some(revision),
        target: Some(key.as_str().to_owned()),
        client_ip: credential.client.clone(),
        before: before.map(|(old, _)| summary(old)),
        after: Some(summary(value)),
        ..AuditRow::by(&principal, AuditAction::SettingChange, now)
    };
    audit::append_audit(tx, &row).await?;
    Ok(revision)
}

const PAGE: Sql = Sql::both(
    "SELECT key, value, revision, updated_at, updated_by FROM console_settings \
     ORDER BY key LIMIT 8",
);

/// Reads the stored settings by key (keys without a row hold their default and are not
/// listed). The credential is `credential`.
///
/// Fails like [`access::authorize_in`] for an administrator's browser session, with
/// [`sibuna_storage::StorageError::InvalidRow`] for a stored row outside the catalogue,
/// and with the driver's error.
pub async fn query_settings(
    tx: &mut Transaction,
    credential: &Credential,
    now: u64,
) -> Result<SettingsPage, ConsoleStorageError> {
    access::authorize_in(tx, credential, SETTINGS_NEED, now).await?;
    let rows = tx.fetch_all(PAGE, &[]).await?;
    let rows = rows
        .into_iter()
        .map(|cells| {
            let mut fields = Fields::new(cells, "console_settings");
            let key = fields.parsed("key", SettingKey::parse)?;
            let value: u32 = fields.integer("value")?;
            if !(1..=key.maximum()).contains(&value) {
                return Err(fields.invalid("value"));
            }
            Ok(Setting {
                key: Text::new(key.as_str()).map_err(|_| fields.invalid("key"))?,
                value: Text::new(&value.to_string()).map_err(|_| fields.invalid("value"))?,
                revision: fields.integer("revision")?,
                updated_at: fields.integer("updated_at")?,
                updated_by: fields.integer("updated_by")?,
            })
        })
        .collect::<Result<Vec<_>, ConsoleStorageError>>()?;
    debug_assert!(rows.len() <= notifications::KNOWN_SETTINGS.len());
    Ok(SettingsPage { rows })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_follow_the_catalogue() {
        for (key, definition) in SettingKey::ALL.into_iter().zip(&settings::CATALOG) {
            assert_eq!(key.as_str(), definition.key);
            assert_eq!(SettingKey::parse(definition.key), Some(key));
            assert!((1..=key.maximum()).contains(&key.default_value()));
            assert_eq!(key.default_value().to_string(), definition.default);
        }
        assert_eq!(SettingKey::parse("retention.other"), None);
        assert!(SettingKey::RetentionAudit.is_retention());
        assert!(!SettingKey::SpikeFactor.is_retention());
        let defaults: Vec<u32> = SettingKey::ALL.iter().map(|key| key.default_value()).collect();
        assert_eq!(defaults, [3, 100, 90, 7, 30, 365]);
    }
}
