//! The routes `challenges/summary`, `challenges/records` and `challenges/difficulty` (the
//! stored windows of Zig's `challenge_routes.zig`; the live snapshot is `api/live`).
//!
//! Each reads a window of 1, 24 or 168 hours ending now. A summary sums durable challenge
//! minutes ending at the last sealed minute, one bounded part at a time, and a longer
//! window continues from the returned cursor; records and difficulty transitions are
//! pages of stored rows.

use sibuna_console_protocol::challenge_minutes;
use sibuna_console_protocol::challenge_records::{self, DifficultyQuery, Outcome};
use sibuna_console_protocol::codec::{Decode, DecodeError, Fields, Path};
use sibuna_console_protocol::{Text, minutes};
use sibuna_console_storage::observations::{
    query_challenge_records, query_difficulty, summarize_challenges,
};
use sibuna_json::Value;
use sibuna_serve::Context;

use super::events::read_error;
use super::policies::{spend, work_bound};
use crate::collector::configured_bin;
use crate::dispatch::Call;
use crate::http::body::read_json;
use crate::http::{RouteError, reply};
use crate::limits::Spend;
use crate::routes::Handler;
use crate::shared::Shared;

/// The failure code of these routes.
const CODE: &str = "CONSOLECHALLENGE";

/// Serves `call.route`, one of this module's routes, after the dispatcher's checks.
///
/// Fails with 429 `CONSOLE429` past the query allowance, 400 `CONSOLE002` for a window
/// other than 1, 24 or 168 hours, and `CONSOLECHALLENGE` for refused or unanswered reads.
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    match call.route.handler {
        Handler::ChallengeSummary => summary(shared, context, call),
        Handler::ChallengeRecords => records(shared, context, call),
        Handler::ChallengeDifficulty => difficulty(shared, context, call),
        _ => Err(RouteError::Unavailable),
    }
}

/// Checks a window length.
fn hours(hours: u16) -> Result<u64, RouteError> {
    match hours {
        1 | 24 | 168 => Ok(u64::from(hours)),
        _ => Err(RouteError::BadRequest),
    }
}

/// A summary cursor as the interface sends it: the boot as 32 hex digits.
struct CursorForm {
    minute: u64,
    node: u32,
    boot: String,
    epoch: u32,
}

impl Decode for CursorForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<CursorForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = CursorForm {
            minute: fields.required("minute")?,
            node: fields.required("node")?,
            boot: fields.required("boot")?,
            epoch: fields.required("epoch")?,
        };
        fields.finish()?;
        Ok(form)
    }
}

impl CursorForm {
    fn cursor(&self) -> Result<minutes::Cursor, RouteError> {
        let mut boot = [0u8; 16];
        if self.boot.len() != 32
            || sibuna_encoding::hex::decode_to_slice(self.boot.as_bytes(), &mut boot).is_err()
        {
            return Err(RouteError::BadRequest);
        }
        Ok(minutes::Cursor { minute: self.minute, node: self.node, boot, epoch: self.epoch })
    }
}

/// The body of `challenges/summary`.
struct SummaryForm {
    hours: u16,
    node: Option<u32>,
    bin: Option<u8>,
    before: Option<CursorForm>,
}

impl Decode for SummaryForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<SummaryForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = SummaryForm {
            hours: fields.or("hours", 24)?,
            node: fields.or_default("node")?,
            bin: fields.or_default("bin")?,
            before: fields.or_with("before", None, |value, path| match value {
                Value::Null => Ok(None),
                _ => CursorForm::decode(value, path).map(Some),
            })?,
        };
        fields.finish()?;
        Ok(form)
    }
}

/// `challenges/summary`: durable challenge minutes summed under the work bound.
fn summary(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    spend(shared, call, Spend::Query, "CONSOLE429")?;
    let mut body = [0u8; 512];
    let form: SummaryForm = read_json(context, &mut body)?;
    let now = call.now;
    let until = (now / 60).saturating_sub(1);
    let query = challenge_minutes::Query {
        session_digest: [0; 32],
        require_totp: shared.config.behind_proxy,
        observed_at: now,
        from_minute: until.saturating_sub(hours(form.hours)? * 60 - 1),
        until_minute: until,
        node: form.node,
        before: form.before.as_ref().map(CursorForm::cursor).transpose()?,
        selected: form.bin.unwrap_or(configured_bin(&shared.identity.challenge_defaults)),
        ..challenge_minutes::Query::default()
    };
    let credential = call.credential(shared)?;
    let bound = work_bound(shared);
    let summary = shared
        .storage
        .transact(move |tx| {
            Box::pin(
                async move { summarize_challenges(tx, &credential, &query, bound, now).await },
            )
        })
        .map_err(|failure| read_error(failure, CODE))?;
    Ok(reply::json(context, &summary)?)
}

/// The body of `challenges/records`.
struct RecordsForm {
    hours: u16,
    node: Option<u32>,
    outcome: Option<Outcome>,
    cause: Option<u8>,
    address: Text<48>,
    before: Option<challenge_records::Cursor>,
}

impl Decode for RecordsForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<RecordsForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = RecordsForm {
            hours: fields.or("hours", 24)?,
            node: fields.or_default("node")?,
            outcome: fields.or_default("outcome")?,
            cause: fields.or_default("cause")?,
            address: fields.or_default("address")?,
            before: fields.or_default("before")?,
        };
        fields.finish()?;
        Ok(form)
    }
}

/// `challenges/records`: per-address challenge records of the window.
fn records(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    spend(shared, call, Spend::Query, "CONSOLE429")?;
    let mut body = [0u8; 512];
    let form: RecordsForm = read_json(context, &mut body)?;
    let now = call.now;
    let query = challenge_records::Query {
        session_digest: [0; 32],
        require_totp: shared.config.behind_proxy,
        observed_at: now,
        from: now.saturating_sub(hours(form.hours)? * 3600),
        until: now,
        node: form.node,
        outcome: form.outcome,
        cause: form.cause,
        address: form.address,
        before: form.before,
        ..challenge_records::Query::default()
    };
    let credential = call.credential(shared)?;
    let mut page = shared
        .storage
        .transact(move |tx| {
            Box::pin(async move { query_challenge_records(tx, &credential, &query, now).await })
        })
        .map_err(|failure| read_error(failure, CODE))?;
    // Losses since boot are this node's, not storage's.
    shared.live.record_coverage(shared).fill_records(&mut page);
    Ok(reply::json(context, &page)?)
}

/// The body of `challenges/difficulty`.
struct DifficultyForm {
    hours: u16,
    node: Option<u32>,
}

impl Decode for DifficultyForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<DifficultyForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form =
            DifficultyForm { hours: fields.or("hours", 24)?, node: fields.or_default("node")? };
        fields.finish()?;
        Ok(form)
    }
}

/// `challenges/difficulty`: adaptive-difficulty transitions of the window.
fn difficulty(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    spend(shared, call, Spend::Query, "CONSOLE429")?;
    let mut body = [0u8; 256];
    let form: DifficultyForm = read_json(context, &mut body)?;
    let now = call.now;
    let query = DifficultyQuery {
        session_digest: [0; 32],
        require_totp: shared.config.behind_proxy,
        observed_at: now,
        from: now.saturating_sub(hours(form.hours)? * 3600),
        until: now,
        node: form.node,
        ..DifficultyQuery::default()
    };
    let credential = call.credential(shared)?;
    let mut page = shared
        .storage
        .transact(move |tx| {
            Box::pin(async move { query_difficulty(tx, &credential, &query, now).await })
        })
        .map_err(|failure| read_error(failure, CODE))?;
    shared.live.record_coverage(shared).fill_difficulty(&mut page);
    Ok(reply::json(context, &page)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_console_protocol::codec::from_json;

    #[test]
    fn forms_accept_the_interface_bodies() {
        let summary: SummaryForm = from_json(br#"{"hours":24,"bin":null,"before":null}"#).unwrap();
        assert_eq!((summary.hours, summary.bin), (24, None));
        let cursor: SummaryForm = from_json(
            br#"{"hours":1,"bin":3,"before":{"minute":9,"node":1,
            "boot":"0707070707070707070707070707070707","epoch":2}}"#,
        )
        .unwrap();
        assert_eq!(cursor.before.unwrap().cursor(), Err(RouteError::BadRequest));
        let records: RecordsForm =
            from_json(br#"{"hours":24,"outcome":"rejected","cause":3,"before":null}"#).unwrap();
        assert_eq!(records.outcome, Some(Outcome::Rejected));
        let difficulty: DifficultyForm = from_json(br#"{"hours":24}"#).unwrap();
        assert_eq!(hours(difficulty.hours), Ok(24));
        assert_eq!(hours(2), Err(RouteError::BadRequest));
    }
}
