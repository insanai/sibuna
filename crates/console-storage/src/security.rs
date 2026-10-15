//! The security overview and trends (`security/query`, `security/trends`; SID 0007): counts
//! of retained incidents in a window of at most 30 days, by finding source (inspection,
//! honeypot, other) with a 60-bucket trend and the top three addresses, or the top five
//! categories or paths.
//!
//! Every statement aggregates over the window and runs under the work bound
//! ([`crate::bound`]). Counts describe retained incident rows, not all attacks. An
//! aggregate-only read (the kiosk's trends) never selects addresses, paths or categories.
//!
//! # Changes from the Zig version
//!
//! - Zig ran one statement with `MATERIALIZED` common table expressions and packed each
//!   trend into a text cell. Here each part (totals, trend buckets, ranked sources, ranked
//!   labels) is one statement in the same transaction, written for both dialects; the
//!   classification compares prefixes with `substr`, which both dialects evaluate by
//!   bytes, where Zig used SQLite's `GLOB`.
//! - Paths are stored bytes: the query string and fragment are cut from the bytes before
//!   grouping, and labels are display copies of the bytes. Ties are broken by the label's
//!   bytes on both backends (`COLLATE "C"` on PostgreSQL).

use sibuna_console_protocol::security::{self, Findings, Page, Query, Rank, View};
use sibuna_console_protocol::tokens::Scope;
use sibuna_storage::{Param, Row as Cells, Sql, Transaction};

use crate::access::{self, Credential, Need};
use crate::bound::{self, WorkBound};
use crate::error::ConsoleStorageError;
use crate::events::classification;
use crate::events::display;
use crate::row::{self, Fields};

/// What the full overview requires: events access, because it names addresses and paths.
pub const OVERVIEW_NEED: Need = Need::read(Some(Scope::EventsRead));
/// What the aggregate-only trends require: statistics access; kiosk sessions may read them.
pub const TRENDS_NEED: Need = Need { kiosk: true, ..Need::read(Some(Scope::StatsRead)) };

/// The rows of the window: `$1` from (inclusive), `$2` until (exclusive), `$3` the node or
/// `NULL` for all.
macro_rules! window {
    () => {
        " FROM security_incidents s WHERE s.recorded_at >= $1 AND s.recorded_at < $2 \
         AND ($3 IS NULL OR s.node_id = $3)"
    };
}

const TOTALS: Sql = Sql::both(concat!(
    "SELECT ",
    classification!(),
    " AS module, COUNT(*)",
    window!(),
    " GROUP BY 1"
));

const TREND: Sql = Sql::both(concat!(
    "SELECT ",
    classification!(),
    " AS module, (s.recorded_at - $1) * 60 / ($2 - $1) AS bucket, COUNT(*)",
    window!(),
    " GROUP BY 1, 2"
));

const SOURCES: Sql = Sql {
    sqlite: concat!(
        "SELECT module, client_ip, n FROM (SELECT module, client_ip, n, ROW_NUMBER() OVER \
         (PARTITION BY module ORDER BY n DESC, client_ip) AS place FROM (SELECT module, \
         client_ip, COUNT(*) AS n FROM (SELECT ",
        classification!(),
        " AS module, s.client_ip",
        window!(),
        ") f GROUP BY module, client_ip) g) r WHERE place <= 3 ORDER BY module, n DESC, client_ip"
    ),
    postgres: concat!(
        "SELECT module, client_ip, n FROM (SELECT module, client_ip, n, ROW_NUMBER() OVER \
         (PARTITION BY module ORDER BY n DESC, client_ip COLLATE \"C\") AS place FROM \
         (SELECT module, client_ip, COUNT(*) AS n FROM (SELECT ",
        classification!(),
        " AS module, s.client_ip",
        window!(),
        ") f GROUP BY module, client_ip) g) r WHERE place <= 3 \
         ORDER BY module, n DESC, client_ip COLLATE \"C\""
    ),
};

/// Categories as bytes, so both backends order ties by the same bytes.
const CATEGORIES: Sql = Sql {
    sqlite: concat!(
        "SELECT CAST(s.violation_category AS BLOB) AS label, COUNT(*) AS n",
        window!(),
        " GROUP BY 1 ORDER BY n DESC, label LIMIT 5"
    ),
    postgres: concat!(
        "SELECT convert_to(s.violation_category, 'UTF8') AS label, COUNT(*) AS n",
        window!(),
        " GROUP BY 1 ORDER BY n DESC, label LIMIT 5"
    ),
};

/// Paths without their query and fragment, cut at the first `?` or `#` byte.
const PATHS: Sql = Sql {
    sqlite: concat!(
        "SELECT label, COUNT(*) AS n FROM (SELECT substr(s.path, 1, CASE \
         WHEN instr(s.path, X'3F') = 0 AND instr(s.path, X'23') = 0 THEN length(s.path) \
         WHEN instr(s.path, X'3F') = 0 THEN instr(s.path, X'23') - 1 \
         WHEN instr(s.path, X'23') = 0 THEN instr(s.path, X'3F') - 1 \
         ELSE MIN(instr(s.path, X'3F'), instr(s.path, X'23')) - 1 END) AS label",
        window!(),
        ") f GROUP BY label ORDER BY n DESC, label LIMIT 5"
    ),
    postgres: concat!(
        "SELECT label, COUNT(*) AS n FROM (SELECT substring(s.path FROM 1 FOR CASE \
         WHEN position('\\x3f'::bytea IN s.path) = 0 AND position('\\x23'::bytea IN s.path) = 0 \
         THEN octet_length(s.path) \
         WHEN position('\\x3f'::bytea IN s.path) = 0 THEN position('\\x23'::bytea IN s.path) - 1 \
         WHEN position('\\x23'::bytea IN s.path) = 0 THEN position('\\x3f'::bytea IN s.path) - 1 \
         ELSE LEAST(position('\\x3f'::bytea IN s.path), position('\\x23'::bytea IN s.path)) - 1 \
         END) AS label",
        window!(),
        ") f GROUP BY label ORDER BY n DESC, label LIMIT 5"
    ),
};

const TOTAL: Sql = Sql::both(concat!("SELECT COUNT(*)", window!()));

/// Reads the overview of `input.request` at `now` (its `observed_at`): with
/// `input.aggregate_only`, only the per-source totals and trends. The credential is
/// `credential`; `input.session_digest` is not read. Borrows everything.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a query the protocol refuses, like
/// [`access::authorize_in`] with [`OVERVIEW_NEED`] (or [`TRENDS_NEED`] for aggregate-only
/// reads), with [`ConsoleStorageError::Unavailable`] when a statement passes `bound`, and
/// with the driver's error or [`sibuna_storage::StorageError::InvalidRow`].
pub async fn query_security(
    tx: &mut Transaction,
    credential: &Credential,
    input: &Query,
    bound: WorkBound,
    now: u64,
) -> Result<Page, ConsoleStorageError> {
    security::validate(input).map_err(|_| ConsoleStorageError::InvalidInput("security"))?;
    let need = if input.aggregate_only { TRENDS_NEED } else { OVERVIEW_NEED };
    access::authorize_in(tx, credential, need, now).await?;
    let request = input.request;
    let node = (request.node != 0).then_some(i64::from(request.node));
    let params: [Param<'_>; 3] =
        [row::int(request.from)?.into(), row::int(request.until)?.into(), node.into()];
    let mut page = Page { request, observed_at: now, ..Page::default() };
    bound::begin(tx, bound).await?;
    let read = match request.view {
        View::Modules => read_modules(tx, &params, input.aggregate_only, &mut page).await,
        View::Categories => read_ranks(tx, CATEGORIES, &params, &mut page).await,
        View::Paths => read_ranks(tx, PATHS, &params, &mut page).await,
    };
    // The bound ends also after a failed read, so later statements of the transaction run
    // without it.
    let ended = bound::end(tx).await;
    // A failed read reports its own error; PostgreSQL then refuses every statement.
    read?;
    ended?;
    Ok(page)
}

/// Fills the per-source totals, trends and (unless `aggregate_only`) top addresses.
async fn read_modules(
    tx: &mut Transaction,
    params: &[Param<'_>],
    aggregate_only: bool,
    page: &mut Page,
) -> Result<(), ConsoleStorageError> {
    for cells in bound::fetch(tx, TOTALS, params).await? {
        let mut fields = Fields::new(cells, "security_incidents");
        let findings = module(&mut page.modules, &mut fields)?;
        findings.total = fields.integer("count")?;
        page.total = page.total.checked_add(findings.total).ok_or(fields.invalid("count"))?;
    }
    for cells in bound::fetch(tx, TREND, params).await? {
        let mut fields = Fields::new(cells, "security_incidents");
        let findings = module(&mut page.modules, &mut fields)?;
        let bucket: usize = fields.integer("bucket")?;
        let slot = findings.trend.get_mut(bucket).ok_or(fields.invalid("bucket"))?;
        *slot = fields.integer("count")?;
    }
    if aggregate_only {
        return Ok(());
    }
    let mut filled = [0usize; 3];
    for cells in bound::fetch(tx, SOURCES, params).await? {
        let mut fields = Fields::new(cells, "security_incidents");
        let index: usize = fields.integer("module")?;
        let findings = page.modules.get_mut(index).ok_or(fields.invalid("module"))?;
        let used = filled.get_mut(index).ok_or(fields.invalid("module"))?;
        let slot = findings.sources.get_mut(*used).ok_or(fields.invalid("client_ip"))?;
        *slot = Some(rank(fields.text("client_ip")?.as_bytes(), fields.integer("count")?));
        *used += 1;
    }
    Ok(())
}

/// Returns the findings of the module the next column names.
fn module<'a>(
    modules: &'a mut [Findings; 3],
    fields: &mut Fields,
) -> Result<&'a mut Findings, ConsoleStorageError> {
    let index: usize = fields.integer("module")?;
    modules.get_mut(index).ok_or(fields.invalid("module"))
}

/// Fills the top five labels of `statement` and the window's total.
async fn read_ranks(
    tx: &mut Transaction,
    statement: Sql,
    params: &[Param<'_>],
    page: &mut Page,
) -> Result<(), ConsoleStorageError> {
    let rows: Vec<Cells> = bound::fetch(tx, statement, params).await?;
    for (slot, cells) in page.rows.iter_mut().zip(rows) {
        let mut fields = Fields::new(cells, "security_incidents");
        let label = fields.bytes("label")?;
        *slot = Some(rank(&label, fields.integer("count")?));
    }
    let total = row::first(bound::fetch(tx, TOTAL, params).await?).unwrap_or_default();
    page.total = Fields::new(total, "security_incidents").integer("count")?;
    Ok(())
}

fn rank(label: &[u8], count: u64) -> Rank {
    let (label, truncated) = display::copy::<96>(label);
    Rank { label, count, truncated }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_statements_bucket_and_rank_within_the_window() {
        assert!(TREND.sqlite.contains("* 60 / ($2 - $1)"));
        assert!(SOURCES.postgres.contains("COLLATE \"C\""));
        assert_eq!(security::BUCKETS, 60);
        let (label, cut) = display::copy::<96>(&[b'a'; 100]);
        assert!(cut && label.len() == 96);
        assert!(rank(b"x", 3).count == 3);
    }
}
