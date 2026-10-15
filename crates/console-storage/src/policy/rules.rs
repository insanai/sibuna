//! Rows of the core table `policies` as the console reads and writes them: decoding, the
//! management document a stored row stands for, and the upsert of a validated document.

use sibuna_json::Writer;
use sibuna_policy::management::Document;
use sibuna_policy::{Action, Algorithm, Limits};
use sibuna_storage::{Param, Sql, Transaction};

use crate::error::ConsoleStorageError;
use crate::row::{self, Fields};

/// One row of `policies`, enabled or not, with the columns a management document holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRule {
    /// The stable id.
    pub id: String,
    /// The rule name.
    pub name: String,
    /// Lower runs first.
    pub priority: i32,
    /// Disabled rules are stored and listed but not evaluated.
    pub enabled: bool,
    /// The path pattern.
    pub path_pattern: Option<String>,
    /// The User-Agent pattern.
    pub ua_pattern: Option<String>,
    /// What the rule decides.
    pub action: Action,
    /// The challenge difficulty in work bits.
    pub difficulty: Option<u32>,
    /// The challenge algorithm; `None` inherits the daemon's.
    pub algorithm: Option<Algorithm>,
    /// The header matchers as a compact JSON object.
    pub header_matchers: Option<String>,
    /// The CIDR matchers as a compact JSON array.
    pub cidr_matchers: Option<String>,
    /// The WEIGH score.
    pub weight: i32,
    /// The rule's quota.
    pub limits: Option<Limits>,
}

impl StoredRule {
    /// Decodes the rule columns of `policies` in table order (the matchers cast to text).
    /// Fails with [`sibuna_storage::StorageError::InvalidRow`] naming the first column whose
    /// value the types cannot hold (a priority outside `i32`, an unknown action, a matcher
    /// cell that is not JSON).
    pub(crate) fn decode(mut fields: Fields) -> Result<StoredRule, ConsoleStorageError> {
        let id = fields.text("id")?;
        let name = fields.text("name")?;
        let priority = fields.integer("priority")?;
        let enabled = fields.flag("enabled")?;
        let path_pattern = fields.optional_text("path_pattern")?;
        let ua_pattern = fields.optional_text("ua_pattern")?;
        let action = fields.parsed("action", |text| Action::parse(text.as_bytes()))?;
        let difficulty = fields.optional_integer("difficulty")?;
        let algorithm =
            fields.optional_parsed("algorithm", |text| Algorithm::parse(text.as_bytes()))?;
        let header_matchers = compact(&mut fields, "header_matchers")?;
        let cidr_matchers = compact(&mut fields, "cidr_matchers")?;
        let weight = fields.integer("weight")?;
        let rate: Option<u32> = fields.optional_integer("limit_rate")?;
        let window: Option<u32> = fields.optional_integer("limit_window_seconds")?;
        let ban_seconds = fields.integer("limit_ban_seconds")?;
        let limits = match (rate, window) {
            (None, None) => None,
            (Some(rate), Some(window_seconds)) => {
                Some(Limits { rate, window_seconds, ban_seconds })
            }
            _ => return Err(fields.invalid("limit_window_seconds")),
        };
        Ok(StoredRule {
            id,
            name,
            priority,
            enabled,
            path_pattern,
            ua_pattern,
            action,
            difficulty,
            algorithm,
            header_matchers,
            cidr_matchers,
            weight,
            limits,
        })
    }

    /// Returns the management document this row stands for, written as Zig's
    /// `console_policy_candidate.encode` wrote it: every scalar field (absent ones as
    /// `null`), then the matchers and limits that are present.
    pub fn document(&self) -> String {
        let mut json = Writer::new(String::with_capacity(256));
        // Writing into a `String` cannot fail, and the stored matchers are compact JSON
        // that `decode` parsed, so every result below is `Ok`.
        let _ = json.begin_object();
        let _ = json.key("id");
        let _ = json.string(&self.id);
        let _ = json.key("name");
        let _ = json.string(&self.name);
        let _ = json.key("priority");
        let _ = json.int(i64::from(self.priority));
        let _ = json.key("enabled");
        let _ = json.bool(self.enabled);
        optional_string(&mut json, "path", self.path_pattern.as_deref());
        optional_string(&mut json, "user_agent", self.ua_pattern.as_deref());
        let _ = json.key("action");
        let _ = json.string(self.action.name());
        let _ = json.key("difficulty");
        let _ = match self.difficulty {
            Some(difficulty) => json.uint(u64::from(difficulty)),
            None => json.null(),
        };
        optional_string(&mut json, "algorithm", self.algorithm.map(Algorithm::name));
        let _ = json.key("weight");
        let _ = json.int(i64::from(self.weight));
        // The matchers are already JSON text; they follow as raw members.
        let mut text = json.into_inner();
        for (key, value) in [("headers", &self.header_matchers), ("cidrs", &self.cidr_matchers)] {
            if let Some(value) = value {
                text.push_str(&format!(",\"{key}\":{value}"));
            }
        }
        if let Some(limits) = self.limits {
            text.push_str(&format!(
                ",\"limits\":{{\"rate\":{},\"window_seconds\":{},\"ban_seconds\":{}}}",
                limits.rate, limits.window_seconds, limits.ban_seconds
            ));
        }
        text.push('}');
        text
    }
}

fn optional_string(json: &mut Writer<String>, key: &str, value: Option<&str>) {
    let _ = json.key(key);
    let _ = match value {
        Some(value) => json.string(value),
        None => json.null(),
    };
}

/// Takes an optional JSON cell and returns it compact (PostgreSQL renders `JSONB` with
/// spaces); fails when the cell is not JSON.
fn compact(
    fields: &mut Fields,
    column: &'static str,
) -> Result<Option<String>, ConsoleStorageError> {
    let Some(text) = fields.optional_text(column)? else { return Ok(None) };
    compact_json(&text).map(Some).ok_or_else(|| fields.invalid(column))
}

/// Returns `text` re-written without insignificant white space, or `None` when it is not
/// JSON.
pub(crate) fn compact_json(text: &str) -> Option<String> {
    let value = sibuna_json::parse(text.as_bytes()).ok()?;
    let mut json = Writer::new(String::with_capacity(text.len()));
    json.value(&value).ok()?;
    Some(json.into_inner())
}

/// Every rule, by id; the candidate reads one row more than an engine holds.
pub(crate) const ALL: Sql = Sql::both(
    "SELECT id, name, priority, enabled, path_pattern, ua_pattern, action, difficulty, \
     algorithm, CAST(header_matchers AS TEXT), CAST(cidr_matchers AS TEXT), weight, \
     limit_rate, limit_window_seconds, limit_ban_seconds FROM policies ORDER BY id LIMIT $1",
);

/// One rule by id, locked on PostgreSQL (the revision lock already serialises workflows;
/// the row lock keeps a direct operator write from interleaving).
pub(crate) const BY_ID: Sql = Sql {
    sqlite: "SELECT id, name, priority, enabled, path_pattern, ua_pattern, action, difficulty, \
             algorithm, CAST(header_matchers AS TEXT), CAST(cidr_matchers AS TEXT), weight, \
             limit_rate, limit_window_seconds, limit_ban_seconds FROM policies WHERE id = $1",
    postgres: "SELECT id, name, priority, enabled, path_pattern, ua_pattern, action, \
               difficulty, algorithm, CAST(header_matchers AS TEXT), \
               CAST(cidr_matchers AS TEXT), weight, limit_rate, limit_window_seconds, \
               limit_ban_seconds FROM policies WHERE id = $1 FOR UPDATE",
};

/// Returns rule `id`, or `None` when no row has it.
pub(crate) async fn rule(
    tx: &mut Transaction,
    id: &str,
) -> Result<Option<StoredRule>, ConsoleStorageError> {
    match row::first(tx.fetch_all(BY_ID, &[id.into()]).await?) {
        Some(cells) => StoredRule::decode(Fields::new(cells, "policies")).map(Some),
        None => Ok(None),
    }
}

const UPSERT: Sql = Sql {
    sqlite: "INSERT INTO policies (id, name, priority, enabled, path_pattern, ua_pattern, \
             action, difficulty, algorithm, header_matchers, cidr_matchers, weight, limit_rate, \
             limit_window_seconds, limit_ban_seconds, created_at, updated_at) \
             VALUES ($1, $2, $3, ($4 <> 0), $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
             $16, $16) ON CONFLICT (id) DO UPDATE SET name = excluded.name, \
             priority = excluded.priority, enabled = excluded.enabled, \
             path_pattern = excluded.path_pattern, ua_pattern = excluded.ua_pattern, \
             action = excluded.action, difficulty = excluded.difficulty, \
             algorithm = excluded.algorithm, header_matchers = excluded.header_matchers, \
             cidr_matchers = excluded.cidr_matchers, weight = excluded.weight, \
             limit_rate = excluded.limit_rate, \
             limit_window_seconds = excluded.limit_window_seconds, \
             limit_ban_seconds = excluded.limit_ban_seconds, updated_at = excluded.updated_at",
    postgres: "INSERT INTO policies (id, name, priority, enabled, path_pattern, ua_pattern, \
               action, difficulty, algorithm, header_matchers, cidr_matchers, weight, \
               limit_rate, limit_window_seconds, limit_ban_seconds, created_at, updated_at) \
               VALUES ($1, $2, $3, ($4 <> 0), $5, $6, $7, $8, $9, CAST($10 AS JSONB), \
               CAST($11 AS JSONB), $12, $13, $14, $15, $16, $16) \
               ON CONFLICT (id) DO UPDATE SET name = excluded.name, \
               priority = excluded.priority, enabled = excluded.enabled, \
               path_pattern = excluded.path_pattern, ua_pattern = excluded.ua_pattern, \
               action = excluded.action, difficulty = excluded.difficulty, \
               algorithm = excluded.algorithm, header_matchers = excluded.header_matchers, \
               cidr_matchers = excluded.cidr_matchers, weight = excluded.weight, \
               limit_rate = excluded.limit_rate, \
               limit_window_seconds = excluded.limit_window_seconds, \
               limit_ban_seconds = excluded.limit_ban_seconds, updated_at = excluded.updated_at",
};

/// Inserts or replaces the rule of a validated `document` at `now`, keeping the creation
/// time of a replaced row. Empty matchers are stored as `NULL`. Fails with the driver's
/// error.
pub(crate) async fn store(
    tx: &mut Transaction,
    document: &Document,
    now: u64,
) -> Result<(), ConsoleStorageError> {
    let rule = &document.rule;
    let headers = header_json(document);
    let cidrs = cidr_json(document);
    let limits = rule.limits;
    let params: [Param<'_>; 16] = [
        document.id.as_str().into(),
        rule.name.as_str().into(),
        i64::from(document.priority).into(),
        i64::from(document.enabled).into(),
        rule.path_pattern.as_deref().into(),
        rule.ua_pattern.as_deref().into(),
        rule.action.name().into(),
        Param::Int(rule.difficulty.map(i64::from)),
        rule.algorithm.map(Algorithm::name).into(),
        headers.as_deref().into(),
        cidrs.as_deref().into(),
        i64::from(rule.weight).into(),
        Param::Int(limits.map(|limits| i64::from(limits.rate))),
        Param::Int(limits.map(|limits| i64::from(limits.window_seconds))),
        i64::from(limits.map_or(0, |limits| limits.ban_seconds)).into(),
        row::int(now)?.into(),
    ];
    tx.execute(UPSERT, &params).await?;
    Ok(())
}

/// The header matchers of `document` as a JSON object in document order, as Zig's
/// `headerJson` wrote them; `None` without matchers.
fn header_json(document: &Document) -> Option<String> {
    let headers = &document.rule.headers;
    if headers.is_empty() {
        return None;
    }
    let mut json = Writer::new(String::with_capacity(64));
    let _ = json.begin_object();
    for header in headers {
        let _ = json.key(&header.name);
        let _ = json.string(&header.pattern);
    }
    let _ = json.end_object();
    Some(json.into_inner())
}

/// The CIDR matchers of `document` as written, as a JSON array; `None` without matchers.
fn cidr_json(document: &Document) -> Option<String> {
    if document.cidrs.is_empty() {
        return None;
    }
    let mut json = Writer::new(String::with_capacity(64));
    let _ = json.begin_array();
    for cidr in &document.cidrs {
        let _ = json.string(cidr);
    }
    let _ = json.end_array();
    Some(json.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_storage::Cell;

    fn cells() -> Vec<Cell> {
        vec![
            Cell::Text("a".into()),
            Cell::Text("A \"quoted\"".into()),
            Cell::Int(-5),
            Cell::Int(0),
            Cell::Text("/x/*".into()),
            Cell::Null,
            Cell::Text("challenge".into()),
            Cell::Int(16),
            Cell::Text("posw".into()),
            Cell::Text("{\"X-Key\": \"v*\"}".into()),
            Cell::Text("[\"10.0.0.0/8\"]".into()),
            Cell::Int(0),
            Cell::Int(2),
            Cell::Int(60),
            Cell::Int(5),
        ]
    }

    #[test]
    fn stored_rows_round_trip_through_their_documents() {
        let rule = StoredRule::decode(Fields::new(cells(), "policies")).unwrap();
        let text = rule.document();
        assert_eq!(
            text,
            "{\"id\":\"a\",\"name\":\"A \\\"quoted\\\"\",\"priority\":-5,\"enabled\":false,\
             \"path\":\"/x/*\",\"user_agent\":null,\"action\":\"challenge\",\"difficulty\":16,\
             \"algorithm\":\"posw\",\"weight\":0,\"headers\":{\"X-Key\":\"v*\"},\
             \"cidrs\":[\"10.0.0.0/8\"],\"limits\":{\"rate\":2,\"window_seconds\":60,\
             \"ban_seconds\":5}}"
        );
        let document = sibuna_policy::management::parse(text.as_bytes()).unwrap();
        assert_eq!((document.id.as_str(), document.priority, document.enabled), ("a", -5, false));
        assert_eq!(header_json(&document).as_deref(), Some("{\"X-Key\":\"v*\"}"));
        assert_eq!(cidr_json(&document).as_deref(), Some("[\"10.0.0.0/8\"]"));
        assert_eq!(document.rule.limits, rule.limits);
    }

    #[test]
    fn rows_the_types_cannot_hold_are_refused() {
        let mut bad = cells();
        bad[2] = Cell::Int(i64::from(i32::MAX) + 1);
        assert!(StoredRule::decode(Fields::new(bad, "policies")).is_err());
        let mut bad = cells();
        bad[9] = Cell::Text("{".into());
        assert!(StoredRule::decode(Fields::new(bad, "policies")).is_err());
        let mut bad = cells();
        bad[13] = Cell::Null;
        assert!(StoredRule::decode(Fields::new(bad, "policies")).is_err());
    }
}
