//! The statements of the Events page, written once per dialect from shared pieces.
//!
//! Parameters: `$1` from, `$2` until, `$3` node, `$4` category, `$5` address, `$6` path
//! prefix (bytes), `$7` country filter, `$8` module ordinal, `$9` campaign, `$10` incident,
//! `$11` and `$12` the cursor's time and id, `$13` the row limit, `$14` the search
//! expression. An absent filter is `NULL`. Statements without a search bind 13 values.

use sibuna_storage::Sql;

/// The finding source of a category: 0 inspection (`waf:` and `audit:`), 1 honeypot, 2
/// other; the ordinals of the protocol's `security::Module`. `substr` compares bytes in
/// both dialects, unlike `LIKE`, which ignores ASCII case on SQLite.
macro_rules! classification {
    () => {
        "(CASE WHEN substr(s.violation_category, 1, 4) = 'waf:' \
         OR substr(s.violation_category, 1, 6) = 'audit:' THEN 0 \
         WHEN s.violation_category = 'honeypot' THEN 1 ELSE 2 END)"
    };
}
pub(crate) use classification;

/// The country filter's view of a row: `not_recorded`, `unknown` or the code.
macro_rules! country_label {
    () => {
        "(CASE WHEN c.incident_id IS NULL THEN 'not_recorded' \
         ELSE COALESCE(c.country, 'unknown') END)"
    };
}

macro_rules! joins {
    () => {
        " FROM security_incidents s \
         LEFT JOIN console_incident_evidence e ON e.incident_id = s.id \
         LEFT JOIN console_incident_country c ON c.incident_id = s.id \
         WHERE s.recorded_at BETWEEN $1 AND $2 AND ($3 IS NULL OR s.node_id = $3) \
         AND ($4 IS NULL OR s.violation_category = $4) AND ($5 IS NULL OR s.client_ip = $5) "
    };
}

macro_rules! filters {
    () => {
        concat!(
            " AND ($7 IS NULL OR ",
            country_label!(),
            " = $7) AND ($8 IS NULL OR ",
            classification!(),
            " = $8) AND ($9 IS NULL OR s.campaign_id = $9) AND ($10 IS NULL OR s.id = $10) "
        )
    };
}

macro_rules! sqlite_prefix {
    () => {
        "AND substr(s.path, 1, length($6)) = $6"
    };
}

macro_rules! postgres_prefix {
    () => {
        "AND substring(s.path FROM 1 FOR octet_length($6)) = $6"
    };
}

macro_rules! sqlite_generation {
    () => {
        "(CASE WHEN c.generation IS NULL THEN NULL ELSE lower(hex(c.generation)) END)"
    };
}

macro_rules! postgres_generation {
    () => {
        "encode(c.generation, 'hex')"
    };
}

/// The columns of one incident, in the order `decode_row` reads them.
macro_rules! raw_select {
    ($generation:ident) => {
        concat!(
            "SELECT s.id, s.node_id, s.recorded_at, s.client_ip, s.method, s.path, \
             s.violation_category, s.user_agent, s.campaign_id, 1, s.recorded_at, \
             e.incident_id IS NOT NULL, e.selected_status, e.query_bytes, e.body_bytes, \
             e.declared_body_bytes, e.truncated, c.country, ",
            $generation!(),
            ", 0, c.incident_id IS NOT NULL"
        )
    };
}

/// The columns of one source group (node and address), in the same order.
macro_rules! group_select {
    ($generation:ident) => {
        concat!(
            "SELECT MAX(s.id), s.node_id, MAX(s.recorded_at), s.client_ip, NULL, NULL, NULL, \
             NULL, NULL, COUNT(*), MIN(s.recorded_at), 1 = 0, NULL, NULL, NULL, NULL, NULL, \
             CASE WHEN COUNT(DISTINCT COALESCE(c.country, '')) = 1 THEN MIN(c.country) END, \
             CASE WHEN COUNT(DISTINCT COALESCE(",
            $generation!(),
            ", '')) = 1 THEN MIN(",
            $generation!(),
            ") END, COUNT(DISTINCT ",
            country_label!(),
            ") > 1, COUNT(c.incident_id) = COUNT(*)"
        )
    };
}

macro_rules! raw_order {
    () => {
        " AND (s.recorded_at < $11 OR (s.recorded_at = $11 AND s.id < $12)) \
         ORDER BY s.recorded_at DESC, s.id DESC LIMIT $13"
    };
}

macro_rules! group_order {
    () => {
        " GROUP BY s.node_id, s.client_ip \
         HAVING MAX(s.recorded_at) < $11 OR (MAX(s.recorded_at) = $11 AND MAX(s.id) < $12) \
         ORDER BY MAX(s.recorded_at) DESC, MAX(s.id) DESC LIMIT $13"
    };
}

macro_rules! statement {
    ($select:ident, $order:ident, $search_sqlite:expr, $search_postgres:expr) => {
        Sql {
            sqlite: concat!(
                $select!(sqlite_generation),
                joins!(),
                sqlite_prefix!(),
                filters!(),
                $search_sqlite,
                $order!()
            ),
            postgres: concat!(
                $select!(postgres_generation),
                joins!(),
                postgres_prefix!(),
                filters!(),
                $search_postgres,
                $order!()
            ),
        }
    };
}

/// Incident rows, newest first.
pub const ROWS: Sql = statement!(raw_select, raw_order, "", "");
/// Incident rows that match a search, newest first.
pub const ROWS_SEARCH: Sql = statement!(
    raw_select,
    raw_order,
    " AND s.id IN (SELECT rowid FROM incidents_fts WHERE incidents_fts MATCH $14) ",
    " AND s.search @@ CAST($14 AS tsquery) "
);
/// Source groups, newest first.
pub const GROUPS: Sql = statement!(group_select, group_order, "", "");
/// Source groups of the incidents that match a search, newest first.
pub const GROUPS_SEARCH: Sql = statement!(
    group_select,
    group_order,
    " AND s.id IN (SELECT rowid FROM incidents_fts WHERE incidents_fts MATCH $14) ",
    " AND s.search @@ CAST($14 AS tsquery) "
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_clauses_appear_only_in_search_statements() {
        assert!(ROWS_SEARCH.sqlite.contains("incidents_fts MATCH $14"));
        assert!(GROUPS_SEARCH.postgres.contains("s.search @@ CAST($14 AS tsquery)"));
        assert!(!ROWS.sqlite.contains("$14") && !GROUPS.postgres.contains("$14"));
        assert!(ROWS.postgres.contains("encode(c.generation, 'hex')"));
        assert!(GROUPS.sqlite.contains("lower(hex(c.generation))"));
    }
}
