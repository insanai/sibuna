//! The search conformance test of SID 0013 (acceptance criterion 5): a corpus of recorded
//! attack paths and payloads is indexed through the incident writer, and a corpus of queries
//! covering every construct of the grammar returns, on each backend, exactly the incidents a
//! reference evaluator over [`search::index_tokens`] finds. Both backends therefore return
//! identical sets; when both run in one process, their results are also compared directly.
//! The index contents (`fts5vocab`, the `tsvector`) are compared with the canonical tokens.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use sibuna_core::Incident;

use crate::database::{Dialect, Sql, Target};
use crate::search::{self, Field, Query, Term};
use crate::testing::{Fixture, for_each_backend};

/// Recorded attack paths and payloads: percent-encoding, non-ASCII letters, invalid UTF-8,
/// long tokens, repeated tokens and more tokens than a field keeps.
fn corpus() -> Vec<(Vec<u8>, Vec<u8>)> {
    let text = |path: &str, payload: &str| (path.as_bytes().to_vec(), payload.as_bytes().to_vec());
    vec![
        text("/etc/passwd", "file=../../etc/passwd"),
        text("/search", "q=1%27%20UNION%20SELECT%20username,password%20FROM%20users--"),
        text("/wp-admin/admin-ajax.php", "action=revslider_show_image&img=../wp-config.php"),
        text(
            "/caf%C3%A9/men%C3%BC",
            "Stra\u{df}e \u{c9}COLE \u{41c}\u{43e}\u{441}\u{43a}\u{432}\u{430}",
        ),
        text("/admin", "login=admin&password=admin&admin=1"),
        text(&format!("/{}", "a".repeat(150)), "x"),
        text("/repeat", &"spam ".repeat(200)),
        text("/index.php", "<script>alert(document.cookie)</script>"),
        text("/api/v1/users/42", "{\"$where\": \"sleep(5000)\"}"),
        text("/cgi-bin/test.cgi", "() { :; }; /bin/bash -c 'cat /etc/shadow'"),
        text("/admin/login", "user=root"),
        text("/%2e%2e/%2e%2e/etc/hosts", ""),
        text("/\u{130}stanbul/K", "\u{212a}elvin"),
        (b"/raw\xff\xfeunion".to_vec(), b"\x00select\xc3\x28from".to_vec()),
        text("/UNION%20SELECT", "union select"),
        text("/%zz%4/100%", "%41%42 %%41"),
    ]
}

/// Queries that cover every construct of the grammar: words, phrases, both field prefixes,
/// conjunction, `OR`, percent-encoding, case, non-ASCII letters, split long tokens, repeated
/// tokens, a phrase across the field boundary, and queries matching nothing.
fn queries() -> Vec<String> {
    let mut list: Vec<String> = [
        "passwd",
        "etc passwd",
        "/etc/passwd",
        "path:/etc/passwd",
        "payload:passwd",
        "path:\"etc passwd\"",
        "union select",
        "UNION%20SELECT",
        "\"union select\"",
        "path:union",
        "payload:\"union select username\"",
        "admin OR shadow",
        "admin password OR path:hosts",
        "caf\u{e9}",
        "CAF\u{c9}",
        "men\u{fc}",
        "stra\u{df}e",
        "\u{41c}\u{43e}\u{441}\u{43a}\u{432}\u{430}",
        "\u{c9}cole",
        "spam",
        "\"spam spam spam\"",
        "payload:spam path:repeat",
        "script alert",
        "payload:script path:index",
        "\"login user\"",
        "login user",
        "sleep 5000",
        "\"bin bash\"",
        "\u{130}stanbul",
        "istanbul",
        "kelvin",
        "path:k",
        "raw",
        "select from",
        "payload:\"select from\"",
        "hosts",
        "\"etc hosts\"",
        "path:etc OR payload:etc",
        "nothingmatches",
        "admin OR nothing OR spam",
        "zz 100",
        "ab",
        "41",
        "\"OR\"",
        "x",
    ]
    .iter()
    .map(|query| (*query).to_owned())
    .collect();
    list.push("a".repeat(150));
    list.push(format!("path:{}", "a".repeat(128)));
    list.push(format!("payload:{}", "a".repeat(64)));
    list
}

/// The tokens the index keeps for each incident id: (path, payload).
type Indexed = BTreeMap<i64, (Vec<String>, Vec<String>)>;

/// True when `needle` occurs in `haystack` as consecutive tokens.
fn contains(haystack: &[String], needle: &[String]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

fn term_matches(term: &Term, path: &[String], payload: &[String]) -> bool {
    match term.field {
        Some(Field::Path) => contains(path, &term.tokens),
        Some(Field::Payload) => contains(payload, &term.tokens),
        None => contains(path, &term.tokens) || contains(payload, &term.tokens),
    }
}

/// The reference evaluator: the incidents whose indexed tokens satisfy `query`.
fn reference(query: &Query, indexed: &Indexed) -> BTreeSet<i64> {
    indexed
        .iter()
        .filter(|(_, (path, payload))| {
            query
                .groups
                .iter()
                .any(|group| group.iter().all(|term| term_matches(term, path, payload)))
        })
        .map(|(id, _)| *id)
        .collect()
}

/// Each backend's results, by query, to compare SQLite with PostgreSQL in one process.
static RESULTS: Mutex<Vec<(Dialect, Vec<BTreeSet<i64>>)>> = Mutex::new(Vec::new());

#[test]
fn both_backends_return_the_reference_matches() {
    for_each_backend("search_conformance", |target| Box::pin(conformance(target)));
    let results = RESULTS.lock().unwrap();
    if let [(_, first), (_, second)] = results.as_slice() {
        assert_eq!(first, second, "SQLite and PostgreSQL disagree");
    }
}

async fn conformance(target: Target) {
    let mut p = Fixture::open(&target).await;
    let corpus = corpus();
    for (now, (path, payload)) in (1_000u64..).zip(&corpus) {
        p.record(&Incident {
            client_ip: "203.0.113.5",
            method: "GET",
            category: "waf:sqli",
            path,
            payload,
            now,
            ..Incident::default()
        });
    }
    while p.worker.drain().await.unwrap() > 0 {}
    let indexed: Indexed = (1i64..)
        .zip(&corpus)
        .map(|(sequence, (path, payload))| {
            let id = (1i64 << 40) | sequence;
            // The record keeps at most 512 bytes of each field.
            let (path, payload) =
                (&path[..path.len().min(512)], &payload[..payload.len().min(512)]);
            (id, (search::index_tokens(path), search::index_tokens(payload)))
        })
        .collect();
    assert_eq!(stored_tokens(&p, target.dialect()).await, indexed, "{:?}", target.dialect());
    let mut found = Vec::new();
    for text in queries() {
        let query = Query::parse(&text).unwrap().unwrap();
        let hits = p.worker.db.search_incidents(&text, 1000).await.unwrap();
        let ids: BTreeSet<i64> = hits.iter().map(|hit| hit.id).collect();
        assert_eq!(ids, reference(&query, &indexed), "{:?}: {text}", target.dialect());
        found.push(ids);
    }
    // The phrase across the boundary of path and payload matches nothing.
    assert!(found[24].is_empty());
    assert_eq!(found[25].len(), 1);
    RESULTS.lock().unwrap().push((target.dialect(), found));
    p.close().await;
}

/// Reads back the token sequences the index holds for every incident, from `fts5vocab` on
/// SQLite and from the `tsvector` on PostgreSQL.
async fn stored_tokens(p: &Fixture, dialect: Dialect) -> Indexed {
    let mut tx = p.worker.db.begin().await.unwrap();
    let sql = match dialect {
        Dialect::Sqlite => {
            tx.execute_script(
                "CREATE VIRTUAL TABLE temp.incidents_vocab \
                 USING fts5vocab(main, incidents_fts, instance)",
            )
            .await
            .unwrap();
            Sql::both(
                "SELECT doc, CASE col WHEN 'path' THEN 'A' ELSE 'B' END, \"offset\", term \
                 FROM temp.incidents_vocab",
            )
        }
        Dialect::Postgres => Sql::both(
            "SELECT s.id, p.w, CAST(p.pos AS BIGINT), u.lexeme \
             FROM security_incidents s, unnest(s.search) AS u(lexeme, positions, weights), \
             unnest(u.positions, u.weights) AS p(pos, w)",
        ),
    };
    let rows = tx.fetch_all(sql, &[]).await.unwrap();
    let mut places: BTreeMap<(i64, String), BTreeMap<i64, String>> = BTreeMap::new();
    for row in rows {
        let id = row[0].as_i64().unwrap();
        let weight = row[1].as_str().unwrap().to_owned();
        let position = row[2].as_i64().unwrap();
        places.entry((id, weight)).or_default().insert(position, row[3].as_str().unwrap().into());
    }
    let mut indexed = Indexed::new();
    for ((id, weight), tokens) in places {
        let entry = indexed.entry(id).or_default();
        let tokens: Vec<String> = tokens.into_values().collect();
        if weight == "A" { entry.0 = tokens } else { entry.1 = tokens }
    }
    // Incidents without any token have no row in either index.
    for id in 1..=16i64 {
        indexed.entry((1i64 << 40) | id).or_default();
    }
    indexed
}
