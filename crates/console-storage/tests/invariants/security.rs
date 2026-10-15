//! The security overview and trends: per-source totals, 60-bucket trends and top addresses,
//! top categories and paths without their queries, the aggregate-only read, and the work
//! bound.

use sibuna_console_protocol::security::{Query, Request, View};
use sibuna_console_storage::ConsoleStorageError;
use sibuna_console_storage::security::query_security;
use sibuna_storage::WorkBound;

use crate::common::{NOW, for_each_backend};
use crate::events::{Stored, TINY, admin, many, store};

fn query(view: View, aggregate_only: bool) -> Query {
    Query {
        request: Request { view, node: 0, from: 1000, until: 1600 },
        aggregate_only,
        ..Query::default()
    }
}

/// Stores the window's incidents: inspection from three addresses, honeypot hits, others,
/// and one incident outside the window.
async fn findings(tx: &mut sibuna_storage::Transaction) {
    let rows: [(&'static str, &'static str, &[u8], u64); 9] = [
        ("203.0.113.1", "waf:sqli", b"/login?user=a", 1000),
        ("203.0.113.1", "waf:sqli", b"/login?user=b", 1010),
        ("203.0.113.1", "audit:xss", b"/search#frag", 1020),
        ("203.0.113.2", "waf:sqli", b"/login", 1300),
        ("203.0.113.3", "waf:rce", b"/cgi", 1590),
        ("203.0.113.9", "honeypot", b"/trap", 1100),
        ("203.0.113.9", "honeypot", b"/trap", 1110),
        ("203.0.113.8", "rate", b"/api", 1200),
        ("203.0.113.8", "rate", b"/api", 1600),
    ];
    for (sequence, (ip, category, path, time)) in (1u64..).zip(rows) {
        let incident = Stored { ip, category, path: path.to_vec(), ..Stored::new(sequence, time) };
        store(tx, &incident).await;
    }
}

#[test]
fn modules_report_totals_trends_and_top_sources() {
    for_each_backend("security_modules", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = admin(&mut tx).await;
        findings(&mut tx).await;
        let input = query(View::Modules, false);
        let page = query_security(&mut tx, &admin, &input, WorkBound::default(), NOW)
            .await
            .expect("page");
        assert_eq!((page.total, page.observed_at, page.request), (8, NOW, input.request));
        let [inspection, honeypot, other] = &page.modules;
        assert_eq!((inspection.total, honeypot.total, other.total), (5, 2, 1));
        // Ten seconds per bucket over 600 seconds.
        assert_eq!((inspection.trend[0], inspection.trend[1], inspection.trend[2]), (1, 1, 1));
        assert_eq!((inspection.trend[30], inspection.trend[59]), (1, 1));
        assert_eq!(honeypot.trend[10] + honeypot.trend[11], 2);
        assert_eq!(inspection.trend.iter().sum::<u64>(), 5);
        let sources: Vec<(&str, u64)> = inspection
            .sources
            .iter()
            .flatten()
            .map(|rank| (rank.label.as_str(), rank.count))
            .collect();
        assert_eq!(sources, [("203.0.113.1", 3), ("203.0.113.2", 1), ("203.0.113.3", 1)]);
        assert_eq!(honeypot.sources[0].as_ref().map(|rank| rank.count), Some(2));
        assert!(honeypot.sources[1].is_none());
        // The kiosk's aggregate-only read never names an address.
        let trends = query(View::Modules, true);
        let page = query_security(&mut tx, &admin, &trends, WorkBound::default(), NOW)
            .await
            .expect("trends");
        assert_eq!(page.modules[0].total, 5);
        assert!(page.modules.iter().all(|module| module.sources.iter().all(Option::is_none)));
    });
}

#[test]
fn categories_and_paths_rank_the_top_five_without_queries() {
    for_each_backend("security_ranks", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = admin(&mut tx).await;
        findings(&mut tx).await;
        let page = query_security(
            &mut tx,
            &admin,
            &query(View::Categories, false),
            WorkBound::default(),
            NOW,
        )
        .await
        .expect("categories");
        let ranks: Vec<(&str, u64)> =
            page.rows.iter().flatten().map(|rank| (rank.label.as_str(), rank.count)).collect();
        assert_eq!(
            ranks,
            [("waf:sqli", 3), ("honeypot", 2), ("audit:xss", 1), ("rate", 1), ("waf:rce", 1)]
        );
        assert_eq!(page.total, 8);
        let page =
            query_security(&mut tx, &admin, &query(View::Paths, false), WorkBound::default(), NOW)
                .await
                .expect("paths");
        let ranks: Vec<(&str, u64)> =
            page.rows.iter().flatten().map(|rank| (rank.label.as_str(), rank.count)).collect();
        assert_eq!(ranks, [("/login", 3), ("/trap", 2), ("/api", 1), ("/cgi", 1), ("/search", 1)]);
        let node = Query {
            request: Request { node: 2, ..query(View::Paths, false).request },
            ..query(View::Paths, false)
        };
        let page =
            query_security(&mut tx, &admin, &node, WorkBound::default(), NOW).await.expect("node");
        assert_eq!(page.total, 0);
        assert!(page.rows.iter().all(Option::is_none));
    });
}

#[test]
fn invalid_windows_and_aggregate_views_are_refused() {
    for_each_backend("security_invalid", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = admin(&mut tx).await;
        let empty = Query {
            request: Request { from: 10, until: 10, ..Request::default() },
            ..Query::default()
        };
        let refused = query_security(&mut tx, &admin, &empty, WorkBound::default(), NOW).await;
        assert!(matches!(refused, Err(ConsoleStorageError::InvalidInput(_))));
        let paths = query(View::Paths, true);
        let refused = query_security(&mut tx, &admin, &paths, WorkBound::default(), NOW).await;
        assert!(matches!(refused, Err(ConsoleStorageError::InvalidInput(_))));
    });
}

#[test]
fn security_reads_past_their_work_bound_are_unavailable() {
    for_each_backend("security_bound", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = admin(&mut tx).await;
        many(&mut tx).await;
        tx.commit().await.expect("commit");
        let mut tx = db.begin().await.expect("begin");
        let refused =
            query_security(&mut tx, &admin, &query(View::Modules, false), TINY, NOW).await;
        assert!(matches!(refused, Err(ConsoleStorageError::Unavailable)), "{refused:?}");
        drop(tx);
        let mut tx = db.begin().await.expect("begin");
        let page = query_security(
            &mut tx,
            &admin,
            &query(View::Modules, false),
            WorkBound::default(),
            NOW,
        )
        .await
        .expect("within the default bound");
        assert_eq!(page.total, 20_000);
        assert_eq!(page.modules[0].sources.iter().flatten().count(), 3);
    });
}
