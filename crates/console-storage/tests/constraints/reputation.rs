//! The constraints of reputation ownership and staged country chunks.

use sibuna_storage::Sql;

use crate::common::{bytes, for_each_backend, insert, scalar};
use crate::policy::cases;
use crate::{refuses, with};

#[test]
fn reputation_sources_refuse_rows_the_types_cannot_hold() {
    for_each_backend("constraint_reputation_sources", |db| async move {
        let d = db.dialect();
        for prefix in ["192.0.2.0/24", "198.51.100.0/24"] {
            let row = cases(&[
                ("ip_or_cidr", &format!("'{prefix}'")),
                ("reputation_score", "-100"),
                ("last_seen", "0"),
            ]);
            insert(&db, "ip_reputation", &row).await.expect("reputation");
        }
        let template = cases(&[("ip_or_cidr", "'192.0.2.0/24'"), ("note", "'abuse'")]);
        let mut bad = cases(&[
            ("ip_or_cidr", "'203.0.113.0/24'"),
            ("ip_or_cidr", "NULL"),
            ("note", "NULL"),
            // A country needs its generation, and the reverse.
            ("country", "'US'"),
        ]);
        bad.push(("geo_generation", bytes(d, 32, 1)));
        bad.push(("note", format!("'{}'", "n".repeat(129))));
        refuses(&db, "console_reputation_sources", &template, &bad).await;
        let country = with(
            &with(&cases(&[("ip_or_cidr", "'198.51.100.0/24'")]), "country", "'US'"),
            "geo_generation",
            &bytes(d, 32, 1),
        );
        for (column, value) in [
            ("country", "'us'".to_owned()),
            ("country", "'USA'".to_owned()),
            ("geo_generation", bytes(d, 31, 1)),
            // A country action carries no note.
            ("note", "'x'".to_owned()),
        ] {
            let row = with(&country, column, &value);
            assert!(insert(&db, "console_reputation_sources", &row).await.is_err(), "{column}");
        }
        insert(&db, "console_reputation_sources", &country).await.expect("a country row");
        // A direct deletion of the reputation row removes its ownership.
        db.execute(Sql::both("DELETE FROM ip_reputation WHERE ip_or_cidr = '192.0.2.0/24'"), &[])
            .await
            .expect("delete");
        let mut tx = db.begin().await.expect("begin");
        let owned = "SELECT CAST(COUNT(*) AS BIGINT) FROM console_reputation_sources";
        assert_eq!(scalar(&mut tx, owned).await, 1);
    });
}

#[test]
fn country_chunks_refuse_rows_the_types_cannot_hold() {
    for_each_backend("constraint_country_chunks", |db| async move {
        let d = db.dialect();
        let template = vec![
            ("digest", bytes(d, 32, 7)),
            ("ordinal", "0".to_owned()),
            ("prefix", "'192.0.2.0/24'".to_owned()),
            ("recorded_at", "0".to_owned()),
        ];
        let mut bad = cases(&[
            ("digest", "NULL"),
            ("ordinal", "-1"),
            ("ordinal", "1024"),
            ("ordinal", "NULL"),
            ("prefix", "''"),
            ("prefix", "NULL"),
            ("recorded_at", "-1"),
        ]);
        bad.push(("digest", bytes(d, 31, 7)));
        bad.push(("prefix", format!("'{}'", "1".repeat(49))));
        refuses(&db, "console_country_chunks", &template, &bad).await;
        // One prefix per ordinal, and each prefix once per set.
        let same_ordinal = with(&template, "prefix", "'198.51.100.0/24'");
        assert!(insert(&db, "console_country_chunks", &same_ordinal).await.is_err());
        let same_prefix = with(&template, "ordinal", "1");
        assert!(insert(&db, "console_country_chunks", &same_prefix).await.is_err());
        let other_set = with(&template, "digest", &bytes(d, 32, 8));
        insert(&db, "console_country_chunks", &other_set).await.expect("another set");
    });
}
