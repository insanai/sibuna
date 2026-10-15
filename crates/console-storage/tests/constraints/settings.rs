//! The constraints of the settings catalogue.

use crate::common::{for_each_backend, insert};
use crate::policy::{admin, cases};
use crate::{refuses, with};

#[test]
fn settings_outside_the_catalogue_are_refused_by_the_schema() {
    for_each_backend("constraint_settings", |db| async move {
        admin(&db).await;
        let template = cases(&[
            ("key", "'retention.audit'"),
            ("value", "365"),
            ("revision", "1"),
            ("updated_at", "0"),
            ("updated_by", "1"),
        ]);
        let bad = cases(&[
            ("key", "'retention.other'"),
            ("key", "NULL"),
            ("value", "0"),
            ("value", "366"),
            ("value", "NULL"),
            ("value", "'thirty'"),
            ("revision", "0"),
            ("updated_at", "-1"),
            ("updated_by", "999"),
        ]);
        refuses(&db, "console_settings", &template, &bad).await;
        // Each key has its own bound.
        let bounds = [
            ("'notify.spike_factor'", "1000001", "1000000"),
            ("'notify.spike_minimum'", "1000001", "1000000"),
            ("'retention.minutes'", "91", "90"),
            ("'retention.rankings'", "8", "7"),
            ("'retention.incidents'", "31", "30"),
        ];
        for (key, over, maximum) in bounds {
            let row = with(&template, "key", key);
            assert!(insert(&db, "console_settings", &with(&row, "value", over)).await.is_err());
            insert(&db, "console_settings", &with(&row, "value", maximum)).await.expect(key);
        }
    });
}
