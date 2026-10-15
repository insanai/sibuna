//! Port of `rule_hit_history_test.zig`.

use super::*;
use crate::codec::{from_json, to_json};

fn request() -> Request {
    Request {
        key: Key::new("m:rule").unwrap(),
        node: 7,
        from_minute: 2,
        until_minute: 3,
        ..Request::default()
    }
}

fn row(minute: u64, hits: Option<u64>) -> Row {
    Row {
        hits,
        span: Span {
            node: 7,
            boot: [1; 16],
            generation: 1,
            revision: 1,
            sequence: minute,
            minute,
            utc_start: minute * 60 - 1,
            utc_end: minute * 60 + 59,
            start_ms: minute * 60_000 - 1000,
            end_ms: minute * 60_000 + 59_000,
            observed_ms: 60_000,
            observations: 60,
            complete: true,
            ..Span::default()
        },
    }
}

fn part(finished: bool) -> Part {
    let mut window = Window::new(request());
    window.retention_days = Some(90);
    window.finished = finished;
    Part { version: 1, observed_at: 300, window }
}

#[test]
fn rule_comparison_pages_freeze_scope_and_preserve_full_counter_and_coverage_arithmetic() {
    let mut window = Window::new(request());
    let mut item = part(false);
    item.window.add(&row(3, Some(5))).unwrap();
    item.window.next = item.window.last;
    accept(&mut window, &item).unwrap();
    assert!(!window.covered());
    let previous = window.clone();
    assert_eq!(accept(&mut window, &item), Err(InvalidResponse));
    assert_eq!(previous, window);
    item.window = Window::new(window.request.clone());
    item.window.retention_days = Some(90);
    item.window.finished = true;
    item.window.add(&row(2, Some(7))).unwrap();
    accept(&mut window, &item).unwrap();
    assert!(window.covered());
    assert_eq!(window.hits, Some(12));
    assert_eq!(window.bins[12].hits, Some(5));
    assert_eq!(window.bins[0].hits, Some(7));
}

#[test]
fn missing_counters_overlapping_boots_and_malformed_summaries_cannot_support_a_deviation() {
    let mut item = part(true);
    item.window.add(&row(3, None)).unwrap();
    let mut duplicate = row(3, Some(10));
    duplicate.span.sequence -= 1;
    item.window.add(&duplicate).unwrap();
    let mut window = Window::new(request());
    accept(&mut window, &item).unwrap();
    assert!(window.ambiguous);
    assert_eq!(window.hits, None);
    assert!(!window.covered());
    window = Window::new(request());
    item.window.bins[12].rows += 1;
    assert_eq!(accept(&mut window, &item), Err(InvalidResponse));
    assert_eq!(window.rows, 0);
}

#[test]
fn rule_history_rejects_open_windows_zero_nodes_and_invalid_revision_cursors() {
    let mut query = Query {
        request: request(),
        observed_at: 300,
        session_digest: [1; 32],
        ..Query::default()
    };
    assert_eq!(validate(&query), Ok(()));
    query.request.until_minute = 5;
    assert_eq!(validate(&query), Err(ValidationError::InvalidLimit));
    query.request = request();
    query.request.node = 0;
    assert_eq!(validate(&query), Err(ValidationError::InvalidLimit));
    query.request = request();
    query.request.revision = Some(u64::MAX);
    assert_eq!(validate(&query), Err(ValidationError::InvalidLimit));
}

#[test]
fn malformed_revision_metadata_and_cursors_never_publish_a_partial_history_page() {
    let mut valid = part(true);
    valid.window.add(&row(3, Some(5))).unwrap();
    let mut window = Window::new(request());
    for variant in 0..4 {
        let mut item = valid.clone();
        match variant {
            0 => item.window.max_revision = None,
            1 => item.window.min_revision = Some(2),
            2 => item.window.first.as_mut().unwrap().boot = [0; 16],
            _ => item.window.last.as_mut().unwrap().sequence = 0,
        }
        assert_eq!(accept(&mut window, &item), Err(InvalidResponse));
        assert_eq!(window.rows, 0);
    }
}

#[test]
fn display_bins_partition_short_and_retained_windows_without_inventing_missing_minutes() {
    for duration in [1u64, 5, 24, 25, 60, 1440, 129_600] {
        let mut input = request();
        input.until_minute = input.from_minute + duration - 1;
        let mut next = input.from_minute;
        for index in 0..BIN_COUNT {
            let Some(range) = bin_range(&input, index) else { continue };
            assert_eq!(next, range.from_minute);
            let first = (range.from_minute - input.from_minute) * BIN_COUNT as u64 / duration;
            let last = (range.until_minute - input.from_minute) * BIN_COUNT as u64 / duration;
            assert_eq!(index as u64, first);
            assert_eq!(index as u64, last);
            next = range.until_minute + 1;
        }
        assert_eq!(input.until_minute + 1, next);
    }
    assert_eq!(bin_range(&request(), BIN_COUNT), None);
}

// Port of json_counters.zig "bounded record serialization preserves maximum counters and
// nullable array elements": the same field rules, shown on a bin and today's hours.
#[test]
fn bounded_record_serialization_preserves_maximum_counters_and_nullable_array_elements() {
    let mut today = Today { hits: Some(u64::MAX), ..Today::default() };
    today.hours[0] = Some(u64::MAX);
    let text = to_json(&today);
    assert!(text.starts_with(
        "{\"hits\":\"18446744073709551615\",\"hours\":[\"18446744073709551615\",null,"
    ));
    assert_eq!(from_json::<Today>(text.as_bytes()), Ok(today));
    let bin = Bin { hits: None, rows: 7, complete: 1 };
    assert_eq!(to_json(&bin), "{\"hits\":null,\"rows\":7,\"complete\":1}");
}

#[test]
fn windows_and_parts_round_trip() {
    let mut item = part(true);
    item.window.add(&row(3, Some(9_007_199_254_740_993))).unwrap();
    item.window.request.before = Some(Cursor { minute: 4, boot: [2; 16], sequence: 9 });
    let text = to_json(&item);
    assert!(text.starts_with(
        "{\"version\":1,\"observed_at\":300,\"window\":{\"request\":{\"key\":\"m:rule\",\
         \"node\":7,\
         \"from_minute\":2,\"until_minute\":3,\"revision\":null,\"before\":{\"minute\":4,\
         \"boot\":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],\"sequence\":9}},\
         \"hits\":\"9007199254740993\","
    ));
    assert_eq!(from_json::<Part>(text.as_bytes()), Ok(item));
}
