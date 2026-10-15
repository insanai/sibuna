use super::*;
use crate::app::App;
use crate::golden::{self, configure};
use crate::testing::{ADMIN_SESSION, Harness};

fn similarity(app: &mut App) -> &mut Similarity {
    app.pages_mut().find_mut::<Similarity>().unwrap()
}

fn signed_in() -> Harness {
    let mut harness = Harness::new();
    harness.respond("session", 200, ADMIN_SESSION);
    harness
}

#[test]
fn golden_similarity_page() {
    let mut app = App::new();
    configure(&mut app, Phase::Similarity);
    golden::check("similarity", app.render_now());
}

/// Ported from `similarity_state.zig`.
#[test]
fn invalid_parts_cannot_alter_accumulated_matches_or_move_the_cursor_forward() {
    let mut model = Model {
        source: 1,
        until: 200,
        next: Some(Cursor { time: 190, id: 10 }),
        ..Model::default()
    };
    let previous = model.clone();
    let forward = Part { scanned: 64, next: Some((191, "10")), ..Part::default() };
    assert_eq!(model.accept(&forward), Err(UiError::InvalidResponse));
    assert_eq!(model, previous);
    let same = Part { scanned: 64, next: Some((190, "10")), ..Part::default() };
    assert_eq!(model.accept(&same), Err(UiError::InvalidResponse));
    let rows = vec![
        PartRow { id: "2", node: 1, time: 180, distance: 0.1 },
        PartRow { id: "3", node: 1, time: 180, distance: f64::NAN },
    ];
    let nan = Part { scanned: 2, rows, ..Part::default() };
    assert_eq!(model.accept(&nan), Err(UiError::InvalidResponse));
    assert_eq!(model, previous);
    let source = Part {
        scanned: 1,
        rows: vec![PartRow { id: "1", node: 1, time: 1, distance: 0.0 }],
        ..Part::default()
    };
    assert_eq!(model.accept(&source), Err(UiError::InvalidResponse));
    let unfinished = Part { scanned: 63, next: Some((100, "1")), ..Part::default() };
    assert_eq!(model.accept(&unfinished), Err(UiError::InvalidResponse));
    assert_eq!(model, previous);
}

#[test]
fn parts_accumulate_until_the_range_is_exhausted() {
    let mut model = Model { source: 1, until: 200, running: true, ..Model::default() };
    let first = Part {
        source_available: true,
        scanned: 64,
        invalid: 2,
        rows: vec![PartRow { id: "9007199254740993", node: 2, time: 150, distance: 0.25 }],
        next: Some((150, "8")),
        ..Part::default()
    };
    model.accept(&first).unwrap();
    assert!(model.running && !model.complete);
    let last = Part {
        source_available: true,
        scanned: 3,
        rows: vec![PartRow { id: "4", node: 1, time: 100, distance: 0.125 }],
        ..Part::default()
    };
    model.accept(&last).unwrap();
    assert!(model.complete && !model.running);
    assert_eq!(model.scanned, 67);
    assert_eq!(model.invalid, 2);
    let ids: Vec<u64> = model.best.rows().iter().map(|row| row.id).collect();
    assert_eq!(ids, [4, 9_007_199_254_740_993]);
}

/// Ported from `main.zig`.
#[test]
fn paused_similarity_rejects_delayed_parts_and_resumes_with_a_fresh_generation() {
    let mut harness = signed_in();
    harness.send(1, "{\"action\":\"events\",\"browser_time\":200}");
    harness.send(1, "{\"action\":\"events-similar-9007199254740993\",\"browser_time\":200}");
    assert_eq!(harness.app.state().phase, Phase::Similarity);
    let old_generation = similarity(&mut harness.app).model.generation;
    assert!(harness.commands().contains(&format!(
        "\"id\":\"similarity-{old_generation}\",\"path\":\"/console/api/events/similar\",\
         \"csrf\":\"test\",\"body\":{{\"source\":\"9007199254740993\",\
         \"generation\":{old_generation},\"before\":null,\"from\":0,\"until\":200}}"
    )));
    harness.action("similarity-pause", "null");
    assert!(!similarity(&mut harness.app).model.running);
    let delayed = format!("{{\"generation\":{old_generation},\"scanned\":64}}");
    harness.respond(&format!("similarity-{old_generation}"), 200, &delayed);
    assert_eq!(similarity(&mut harness.app).model.scanned, 0);
    harness.action("similarity-resume", "null");
    let model = &similarity(&mut harness.app).model;
    assert!(model.running && model.busy);
    assert_ne!(model.generation, old_generation);
}

/// Ported from `main.zig`.
#[test]
fn inspecting_a_match_preserves_similarity_results_for_return_navigation() {
    let mut harness = signed_in();
    harness.app.state_mut().phase = Phase::Similarity;
    let model = &mut similarity(&mut harness.app).model;
    *model = Model { source: 1, complete: true, ..Model::default() };
    model.best.add(Match { id: 2, distance: 0.1, ..Match::default() });
    harness.action("events-incident-2", "null");
    assert_eq!(harness.app.state().phase, Phase::Events);
    assert_eq!(harness.app.pages().find::<Events>().unwrap().model.incident, 2);
    harness.action("similarity-return", "null");
    assert_eq!(harness.app.state().phase, Phase::Similarity);
    let model = &similarity(&mut harness.app).model;
    assert_eq!(model.best.rows().len(), 1);
    assert!(model.complete);
}

#[test]
fn parts_continue_on_a_timer_and_draw_their_matches() {
    let mut harness = signed_in();
    harness.send(1, "{\"action\":\"events\",\"browser_time\":7400}");
    harness.respond("events", 200, "{\"rows\":[]}");
    harness.send(
        1,
        "{\"action\":\"events-filter\",\"fields\":{\"hours\":\"1\"},\"browser_time\":7400}",
    );
    harness.send(1, "{\"action\":\"events-similar-5\",\"browser_time\":7400}");
    assert!(harness.commands().contains("\"from\":3800,\"until\":7400}"));
    let generation = similarity(&mut harness.app).model.generation;
    let id = format!("similarity-{generation}");
    let part = format!(
        "{{\"generation\":{generation},\"source_available\":true,\"scanned\":64,\"invalid\":1,\
         \"rows\":[{{\"id\":\"9\",\"node\":3,\"time\":7300,\"distance\":0.123456}}],\
         \"next\":{{\"time\":7300,\"id\":\"9\"}}}}"
    );
    harness.respond(&id, 200, &part);
    assert!(
        harness.commands().contains("{\"op\":\"timer\",\"id\":\"similarity\",\"delay_ms\":250}")
    );
    let html = harness.html();
    assert!(html.contains("Searching: 64 records scanned,\n  1 missing or invalid vectors."));
    assert!(html.contains("<p>Node 3 \u{b7} Cosine distance 0.12346</p>"));
    assert!(html.contains("<p>1970-01-01 02:01:40 UTC</p>"));
    assert!(html.contains("data-action=\"events-incident-9\""));
    harness.send(3, "{\"id\":\"age\",\"browser_time\":7400}");
    assert!(!harness.commands().contains(&id));
    harness.send(3, "{\"id\":\"similarity\",\"browser_time\":7400}");
    assert!(harness.commands().contains("\"before\":{\"time\":7300,\"id\":\"9\"}"));
    harness.respond(&id, 429, "{}");
    assert!(harness.commands().contains("\"delay_ms\":60000"));
    assert!(harness.app.state().message.as_str().starts_with("Query allowance reached."));
    harness.send(3, "{\"id\":\"similarity\",\"browser_time\":7400}");
    harness.respond(&id, 500, "{}");
    assert!(!similarity(&mut harness.app).model.running);
    assert!(harness.html().contains("data-action=\"similarity-resume\""));
}

#[test]
fn unreadable_parts_pause_and_revoked_access_signs_out() {
    let mut harness = signed_in();
    harness.action("events-similar-5", "null");
    let generation = similarity(&mut harness.app).model.generation;
    let id = format!("similarity-{generation}");
    harness.respond(&id, 200, "{\"rows\":7}");
    assert!(!similarity(&mut harness.app).model.running);
    assert_eq!(
        harness.app.state().message.as_str(),
        "Could not read similarity results. Resume to retry this part."
    );
    harness.action("similarity-resume", "null");
    let generation = similarity(&mut harness.app).model.generation;
    harness.respond(&format!("similarity-{generation}"), 401, "{}");
    assert_eq!(harness.app.state().phase, Phase::Login);
    assert!(harness.app.state().csrf.is_empty());
    assert_eq!(similarity(&mut harness.app).model, Model::default());
    // The generation counter survives the sign-out.
    harness.respond("session", 200, ADMIN_SESSION);
    harness.action("events-similar-5", "null");
    assert!(similarity(&mut harness.app).model.generation > generation);
}

#[test]
fn an_unavailable_source_says_so() {
    let mut app = App::new();
    configure(&mut app, Phase::Similarity);
    let model = &mut app.pages_mut().find_mut::<Similarity>().unwrap().model;
    *model = Model { source: 3, unavailable: true, complete: true, ..Model::default() };
    let html = app.render_now();
    assert!(html.contains("Unavailable: 0 records scanned"));
    assert!(html.contains("The source has no usable retained vector."));
    assert!(!html.contains("Closest matches"));
}
