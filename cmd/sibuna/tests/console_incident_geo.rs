//! Incident geography from real traffic (the Zig e2e script `console_incident_geo_test.py`):
//! committed incidents drive the geography without a subscriber or a sampling draw;
//! incidents before a GeoIP import stay unknown, later ones are attributed; events filter
//! by country through the query route and the `events` topic; the `stats` topic carries the
//! geography.
#![cfg(feature = "console")]
#![allow(clippy::unwrap_used)]

mod support;

use sibuna_console_protocol::subscriptions::Topic;
use support::console::{
    Console, Node, Session, Stream, console_config, data_plane, field, field_of, geo_import,
    init_admin, length, number, scratch, until,
};
use support::get;

/// The United States as the stats report a country: two big-endian ASCII bytes.
const US: u64 = 0x5553;

/// Waits until the incident geography satisfies `done`; checks its invariants on the way.
fn geography(
    console: &Console,
    session: &Session,
    done: impl Fn(&support::Response) -> bool,
) -> support::Response {
    until("the incident geography", 15, || {
        let stats = console.stats(session);
        assert_eq!(field(&stats, "incident_geo.version"), "1");
        assert!(number(&stats, "incident_geo.started_at") > 0);
        assert_eq!(field(&stats, "node"), "1");
        for counter in ["dropped", "expired", "future"] {
            assert_eq!(number(&stats, &format!("incident_geo.{counter}")), 0, "{counter}");
        }
        done(&stats).then_some(stats)
    })
}

/// The samples of country `code` in the stats' incident geography, or 0.
fn samples(stats: &support::Response, code: u64) -> u64 {
    (0..length(stats, "incident_geo.countries"))
        .find(|&row| number(stats, &format!("incident_geo.countries.{row}.code")) == code)
        .map_or(0, |row| number(stats, &format!("incident_geo.countries.{row}.samples")))
}

#[test]
fn committed_incidents_drive_the_geography() {
    let dir = scratch("incident-geo");
    let config = data_plane(&dir);
    let temporary = init_admin(&config);
    let mut node = Node::start(config, console_config(), None);
    let console = node.console();
    let session = console.change_password(&temporary);
    let port = node.port();
    let honeypot = |ip: &str| {
        let reply = get(port, "/__sibuna/honeypot", ip, "Mozilla/5.0", "");
        assert_eq!(reply.status(), 403);
    };

    // Fifteen findings before any GeoIP generation stay unknown; a build with an embedded
    // snapshot (`SIBUNA_GEOIP_DATA`) may already attribute them.
    let geoip = console.get("/console/api/geoip", Some(&session));
    let embedded = field(&geoip, "source") == "embedded snapshot";
    for index in 0..15 {
        honeypot(&format!("8.8.8.{}", index + 1));
    }
    let attributed = |stats: &support::Response| {
        let countries = length(stats, "incident_geo.countries");
        (0..countries)
            .map(|row| number(stats, &format!("incident_geo.countries.{row}.samples")))
            .sum::<u64>()
    };
    let before = geography(&console, &session, |stats| {
        number(stats, "incident_geo.unknown") + attributed(stats) == 15
    });
    assert_eq!(field(&before, "geoip_available"), embedded.to_string());
    let unknown = number(&before, "incident_geo.unknown");
    assert!(embedded || unknown == 15);
    let us_before = samples(&before, US);

    geo_import(&console, &session, 0);
    for index in 0..5 {
        honeypot(&format!("8.8.18.{}", index + 1));
    }
    let after = geography(&console, &session, |stats| samples(stats, US) == us_before + 5);
    assert_eq!(field(&after, "geoip_available"), "true");
    assert_eq!(number(&after, "incidents"), 20);
    // Earlier findings keep their attribution: an import never relocates them.
    assert_eq!(number(&after, "incident_geo.unknown"), unknown);

    events(&console, &session);
    let mut stream = Stream::open(&console, &session);
    stream.subscribe("stats", "{}");
    let view = stream.until(Topic::Stats, 10, |_| true);
    assert_eq!(field_of(view.as_bytes(), "incident_geo.countries.0.code"), US.to_string());
    let shown = field_of(view.as_bytes(), "incident_geo.countries.0.samples");
    assert_eq!(shown, (us_before + 5).to_string());
    node.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Events filter by country on the query route and on the `events` topic.
fn events(console: &Console, session: &Session) {
    let endpoint = "/console/api/events/query";
    assert_eq!(console.post(endpoint, "{\"country\":\"us\"}", session).status(), 400);
    let page = until("the attributed incident", 15, || {
        let page = console.ok(endpoint, "{\"country\":\"US\",\"ip\":\"8.8.18.1\"}", session);
        (length(&page, "rows") == 1).then_some(page)
    });
    assert_eq!(field(&page, "rows.0.country"), "US");
    assert_eq!(field(&page, "rows.0.geography.code"), "US");
    assert_eq!(field(&page, "rows.0.geography.recorded"), "true");
    assert_eq!(field(&page, "rows.0.geography.generation").len(), 64);
    let other = console.ok(endpoint, "{\"country\":\"DE\",\"ip\":\"8.8.18.1\"}", session);
    assert_eq!(length(&other, "rows"), 0);

    let mut stream = Stream::open(console, session);
    stream.subscribe("events", "{\"country\":\"US\"}");
    let view = stream.until(Topic::Events, 15, |view| {
        field_of(view.as_bytes(), "rows")
            .trim_matches(['[', ']'])
            .matches("\"code\":\"US\"")
            .count()
            >= 5
    });
    let rows = field_of(view.as_bytes(), "rows");
    assert!(!rows.contains("\"code\":\"DE\""), "{rows}");
}
