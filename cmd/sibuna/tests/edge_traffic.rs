//! Traffic management through the edge binary (SID 0019): timeouts, failover, passive
//! health, slow start, sticky sessions, round robin and the HTTP policy of a frontend.
#![allow(clippy::unwrap_used)]
#![cfg(unix)]

mod traffic;

use std::collections::BTreeSet;
use std::io::Write;
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use traffic::{
    Origin, Topology, blackhole, both, get, get_with, logged, post, refused, request, shown,
};

#[test]
fn a_slow_server_has_its_own_bound_and_not_the_client_idle_timeout() {
    both(|event_loop| {
        let origin = Origin::start("a");
        // The client idle timeout is far shorter than the answer takes.
        let edge =
            Topology::new(&[origin.address]).http(r#","idle_timeout":"1s""#).start(event_loop);
        let started = Instant::now();
        let answer = get(&edge, "/slow/2500");
        assert_eq!((answer.status(), answer.text()), (200, "slept".into()));
        assert!(started.elapsed() >= Duration::from_millis(2500));

        // A pool with a short bound answers 504 soon after it.
        let edge = Topology::new(&[origin.address])
            .backend(r#""response_timeout":"1s","#)
            .start(event_loop);
        let started = Instant::now();
        assert_eq!(get(&edge, "/slow/6000").status(), 504);
        let waited = started.elapsed();
        assert!(waited >= Duration::from_secs(1) && waited < Duration::from_secs(4), "{waited:?}");
        // The bound is on silence. A quick answer on the same pool is unaffected.
        assert_eq!(get(&edge, "/who").text(), "a");
    });
}

#[test]
fn a_slow_upload_keeps_the_client_bound_whatever_the_server_bound_is() {
    both(|event_loop| {
        let origin = Origin::start("a");
        let edge = Topology::new(&[origin.address])
            .http(r#","idle_timeout":"1s""#)
            .backend(r#""response_timeout":"30s","#)
            .start(event_loop);
        let started = Instant::now();
        let mut client = edge.connect();
        request(
            &mut client,
            b"POST /who HTTP/1.1\r\nHost: a\r\nContent-Length: 100000\r\n\r\nabc",
        );
        let mut rest = Vec::new();
        let _ = std::io::Read::read_to_end(&mut client, &mut rest);
        // The client owed the body, so its own bound of one second ended the wait.
        assert!(started.elapsed() < Duration::from_secs(6), "{:?}", started.elapsed());
        let _ = client.get_ref().shutdown(Shutdown::Both);
    });
}

#[test]
fn a_connect_that_hangs_ends_at_the_connect_timeout_of_the_pool() {
    both(|event_loop| {
        let hole = blackhole();
        let edge = Topology::new(&[hole.address])
            .backend(r#""connect_timeout":"1s","retries":0,"#)
            .start(event_loop);
        let started = Instant::now();
        assert_eq!(get(&edge, "/who").status(), 502);
        let waited = started.elapsed();
        // The fixed bound was five seconds.
        assert!(
            waited >= Duration::from_millis(900) && waited < Duration::from_secs(4),
            "{waited:?}"
        );
    });
}

#[test]
fn the_traffic_members_are_checked_when_the_file_is_read() {
    let origin = Origin::start("a");
    let refused = Topology::new(&[origin.address]).backend(r#""response_timeout":"never","#);
    let message = refused.check().unwrap_err();
    assert!(message.contains("backends.app.response_timeout"), "{message}");
    assert!(message.contains("Hint:"), "{message}");
    assert!(Topology::new(&[origin.address]).backend(r#""retries":3,"#).check().is_ok());
    both(|event_loop| {
        // A topology without any member of SID 0019 serves as before.
        let edge = Topology::new(&[origin.address]).start(event_loop);
        assert_eq!(get(&edge, "/who").text(), "a", "{event_loop}");
    });
    assert!(origin.connections.load(Ordering::SeqCst) >= 2);
    let _ = TcpStream::connect(origin.address);
}

#[test]
fn a_failed_connect_moves_any_request_to_another_server() {
    both(|event_loop| {
        let good = Origin::start("good");
        // Least connections tries the servers in the order of the file, so the dead one is
        // selected first.
        let edge = Topology::new(&[refused(), good.address]).start(event_loop);
        let answer = post(&edge, "/length", b"twelve bytes");
        assert_eq!((answer.status(), answer.text()), (200, "12".into()));
        assert_eq!(good.requests.load(Ordering::SeqCst), 1);

        // A connect that hangs moves on at the connect bound of the pool.
        let hole = blackhole();
        let edge = Topology::new(&[hole.address, good.address])
            .backend(r#""connect_timeout":"1s","#)
            .start(event_loop);
        let started = Instant::now();
        assert_eq!(get(&edge, "/who").text(), "good");
        assert!(started.elapsed() < Duration::from_secs(4), "{:?}", started.elapsed());
    });
}

#[test]
fn a_request_tries_at_most_its_retries_and_no_server_twice() {
    both(|event_loop| {
        let good = Origin::start("good");
        let servers = [refused(), refused(), refused(), good.address];
        // The default allows two other servers: three dead ones exhaust it.
        let edge = Topology::new(&servers).start(event_loop);
        assert_eq!(get(&edge, "/who").status(), 502);
        assert_eq!(good.requests.load(Ordering::SeqCst), 0);
        let edge = Topology::new(&servers).backend(r#""retries":3,"#).start(event_loop);
        assert_eq!(get(&edge, "/who").text(), "good");
        // Without retries the first failure is final.
        let edge = Topology::new(&servers[2..]).backend(r#""retries":0,"#).start(event_loop);
        assert_eq!(get(&edge, "/who").status(), 502);
        // A pool of dead servers ends once each was tried, whatever the retries allow.
        let edge = Topology::new(&servers[..2]).backend(r#""retries":8,"#).start(event_loop);
        assert_eq!(get(&edge, "/who").status(), 502);
    });
}

#[test]
fn after_bytes_were_sent_only_a_safe_buffered_request_moves() {
    both(|event_loop| {
        let closing = Origin::start("closing");
        closing.closing.store(true, Ordering::SeqCst);
        let good = Origin::start("good");
        let edge = Topology::new(&[closing.address, good.address]).start(event_loop);
        // The first server read the GET and closed without an answer. The request is safe
        // and was held whole, so the second server serves it.
        let answer = get(&edge, "/who");
        assert_eq!((answer.status(), answer.text()), (200, "good".into()));
        assert_eq!(closing.requests.load(Ordering::SeqCst), 1);
        // The failure marked the first server for two seconds. Wait until it is selected
        // again. Both servers have admitted one request, so the first is chosen.
        std::thread::sleep(Duration::from_millis(2200));
        // The first server read the POST and closed. It may have acted, so nothing is sent
        // to the second server.
        assert_eq!(post(&edge, "/length", b"abc").status(), 502);
        assert_eq!(closing.requests.load(Ordering::SeqCst), 2);
        assert_eq!(good.requests.load(Ordering::SeqCst), 1);
    });
}

/// Sends `count` requests one after another and returns their statuses and bodies.
fn answers(edge: &traffic::Edge, count: usize) -> Vec<(u16, String)> {
    (0..count)
        .map(|_| {
            let answer = get(edge, "/who");
            (answer.status(), answer.text())
        })
        .collect()
}

#[test]
fn a_server_that_stops_answering_is_ejected_after_consecutive_timeouts() {
    both(|event_loop| {
        let silent = Origin::start("silent");
        silent.stalled.store(true, Ordering::SeqCst);
        let good = Origin::start("good");
        let members =
            r#""response_timeout":"1s","passive_health":{"failures":2,"ejection":"30s"},"#;
        let edge =
            Topology::new(&[silent.address, good.address]).backend(members).start(event_loop);
        // Requests alternate between the two servers until the silent one has failed twice.
        let first = answers(&edge, 4);
        let timeouts = first.iter().filter(|(status, _)| *status == 504).count();
        assert_eq!(timeouts, 2, "{first:?}");
        // From then on the pool serves from the other server alone, without a wait.
        let started = Instant::now();
        let later = answers(&edge, 10);
        assert!(later.iter().all(|answer| *answer == (200, "good".into())), "{later:?}");
        assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());
        // The operator sees the ejection, how long it lasts, and its count.
        let left = shown(&edge, "s0", "ejected");
        let seconds: u64 = left.trim_end_matches('s').parse().unwrap_or_else(|_| panic!("{left}"));
        assert!((20..=30).contains(&seconds), "{left}");
        assert_eq!(shown(&edge, "s1", "ejected"), "-");
        let metrics = get(&edge, "/__sibuna/metrics").text();
        for series in [
            "sibuna_edge_server_ejections_total{backend=\"app\",server=\"s0\"} 1\n",
            "sibuna_edge_server_ejections_total{backend=\"app\",server=\"s1\"} 0\n",
        ] {
            assert!(metrics.contains(series), "{series} is missing:\n{metrics}");
        }

        // A pool of one server keeps serving: there is nothing to eject it for.
        let edge = Topology::new(&[silent.address]).backend(members).start(event_loop);
        assert_eq!(answers(&edge, 3).iter().filter(|(status, _)| *status == 504).count(), 3);
        silent.stalled.store(false, Ordering::SeqCst);
        assert_eq!(get(&edge, "/who").text(), "silent");
    });
}

#[test]
fn server_errors_eject_only_when_the_pool_counts_them() {
    both(|event_loop| {
        let failing = Origin::start("failing");
        failing.failing.store(true, Ordering::SeqCst);
        let good = Origin::start("good");
        let servers = [failing.address, good.address];
        // By default a 503 of the server is relayed and counts nothing.
        let edge = Topology::new(&servers).start(event_loop);
        let relayed = answers(&edge, 10);
        assert_eq!(relayed.iter().filter(|(status, _)| *status == 503).count(), 5, "{relayed:?}");
        let members = r#""passive_health":{"failures":2,"http_5xx":true},"#;
        let edge = Topology::new(&servers).backend(members).start(event_loop);
        let counted = answers(&edge, 12);
        assert_eq!(counted.iter().filter(|(status, _)| *status == 503).count(), 2, "{counted:?}");
        assert!(counted[4..].iter().all(|answer| *answer == (200, "good".into())), "{counted:?}");
    });
}

/// The `name=value` pair of the sticky cookie that `answer` sets, if it sets one.
fn sticky_pair(answer: &traffic::Message, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    let line = answer.fields("set-cookie").find(|line| line.starts_with(&prefix))?;
    Some(line.split(';').next().unwrap_or_default().to_owned())
}

#[test]
fn a_cookie_keeps_a_client_on_the_server_it_was_given() {
    let origins = [Origin::start("a"), Origin::start("b"), Origin::start("c")];
    let servers = origins.each_ref().map(|origin| origin.address);
    both(|event_loop| {
        let edge = Topology::new(&servers).backend(r#""sticky":"cookie","#).start(event_loop);
        // The first answer carries our cookie beside the cookie of the application.
        let first = get(&edge, "/cookie");
        let line = first.fields("set-cookie").find(|line| line.starts_with("sibuna_srv="));
        let line = line.expect("the sticky cookie").to_owned();
        assert!(line.ends_with("; Path=/; HttpOnly; SameSite=Lax"), "{line}");
        assert!(first.fields("set-cookie").any(|line| line == "app=1"));
        let pair = sticky_pair(&first, "sibuna_srv").unwrap();
        let name = first.text();
        // With the cookie every request reaches that server and no cookie is set again.
        let cookie = format!("Cookie: theme=dark; {pair}\r\n");
        for _ in 0..9 {
            let answer = get_with(&edge, "/who", &cookie);
            assert_eq!(answer.text(), name);
            assert_eq!(sticky_pair(&answer, "sibuna_srv"), None);
        }
        // Without it the requests are balanced over the pool.
        let spread: BTreeSet<String> = (0..9).map(|_| get(&edge, "/who").text()).collect();
        assert!(spread.len() >= 2, "{spread:?}");
        // A token we did not issue selects nothing and is replaced.
        let forged = get_with(&edge, "/who", "Cookie: sibuna_srv=0123456789abcdef\r\n");
        assert!(sticky_pair(&forged, "sibuna_srv").is_some());
    });
}

#[test]
fn a_sticky_server_that_fails_gives_way_to_normal_selection() {
    both(|event_loop| {
        let silent = Origin::start("silent");
        let good = Origin::start("good");
        let members = r#""sticky":{"kind":"cookie","cookie":"srv"},"response_timeout":"1s",
        "passive_health":{"failures":1,"ejection":"30s"},"#;
        let edge =
            Topology::new(&[silent.address, good.address]).backend(members).start(event_loop);
        // Find the cookie of the server that will fail.
        let pair = (0..8)
            .find_map(|_| {
                let answer = get(&edge, "/who");
                (answer.text() == "silent").then(|| sticky_pair(&answer, "srv").unwrap())
            })
            .expect("a request on the first server");
        let cookie = format!("Cookie: {pair}\r\n");
        assert_eq!(get_with(&edge, "/who", &cookie).text(), "silent");
        silent.stalled.store(true, Ordering::SeqCst);
        assert_eq!(get_with(&edge, "/who", &cookie).status(), 504);
        // The server is ejected. Its client is served by the other and gets its cookie.
        let moved = get_with(&edge, "/who", &cookie);
        assert_eq!((moved.status(), moved.text()), (200, "good".into()));
        let other = sticky_pair(&moved, "srv").expect("a new cookie");
        assert_ne!(other, pair);
    });
}

#[test]
fn a_client_address_keeps_its_server_without_a_cookie() {
    let origins = [Origin::start("a"), Origin::start("b"), Origin::start("c")];
    let servers = origins.each_ref().map(|origin| origin.address);
    both(|event_loop| {
        let edge = Topology::new(&servers).backend(r#""sticky":"source","#).start(event_loop);
        // Every connection has another client port and the same client address.
        let answers: Vec<_> = (0..12).map(|_| get(&edge, "/who")).collect();
        let names: BTreeSet<String> = answers.iter().map(traffic::Message::text).collect();
        assert_eq!(names.len(), 1, "{names:?}");
        assert!(answers.iter().all(|answer| answer.field("set-cookie").is_none()));
    });
}

#[test]
fn a_cleartext_frontend_redirects_to_https_and_a_route_may_opt_out() {
    let origin = Origin::start("a");
    both(|event_loop| {
        let members = r#""redirect_https":true,
            "routes":[{"path_prefix":"/plain","backend":"app","redirect_https":false},
                      {"path_prefix":"/old","backend":"app",
                       "redirect_https":{"status":301,"port":8443}}],"#;
        let edge = Topology::new(&[origin.address]).frontend(members).start(event_loop);
        let before = origin.requests.load(Ordering::SeqCst);
        let answer = get(&edge, "/a/b?x=1&y=2");
        assert_eq!(answer.status(), 308, "{}", answer.start);
        assert_eq!(answer.field("location"), Some("https://app.example/a/b?x=1&y=2"));
        assert!(answer.body.is_empty());
        let answer = get(&edge, "/old/page");
        assert_eq!(answer.status(), 301, "{}", answer.start);
        assert_eq!(answer.field("location"), Some("https://app.example:8443/old/page"));
        // A redirected request never reaches a server.
        assert_eq!(origin.requests.load(Ordering::SeqCst), before);
        assert_eq!(get(&edge, "/plain/who").text(), "a");
        // The connection stays usable after a redirect without a body.
        let mut client = edge.connect();
        for _ in 0..2 {
            request(&mut client, b"GET /x HTTP/1.1\r\nHost: app.example\r\n\r\n");
            assert_eq!(traffic::read_message(&mut client, false).unwrap().status(), 308);
        }
    });
}

#[test]
fn header_edits_and_the_forwarded_host_and_port_reach_both_sides() {
    let origin = Origin::start("a");
    both(|event_loop| {
        let members = r#""request_headers":{"set":{"X-Tenant":"blue"},"remove":["X-Debug"]},
            "response_headers":{"set":{"X-Frame-Options":"DENY"},"remove":["Server","X-Debug"]},
            "routes":[{"path_prefix":"/raw","backend":"app",
                       "request_headers":{},"response_headers":{}}],"#;
        let edge = Topology::new(&[origin.address]).frontend(members).start(event_loop);
        let sent =
            "X-Tenant: forged\r\nx_tenant: forged\r\nX-Debug: 1\r\nX-Forwarded-Host: evil\r\n";
        let head = get_with(&edge, "/head", sent).text();
        assert!(head.contains("X-Tenant: blue\n"), "{head}");
        assert!(!head.contains("forged") && !head.contains("X-Debug"), "{head}");
        assert!(head.contains("X-Forwarded-Host: app.example\n"), "{head}");
        assert!(head.contains(&format!("X-Forwarded-Port: {}\n", edge.vip.port())), "{head}");
        assert!(!head.contains("evil"), "{head}");
        let answer = get(&edge, "/cookie");
        assert_eq!(answer.field("x-frame-options"), Some("DENY"));
        assert_eq!(answer.field("server"), None);
        assert_eq!(answer.field("x-debug"), None);
        assert_eq!(answer.field("set-cookie"), Some("app=1"));
        assert_eq!(answer.text(), "a");
        // A route that states empty edits has none.
        let raw = get_with(&edge, "/raw/cookie", "X-Debug: 1\r\n");
        assert_eq!(raw.field("server"), Some("origin/1"));
        assert_eq!(raw.field("x-frame-options"), None);
    });
}

#[test]
fn a_body_above_max_body_is_answered_with_413() {
    let origin = Origin::start("a");
    both(|event_loop| {
        let members = r#""max_body":16,
            "routes":[{"path_prefix":"/upload","backend":"app","max_body":"1k"}],"#;
        let edge = Topology::new(&[origin.address]).frontend(members).start(event_loop);
        assert_eq!(post(&edge, "/length", &[b'x'; 16]).text(), "16");
        let before = origin.requests.load(Ordering::SeqCst);
        assert_eq!(post(&edge, "/length", &[b'x'; 17]).status(), 413);
        assert_eq!(origin.requests.load(Ordering::SeqCst), before);
        assert_eq!(post(&edge, "/upload/length", &[b'x'; 1024]).status(), 200);
        assert_eq!(post(&edge, "/upload/length", &[b'x'; 1025]).status(), 413);
        assert_eq!(get(&edge, "/who").text(), "a");
    });
    both(|event_loop| {
        // A chunked body has no declared length. One that ends inside the request buffer is
        // measured exactly before it is admitted.
        let edge =
            Topology::new(&[origin.address]).frontend(r#""max_body":"4k","#).start(event_loop);
        let chunk = format!("400\r\n{}\r\n", "x".repeat(1024));
        assert_eq!(chunked(&edge, &chunk, 4, true).text(), "4096");
        assert_eq!(chunked(&edge, &chunk, 5, true).status(), 413);
        // A longer one is admitted when the buffer is full. The rest is counted as it
        // arrives, and the answer comes when the bound is passed.
        let edge =
            Topology::new(&[origin.address]).frontend(r#""max_body":"100k","#).start(event_loop);
        let before = origin.requests.load(Ordering::SeqCst);
        assert_eq!(chunked(&edge, &chunk, 101, false).status(), 413);
        assert_eq!(origin.requests.load(Ordering::SeqCst), before);
        // The refusal is the fault of the client: no server error is counted.
        let metrics = get(&edge, "/__sibuna/metrics").text();
        assert!(metrics.contains("sibuna_upstream_errors_total 0\n"), "({event_loop})\n{metrics}");
    });
}

/// Posts `count` copies of `chunk` to `/length` as a chunked body, with its end when
/// `ended`, and returns the answer.
fn chunked(edge: &traffic::Edge, chunk: &str, count: usize, ended: bool) -> traffic::Message {
    let mut client = edge.connect();
    let head = "POST /length HTTP/1.1\r\nHost: app.example\r\nTransfer-Encoding: chunked\r\n\r\n";
    request(&mut client, head.as_bytes());
    for sent in 0..count {
        // The last chunks go slowly, so that few bytes are unread when the edge answers.
        if sent + 3 >= count {
            std::thread::sleep(Duration::from_millis(60));
        }
        if client.get_mut().write_all(chunk.as_bytes()).is_err() {
            break;
        }
    }
    if ended {
        let _ = client.get_mut().write_all(b"0\r\n\r\n");
    }
    traffic::read_message(&mut client, false).expect("an answer")
}

#[test]
fn the_policy_members_are_checked_when_the_file_is_read() {
    let origin = refused();
    for (members, expected) in [
        (r#""hsts":true,"#, "cleartext"),
        (r#""redirect_https":302,"#, "301 or 308"),
        (r#""max_body":"big","#, "max_body"),
        (r#""request_headers":{"set":{"Host":"x"}},"#, "cannot be edited"),
        (r#""response_headers":{"set":{"X-A":"a\r\nb"}},"#, "line break"),
    ] {
        let error = Topology::new(&[origin]).frontend(members).check().unwrap_err();
        assert!(error.contains(expected), "{members}: {error}");
        assert!(error.contains("Hint:"), "{members}: {error}");
    }
    for (members, expected) in [
        (r#""sticky":"ip","#, "unknown kind"),
        (r#""sticky":{"kind":"cookie","cookie":"a b"},"#, "cookie"),
    ] {
        let error = Topology::new(&[origin]).backend(members).check().unwrap_err();
        assert!(error.contains(expected) && error.contains("Hint:"), "{members}: {error}");
    }
    assert_eq!(Topology::new(&[origin]).frontend(r#""max_body":"10m","#).check(), Ok(()));
}

#[test]
fn round_robin_serves_each_server_in_turn() {
    let origins = [Origin::start("a"), Origin::start("b"), Origin::start("c")];
    let servers = origins.each_ref().map(|origin| origin.address);
    both(|event_loop| {
        let members = r#""balance":{"kind":"round_robin"},"#;
        let edge = Topology::new(&servers).backend(members).start(event_loop);
        let names: Vec<String> = (0..9).map(|_| get(&edge, "/who").text()).collect();
        for window in names.chunks(3) {
            let distinct: BTreeSet<&String> = window.iter().collect();
            assert_eq!(distinct.len(), 3, "{names:?}");
        }
        // A weight of three gives three turns in five.
        let edge = Topology::new(&servers[..2])
            .backend(members)
            .server(0, format!(r#"{{"name":"s0","addr":"{}","weight":3}}"#, servers[0]))
            .start(event_loop);
        let names: Vec<String> = (0..12).map(|_| get(&edge, "/who").text()).collect();
        assert_eq!(names.iter().filter(|name| *name == "a").count(), 9, "{names:?}");
    });
}

#[test]
fn a_server_that_returns_takes_few_requests_while_it_ramps() {
    both(|event_loop| {
        let returning = Origin::start("returning");
        let steady = Origin::start("steady");
        let servers = [returning.address, steady.address];
        // The share of the returning server in twenty requests, just after its ejection ends.
        let share = |members: &str| {
            let edge = Topology::new(&servers).backend(members).start(event_loop);
            returning.stalled.store(true, Ordering::SeqCst);
            let failed = answers(&edge, 2).iter().filter(|(status, _)| *status == 504).count();
            assert_eq!(failed, 1);
            returning.stalled.store(false, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(1200));
            let later = answers(&edge, 20);
            assert!(later.iter().all(|(status, _)| *status == 200), "{later:?}");
            // The operator sees the ramp while it lasts, as a share of the weight.
            let ramp = shown(&edge, "s0", "ramp");
            assert_eq!(ramp.ends_with('%'), members.contains("slow_start"), "{ramp}");
            assert_eq!(shown(&edge, "s1", "ramp"), "-");
            later.iter().filter(|(_, name)| name == "returning").count()
        };
        let health = r#""response_timeout":"1s","passive_health":{"failures":1,"ejection":"1s"},"#;
        let ramped = share(&format!(r#"{health}"slow_start":"30s","#));
        assert!(ramped <= 2, "{ramped}");
        // Without a slow start it takes its half at once, and more to catch up.
        let direct = share(health);
        assert!(direct >= 10, "{direct}");
    });
}

/// The names of the servers that answer `count` requests for `/who`.
fn names(edge: &traffic::Edge, count: usize, fields: &str) -> BTreeSet<String> {
    (0..count).map(|_| get_with(edge, "/who", fields).text()).collect()
}

#[test]
fn a_drained_server_gives_up_its_sticky_clients_and_takes_no_moved_request() {
    let origins = [Origin::start("s0"), Origin::start("s1"), Origin::start("s2")];
    let servers = origins.each_ref().map(|origin| origin.address);
    both(|event_loop| {
        // A cookie names a server. Once that server drains, the client gets another.
        let edge = Topology::new(&servers).backend(r#""sticky":"cookie","#).start(event_loop);
        let first = get(&edge, "/who");
        let pair = sticky_pair(&first, "sibuna_srv").expect("a cookie");
        let cookie = format!("Cookie: {pair}\r\n");
        assert_eq!(names(&edge, 4, &cookie), BTreeSet::from([first.text()]));
        edge.ctl(&format!("set server app/{} state drain", first.text()));
        let moved = get_with(&edge, "/who", &cookie);
        assert_ne!(moved.text(), first.text());
        assert_ne!(sticky_pair(&moved, "sibuna_srv").expect("a new cookie"), pair);
        // The old cookie is honoured again when the drain ends.
        edge.ctl(&format!("set server app/{} state ready", first.text()));
        assert_eq!(names(&edge, 4, &cookie), BTreeSet::from([first.text()]));

        // A client address has one server. While that drains, it has one other.
        let edge = Topology::new(&servers).backend(r#""sticky":"source","#).start(event_loop);
        let home = get(&edge, "/who").text();
        edge.ctl(&format!("set server app/{home} state drain"));
        let away = names(&edge, 8, "");
        assert!(away.len() == 1 && !away.contains(&home), "{away:?}");
        edge.ctl(&format!("set server app/{home} state ready"));
        assert_eq!(names(&edge, 8, ""), BTreeSet::from([home]));
    });
    both(|event_loop| {
        // A request that leaves a dead server passes over a drained one. The pool has the
        // dead server `s0` before the origins that call themselves `s0` and `s1`.
        let pool = [refused(), servers[0], servers[1]];
        let edge = Topology::new(&pool).start(event_loop);
        edge.ctl("set server app/s1 state drain");
        assert_eq!(names(&edge, 4, ""), BTreeSet::from(["s1".to_owned()]));
    });
}

#[test]
fn a_server_added_at_run_time_ramps_like_one_that_returns() {
    both(|event_loop| {
        let steady = Origin::start("steady");
        let added = Origin::start("added");
        // The share of the added server in twenty requests, just after it was added.
        let share = |members: &str| {
            let edge = Topology::new(&[steady.address]).backend(members).start(event_loop);
            assert_eq!(get(&edge, "/who").text(), "steady");
            edge.ctl(&format!("add server app/new {}", added.address));
            let later = answers(&edge, 20);
            assert!(later.iter().all(|(status, _)| *status == 200), "{later:?}");
            later.iter().filter(|(_, name)| name == "added").count()
        };
        let ramped = share(r#""balance":{"kind":"round_robin"},"slow_start":"30s","#);
        assert!(ramped <= 2, "{ramped}");
        let direct = share(r#""balance":{"kind":"round_robin"},"#);
        assert_eq!(direct, 10);
    });
}

#[test]
fn a_moved_request_is_logged_and_counted_once_under_the_server_that_answered() {
    both(|event_loop| {
        let good = Origin::start("good");
        let edge = Topology::new(&[refused(), good.address]).start(event_loop);
        let answer = post(&edge, "/length", b"twelve bytes");
        assert_eq!((answer.status(), answer.text()), (200, "12".into()));
        let line = &edge.log_lines(1)[0];
        assert_eq!((logged(line, "status"), logged(line, "server")), ("200", "s1"), "{line}");
        assert_ne!(logged(line, "ttfb_ms"), "null", "{line}");
        let metrics = get(&edge, "/__sibuna/metrics").text();
        for series in [
            "sibuna_edge_server_failures_total{backend=\"app\",server=\"s0\"} 1\n",
            "sibuna_edge_server_failures_total{backend=\"app\",server=\"s1\"} 0\n",
            "sibuna_edge_server_failovers_total{backend=\"app\",server=\"s0\"} 1\n",
            "sibuna_edge_server_failovers_total{backend=\"app\",server=\"s1\"} 0\n",
            "sibuna_origin_retries_total 1\n",
            "sibuna_edge_server_requests_total{backend=\"app\",server=\"s0\",code=\"2xx\"} 0\n",
            "sibuna_edge_server_requests_total{backend=\"app\",server=\"s0\",code=\"5xx\"} 0\n",
            "sibuna_edge_server_requests_total{backend=\"app\",server=\"s1\",code=\"2xx\"} 1\n",
            "sibuna_edge_frontend_requests_total{frontend=\"web\",code=\"2xx\"} 1\n",
        ] {
            assert!(metrics.contains(series), "{series} is missing:\n{metrics}");
        }
    });
}

#[test]
fn a_redirect_and_a_refused_body_are_in_the_access_log() {
    let origin = Origin::start("a");
    both(|event_loop| {
        let members = r#""redirect_https":true,
            "routes":[{"path_prefix":"/up","backend":"app","redirect_https":false,
                       "max_body":8}],"#;
        let edge = Topology::new(&[origin.address]).frontend(members).start(event_loop);
        assert_eq!(get(&edge, "/page").status(), 308);
        assert_eq!(post(&edge, "/up/length", b"twelve bytes").status(), 413);
        let lines = edge.log_lines(2);
        for (line, status, path) in [(&lines[0], "308", "/page"), (&lines[1], "413", "/up/length")]
        {
            let seen = (logged(line, "status"), logged(line, "path"), logged(line, "server"));
            assert_eq!(seen, (status, path, "-"), "{line} ({event_loop})");
            assert_eq!(logged(line, "frontend"), "web", "{line}");
        }
    });
}

#[test]
fn source_stickiness_follows_the_client_that_a_trusted_proxy_names() {
    let origins = [Origin::start("a"), Origin::start("b"), Origin::start("c")];
    let servers = origins.each_ref().map(|origin| origin.address);
    let client = |last: u8| format!("X-Forwarded-For: 203.0.113.{last}\r\n");
    both(|event_loop| {
        let edge = Topology::new(&servers)
            .frontend(r#""trusted_proxies":["127.0.0.0/8"],"#)
            .backend(r#""sticky":"source","#)
            .start(event_loop);
        // Every request has the same socket peer. The clients behind it differ.
        let spread: BTreeSet<String> =
            (1..=24).flat_map(|last| names(&edge, 1, &client(last))).collect();
        assert!(spread.len() > 1, "{spread:?} ({event_loop})");
        for last in 1..=4 {
            assert_eq!(names(&edge, 4, &client(last)).len(), 1, "{last} ({event_loop})");
        }
        // Without the option the field is ignored: the socket peer is the client.
        let edge = Topology::new(&servers).backend(r#""sticky":"source","#).start(event_loop);
        let spread: BTreeSet<String> =
            (1..=24).flat_map(|last| names(&edge, 1, &client(last))).collect();
        assert_eq!(spread.len(), 1, "{spread:?} ({event_loop})");
    });
}

#[test]
fn a_client_that_still_sends_a_refused_body_reads_the_413() {
    let origin = Origin::start("a");
    both(|event_loop| {
        let edge =
            Topology::new(&[origin.address]).frontend(r#""max_body":16,"#).start(event_loop);
        let mut client = edge.connect();
        let head = "POST /length HTTP/1.1\r\nHost: app.example\r\nContent-Length: 400000\r\n\r\n";
        request(&mut client, head.as_bytes());
        // The answer is on its way while the body is still written. A close over unread
        // bytes would reset the connection and lose the answer.
        for _ in 0..100 {
            request(&mut client, &[b'x'; 4000]);
            std::thread::sleep(Duration::from_millis(2));
        }
        let answer = traffic::read_message(&mut client, false).expect("the answer, not a reset");
        assert_eq!(answer.status(), 413, "({event_loop})");
        // The refusal is the client's fault: no server error is counted.
        let metrics = get(&edge, "/__sibuna/metrics").text();
        assert!(metrics.contains("sibuna_upstream_errors_total 0\n"), "({event_loop})\n{metrics}");
    });
}
