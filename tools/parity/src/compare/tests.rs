use super::*;
use crate::response::Framing;

fn response(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Response {
    Response {
        status_line: status.to_owned(),
        status: status.get(9..12).and_then(|code| code.parse().ok()).unwrap_or(0),
        headers: headers.iter().map(|(n, v)| ((*n).to_owned(), (*v).to_owned())).collect(),
        body: body.to_vec(),
        framing: Framing::Length,
    }
}

fn transcript(events: Vec<Event>) -> Transcript {
    Transcript {
        connections: vec![vec![Exchange { request: b"GET / HTTP/1.1\r\n\r\n".to_vec(), events }]],
        connect_error: None,
    }
}

#[test]
fn random_values_are_masked() {
    let issued = |id: &str, at: u64| {
        format!(
            "{{\"id\":\"{id}\",\"algorithm\":\"hashcash\",\"difficulty\":8,\"expires_at\":{at}}}"
        )
    };
    let (a, hit) = mask_body(issued("aaaa", 100).as_bytes());
    let (b, _) = mask_body(issued("bbbbbb", 101).as_bytes());
    assert!(hit);
    assert_eq!(a, b);
    assert!(find(&a, b"\"difficulty\":8").is_some());
    let page = |reference: &str, ticket: &str| {
        format!("<p>Reference {reference} on node 0.</p><div data-ticket=\"{ticket}\"></div>")
    };
    assert_eq!(
        mask_body(page("0123", "t1").as_bytes()).0,
        mask_body(page("4567", "t22").as_bytes()).0
    );
    let need =
        |ticket: &str| format!("{{\"challenge\":\"/__sibuna/challenge.json?need={ticket}\"}}");
    assert_eq!(mask_body(need("x").as_bytes()).0, mask_body(need("yy").as_bytes()).0);
    let (plain, hit) = mask_body(b"nothing random");
    assert!(!hit);
    assert_eq!(plain, b"nothing random");
}

#[test]
fn cookies_keep_their_attributes_and_lengths_are_checked() {
    let a = response(
        "HTTP/1.1 200 OK",
        &[("Set-Cookie", "__sibuna_token=AAA; Max-Age=60; HttpOnly"), ("Content-Length", "9")],
        b"{\"id\":\"x\"}",
    );
    let masked = mask_response(&a);
    assert!(
        masked.headers.contains(&(
            "set-cookie".into(),
            "__sibuna_token=<token>; Max-Age=60; HttpOnly".into()
        ))
    );
    // The declared length (9) is not the body's (10), so it stays visible.
    assert!(masked.headers.contains(&("content-length".into(), "9".into())));
    let b = response("HTTP/1.1 200 OK", &[("Content-Length", "10")], b"{\"id\":\"x\"}");
    assert!(mask_response(&b).headers.contains(&("content-length".into(), "<checked>".into())));
}

#[test]
fn identical_answers_have_no_differences() {
    let answer = || response("HTTP/1.1 200 OK", &[("B", "2"), ("A", "1")], b"same");
    let mut reordered = answer();
    reordered.headers.reverse();
    let zig = transcript(vec![Event::Response(answer()), Event::Closed]);
    let rust = transcript(vec![Event::Response(reordered), Event::Closed]);
    assert_eq!(compare(&zig, &rust), Vec::new());
}

#[test]
fn each_differing_field_is_named() {
    let zig = transcript(vec![Event::Response(response(
        "HTTP/1.1 200 OK",
        &[("X-Rule", "a"), ("X-Only", "z")],
        b"ORIGIN\nline: GET / HTTP/1.1\n",
    ))]);
    let rust = transcript(vec![Event::Response(response(
        "HTTP/1.1 403 Forbidden",
        &[("X-Rule", "b")],
        b"ORIGIN\nline: GET /x HTTP/1.1\n",
    ))]);
    let fields: Vec<String> = compare(&zig, &rust).into_iter().map(|d| d.field).collect();
    assert_eq!(fields, ["status", "header:x-only", "header:x-rule", "origin"]);
    let closed = transcript(vec![Event::Closed]);
    let differences = compare(&zig, &closed);
    assert_eq!(differences[0].field, "event");
    assert_eq!(differences[0].rust, "connection closed");
}

#[test]
fn missing_exchanges_and_connections_are_reported() {
    let one = transcript(vec![Event::Closed]);
    let mut two = one.clone();
    let again = two.connections[0][0].clone();
    two.connections[0].push(again);
    assert_eq!(compare(&one, &two)[0].field, "exchanges");
    let mut more = one.clone();
    more.connections.push(Vec::new());
    assert_eq!(compare(&one, &more)[0].field, "connections");
}

#[test]
fn escaping_keeps_text_readable() {
    assert_eq!(escape(b"a\r\nb\x00", 100), "a\\r\\n\nb\\x00");
    assert_eq!(escape(b"abcdef", 3), "abc... (6 bytes in all)");
}
