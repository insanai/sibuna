use sibuna_json::Limits;

use super::*;

fn message(text: &str) -> Message {
    Message::parse(text.to_owned(), &Limits::default()).unwrap()
}

#[test]
fn params_escape_and_nest() {
    let inner = Params::new().int("x", -3).float("y", 1.5).float("z", f64::NAN);
    let params = Params::new()
        .string("expression", "a\n\"b\"\u{1}")
        .bool("returnByValue", true)
        .object("point", &inner);
    assert_eq!(
        params.as_json(),
        r#"{"expression":"a\n\"b\"\u0001","returnByValue":true,"point":{"x":-3,"y":1.5,"z":null}}"#
    );
    assert_eq!(Params::new().as_json(), "{}");
    let list = Params::new().array("patterns", &[Params::new().int("a", 1), Params::new()]);
    assert_eq!(list.as_json(), r#"{"patterns":[{"a":1},{}]}"#);
    assert_eq!(Params::new().array("empty", &[]).as_json(), r#"{"empty":[]}"#);
    assert!(sibuna_json::parse(params.as_json().as_bytes()).is_ok());
}

#[test]
fn encodes_commands_with_and_without_a_session() {
    let mut out = String::from("stale");
    encode_command(&mut out, 7, None, "Browser.getVersion", &Params::new());
    assert_eq!(out, r#"{"id":7,"method":"Browser.getVersion","params":{}}"#);
    let params = Params::new().string("url", "about:blank");
    encode_command(&mut out, 8, Some("S1"), "Page.navigate", &params);
    assert_eq!(
        out,
        r#"{"id":8,"method":"Page.navigate","params":{"url":"about:blank"},"sessionId":"S1"}"#
    );
    let parsed = message(&out);
    assert_eq!(parsed.kind(), MessageKind::Response(8));
    assert_eq!(parsed.session_id(), Some("S1"));
}

#[test]
fn decodes_responses_errors_and_events() {
    let response = message(r#"{"id":3,"result":{"frameId":"F","loaderId":"L"}}"#);
    assert_eq!(response.kind(), MessageKind::Response(3));
    assert_eq!(response.error(), None);
    let body = response.body().unwrap();
    assert_eq!(string_at(&body, &["result", "loaderId"]), "L");
    assert_eq!(string_at(&body, &["result", "missing"]), "");

    let failure = message(r#"{"id":4,"error":{"code":-32000,"message":"No target"}}"#);
    assert_eq!(failure.error(), Some((-32000, "No target")));

    let event =
        message(r#"{"method":"Page.loadEventFired","params":{"timestamp":1.5},"sessionId":"S"}"#);
    assert_eq!(event.kind(), MessageKind::Event("Page.loadEventFired"));
    assert_eq!(event.session_id(), Some("S"));
    let body = event.body().unwrap();
    let timestamp = field(&body, &["params", "timestamp"]).and_then(Value::as_number);
    assert_eq!(timestamp.and_then(|n| n.as_f64().ok()), Some(1.5));
}

#[test]
fn refuses_messages_that_cannot_be_routed() {
    for text in ["[]", "{}", r#"{"id":-1}"#, r#"{"id":"1"}"#, r#"{"id":1.5}"#, "{", ""] {
        assert!(Message::parse(text.to_owned(), &Limits::default()).is_err(), "{text}");
    }
    let tight = Limits { max_input_bytes: 8, ..Limits::default() };
    assert!(Message::parse(r#"{"id":1,"result":{}}"#.to_owned(), &tight).is_err());
}

#[test]
fn inbox_returns_the_awaited_response_and_queues_events() {
    let mut inbox = Inbox::new(8);
    assert!(inbox.accept(message(r#"{"method":"A.one","params":{}}"#), Some(5)).is_none());
    // A response to another command (an unawaited acknowledgement) is dropped.
    assert!(inbox.accept(message(r#"{"id":4,"result":{}}"#), Some(5)).is_none());
    assert!(inbox.accept(message(r#"{"method":"A.two","params":{}}"#), Some(5)).is_none());
    let response = inbox.accept(message(r#"{"id":5,"result":{}}"#), Some(5)).unwrap();
    assert_eq!(response.kind(), MessageKind::Response(5));
    assert_eq!(inbox.event_count(), 2);
    let methods: Vec<String> = std::iter::from_fn(|| inbox.pop())
        .map(|event| match event.kind() {
            MessageKind::Event(method) => method.to_owned(),
            MessageKind::Response(id) => panic!("response {id} queued"),
        })
        .collect();
    assert_eq!(methods, ["A.one", "A.two"]);
    // With nothing awaited, every response is dropped.
    assert!(inbox.accept(message(r#"{"id":5,"result":{}}"#), None).is_none());
    assert_eq!(inbox.event_count(), 0);
}

#[test]
fn inbox_drops_the_oldest_event_when_full() {
    let mut inbox = Inbox::new(2);
    for n in 0..5 {
        let text = format!(r#"{{"method":"E.n{n}","params":{{}}}}"#);
        inbox.accept(message(&text), None);
    }
    assert_eq!((inbox.event_count(), inbox.dropped_count()), (2, 3));
    assert_eq!(inbox.pop().unwrap().kind(), MessageKind::Event("E.n3"));
}
