#![allow(clippy::unwrap_used)]

use std::cell::RefCell;

use super::*;

const TOKEN: &str = "cf-test-token-0123456789";
const OWNER: &str = "_acme-challenge.a.example.org";
const VALUE: &str = "LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ";

/// The status and the body of an answer.
type Answer = (u16, String);

/// An API inside the test: the answers by method and URL, and the calls it received.
struct Api {
    calls: RefCell<Vec<Call>>,
    answer: Box<dyn Fn(&Call) -> Answer>,
}

impl Api {
    fn new(answer: impl Fn(&Call) -> Answer + 'static) -> Self {
        Self { calls: RefCell::default(), answer: Box::new(answer) }
    }

    fn send(&self, call: &Call) -> Result<Response, Error> {
        self.calls.borrow_mut().push(call.clone());
        let (status, body) = (self.answer)(call);
        Ok(Response { status, body: body.into_bytes(), ..Response::default() })
    }

    /// The method and the path of every call, in order.
    fn seen(&self) -> Vec<String> {
        let calls = self.calls.borrow();
        calls.iter().map(|call| format!("{} {}", call.method, &call.url[16..])).collect()
    }
}

fn account(zone: Option<&'static str>) -> Cloudflare<'static> {
    Cloudflare { api: "http://127.0.0.1/", token: TOKEN, zone }
}

fn ok(result: &str) -> (u16, String) {
    (200, format!(r#"{{"success":true,"errors":[],"messages":[],"result":{result}}}"#))
}

/// The usual account: it has the zone `example.org`, and two TXT records at the owner.
fn usual(call: &Call) -> (u16, String) {
    let path = &call.url[16..];
    match (call.method, path) {
        ("GET", "/zones?name=example.org") => ok(r#"[{"id":"z0ne1d","name":"example.org"}]"#),
        ("GET", path) if path.starts_with("/zones?name=") => ok("[]"),
        ("POST", "/zones/z0ne1d/dns_records") => ok(r#"{"id":"rec1"}"#),
        ("GET", path) if path.starts_with("/zones/z0ne1d/dns_records?") => ok(&format!(
            r#"[{{"id":"rec1","name":"{OWNER}","content":"\"{VALUE}\""}},
                {{"id":"rec2","name":"{OWNER}","content":"another-value"}},
                {{"id":"rec3","name":"{OWNER}","content":"{VALUE}"}},
                {{"id":"../x","name":"{OWNER}","content":"{VALUE}"}},
                {{"id":"rec4","name":"other.example.org","content":"{VALUE}"}}]"#
        )),
        ("DELETE", _) => ok(r#"{"id":"gone"}"#),
        _ => (404, r#"{"success":false,"errors":[{"code":7003,"message":"no route"}]}"#.into()),
    }
}

fn message(result: Result<(), Error>) -> String {
    let error = result.unwrap_err();
    assert_eq!((error.code, error.title), ("ACME009", "DNS PROVIDER FAILED"));
    assert!(!error.message.contains(TOKEN), "{}", error.message);
    assert!(error.hint.contains("Zone / DNS / Edit"), "{}", error.hint);
    error.message
}

#[test]
fn present_finds_the_zone_from_the_owner_upwards_and_creates_the_record() {
    let api = Api::new(usual);
    account(None).present(&|call| api.send(call), OWNER, VALUE).unwrap();
    assert_eq!(
        api.seen(),
        [
            "GET /zones?name=_acme-challenge.a.example.org",
            "GET /zones?name=a.example.org",
            "GET /zones?name=example.org",
            "POST /zones/z0ne1d/dns_records",
        ]
    );
    let calls = api.calls.borrow();
    for call in calls.iter() {
        assert_eq!(call.headers[0], ("authorization", format!("Bearer {TOKEN}")));
    }
    let create = calls.last().unwrap();
    assert_eq!(create.headers[1], ("content-type", "application/json".to_owned()));
    let body = format!(r#"{{"type":"TXT","name":"{OWNER}","content":"\"{VALUE}\"","ttl":120}}"#);
    assert_eq!(String::from_utf8_lossy(&create.body), body);
    // The debug form of a call and of the account hold no token.
    assert!(!format!("{create:?} {:?}", account(None)).contains(TOKEN));
}

#[test]
fn a_named_zone_is_asked_alone_and_a_final_dot_is_dropped() {
    let api = Api::new(usual);
    let owner = format!("{OWNER}.");
    account(Some("example.org.")).present(&|call| api.send(call), &owner, VALUE).unwrap();
    assert_eq!(api.seen(), ["GET /zones?name=example.org", "POST /zones/z0ne1d/dns_records"]);
}

#[test]
fn cleanup_deletes_the_records_with_our_value_only() {
    let api = Api::new(usual);
    account(Some("example.org")).cleanup(&|call| api.send(call), OWNER, VALUE).unwrap();
    assert_eq!(
        api.seen(),
        [
            "GET /zones?name=example.org".to_owned(),
            format!("GET /zones/z0ne1d/dns_records?type=TXT&name={OWNER}"),
            "DELETE /zones/z0ne1d/dns_records/rec1".to_owned(),
            "DELETE /zones/z0ne1d/dns_records/rec3".to_owned(),
        ]
    );
}

#[test]
fn a_record_that_exists_is_success_and_other_failures_are_reported() {
    let exists = Api::new(|call| match call.method {
        "POST" => {
            let error = r#"{"code":81058,"message":"An identical record already exists."}"#;
            (400, format!(r#"{{"success":false,"errors":[{error}],"result":null}}"#))
        }
        _ => usual(call),
    });
    account(Some("example.org")).present(&|call| exists.send(call), OWNER, VALUE).unwrap();

    let denied = Api::new(|_| {
        let error = format!(r#"{{"code":10000,"message":"Authentication error for {TOKEN}"}}"#);
        (403, format!(r#"{{"success":false,"errors":[{error}]}}"#))
    });
    let text = message(account(None).present(&|call| denied.send(call), OWNER, VALUE));
    assert!(text.contains("did not find the zone"), "{text}");
    assert!(text.contains("answered 403 with Authentication error for [token] (10000)"), "{text}");
    // One refusal ends the search: the other candidates are not asked.
    assert_eq!(denied.calls.borrow().len(), 1);

    let nowhere = Api::new(|_| ok("[]"));
    let text = message(account(None).cleanup(&|call| nowhere.send(call), OWNER, VALUE));
    assert!(text.contains(&format!("the account has no zone for `{OWNER}`")), "{text}");
    assert_eq!(nowhere.calls.borrow().len(), 3);
}

#[test]
fn answers_that_cannot_be_used_and_a_client_that_fails_are_failures() {
    let bodies = [
        "",
        "<html>",
        "[]",
        r#"{"success":true}"#,
        r#"{"success":true,"result":7}"#,
        r#"{"success":"yes","result":[]}"#,
    ];
    for body in bodies {
        let api = Api::new(move |_| (200, body.to_owned()));
        let text = message(account(None).present(&|call| api.send(call), OWNER, VALUE));
        assert!(text.contains("did not find the zone"), "{body}: {text}");
    }
    // A zone whose identifier cannot stand in a URL is not used.
    let odd = Api::new(|_| ok(r#"[{"id":"a/../b","name":"example.org"}]"#));
    let text = message(account(Some("example.org")).present(&|call| odd.send(call), OWNER, VALUE));
    assert!(text.contains("has no zone"), "{text}");
    let down = |_: &Call| Err(Error::unreachable(format!("no connection for {TOKEN}")));
    let text = message(account(None).present(&down, OWNER, VALUE));
    assert!(text.contains("no connection for [token]"), "{text}");
    // A record that the API could not carry is refused before any call.
    let silent = Api::new(usual);
    let text = message(account(None).present(&|call| silent.send(call), "a b.example", VALUE));
    assert!(text.contains("unusual character"), "{text}");
    assert!(silent.calls.borrow().is_empty());
}

#[test]
fn the_search_is_bounded_and_a_token_is_one_printable_word() {
    assert_eq!(zone_candidates(OWNER), [OWNER, "a.example.org", "example.org"]);
    assert_eq!(zone_candidates("example.org."), ["example.org"]);
    assert!(zone_candidates("org").is_empty() && zone_candidates("").is_empty());
    let deep = vec!["x"; 40].join(".");
    let candidates = zone_candidates(&deep);
    assert_eq!(candidates.len(), MAX_ZONE_QUESTIONS);
    assert!(candidates.windows(2).all(|pair| pair[0].len() > pair[1].len()));
    assert_eq!(token(" abc-DEF_123\n"), Some("abc-DEF_123"));
    for bad in ["", "  \n", "two words", "line\nbreak", "caf\u{e9}"] {
        assert_eq!(token(bad), None, "{bad:?}");
    }
    assert_eq!(token(&"t".repeat(513)), None);
}
