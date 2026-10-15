use std::time::Instant;

use super::*;
use crate::response::Framing;

fn response(headers: &[(&str, &str)], body: &str) -> Response {
    Response {
        status_line: "HTTP/1.1 200 OK".into(),
        status: 200,
        headers: headers.iter().map(|(n, v)| ((*n).to_owned(), (*v).to_owned())).collect(),
        body: body.as_bytes().to_vec(),
        framing: Framing::Length,
    }
}

#[test]
fn the_state_learns_challenges_cookies_and_tickets() {
    let mut state = State::default();
    state.observe(&response(
        &[],
        "{\"id\":\"abc.def\",\"algorithm\":\"hashcash\",\"difficulty\":8,\"challenges\":1,\
         \"expires_at\":99}",
    ));
    let challenge = state.challenge.clone().unwrap();
    assert_eq!((challenge.id.as_str(), challenge.difficulty), ("abc.def", 8));
    state.observe(&response(&[("Set-Cookie", "__sibuna_token=v1.x.y; Max-Age=60")], ""));
    assert_eq!(state.cookie.as_deref(), Some("__sibuna_token=v1.x.y"));
    state.observe(&response(&[], "<div data-ticket=\"T1\"></div>"));
    assert_eq!(state.ticket.as_deref(), Some("T1"));
    state.observe(&response(&[], "{\"challenge\":\"/__sibuna/challenge.json?need=T2\"}"));
    assert_eq!(state.ticket.as_deref(), Some("T2"));
    // A cookie of another name is not the session.
    state.observe(&response(&[("Set-Cookie", "origin=1")], ""));
    assert_eq!(state.cookie.as_deref(), Some("__sibuna_token=v1.x.y"));
}

#[test]
fn placeholders_are_filled_and_the_length_follows() {
    let state = State {
        challenge: Some(Challenge {
            id: "idA".into(),
            algorithm: "hashcash".into(),
            difficulty: 4,
            challenges: 1,
        }),
        cookie: Some("__sibuna_token=t".into()),
        ticket: Some("TK".into()),
    };
    let template = b"POST /v?need=@@TICKET@@ HTTP/1.1\r\nCookie: @@COOKIE@@\r\n\
                     Content-Length: @@LEN@@\r\n\r\n\
                     {\"challenge_id\":\"@@ID@@\",\"x\":\"@@ID_TAMPERED@@\"}";
    let filled = String::from_utf8(state.fill(template)).unwrap();
    let body = "{\"challenge_id\":\"idA\",\"x\":\"AdA\"}";
    assert!(filled.contains("need=TK "), "{filled}");
    assert!(filled.contains("Cookie: __sibuna_token=t\r\n"));
    assert!(
        filled.ends_with(&format!("Content-Length: {}\r\n\r\n{body}", body.len())),
        "{filled}"
    );
    let empty = State::default().fill(b"@@ID@@ @@COOKIE@@ @@TICKET@@");
    assert_eq!(empty, b"none __sibuna_token=none none");
    assert_eq!(State::default().fill(b"plain"), b"plain");
}

#[test]
fn solutions_solve_and_wrong_ones_do_not() {
    let hashcash = Challenge {
        id: "v1.hashcash.x".into(),
        algorithm: "hashcash".into(),
        difficulty: 10,
        challenges: 1,
    };
    let nonce = |field: String| -> u64 {
        field.trim_start_matches("\"nonce\":\"").trim_end_matches('"').parse().unwrap()
    };
    assert!(hashcash::verify_bits(b"v1.hashcash.x", nonce(solution(&hashcash, true)), 10));
    assert!(!hashcash::verify_bits(b"v1.hashcash.x", nonce(solution(&hashcash, false)), 10));
    let hard = Challenge { difficulty: MAX_HASHCASH_BITS + 10, ..hashcash };
    assert!(!hashcash::verify_bits(
        b"v1.hashcash.x",
        nonce(solution(&hard, true)),
        hard.difficulty
    ));

    let posw = Challenge {
        id: "v1.posw.y".into(),
        algorithm: "posw".into(),
        difficulty: 6,
        challenges: 3,
    };
    let proof = |field: String| -> Vec<u8> {
        let text = field.trim_start_matches("\"proof\":\"").trim_end_matches('"').to_owned();
        base64::decode(URL_SAFE_NO_PAD, text.as_bytes()).unwrap()
    };
    let params = posw::Params { depth: 6, challenges: 3 };
    assert!(posw::verify(b"v1.posw.y", params, &proof(solution(&posw, true))));
    let wrong = proof(solution(&posw, false));
    assert_eq!(wrong.len(), params.proof_size());
    assert!(!posw::verify(b"v1.posw.y", params, &wrong));
}

#[test]
fn tampering_changes_only_the_last_character() {
    assert_eq!(tamper("abcAxy"), "abcBxy");
    assert_eq!(tamper("abczxy"), "abcAxy");
    assert_eq!(tamper("ab"), "ab");
    assert_eq!(replace(b"a@@b@@", b"@@", b"-"), b"a-b-");
}

#[test]
fn the_pacer_holds_issues_within_one_second() {
    let pacer = Pacer::new(3);
    let started = Instant::now();
    let second = || SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    pacer.acquire(2);
    pacer.acquire(1);
    let first = second();
    pacer.acquire(1);
    // The fourth issue waited for the next second.
    assert!(second() > first || started.elapsed() >= Duration::from_millis(500));
}
