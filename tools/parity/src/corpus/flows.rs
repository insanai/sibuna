//! Stateful scenarios: challenge issuance, solving and verification with their failure
//! modes, and the dedicated rate-limit, quota, ban and challenge-budget scenarios.

use super::web::BROWSERS;
use super::{COOKIE, ID, ID_TAMPERED, Request, SOLUTION, Scenario, Scene, TICKET, WRONG};
use crate::configs::{CHALLENGE_BUDGET, RATE_LIMIT};

/// The browser every flow uses, so the fingerprint stays the same across its requests.
const AGENT: &str = BROWSERS[0];
const HTML: &str = "text/html,application/xhtml+xml,*/*;q=0.8";

/// A request of the flow's client: always the same forwarded address and agent.
fn flow_request(scene: &Scene<'_>, method: &str, target: &str) -> Request {
    Request::new(method, target)
        .header("X-Forwarded-For", scene.client())
        .header("User-Agent", AGENT)
}

/// A verification submission with `body`.
fn submit(scene: &Scene<'_>, body: &str) -> Vec<u8> {
    flow_request(scene, "POST", "/__sibuna/verify")
        .header("Content-Type", "application/json")
        .body(super::Body::Length(body.as_bytes().to_vec()))
        .encode()
}

/// Issuance for the reported `path`.
fn issue(scene: &Scene<'_>, path: &str) -> Vec<u8> {
    flow_request(scene, "GET", &format!("/__sibuna/challenge.json?path={path}")).encode()
}

/// A page load that presents the session cookie.
fn with_cookie(scene: &Scene<'_>, target: &str) -> Vec<u8> {
    flow_request(scene, "GET", target).header("Accept", HTML).header("Cookie", COOKIE).encode()
}

fn solution_body() -> String {
    format!("{{\"challenge_id\":\"{ID}\",{SOLUTION}}}")
}

/// Malformed or hostile submissions.
const BAD_SUBMISSIONS: [&str; 12] = [
    "{}",
    "{\"challenge_id\":\"@@ID@@\"}",
    "{\"challenge_id\":\"@@ID@@\",\"nonce\":\"abc\"}",
    "{\"challenge_id\":\"@@ID@@\",\"nonce\":\"-1\"}",
    "{\"challenge_id\":\"@@ID@@\",\"nonce\":\"1_0\"}",
    "{\"challenge_id\":\"@@ID@@\",\"proof\":\"!!\"}",
    "{\"challenge_id\":\"@@ID@@\",\"proof\":\"AAAA\"}",
    "{\"challenge_id\":\"@@ID@@\",\"proof\":\"AQI=\"}",
    "{\"nonce\":\"1\"}",
    "not json at all",
    "{\"challenge_id\":\"zzz\",\"nonce\":\"1\"}",
    "{ \"challenge_id\" : \"@@ID@@\" , \"nonce\" : 18446744073709551616 }",
];

/// A challenge flow: issuance (by reported path or by a challenged response's ticket),
/// solving, verification with its failure modes, and the session afterwards.
pub fn challenge(scene: &mut Scene<'_>) -> Scenario {
    let target =
        *scene.rng.pick(&["/private", "/", "/exact", "/blog/post-1", "/login"]).unwrap_or(&"/");
    let variant = scene.rng.below(10);
    let (label, steps) = match variant {
        0 | 1 => {
            let first = issue(scene, target);
            ("issue, solve, verify, use", solved_flow(scene, first, target))
        }
        2 => {
            let page = flow_request(scene, "GET", target).header("Accept", HTML).encode();
            ("page ticket, issue, solve, verify, use", ticket_flow(scene, page, target))
        }
        3 => {
            let api =
                flow_request(scene, "GET", target).header("Accept", "application/json").encode();
            ("API ticket, wrong proof, solve, verify, use", ticket_flow(scene, api, target))
        }
        4 => {
            let body = solution_body();
            (
                "double spend",
                vec![issue(scene, target), submit(scene, &body), submit(scene, &body)],
            )
        }
        5 => ("fingerprint mismatch", fingerprint_flow(scene, target)),
        6 => {
            let body = format!("{{\"challenge_id\":\"{ID_TAMPERED}\",{SOLUTION}}}");
            ("tampered identifier", vec![issue(scene, target), submit(scene, &body)])
        }
        7 => {
            let bad = scene.rng.pick(&BAD_SUBMISSIONS).copied().unwrap_or("{}");
            ("malformed submission", vec![issue(scene, target), submit(scene, bad)])
        }
        8 => ("forged ticket", forged_ticket_flow(scene, target)),
        _ => ("oversized or truncated submission", oversized_flow(scene, target)),
    };
    let label = format!("{label} ({target})");
    if scene.rng.chance(50) {
        return Scenario::keep_alive(label, steps);
    }
    Scenario { label, connections: steps.into_iter().map(|step| vec![step]).collect() }
}

/// Issue, solve and verify, then load `target` with the cookie and once more without.
fn solved_flow(scene: &mut Scene<'_>, issuance: Vec<u8>, target: &str) -> Vec<Vec<u8>> {
    let mut steps = vec![issuance, submit(scene, &solution_body()), with_cookie(scene, target)];
    if scene.rng.chance(30) {
        // The session is bound to the agent: another agent is challenged again.
        let other = Request::new("GET", target)
            .header("X-Forwarded-For", scene.client())
            .header("User-Agent", BROWSERS[2])
            .header("Accept", HTML)
            .header("Cookie", COOKIE);
        steps.push(other.encode());
    }
    steps
}

/// A challenged response whose ticket sets the issued work, then the solved flow; the
/// API variant first submits a wrong solution.
fn ticket_flow(scene: &mut Scene<'_>, first: Vec<u8>, target: &str) -> Vec<Vec<u8>> {
    let issuance = flow_request(scene, "GET", &format!("/__sibuna/challenge.json?need={TICKET}"));
    let mut steps = vec![first, issuance.encode()];
    if scene.rng.chance(50) {
        steps.push(submit(scene, &format!("{{\"challenge_id\":\"{ID}\",{WRONG}}}")));
    }
    steps.push(submit(scene, &solution_body()));
    steps.push(with_cookie(scene, target));
    steps
}

/// The solution submitted by another agent (and, when forwarded addresses are trusted,
/// from another address).
fn fingerprint_flow(scene: &mut Scene<'_>, target: &str) -> Vec<Vec<u8>> {
    let body = solution_body();
    let address = if scene.rng.chance(50) { scene.other_client() } else { scene.client() };
    let foreign = Request::new("POST", "/__sibuna/verify")
        .header("X-Forwarded-For", address)
        .header("User-Agent", "other-agent/1.0")
        .header("Content-Type", "application/json")
        .body(super::Body::Length(body.clone().into_bytes()));
    vec![issue(scene, target), foreign.encode(), submit(scene, &body)]
}

/// Issuance with a ticket that is garbage, cut short or extended.
fn forged_ticket_flow(scene: &mut Scene<'_>, target: &str) -> Vec<Vec<u8>> {
    let page = flow_request(scene, "GET", target).header("Accept", "application/json").encode();
    let need = *scene
        .rng
        .pick(&["garbage", "@@TICKET@@x", "", "AAAA", "@@TICKET@@&path=/exact"])
        .unwrap_or(&"");
    let forged = flow_request(scene, "GET", &format!("/__sibuna/challenge.json?need={need}"));
    vec![page, forged.encode()]
}

/// A submission larger than the 64 KiB solution bound, or shorter than declared, or a
/// `GET` of the verification route.
fn oversized_flow(scene: &mut Scene<'_>, target: &str) -> Vec<Vec<u8>> {
    let first = issue(scene, target);
    match scene.rng.below(3) {
        0 => {
            let padding = "x".repeat(70_000);
            let body = format!("{{\"challenge_id\":\"{ID}\",{SOLUTION},\"pad\":\"{padding}\"}}");
            vec![first, submit(scene, &body)]
        }
        1 => {
            let mut short = flow_request(scene, "POST", "/__sibuna/verify").encode();
            short.truncate(short.len() - 2);
            short.extend_from_slice(b"Content-Length: 500\r\n\r\n{\"challenge_id\":\"");
            vec![first, short]
        }
        _ => vec![first, flow_request(scene, "GET", "/__sibuna/verify").encode()],
    }
}

/// The dedicated limit scenarios: the per-client limiter, the sample policy's rule quotas
/// (with a ban), the honeypot ban and the challenge budget.
pub fn rate(scene: &mut Scene<'_>) -> Scenario {
    match scene.rng.below(4) {
        0 => {
            let steps = (0..RATE_LIMIT + 3)
                .map(|n| flow_request(scene, "GET", &format!("/limited/{n}")).encode())
                .collect();
            Scenario::keep_alive("client rate limit", steps)
        }
        1 if scene.sample_policy() => {
            let mut steps: Vec<Vec<u8>> =
                (0..3).map(|_| flow_request(scene, "GET", "/admin").encode()).collect();
            steps.extend((0..7).map(|_| flow_request(scene, "GET", "/api/checkout/pay").encode()));
            steps.push(flow_request(scene, "GET", "/robots.txt").encode());
            Scenario::keep_alive("rule quotas and quota ban", steps)
        }
        1 | 2 => {
            // Browsers load a honeypot link as a page, or as a subresource of another site.
            let fetch = [
                ("page", "", ""),
                ("navigation", "document", "same-origin"),
                ("cross-site image", "image", "cross-site"),
                ("same-site script", "script", "same-site"),
            ];
            let (kind, dest, site) = scene.rng.pick(&fetch).copied().unwrap_or(fetch[0]);
            let mut trap = flow_request(scene, "GET", "/__sibuna/honeypot").header("Accept", HTML);
            if !dest.is_empty() {
                trap = trap.header("Sec-Fetch-Dest", dest).header("Sec-Fetch-Site", site);
            }
            let steps = vec![
                trap.encode(),
                flow_request(scene, "GET", "/").encode(),
                flow_request(scene, "GET", "/__sibuna/challenge.json?path=/").encode(),
                flow_request(scene, "GET", "/").header("Accept", HTML).encode(),
            ];
            Scenario {
                label: format!("honeypot ban ({kind})"),
                connections: steps.into_iter().map(|s| vec![s]).collect(),
            }
        }
        _ => {
            let steps = (0..CHALLENGE_BUDGET + 2).map(|_| issue(scene, "/")).collect();
            Scenario::keep_alive("challenge budget", steps)
        }
    }
}
