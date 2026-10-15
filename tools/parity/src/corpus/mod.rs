//! The deterministic request corpus: scenarios drawn by a seeded generator, each a list of
//! connections, each a list of raw requests sent in order.
//!
//! A request may hold placeholders that the client fills per daemon from that daemon's own
//! earlier answers in the same scenario (a challenge identifier, its solution, a session
//! cookie, a requirement ticket), because those values differ between the daemons by
//! design. Every scenario has its own client: its own loopback source address and, where
//! it sends one, its own `X-Forwarded-For` address, so per-client tables (rate limits,
//! bans, challenge budgets) of different scenarios never interact.

mod flows;
mod framing;
mod request;
mod web;

use std::net::Ipv4Addr;

pub use request::{Body, Request};

use crate::configs::{Config, Mode, Policy};
use crate::fragments::Fragments;
use crate::rng::Rng;

/// Placeholder for the identifier of the challenge last issued to this scenario.
pub const ID: &str = "@@ID@@";
/// Placeholder for that identifier with its last character changed.
pub const ID_TAMPERED: &str = "@@ID_TAMPERED@@";
/// Placeholder for a JSON solution field of that challenge: `"nonce":"N"` or
/// `"proof":"..."`. A challenge harder than the solver limit gets a wrong solution.
pub const SOLUTION: &str = "@@SOLUTION@@";
/// Placeholder for a well-formed but wrong solution field of that challenge.
pub const WRONG: &str = "@@WRONG@@";
/// Placeholder for the `name=value` pair of the last session cookie set.
pub const COOKIE: &str = "@@COOKIE@@";
/// Placeholder for the last requirement ticket seen (`data-ticket` or `need=`).
pub const TICKET: &str = "@@TICKET@@";
/// Placeholder for the length of the body after the other placeholders are filled.
pub const LEN: &str = "@@LEN@@";

/// Every placeholder except [`LEN`].
pub const PLACEHOLDERS: [&str; 6] = [ID, ID_TAMPERED, SOLUTION, WRONG, COOKIE, TICKET];

/// True when `bytes` hold a placeholder other than [`LEN`].
pub fn has_placeholder(bytes: &[u8]) -> bool {
    PLACEHOLDERS.iter().any(|placeholder| request::contains(bytes, placeholder.as_bytes()))
}

/// The kinds of scenario, for the summary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Category {
    /// Browser page loads.
    Navigation,
    /// API clients with JSON and tokens.
    Api,
    /// Known bot, AI crawler and scraper library User-Agents.
    Bot,
    /// Paths with traversal and encodings.
    Traversal,
    /// SQL injection, cross-site scripting and command injection in queries, bodies and
    /// headers.
    Payload,
    /// Content-Length and chunked uploads, small and streamed.
    Upload,
    /// Ambiguous framing and smuggling attempts.
    Framing,
    /// Oversized heads, targets and header counts.
    Oversized,
    /// Invalid session tokens and cookies.
    Token,
    /// Challenge issuance and verification with solved and wrong proofs.
    Challenge,
    /// Forwarded headers, trusted or not, and forward-authorization metadata.
    Forwarded,
    /// Several requests on one connection, and pipelining.
    KeepAlive,
    /// HTTP/1.0 requests.
    Http10,
    /// `Expect: 100-continue` and other expectations.
    Expect,
    /// Rate limits, rule quotas, bans and the challenge budget.
    Rate,
    /// Methods and malformed request lines and headers.
    Method,
    /// Origin answers of every framing.
    Origin,
    /// The reserved `/__sibuna/` routes.
    Internal,
    /// The metrics each daemon reports after its corpus (added by the runner).
    Metrics,
}

impl Category {
    /// The generated categories with their relative weights.
    const WEIGHTS: [(Category, u32); 18] = [
        (Category::Navigation, 12),
        (Category::Api, 9),
        (Category::Bot, 9),
        (Category::Traversal, 8),
        (Category::Payload, 13),
        (Category::Upload, 6),
        (Category::Framing, 7),
        (Category::Oversized, 3),
        (Category::Token, 5),
        (Category::Challenge, 9),
        (Category::Forwarded, 6),
        (Category::KeepAlive, 5),
        (Category::Http10, 3),
        (Category::Expect, 3),
        (Category::Rate, 1),
        (Category::Method, 5),
        (Category::Origin, 4),
        (Category::Internal, 3),
    ];

    /// The category's name in reports.
    pub fn name(self) -> &'static str {
        match self {
            Category::Navigation => "navigation",
            Category::Api => "api",
            Category::Bot => "bot",
            Category::Traversal => "traversal",
            Category::Payload => "payload",
            Category::Upload => "upload",
            Category::Framing => "framing",
            Category::Oversized => "oversized",
            Category::Token => "token",
            Category::Challenge => "challenge",
            Category::Forwarded => "forwarded",
            Category::KeepAlive => "keepalive",
            Category::Http10 => "http10",
            Category::Expect => "expect",
            Category::Rate => "rate",
            Category::Method => "method",
            Category::Origin => "origin",
            Category::Internal => "internal",
            Category::Metrics => "metrics",
        }
    }
}

/// One scenario: what to send, on which connections, from which client.
#[derive(Clone, Debug)]
pub struct Case {
    /// Position in the corpus; with the seed it names the scenario.
    pub id: usize,
    /// Index of the configuration it runs in.
    pub config: usize,
    /// Its kind.
    pub category: Category,
    /// A short description of the scenario.
    pub label: String,
    /// The loopback address its sockets are bound to.
    pub source: Ipv4Addr,
    /// The connections in order; each holds raw requests sent one after the other. The
    /// last request of a connection is followed by a half-close.
    pub connections: Vec<Vec<Vec<u8>>>,
}

impl Case {
    /// The number of requests the scenario sends.
    pub fn request_count(&self) -> usize {
        self.connections.iter().map(Vec::len).sum()
    }
}

/// What a category generator returns: a label and the connections.
#[derive(Debug, Default)]
pub struct Scenario {
    /// A short description.
    pub label: String,
    /// Connections of encoded requests.
    pub connections: Vec<Vec<Vec<u8>>>,
}

impl Scenario {
    /// A scenario of one request on one connection.
    pub fn single(label: impl Into<String>, request: Vec<u8>) -> Scenario {
        Scenario { label: label.into(), connections: vec![vec![request]] }
    }

    /// A scenario of one connection carrying `requests` in order.
    pub fn keep_alive(label: impl Into<String>, requests: Vec<Vec<u8>>) -> Scenario {
        Scenario { label: label.into(), connections: vec![requests] }
    }
}

/// The generator's view of one scenario under construction.
pub struct Scene<'a> {
    /// The seeded generator.
    pub rng: &'a mut Rng,
    /// The shared fragment lists.
    pub fragments: &'a Fragments,
    /// The configuration the scenario runs in.
    pub config: &'a Config,
    /// The scenario's position in the corpus, which makes its addresses unique.
    pub index: usize,
}

impl Scene<'_> {
    /// The scenario's own forwarded client address in 198.18.0.0/15 (RFC 2544).
    pub fn client(&self) -> String {
        let n = self.index;
        format!("198.{}.{}.{}", 18 + (n >> 16) % 2, (n >> 8) % 256, n % 256)
    }

    /// A second unique address of the scenario, in 100.64.0.0/10.
    pub fn other_client(&self) -> String {
        let n = self.index;
        format!("100.{}.{}.{}", 64 + (n >> 16) % 64, (n >> 8) % 256, n % 256)
    }

    /// The scenario's own IPv6 address in 2001:db8::/32.
    pub fn client_v6(&self) -> String {
        format!("2001:db8:{:x}:{:x}::1", self.index >> 16, self.index & 0xffff)
    }

    /// True in the forward-authorization configurations.
    pub fn forward_auth(&self) -> bool {
        self.config.mode == Mode::ForwardAuth
    }

    /// True when the sample policy is loaded.
    pub fn sample_policy(&self) -> bool {
        self.config.policy == Policy::Sample
    }

    /// Adds the scenario's `X-Forwarded-For` most of the time; the rest of the requests
    /// rely on the source address alone.
    pub fn identify(&mut self, request: Request) -> Request {
        if self.rng.chance(85) {
            let client = self.client();
            return request.header("X-Forwarded-For", client);
        }
        request
    }

    /// In forward authorization, usually describes the request the way an ingress does:
    /// a `GET` of the authorization endpoint whose `X-Forwarded-Uri` (or `X-Original-URI`)
    /// and `X-Forwarded-Method` carry the original target and method.
    pub fn adapt(&mut self, request: Request) -> Request {
        if !self.forward_auth() || self.rng.chance(25) {
            return request;
        }
        let name = if self.rng.chance(70) { "X-Forwarded-Uri" } else { "X-Original-URI" };
        let endpoint = if self.rng.chance(50) { "/auth" } else { "/" };
        let method_too = self.rng.chance(60);
        let original_method = request.method.clone();
        let original_target = request.target.clone();
        let mut described = Request {
            method: "GET".into(),
            target: endpoint.as_bytes().to_vec(),
            body: Body::Empty,
            ..request
        };
        described = described.header(name, original_target);
        if method_too {
            described = described.header("X-Forwarded-Method", original_method);
        }
        described
    }

    /// Picks one entry of the fragment list `list` selects, cloned; empty when the list is
    /// empty.
    pub fn fragment(&mut self, list: fn(&Fragments) -> &Vec<Vec<u8>>) -> Vec<u8> {
        let fragments = self.fragments;
        self.rng.pick(list(fragments)).cloned().unwrap_or_default()
    }
}

/// Generates scenarios until they hold at least `requests` requests, spread over
/// `configs` by weight. The result depends only on `seed`, `requests` and `configs`.
pub fn generate(seed: u64, requests: usize, configs: &[Config]) -> Vec<Case> {
    let fragments = Fragments::load();
    let mut rng = Rng::new(seed);
    let config_weights: Vec<u32> = configs.iter().map(|config| config.weight).collect();
    let category_weights: Vec<u32> = Category::WEIGHTS.iter().map(|&(_, w)| w).collect();
    let mut cases = Vec::new();
    let mut total = 0;
    while total < requests && !configs.is_empty() {
        let index = cases.len();
        let config_index = rng.weighted(&config_weights);
        let config = &configs[config_index];
        let (category, _) = Category::WEIGHTS[rng.weighted(&category_weights)];
        let mut scene = Scene { rng: &mut rng, fragments: &fragments, config, index };
        let scenario = scenario(&mut scene, category);
        let case = Case {
            id: index,
            config: config_index,
            category,
            label: scenario.label,
            source: source_address(index),
            connections: scenario.connections,
        };
        total += case.request_count();
        cases.push(case);
    }
    cases
}

/// Calls the generator of `category`.
fn scenario(scene: &mut Scene<'_>, category: Category) -> Scenario {
    match category {
        Category::Navigation => web::navigation(scene),
        Category::Api => web::api(scene),
        Category::Bot => web::bot(scene),
        Category::Traversal => web::traversal(scene),
        Category::Payload => web::payload(scene),
        Category::Token => web::token(scene),
        Category::Forwarded => web::forwarded(scene),
        Category::Method => web::method(scene),
        Category::Origin => web::origin(scene),
        Category::Internal => web::internal(scene),
        Category::Upload => framing::upload(scene),
        Category::Framing => framing::framing(scene),
        Category::Oversized => framing::oversized(scene),
        Category::KeepAlive => framing::keep_alive(scene),
        Category::Http10 => framing::http10(scene),
        Category::Expect => framing::expect(scene),
        Category::Challenge => flows::challenge(scene),
        Category::Rate | Category::Metrics => flows::rate(scene),
    }
}

/// The loopback source address of scenario `index`: 127.a.b.c with `a` from 1 and `c`
/// from 1 to 254, so no scenario shares 127.0.0.1 or an address with another.
pub fn source_address(index: usize) -> Ipv4Addr {
    let c = 1 + index % 254;
    let b = (index / 254) % 256;
    let a = 1 + (index / (254 * 256)) % 254;
    // Each part is below 256 by construction.
    Ipv4Addr::new(127, a as u8, b as u8, c as u8)
}

#[cfg(test)]
mod tests;
