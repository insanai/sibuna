//! Scenarios of ordinary and hostile web traffic: page loads, API calls, bots, traversal,
//! injection payloads, session tokens, forwarded headers, methods, origin framings and the
//! reserved routes.

use super::{Body, Request, Scenario, Scene};
use crate::fragments::bot_table;

/// Browser User-Agents, including a headless and an old Chrome that the sample policy
/// weighs.
pub const BROWSERS: [&str; 6] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
     Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) \
     Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/79.0 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 HeadlessChrome/120.0 Safari/537.36",
];

/// API client User-Agents, some of them scraper libraries.
const API_CLIENTS: [&str; 7] = [
    "curl/8.5.0",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "okhttp/4.12.0",
    "PostmanRuntime/7.36.0",
    "MyApp/1.0 (iOS 17.5)",
    "billing-service/2.3",
];

/// `Accept` values: page loads, API calls, wildcards and edge cases.
const ACCEPTS: [&str; 8] = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html",
    "*/*",
    "application/json",
    "TEXT/HTML",
    "application/xhtml+xml",
    "text/html;q=0",
    "image/avif,image/webp,*/*",
];

/// Benign paths the corpus mixes with the fragment paths.
const PAGES: [&str; 12] = [
    "/",
    "/blog/post-1",
    "/products/42",
    "/private",
    "/private/area",
    "/exact",
    "/search",
    "/api/v1/items",
    "/api/checkout/pay",
    "/admin",
    "/trusted/page",
    "/login",
];

/// The request's page: a benign path or a fragment path, sometimes with a query.
fn page_target(scene: &mut Scene<'_>) -> Vec<u8> {
    let mut target = if scene.rng.chance(50) {
        scene.rng.pick(&PAGES).map_or(b"/".to_vec(), |page| page.as_bytes().to_vec())
    } else {
        scene.fragment(|f| &f.paths)
    };
    if target.is_empty() {
        target.push(b'/');
    }
    if scene.rng.chance(35) {
        let query = scene.fragment(|f| &f.queries);
        if !query.is_empty() {
            target.push(b'?');
            target.extend(query.iter().map(|&byte| if byte == b' ' { b'+' } else { byte }));
        }
    }
    target
}

/// A browser page load.
pub fn navigation(scene: &mut Scene<'_>) -> Scenario {
    let target = page_target(scene);
    let agent = scene.rng.pick(&BROWSERS).copied().unwrap_or_default();
    let accept = scene.rng.pick(&ACCEPTS[..3]).copied().unwrap_or_default();
    let mut request = Request::get(target).header("User-Agent", agent).header("Accept", accept);
    if scene.rng.chance(70) {
        request = request.header("Accept-Language", "en-US,en;q=0.5");
    }
    if scene.rng.chance(50) {
        request =
            request.header("Sec-Fetch-Mode", "navigate").header("Sec-Fetch-Dest", "document");
    }
    if scene.rng.chance(25) {
        request = request.header("Referer", "https://example.com/start");
    }
    if scene.rng.chance(15) {
        let name = scene.fragment(|f| &f.header_names);
        let value = scene.fragment(|f| &f.header_values);
        let name = String::from_utf8_lossy(&name).into_owned();
        request = request.header(&name, value);
    }
    let request = scene.identify(request);
    let request = scene.adapt(request);
    Scenario::single("page load", request.encode())
}

/// An API call: JSON, tokens, any method.
pub fn api(scene: &mut Scene<'_>) -> Scenario {
    let target = page_target(scene);
    let agent = scene.rng.pick(&API_CLIENTS).copied().unwrap_or_default();
    let method =
        *scene.rng.pick(&["GET", "GET", "POST", "PUT", "DELETE", "PATCH"]).unwrap_or(&"GET");
    let mut request = Request::new(method, target).header("User-Agent", agent);
    request =
        request.header("Accept", if scene.rng.chance(80) { "application/json" } else { "*/*" });
    if scene.rng.chance(40) {
        request = request.header("Authorization", "Bearer abc.def.ghi");
    }
    if scene.rng.chance(20) {
        request = request.header("X-Api", "v2").header("X-Token", "test-123");
    }
    if method != "GET" && method != "DELETE" {
        let body = scene.fragment(|f| &f.bodies);
        let content_type = scene.fragment(|f| &f.content_types);
        if content_type != b"(none)" {
            request = request.header("Content-Type", content_type);
        }
        request = request.body(Body::Length(body));
    }
    let request = scene.identify(request);
    let request = scene.adapt(request);
    Scenario::single(format!("api {method}"), request.encode())
}

/// A known bot, AI crawler, scraper library or search crawler.
pub fn bot(scene: &mut Scene<'_>) -> Scenario {
    let table = match scene.rng.below(4) {
        0 => bot_table("AI_SCRAPERS"),
        1 => bot_table("SCRAPER_LIBRARIES"),
        2 => bot_table("SEARCH_CRAWLERS"),
        _ => Vec::new(),
    };
    let agent = match scene.rng.pick(&table) {
        Some(name) => match scene.rng.below(3) {
            0 => (*name).to_owned(),
            1 => format!("Mozilla/5.0 (compatible; {name}/1.0; +https://example.com/bot)"),
            _ => format!("{}/2.1", name.to_ascii_lowercase()),
        },
        None => String::from_utf8_lossy(&scene.fragment(|f| &f.user_agents)).into_owned(),
    };
    let target = if scene.rng.chance(20) { b"/robots.txt".to_vec() } else { page_target(scene) };
    let mut request = Request::get(target).header("User-Agent", agent.as_bytes());
    if scene.rng.chance(50) {
        request = request.header("Accept", ACCEPTS[0]);
    }
    let request = scene.identify(request);
    let request = scene.adapt(request);
    Scenario::single(format!("bot {agent}"), request.encode())
}

/// Traversal sequences and encodings the normalizer must see through.
const TRAVERSALS: [&str; 14] = [
    "../",
    "..%2f",
    "%2e%2e/",
    "%2E%2E%2F",
    "%252e%252e/",
    "..;/",
    "..\\",
    "%c0%ae%c0%ae/",
    "./",
    "//",
    "%00",
    "%2f",
    "....//",
    "%u002e%u002e/",
];

/// A path with traversal and encodings.
pub fn traversal(scene: &mut Scene<'_>) -> Scenario {
    let mut target = b"/".to_vec();
    for _ in 0..scene.rng.range(1, 4) {
        if scene.rng.chance(50) {
            let piece = scene.rng.pick(&TRAVERSALS).copied().unwrap_or_default();
            target.extend_from_slice(piece.as_bytes());
        } else {
            let segment =
                *scene.rng.pick(&["static", "img", "a b", "etc", "admin", "x"]).unwrap_or(&"x");
            target.extend_from_slice(segment.replace(' ', "%20").as_bytes());
            target.push(b'/');
        }
    }
    let tail =
        *scene.rng.pick(&["etc/passwd", "win.ini", "index.html", "", ".env"]).unwrap_or(&"");
    target.extend_from_slice(tail.as_bytes());
    if scene.rng.chance(30) {
        target = scene.fragment(|f| &f.paths);
    }
    let agent = if scene.rng.chance(50) { BROWSERS[0] } else { API_CLIENTS[5] };
    let mut request = Request::get(target).header("User-Agent", agent);
    if scene.rng.chance(50) {
        request = request.header("Accept", ACCEPTS[0]);
    }
    let request = scene.identify(request);
    let request = scene.adapt(request);
    Scenario::single("traversal", request.encode())
}

/// Percent-encodes the bytes a request target may not hold raw.
pub fn url_encode(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 3);
    for &byte in bytes {
        if byte.is_ascii_alphanumeric() || b"-._~/".contains(&byte) {
            out.push(byte);
        } else {
            out.extend_from_slice(format!("%{byte:02X}").as_bytes());
        }
    }
    out
}

/// Where a payload goes.
const PLACES: [&str; 8] =
    ["query", "query-raw", "form", "json", "multipart", "header", "path", "cookie"];

/// An injection payload (SQL, script, command, traversal) in a query, body or header.
pub fn payload(scene: &mut Scene<'_>) -> Scenario {
    let payload = scene.fragment(|f| &f.payloads);
    let place = scene.rng.pick(&PLACES).copied().unwrap_or("query");
    let agent = if scene.rng.chance(60) { API_CLIENTS[5] } else { BROWSERS[0] };
    let request = match place {
        "query" => Request::get([b"/search?q=".to_vec(), url_encode(&payload)].concat()),
        "query-raw" => Request::get([b"/search?q=".to_vec(), safe_raw(&payload)].concat()),
        "form" => Request::post(
            "/submit",
            "application/x-www-form-urlencoded",
            [b"name=bob&note=".to_vec(), url_encode(&payload)].concat(),
        ),
        "json" => Request::post("/api/v1/items", "application/json", json_string_body(&payload)),
        "multipart" => Request::post(
            "/upload",
            "multipart/form-data; boundary=b",
            [
                b"--b\r\nContent-Disposition: form-data; name=\"t\"\r\n\r\n".to_vec(),
                payload.clone(),
                b"\r\n--b--\r\n".to_vec(),
            ]
            .concat(),
        ),
        "header" => Request::get("/page").header("X-Query", safe_raw(&payload)),
        "path" => Request::get([b"/items/".to_vec(), url_encode(&payload)].concat()),
        _ => Request::get("/account")
            .header("Cookie", [b"pref=".to_vec(), url_encode(&payload)].concat()),
    };
    let mut request = request.header("User-Agent", agent);
    if scene.rng.chance(40) {
        request = request.header("Accept", ACCEPTS[0]);
    }
    let request = scene.identify(request);
    let request = scene.adapt(request);
    Scenario::single(format!("payload in {place}"), request.encode())
}

/// The payload with the bytes that would break the request line or a header field
/// (controls, space) percent-encoded and everything else raw.
fn safe_raw(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len());
    for &byte in payload {
        if byte <= b' ' || byte == 0x7f {
            out.extend_from_slice(format!("%{byte:02X}").as_bytes());
        } else {
            out.push(byte);
        }
    }
    out
}

/// `{"q":"<payload>"}` with JSON escaping.
fn json_string_body(payload: &[u8]) -> Vec<u8> {
    let mut out = b"{\"q\":\"".to_vec();
    for &byte in payload {
        match byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0..0x20 => out.extend_from_slice(format!("\\u{byte:04x}").as_bytes()),
            _ => out.push(byte),
        }
    }
    out.extend_from_slice(b"\"}");
    out
}

/// Session cookies that are malformed, forged, truncated or misnamed.
const TOKENS: [&str; 12] = [
    "__sibuna_token=bogus",
    "__sibuna_token=",
    "__sibuna_token=v1_YWJjZGVmZ2hpams",
    "__sibuna_token=v1.AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA",
    "__sibuna_token=v2.eyJhbGciOiJub25lIn0.e30.",
    "session=xyz; __sibuna_token=abc; theme=dark",
    "__sibuna_token=a; __sibuna_token=b",
    "__sibuna_tokenx=abc",
    "__SIBUNA_TOKEN=abc",
    "__sibuna_token=\"quoted\"",
    "__sibuna_token=abc%3Bdef",
    "__sibuna_token= spaced ",
];

/// A request carrying an invalid session cookie.
pub fn token(scene: &mut Scene<'_>) -> Scenario {
    let cookie = if scene.rng.chance(15) {
        format!("__sibuna_token={}", "A".repeat(scene.rng.range(200, 6000)))
    } else {
        scene.rng.pick(&TOKENS).copied().unwrap_or_default().to_owned()
    };
    let target =
        *scene.rng.pick(&["/private", "/", "/exact", "/api/checkout/pay"]).unwrap_or(&"/");
    let agent = scene.rng.pick(&BROWSERS).copied().unwrap_or_default();
    let mut request = Request::get(target).header("User-Agent", agent).header("Cookie", cookie);
    let accept = if scene.rng.chance(60) { ACCEPTS[0] } else { "application/json" };
    request = request.header("Accept", accept);
    let request = scene.identify(request);
    let request = scene.adapt(request);
    Scenario::single("invalid session cookie", request.encode())
}

/// Forwarded-header variants: address lists, IPv6, invalid values, the addresses the
/// sample policy names, `X-Real-IP`, `Forwarded` and forward-authorization metadata.
pub fn forwarded(scene: &mut Scene<'_>) -> Scenario {
    let me = scene.client();
    let other = scene.other_client();
    let n = scene.index;
    let values = [
        format!("{me}, {other}"),
        format!("{other},{me}"),
        scene.client_v6(),
        format!("[{}]", scene.client_v6()),
        format!(" {me} "),
        format!("203.0.113.{}", 1 + n % 254),
        format!("10.200.{}.{}", (n / 254) % 256, 1 + n % 254),
        format!("10.{}.{}.{}", 1 + n % 199, (n / 199) % 256, 1 + n % 254),
        format!("8.8.8.{}", 1 + n % 254),
        format!("2a02:1234:{:x}::9", n),
        "not-an-ip".to_owned(),
        String::new(),
        format!("{me}:8080"),
        format!("unknown, {me}"),
    ];
    let value = scene.rng.pick(&values).cloned().unwrap_or_default();
    let agent = if scene.rng.chance(50) { BROWSERS[0] } else { API_CLIENTS[5] };
    let request = Request::get(page_target(scene)).header("User-Agent", agent);
    let (variant, mut request) = match scene.rng.below(8) {
        0 => ("x-real-ip", request.header("X-Real-IP", value.as_bytes())),
        1 => ("forwarded", request.header("Forwarded", format!("for={value};proto=https"))),
        2 => {
            let twice = request.header("X-Forwarded-For", value.as_bytes());
            ("xff-twice", twice.header("X-Forwarded-For", other))
        }
        // Header names with `_` that read as forwarded or Sibuna headers with `-`.
        3 => ("underscore", request.header("X_Forwarded_For", value.as_bytes())),
        4 => {
            let spoofed = request.header("X-Forwarded-For", me.as_bytes());
            (
                "spoofed-sibuna",
                spoofed.header("X_Sibuna_Status", "PASS").header("X-Sibuna-Rule", "x"),
            )
        }
        5 => ("host-twice", request.header("Host", "other.test").header("X-Forwarded-For", me)),
        _ => ("xff", request.header("X-Forwarded-For", value.as_bytes())),
    };
    if scene.rng.chance(30) {
        let proto = *scene.rng.pick(&["https", "http", "ftp", "HTTPS"]).unwrap_or(&"https");
        request = request.header("X-Forwarded-Proto", proto);
    }
    if scene.rng.chance(30) {
        request = request.header("X-Forwarded-Host", "evil.test");
    }
    if scene.forward_auth() {
        request = forward_auth_metadata(scene, request);
    }
    Scenario::single(format!("forwarded {variant} {value}"), request.encode())
}

/// Ingress metadata for forward authorization, valid and invalid.
fn forward_auth_metadata(scene: &mut Scene<'_>, request: Request) -> Request {
    let uris = ["/private?a=1", "/robots.txt", "//bad", "a", "/a#b", "/a\\b", "/exact", "/"];
    let uri = scene.rng.pick(&uris).copied().unwrap_or("/");
    let request = Request { target: b"/auth".to_vec(), ..request };
    match scene.rng.below(5) {
        0 => request.header("X-Original-URI", uri),
        1 => request.header("X-Forwarded-Uri", uri).header("X-Forwarded-Uri", uri),
        2 => request.header("X-Forwarded-Uri", uri).header("X-Forwarded-Method", "GE T"),
        3 => request.header("X-Forwarded-Uri", uri).header("X-Forwarded-Method", "POST"),
        _ => request.header("X-Forwarded-Uri", uri),
    }
}

/// Malformed request lines and header sections, from the parser's own test vectors.
const MALFORMED: [&[u8]; 18] = [
    b"GARBAGE\r\n\r\n",
    b"GET / HTTP/2.0\r\nHost: a\r\n\r\n",
    b"GET  / HTTP/1.1\r\nHost: a\r\n\r\n",
    b"GET /\x00 HTTP/1.1\r\nHost: a\r\n\r\n",
    b"GET / http/1.1\r\nHost: a\r\n\r\n",
    b"GET / HTTP/1.1 extra\r\n\r\n",
    b"GET /bad\npath HTTP/1.1\r\n\r\n",
    b"GET / HTTP/1.1\r\n: empty\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost : a\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: a\nX: b\r\n\r\n",
    b"GET / HTTP/1.1\nHost: a\n\n",
    b"GET / HTTP/1.1\r\nHost: a\r\n X-Folded: yes\r\n\r\n",
    b"GET / HTTP/1.1\r\nX-Nul: a\x00b\r\n\r\n",
    b"GET / HTTP/1.1\r\nno colon\r\n\r\n",
    b"\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n",
    b"GET / HTTP/1.1 \r\n\r\n",
    b"GET / HTTP/1.1\r\r\n\r\n",
    b"OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n",
];

/// Methods: common, rare and unknown ones, and malformed request lines.
pub fn method(scene: &mut Scene<'_>) -> Scenario {
    if scene.rng.chance(40) {
        let raw = scene.rng.pick(&MALFORMED).copied().unwrap_or_default();
        return Scenario::single("malformed request", raw.to_vec());
    }
    let methods = [
        "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH", "PROPFIND", "TRACE", "get", "BREW", "CONNECT",
    ];
    let method = scene.rng.pick(&methods).copied().unwrap_or("HEAD");
    let target = if scene.rng.chance(15) {
        b"http://app.test/abs?x=1".to_vec()
    } else {
        page_target(scene)
    };
    let mut request = Request::new(method, target).header("User-Agent", API_CLIENTS[5]);
    if scene.rng.chance(30) {
        request = request.header("Accept", ACCEPTS[0]);
    }
    if method == "CONNECT" {
        request.target = b"app.test:443".to_vec();
    }
    let request = scene.identify(request);
    let request = scene.adapt(request);
    Scenario::single(format!("method {method}"), request.encode())
}

/// Origin answers the stub origin produces for these paths (see `origin.rs`).
const ORIGIN_PATHS: [&str; 8] = [
    "/__origin/chunked",
    "/__origin/close",
    "/__origin/big",
    "/__origin/empty",
    "/__origin/not-modified",
    "/__origin/cookie",
    "/__origin/headers",
    "/plain/page",
];

/// A request the policy admits whose origin answer has a particular framing. The
/// `X-Api`/`X-Token` pair is the sample policy's allow rule.
pub fn origin(scene: &mut Scene<'_>) -> Scenario {
    if scene.rng.chance(15) {
        return upgrade(scene);
    }
    let path = scene.rng.pick(&ORIGIN_PATHS).copied().unwrap_or("/plain/page");
    let method = if scene.rng.chance(20) { "HEAD" } else { "GET" };
    let request = Request::new(method, path)
        .header("User-Agent", API_CLIENTS[6])
        .header("X-Api", "v2")
        .header("X-Token", "test-1");
    let request = scene.identify(request);
    if scene.rng.chance(40) {
        let again =
            scene.identify(Request::get("/plain/again").header("User-Agent", API_CLIENTS[6]));
        let label = format!("origin {method} {path} then keep-alive");
        return Scenario::keep_alive(label, vec![request.encode(), again.encode()]);
    }
    Scenario::single(format!("origin {method} {path}"), request.encode())
}

/// An upgrade to the origin: accepted with tunnel bytes after the head, or refused for a
/// body (R10 of SID 0009), or for another protocol.
fn upgrade(scene: &mut Scene<'_>) -> Scenario {
    let request = Request::get("/__origin/upgrade")
        .header("User-Agent", API_CLIENTS[6])
        .header("X-Api", "v2")
        .header("X-Token", "test-1")
        .header("Connection", "Upgrade");
    let request = scene.identify(request);
    let (request, label) = match scene.rng.below(4) {
        0 => {
            let request = request
                .header("Upgrade", "websocket")
                .header("Sec-WebSocket-Version", "13")
                .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
                .body(Body::Raw(b"tunnel bytes".to_vec()));
            (request, "websocket upgrade with tunnel bytes")
        }
        1 => {
            let request =
                request.header("Upgrade", "websocket").body(Body::Length(b"hello".to_vec()));
            (request, "upgrade with a Content-Length body")
        }
        2 => {
            let request = request
                .header("Upgrade", "websocket")
                .body(Body::Chunked { data: b"hello".to_vec(), chunk: 0 });
            (request, "upgrade with a chunked body")
        }
        _ => (
            request.header("Upgrade", "h2c").header("HTTP2-Settings", "AAMAAABkAAQAAP__"),
            "h2c upgrade",
        ),
    };
    Scenario::single(label, request.encode())
}

/// The reserved routes, except the metrics the runner compares at the end.
pub fn internal(scene: &mut Scene<'_>) -> Scenario {
    let routes = [
        "/__sibuna/health",
        "/__sibuna/worker.js",
        "/__sibuna/wasm/sibuna-pow.wasm",
        "/__sibuna/challenge",
        "/__sibuna/challenge?x=1",
        "/__sibuna/nope",
        "/__sibuna/",
        "/__sibuna/verify",
        "/__sibuna/challenge.json?path=%2Fprivate",
    ];
    let route = scene.rng.pick(&routes).copied().unwrap_or("/__sibuna/health");
    let agent = scene.rng.pick(&BROWSERS).copied().unwrap_or_default();
    let mut request = Request::get(route).header("User-Agent", agent);
    if scene.rng.chance(50) {
        request = request.header("Accept", ACCEPTS[0]);
    }
    if scene.forward_auth() && scene.rng.chance(50) {
        request = request.header("X-Original-URI", "/private");
    }
    let request = scene.identify(request);
    Scenario::single(format!("internal {route}"), request.encode())
}
