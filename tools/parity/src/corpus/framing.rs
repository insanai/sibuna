//! Scenarios about message framing: uploads, ambiguous framing and smuggling attempts
//! (`sibuna-http` tests, SID 0009), oversized heads, keep-alive and pipelining, HTTP/1.0
//! and `Expect: 100-continue`.

use super::request::chunked;
use super::{Body, Request, Scenario, Scene};

/// A User-Agent no built-in rule or signature names.
const UPLOADER: &str = "uploader/1.0";

/// The pipelined request that follows a smuggling attempt; if a daemon desynchronised, it
/// would answer it differently.
const SMUGGLED: &[u8] =
    b"GET /smuggled HTTP/1.1\r\nHost: app.test\r\nUser-Agent: uploader/1.0\r\n\r\n";

/// A request most configurations admit: the sample policy's allow rule matches the
/// `X-Api`/`X-Token` pair, and the default engine allows an unknown User-Agent.
fn admitted(scene: &mut Scene<'_>, method: &str, target: &str) -> Request {
    let mut request = Request::new(method, target).header("User-Agent", UPLOADER);
    if scene.rng.chance(80) {
        request = request.header("X-Api", "v2").header("X-Token", "test-2");
    }
    scene.identify(request)
}

/// `length` deterministic bytes: printable text, sometimes with binary bytes or an
/// injection payload inside.
fn body_bytes(scene: &mut Scene<'_>, length: usize) -> Vec<u8> {
    let binary = scene.rng.chance(20);
    let mut seed = scene.rng.next_u64() | 1;
    let mut out: Vec<u8> = (0..length)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let byte = (seed >> 24) as u8;
            if binary { byte } else { b' ' + byte % 94 }
        })
        .collect();
    if scene.rng.chance(15) && length > 64 {
        let payload = scene.fragment(|f| &f.payloads);
        let at = scene.rng.below(length - payload.len().min(length));
        for (slot, byte) in out.iter_mut().skip(at).zip(payload) {
            *slot = byte;
        }
    }
    out
}

/// Encodes `data` as chunks with the variations RFC 9112 allows: extensions, upper-case
/// and zero-padded sizes, and trailers.
fn chunked_variant(scene: &mut Scene<'_>, data: &[u8]) -> (Vec<u8>, &'static str) {
    let kind = scene.rng.below(4);
    let size = *scene.rng.pick(&[1usize, 7, 100, 4096, 16_384]).unwrap_or(&100);
    let mut out = Vec::with_capacity(data.len() + 64);
    for piece in data.chunks(size.max(1)) {
        let line = match kind {
            0 => format!("{:x};ext=1\r\n", piece.len()),
            1 => format!("{:X}\r\n", piece.len()),
            2 => format!("00{:x}\r\n", piece.len()),
            _ => format!("{:x} ;name=\"quoted \\\" value\"\r\n", piece.len()),
        };
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(piece);
        out.extend_from_slice(b"\r\n");
    }
    let (last, label): (&[u8], _) = match kind {
        0 => (b"0\r\nX-Trailer: yes\r\n\r\n", "extensions and a trailer"),
        1 => (b"0\r\n\r\n", "upper-case sizes"),
        2 => (b"000\r\n\r\n", "zero-padded sizes"),
        _ => (b"0;end\r\n\r\n", "quoted extensions"),
    };
    out.extend_from_slice(last);
    (out, label)
}

/// A Content-Length or chunked upload of 0 bytes to 300 KiB.
pub fn upload(scene: &mut Scene<'_>) -> Scenario {
    let length = match scene.rng.below(3) {
        0 => scene.rng.below(2048),
        1 => scene.rng.range(8 * 1024, 60 * 1024),
        _ => scene.rng.range(70 * 1024, 300 * 1024),
    };
    let data = body_bytes(scene, length);
    let method = if scene.rng.chance(70) { "POST" } else { "PUT" };
    let request =
        admitted(scene, method, "/upload").header("Content-Type", "application/octet-stream");
    let (bytes, label) = match scene.rng.below(3) {
        0 => (request.body(Body::Length(data)).encode(), "length".to_owned()),
        1 => {
            let chunk = *scene.rng.pick(&[0usize, 1, 7, 1000, 16_384]).unwrap_or(&0);
            let request = request.body(Body::Chunked { data, chunk });
            (request.encode(), format!("chunked by {chunk}"))
        }
        _ => {
            let (body, label) = chunked_variant(scene, &data);
            let request = request.header("Transfer-Encoding", "chunked").body(Body::Raw(body));
            (request.encode(), format!("chunked with {label}"))
        }
    };
    let label = format!("upload {length} bytes, {label}");
    if scene.rng.chance(40) {
        let after = admitted(scene, "GET", "/after-upload").encode();
        return Scenario::keep_alive(label, vec![bytes, after]);
    }
    Scenario::single(label, bytes)
}

/// Ambiguous framing in the head: conflicting or malformed `Content-Length` and
/// `Transfer-Encoding` (R1 to R4 of SID 0009 and the parser's smuggling tests).
const HEAD_FRAMINGS: [&str; 22] = [
    "Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    "Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n",
    "Content-Length: 5\r\nContent-Length: 6\r\n\r\nhello!",
    "Content-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
    "Transfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
    "Transfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n",
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    "Transfer-Encoding : chunked\r\n\r\n0\r\n\r\n",
    "Transfer-Encoding:\x0bchunked\r\n\r\n0\r\n\r\n",
    "Transfer-Encoding: chunked\r\n X-Folded: yes\r\n\r\n0\r\n\r\n",
    "Transfer-Encoding: xchunked\r\n\r\n0\r\n\r\n",
    "Transfer-Encoding: chunked;q=1\r\n\r\n0\r\n\r\n",
    "Transfer-Encoding: , chunked\r\n\r\n0\r\n\r\n",
    "Transfer-Encoding:\r\n\r\n",
    "Transfer-Encoding: \tChunked \r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n\r\n0\r\n\r\n",
    "Content-Length: 0x10\r\n\r\n",
    "Content-Length: 1, 1\r\n\r\na",
    "Content-Length: +5\r\n\r\nhello",
    "Content-Length: -1\r\n\r\n",
    "Content-Length: 99999999999999999999\r\n\r\n",
    "Content-Length: 3\r\n\r\nabc",
];

/// Chunked bodies the decoder must refuse (R5 to R7) or accept, from its tests.
const CHUNKED_BODIES: [&str; 26] = [
    "5\nhello\r\n0\r\n\r\n",
    "5\rX\r\nhello\r\n0\r\n\r\n",
    "5\r\nhello\n0\r\n\r\n",
    "5\r\nhelloXY0\r\n\r\n",
    "5 \r\nhello\r\n0\r\n\r\n",
    " 5\r\nhello\r\n0\r\n\r\n",
    "+5\r\nhello\r\n0\r\n\r\n",
    "0x5\r\nhello\r\n0\r\n\r\n",
    "-1\r\nx\r\n0\r\n\r\n",
    "\r\n",
    "10000000000000000\r\n",
    "5;\r\nhello\r\n0\r\n\r\n",
    "5;a=\r\nhello\r\n0\r\n\r\n",
    "5;a b\r\nhello\r\n0\r\n\r\n",
    "5;a=\"open\r\nhello\r\n0\r\n\r\n",
    "5;a=\"x\ny\"\r\nhello\r\n0\r\n\r\n",
    "5;a=\"x\ry\"\r\nhello\r\n0\r\n\r\n",
    "5;a=\"x\x01\"\r\nhello\r\n0\r\n\r\n",
    "0\r\nBad Name: x\r\n\r\n",
    "0\r\nX : y\r\n\r\n",
    "0\r\nno colon\r\n\r\n",
    "0\r\nX: \x7f\r\n\r\n",
    "0\r\n\n",
    "5;a=b\r\nhello\r\n0\r\n\r\n",
    "5\r\nhello\r\n0\r\nX-T: v\r\n\r\n",
    "5\r\nhello\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: app.test\r\n\r\n",
];

/// A smuggling attempt or ambiguous framing, often followed by a pipelined request.
pub fn framing(scene: &mut Scene<'_>) -> Scenario {
    let version = if scene.rng.chance(10) { "HTTP/1.0" } else { "HTTP/1.1" };
    let mut head = Request::new("POST", "/upload");
    head.version = version;
    let head = scene.identify(
        head.header("User-Agent", UPLOADER).header("X-Api", "v2").header("X-Token", "t"),
    );
    let mut bytes = head.encode();
    // Drop the blank line: the framing fields and the body follow.
    bytes.truncate(bytes.len() - 2);
    let label = if scene.rng.chance(50) {
        let framing = scene.rng.pick(&HEAD_FRAMINGS).copied().unwrap_or_default();
        bytes.extend_from_slice(framing.as_bytes());
        format!("head framing {}", framing.split("\r\n\r\n").next().unwrap_or_default())
    } else {
        let body = scene.rng.pick(&CHUNKED_BODIES).copied().unwrap_or_default();
        bytes.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
        bytes.extend_from_slice(body.as_bytes());
        format!("chunked body {body:?}")
    };
    if scene.rng.chance(50) {
        bytes.extend_from_slice(SMUGGLED);
    }
    Scenario::single(label.replace("\r\n", "|"), bytes)
}

/// Heads beyond the limits: long fields, many fields, long targets.
pub fn oversized(scene: &mut Scene<'_>) -> Scenario {
    let request = Request::get("/page").header("User-Agent", UPLOADER);
    let (request, label) = match scene.rng.below(4) {
        0 => {
            let size =
                *scene.rng.pick(&[8_000usize, 16_000, 32_000, 60_000, 70_000]).unwrap_or(&8_000);
            (request.header("X-Big", "a".repeat(size)), format!("header of {size} bytes"))
        }
        1 => {
            let count = *scene.rng.pick(&[50usize, 63, 64, 65, 100, 128, 200]).unwrap_or(&64);
            let mut request = request;
            for index in 0..count {
                request = request.header(&format!("X-H{index}"), "v");
            }
            (request, format!("{count} extra header fields"))
        }
        2 => {
            let size =
                *scene.rng.pick(&[4_000usize, 8_190, 9_000, 16_000, 70_000]).unwrap_or(&4_000);
            let target = format!("/{}", "p".repeat(size));
            (Request { target: target.into_bytes(), ..request }, format!("target of {size} bytes"))
        }
        _ => {
            let size = *scene.rng.pick(&[4_096usize, 10_000, 66_000]).unwrap_or(&4_096);
            let cookie = format!("a={}", "c".repeat(size));
            (request.header("Cookie", cookie), format!("cookie of {size} bytes"))
        }
    };
    let request = scene.identify(request);
    Scenario::single(label, request.encode())
}

/// Two to five requests on one connection; sometimes a `Connection: close` in the middle
/// and a pipelined pair at the end.
pub fn keep_alive(scene: &mut Scene<'_>) -> Scenario {
    let count = scene.rng.range(2, 5);
    let mut requests = Vec::with_capacity(count);
    for _ in 0..count {
        let target = *scene
            .rng
            .pick(&["/a", "/robots.txt", "/private", "/search?q=1", "/upload"])
            .unwrap_or(&"/a");
        let mut request = if target == "/upload" {
            admitted(scene, "POST", target).body(Body::Length(b"field=value".to_vec()))
        } else {
            admitted(scene, "GET", target)
        };
        if scene.rng.chance(10) {
            request = request.header("Connection", "close");
        }
        if scene.rng.chance(20) {
            request = request.header("Accept", "text/html");
        }
        requests.push(request.encode());
    }
    let mut label = format!("{count} requests on one connection");
    if scene.rng.chance(30) {
        let pipelined =
            [admitted(scene, "GET", "/one").encode(), admitted(scene, "GET", "/two").encode()]
                .concat();
        requests.push(pipelined);
        label.push_str(", then a pipelined pair");
    }
    Scenario::keep_alive(label, requests)
}

/// HTTP/1.0 requests: with and without `Host` and keep-alive, absolute targets, bodies.
pub fn http10(scene: &mut Scene<'_>) -> Scenario {
    let target =
        *scene.rng.pick(&["/", "/page", "http://app.test/abs", "/robots.txt"]).unwrap_or(&"/");
    let method = if scene.rng.chance(20) { "POST" } else { "GET" };
    let mut request = admitted(scene, method, target);
    request.version = "HTTP/1.0";
    if request.method == "POST" {
        request = request.body(Body::Length(b"a=1&b=2".to_vec()));
    }
    if scene.rng.chance(30) {
        request = request.without("Host");
    }
    if scene.rng.chance(40) {
        let request = request.header("Connection", "keep-alive");
        let mut second = admitted(scene, "GET", "/second");
        second.version = "HTTP/1.0";
        return Scenario::keep_alive(
            "HTTP/1.0 keep-alive",
            vec![request.encode(), second.encode()],
        );
    }
    Scenario::single("HTTP/1.0", request.encode())
}

/// `Expect` with Content-Length and chunked bodies, valid and unknown expectations.
pub fn expect(scene: &mut Scene<'_>) -> Scenario {
    let expectation = *scene
        .rng
        .pick(&["100-continue", "100-Continue", "nothing", "100-continue, x"])
        .unwrap_or(&"100-continue");
    let size = if scene.rng.chance(70) {
        scene.rng.range(1, 2000)
    } else {
        scene.rng.range(70_000, 140_000)
    };
    let data = body_bytes(scene, size);
    let request = admitted(scene, "POST", "/upload").header("Expect", expectation);
    let (request, framing) = match scene.rng.below(3) {
        0 => (request.body(Body::Length(data.clone())), "length"),
        1 => {
            (request.body(Body::Raw(Vec::new())).header("Transfer-Encoding", "chunked"), "chunked")
        }
        _ => (Request { method: "GET".into(), ..request }, "no body"),
    };
    let mut bytes = request.encode();
    if framing == "chunked" {
        bytes.extend_from_slice(&chunked(&data, 4096));
    }
    let label = format!("Expect: {expectation} with {framing} ({size} bytes)");
    if scene.rng.chance(30) {
        let after = admitted(scene, "GET", "/after-expect").encode();
        return Scenario::keep_alive(label, vec![bytes, after]);
    }
    Scenario::single(label, bytes)
}
