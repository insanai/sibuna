//! The Zig parser tests, ported, and tests of properties the Rust version adds.

use super::*;

#[test]
fn parse_request_parses_method_path_headers_cookies_zero_copy() {
    let raw = b"GET /dashboard?tab=security HTTP/1.1\r\n\
        Host: localhost:8080\r\n\
        User-Agent: Mozilla/5.0\r\n\
        Cookie: session=abc; __sibuna_token=tok123\r\n\
        \r\n";
    let req = parse_request(raw).unwrap();
    assert_eq!(req.method, Method::Get);
    assert_eq!(req.path, b"/dashboard");
    assert_eq!(req.query, b"tab=security");
    assert_eq!(req.header(b"host").unwrap(), b"localhost:8080");
    assert_eq!(req.cookie(b"__sibuna_token").unwrap(), b"tok123");
    assert!(req.wants_keep_alive());
    assert_eq!(req.content_length(), None);
    assert!(!req.accepts_html());

    let raw10 = b"GET / HTTP/1.0\r\nContent-Length: 12\r\nAccept: text/html\r\n\r\nhello world!";
    let req10 = parse_request(raw10).unwrap();
    assert!(!req10.wants_keep_alive());
    assert_eq!(req10.content_length(), Some(12));
    assert!(req10.accepts_html());
    assert_eq!(req10.body, b"hello world!");
    assert_eq!(parse_request(b"GET / HTTP/2.0\r\n\r\n"), Err(ParseError::UnsupportedVersion));
}

#[test]
fn parse_request_rejects_http_request_smuggling_and_malformed_headers() {
    let te_cl = b"POST /submit HTTP/1.1\r\n\
        Host: localhost\r\n\
        Content-Length: 5\r\n\
        Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    assert_eq!(parse_request(te_cl), Err(ParseError::RequestSmugglingAttempt));

    let dup_cl = b"POST /submit HTTP/1.1\r\n\
        Host: localhost\r\n\
        Content-Length: 5\r\n\
        Content-Length: 10\r\n\r\nhello";
    assert_eq!(parse_request(dup_cl), Err(ParseError::DuplicateContentLength));

    let ws_colon = b"GET / HTTP/1.1\r\nHost : localhost\r\n\r\n";
    assert_eq!(parse_request(ws_colon), Err(ParseError::InvalidHeaderWhitespace));
}

#[test]
fn parser_rejects_ambiguous_framing_and_control_bytes() {
    let bad: [&[u8]; 6] = [
        b"GET / HTTP/1.1 extra\r\n\r\n",
        b"GET /bad\npath HTTP/1.1\r\n\r\n",
        b"GET / HTTP/1.1\r\n: empty\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\nb\r\n\r\n",
        b"POST / HTTP/1.1\r\nContent-Length: +5\r\n\r\n",
        b"POST / HTTP/1.1\r\nContent-Length: invalid\r\n\r\n",
    ];
    for raw in bad {
        assert!(parse_request(raw).is_err(), "{:?}", String::from_utf8_lossy(raw));
    }
    let req = parse_request(b"PROPFIND / HTTP/1.1\r\nCookie: a=1;__sibuna_token=abc\r\n\r\n");
    let req = req.unwrap();
    assert_eq!(req.method_text, b"PROPFIND");
    assert_eq!(req.method, Method::Other);
    assert_eq!(req.cookie(b"__sibuna_token").unwrap(), b"abc");
}

#[test]
fn only_a_single_exact_chunked_coding_frames_an_http11_request_body() {
    let ok = parse_request(b"POST / HTTP/1.1\r\nTransfer-Encoding: \tChunked \r\n\r\n").unwrap();
    assert!(ok.chunked && ok.content_length().is_none());
    assert!(!parse_request(b"POST / HTTP/1.1\r\n\r\n").unwrap().chunked);
    let twice = "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked";
    let cases = [
        (ParseError::RequestSmugglingAttempt, "Content-Length: 5\r\nTransfer-Encoding: chunked"),
        (
            ParseError::InvalidTransferEncoding,
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
        ),
        (ParseError::InvalidTransferEncoding, twice),
        (ParseError::InvalidTransferEncoding, "Transfer-Encoding: chunked, gzip"),
        (ParseError::InvalidTransferEncoding, "Transfer-Encoding: chunked, chunked"),
        (ParseError::InvalidTransferEncoding, "Transfer-Encoding: xchunked"),
        (ParseError::InvalidTransferEncoding, "Transfer-Encoding: , chunked"),
        (ParseError::InvalidTransferEncoding, "Transfer-Encoding: chunked;q=1"),
        (ParseError::InvalidTransferEncoding, "Transfer-Encoding:"),
        (ParseError::UnsupportedTransferEncoding, "Transfer-Encoding: gzip, chunked"),
    ];
    for (error, fields) in cases {
        let raw = format!("POST / HTTP/1.1\r\n{fields}\r\n\r\n");
        assert_eq!(parse_request(raw.as_bytes()), Err(error), "{fields}");
    }
    assert_eq!(
        parse_request(b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n"),
        Err(ParseError::InvalidTransferEncoding),
    );
}

#[test]
fn every_error_is_reachable_in_the_zig_order() {
    let cases: [(&[u8], ParseError); 15] = [
        (b"", ParseError::EmptyRequest),
        (b"\r\nGET / HTTP/1.1\r\n\r\n", ParseError::EmptyRequest),
        (b"GET  / HTTP/1.1\r\n\r\n", ParseError::InvalidRequestLine),
        (b"GET /\x00 HTTP/1.1\r\n\r\n", ParseError::InvalidRequestLine),
        (b"GET / HTTP/1.1 \r\n\r\n", ParseError::InvalidRequestLine),
        (b"GET / HTTP/1.1\r\r\n\r\n", ParseError::UnsupportedVersion),
        (b"GET / http/1.1\r\n\r\n", ParseError::UnsupportedVersion),
        // A NUL byte outranks every other fault of the line.
        (b"GET / HTTP/1.1\r\nBad Name\n: \x00\r\n\r\n", ParseError::NullByteInHeader),
        (b"GET / HTTP/1.1\r\nNoColon\r\n\r\n", ParseError::InvalidHeader),
        (b"GET / HTTP/1.1\r\nName\t: x\r\n\r\n", ParseError::InvalidHeaderWhitespace),
        (b"GET / HTTP/1.1\r\nX: a\rb\r\n\r\n", ParseError::InvalidHeader),
        (b"GET / HTTP/1.1\r\nX: \x7f\r\n\r\n", ParseError::InvalidHeader),
        // Conflicting lengths are found before the head runs out of field slots.
        (b"GET / HTTP/1.1\r\nContent-Length: 1\r\ncontent-length: 2\r\n", {
            ParseError::DuplicateContentLength
        }),
        (b"GET / HTTP/1.1\r\nContent-Length: 99999999999999999999\r\n\r\n", {
            ParseError::InvalidContentLength
        }),
        (b"GET / HTTP/1.1\r\nContent-Length: 18446744073709551616\r\n\r\n", {
            ParseError::InvalidContentLength
        }),
    ];
    for (raw, error) in cases {
        assert_eq!(parse_request(raw), Err(error), "{:?}", String::from_utf8_lossy(raw));
        assert_eq!(reference::parse(raw), Err(error), "{:?}", String::from_utf8_lossy(raw));
    }
}

#[test]
fn heads_without_a_blank_line_parse_to_their_end() {
    let req = parse_request(b"GET /x?y HTTP/1.1").unwrap();
    assert_eq!(
        (req.path, req.query, req.header_count, req.body),
        (&b"/x"[..], &b"y"[..], 0, &b""[..])
    );
    let req = parse_request(b"GET / HTTP/1.1\r\nHost: a").unwrap();
    assert_eq!(req.header(b"HOST"), Some(&b"a"[..]));
    let req = parse_request(b"GET / HTTP/1.1\r\nHost: a\r\n").unwrap();
    assert_eq!(req.header_count, 1);
    assert!(req.body.is_empty());
    let raw = b"GET / HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\n\r\n";
    assert_eq!(parse_request(raw).unwrap().body, &raw[18..]);
    // Two equal lengths are one length.
    let twice = parse_request(b"PUT / HTTP/1.1\r\nContent-Length: 1\r\ncontent-length: 1\r\n\r\n");
    assert_eq!(twice.unwrap().content_length(), Some(1));
    let max = parse_request(b"POST / HTTP/1.1\r\nContent-Length: 18446744073709551615\r\n\r\n");
    assert_eq!(max.unwrap().content_length(), Some(usize::MAX));
}

#[test]
fn thirty_two_headers_fit_and_a_thirty_third_does_not() {
    let mut raw = String::from("GET / HTTP/1.1\r\n");
    for index in 0..MAX_HEADERS {
        raw.push_str(&format!("X-{index}: {index}\r\n"));
    }
    let full = parse_request(format!("{raw}\r\n").as_bytes()).map(|r| r.header_count);
    assert_eq!(full, Ok(MAX_HEADERS));
    raw.push_str("X-Last: 1\r\n\r\n");
    assert_eq!(parse_request(raw.as_bytes()), Err(ParseError::TooManyHeaders));
}

#[test]
fn values_are_trimmed_and_may_hold_tabs_and_obs_text() {
    let raw = b"GET / HTTP/1.1\r\nX-A: \t a\tb \xff \t\r\nX-B:\r\nX-C:   \r\n\r\n";
    let req = parse_request(raw).unwrap();
    assert_eq!(req.header(b"x-a").unwrap(), b"a\tb \xff");
    assert_eq!(req.header(b"x-b").unwrap(), b"");
    assert_eq!(req.header(b"x-c").unwrap(), b"");
    assert_eq!(req, reference::parse(raw).unwrap());
}

#[test]
fn cookies_follow_the_zig_splitting_rules() {
    let raw = b"GET / HTTP/1.1\r\nCookie: a=b=c; flag ;\t t = x; e=\r\nCookie: z=1\r\n\r\n";
    let req = parse_request(raw).unwrap();
    assert_eq!(req.cookie(b"a"), Some(&b"b"[..]));
    assert_eq!(req.cookie(b"flag"), Some(&b""[..]));
    assert_eq!(req.cookie(b"t "), Some(&b" x"[..]));
    assert_eq!(req.cookie(b"e"), Some(&b""[..]));
    // Only the first Cookie field is read.
    assert_eq!(req.cookie(b"z"), None);
}

#[test]
fn keep_alive_follows_the_version_and_connection_field() {
    let cases: [(&[u8], bool); 6] = [
        (b"GET / HTTP/1.1\r\n\r\n", true),
        (b"GET / HTTP/1.1\r\nConnection: CLOSE\r\n\r\n", false),
        (b"GET / HTTP/1.1\r\nConnection: close, x\r\n\r\n", true),
        (b"GET / HTTP/1.0\r\n\r\n", false),
        (b"GET / HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n", true),
        (b"GET / HTTP/1.0\r\nConnection: close\r\n\r\n", false),
    ];
    for (raw, keep) in cases {
        assert_eq!(parse_request(raw).unwrap().wants_keep_alive(), keep);
    }
}

#[test]
fn split_target_cuts_at_the_first_question_mark() {
    assert_eq!(split_target(b"/a?b?c"), Target { path: b"/a", query: b"b?c" });
    assert_eq!(split_target(b"/a?"), Target { path: b"/a", query: b"" });
    assert_eq!(split_target(b"/a"), Target { path: b"/a", query: b"" });
    assert_eq!(split_target(b"?q"), Target { path: b"", query: b"q" });
}

#[test]
fn unique_header_refuses_duplicates() {
    let req = parse_request(b"GET / HTTP/1.1\r\nA: 1\r\na: 2\r\nB: 3\r\n\r\n").unwrap();
    assert_eq!(req.unique_header(b"a"), Err(()));
    assert_eq!(req.unique_header(b"b"), Ok(Some(&b"3"[..])));
    assert_eq!(req.unique_header(b"c"), Ok(None));
}

#[test]
fn default_request_matches_the_zig_defaults() {
    let req = Request::default();
    assert_eq!((req.method, req.method_text, req.path), (Method::Get, &b"GET"[..], &b"/"[..]));
    assert_eq!(req.version.as_bytes(), b"HTTP/1.1");
    assert!(req.headers().is_empty() && req.body.is_empty() && !req.chunked);
    let overfull = Request { header_count: 99, ..Request::default() };
    assert_eq!(overfull.headers().len(), MAX_HEADERS);
}

#[test]
fn only_origin_form_and_options_asterisk_targets_are_accepted() {
    let refused: [&[u8]; 8] = [
        b"GET http://a/admin/x HTTP/1.1\r\nHost: a\r\n\r\n",
        b"GET HTTP://a/admin/x?q HTTP/1.1\r\n\r\n",
        b"GET a:80/admin/x HTTP/1.1\r\nHost: a\r\n\r\n",
        b"CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n\r\n",
        b"GET * HTTP/1.1\r\n\r\n",
        b"options * HTTP/1.1\r\n\r\n",
        b"OPTIONS *?x HTTP/1.1\r\n\r\n",
        b"GET ?/admin HTTP/1.1\r\n\r\n",
    ];
    for raw in refused {
        let error = Err(ParseError::UnsupportedTargetForm);
        assert_eq!(parse_request(raw), error, "{:?}", String::from_utf8_lossy(raw));
        assert_eq!(reference::parse(raw), error, "{:?}", String::from_utf8_lossy(raw));
    }
    let options = parse_request(b"OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
    assert_eq!(
        (options.method, options.path, options.query),
        (Method::Options, &b"*"[..], &b""[..])
    );
    // The target form is checked last, so earlier faults keep their Zig error.
    let both = b"GET http://a/ HTTP/1.1\r\nBad Name: x\r\n\r\n";
    assert_eq!(parse_request(both), Err(ParseError::InvalidHeader));
    // The path is returned as sent; normalisation is a separate step.
    assert_eq!(parse_request(b"GET //a/../b HTTP/1.1\r\n\r\n").unwrap().path, b"//a/../b");
}
