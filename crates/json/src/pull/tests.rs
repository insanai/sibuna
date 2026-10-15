use super::*;

/// Reads every event of `input`, or the first error.
fn events(input: &[u8]) -> Result<Vec<Event<'_>>, Error> {
    let mut reader = PullReader::new(input);
    let mut out = Vec::new();
    while let Some(event) = reader.next()? {
        out.push(event);
    }
    Ok(out)
}

fn error(input: &[u8]) -> (ErrorKind, usize) {
    let error = events(input).unwrap_err();
    (error.kind, error.offset)
}

#[test]
fn reads_every_kind_of_event_in_order() {
    let input = br#" {"a": [true, false, null, -1.5e3, "x\n"], "b": {}} "#;
    let found = events(input).unwrap();
    let expected = [
        Event::BeginObject,
        Event::Key("a".into()),
        Event::BeginArray,
        Event::Bool(true),
        Event::Bool(false),
        Event::Null,
        Event::Number(Number::parse("-1.5e3").unwrap()),
        Event::String("x\n".into()),
        Event::EndArray,
        Event::Key("b".into()),
        Event::BeginObject,
        Event::EndObject,
        Event::EndObject,
    ];
    assert_eq!(found, expected);
    assert_eq!(events(b"7").unwrap(), [Event::Number(Number::parse("7").unwrap())]);
    assert!(matches!(&events(b"\"x\"").unwrap()[0], Event::String(Cow::Borrowed("x"))));
}

#[test]
fn offsets_follow_the_reader() {
    let mut reader = PullReader::new(br#"{ "k" : [ 1 ] }"#);
    assert_eq!(reader.next().unwrap(), Some(Event::BeginObject));
    assert_eq!((reader.event_offset(), reader.offset(), reader.depth()), (0, 1, 1));
    assert_eq!(reader.next().unwrap(), Some(Event::Key("k".into())));
    assert_eq!((reader.event_offset(), reader.offset()), (2, 5));
    assert_eq!(reader.peek().unwrap(), Some(EventKind::BeginArray));
    // Peeking reads the colon and whitespace and stops at the event.
    assert_eq!(reader.offset(), 8);
    assert_eq!(reader.next().unwrap(), Some(Event::BeginArray));
    assert_eq!(reader.depth(), 2);
    assert_eq!(reader.next().unwrap().map(|e| e.kind()), Some(EventKind::Number));
    assert_eq!((reader.event_offset(), reader.offset()), (10, 11));
    assert_eq!(reader.next().unwrap(), Some(Event::EndArray));
    assert_eq!(reader.event_offset(), 12);
    assert_eq!(reader.next().unwrap(), Some(Event::EndObject));
    assert_eq!((reader.depth(), reader.next().unwrap()), (0, None));
    assert_eq!(reader.next().unwrap(), None);
}

// Zig's `peekNextTokenType` decides from one byte; `next` finds the rest.
#[test]
fn peek_decides_from_the_first_byte() {
    let mut reader = PullReader::new(br#"["a\q", nul, -x]"#);
    assert_eq!(reader.next().unwrap(), Some(Event::BeginArray));
    assert_eq!(reader.peek().unwrap(), Some(EventKind::String));
    assert_eq!(reader.next().unwrap_err().kind, ErrorKind::InvalidEscape);
    let mut reader = PullReader::new(b"[1 , nul]");
    reader.next().unwrap();
    reader.next().unwrap();
    assert_eq!(reader.peek().unwrap(), Some(EventKind::Null));
    assert_eq!(reader.next().unwrap_err().kind, ErrorKind::InvalidLiteral);
    let mut reader = PullReader::new(b"[1}");
    reader.next().unwrap();
    reader.next().unwrap();
    assert_eq!(reader.peek().unwrap(), Some(EventKind::EndObject));
    assert_eq!(reader.next().unwrap_err().kind, ErrorKind::ExpectedCommaOrBracket);
    let mut reader = PullReader::new(br#"{"a":1,"b":true}"#);
    reader.next().unwrap();
    assert_eq!(reader.peek().unwrap(), Some(EventKind::Key));
    reader.next().unwrap();
    assert_eq!(reader.peek().unwrap(), Some(EventKind::Number));
    reader.next().unwrap();
    assert_eq!(reader.peek().unwrap(), Some(EventKind::Key));
    reader.next().unwrap();
    assert_eq!(reader.peek().unwrap(), Some(EventKind::Bool));
    reader.next().unwrap();
    assert_eq!(reader.peek().unwrap(), Some(EventKind::EndObject));
    reader.next().unwrap();
    assert_eq!(reader.peek().unwrap(), None);
}

#[test]
fn skip_value_skips_whole_values_and_checks_them() {
    let input = br#"{"a":[1,{"b":"\u00e9"}],"c":"x","d":{}}"#;
    let mut reader = PullReader::new(input);
    assert!(reader.skip_value().unwrap());
    assert_eq!((reader.depth(), reader.next().unwrap()), (0, None));
    let mut reader = PullReader::new(input);
    reader.next().unwrap();
    assert!(!reader.skip_value().unwrap(), "a key is not a value");
    assert_eq!(reader.next().unwrap(), Some(Event::Key("a".into())));
    assert!(reader.skip_value().unwrap());
    assert_eq!(reader.next().unwrap(), Some(Event::Key("c".into())));
    assert!(reader.skip_value().unwrap());
    assert_eq!(reader.next().unwrap(), Some(Event::Key("d".into())));
    assert!(reader.skip_value().unwrap());
    assert!(!reader.skip_value().unwrap(), "a closing bracket is not a value");
    assert_eq!(reader.next().unwrap(), Some(Event::EndObject));
    assert!(!reader.skip_value().unwrap());
    let mut reader = PullReader::new(br#"[[1, "\x"], 2]"#);
    reader.next().unwrap();
    let skipped = reader.skip_value().unwrap_err();
    assert_eq!((skipped.kind, skipped.offset), (ErrorKind::InvalidEscape, 7));
}

#[test]
fn errors_are_sticky() {
    let mut reader = PullReader::new(b"[1 2]");
    reader.next().unwrap();
    reader.next().unwrap();
    let first = reader.next().unwrap_err();
    assert_eq!(first.kind, ErrorKind::ExpectedCommaOrBracket);
    assert_eq!(reader.next().unwrap_err(), first);
    assert_eq!(reader.peek().unwrap_err(), first);
    assert_eq!(reader.skip_value().unwrap_err(), first);
}

// The first problem in document order wins: invalid UTF-8 is found where it is, not before
// the document is read.
#[test]
fn problems_are_found_in_document_order() {
    let mut reader = PullReader::new(b"{\"bogus\": 1, \"x\": \"\xff\"}");
    reader.next().unwrap();
    assert_eq!(reader.next().unwrap(), Some(Event::Key("bogus".into())));
    assert_eq!(error(b"{\"a\" 1, \"\xff\"}"), (ErrorKind::ExpectedColon, 5));
    assert_eq!(error(b"[1, \xff]"), (ErrorKind::ExpectedValue, 4));
    assert_eq!(error(b"\"ok\xc3("), (ErrorKind::InvalidUtf8, 3));
    // A sequence cut short by the end of input is an early end, as in Zig.
    assert_eq!(error(b"\"ok\xe2\x82"), (ErrorKind::UnexpectedEnd, 5));
    assert_eq!(error(b"\"ok\xe2\x82\""), (ErrorKind::InvalidUtf8, 3));
}

// Offsets are where Zig 0.16's scanner stands when it fails.
#[test]
fn escape_errors_are_located_like_zig() {
    let cases: [(&[u8], ErrorKind, usize); 11] = [
        (br#""\x""#, ErrorKind::InvalidEscape, 2),
        (br#""\udc00""#, ErrorKind::LoneSurrogate, 7),
        (br#""\ud800x""#, ErrorKind::LoneSurrogate, 7),
        (br#""\ud800\n""#, ErrorKind::LoneSurrogate, 8),
        (br#""\ud800\u0041""#, ErrorKind::LoneSurrogate, 9),
        (br#""\ud800\ud800""#, ErrorKind::LoneSurrogate, 10),
        (br#""\ud800\uzc00""#, ErrorKind::InvalidEscape, 9),
        (br#""\ud800\udcz0""#, ErrorKind::InvalidEscape, 11),
        (b"\"\\ud800\\", ErrorKind::UnexpectedEnd, 8),
        (b"\"\\ud800\\ud8", ErrorKind::LoneSurrogate, 10),
        (b"\"\\ud800\\udc", ErrorKind::UnexpectedEnd, 11),
    ];
    for (input, kind, offset) in cases {
        assert_eq!(error(input), (kind, offset), "{:?}", String::from_utf8_lossy(input));
    }
}

#[test]
fn limits_are_checked_before_the_work() {
    let tight = Limits { max_values: 2, max_depth: 1, ..Limits::default() };
    let mut reader = PullReader::with_limits(b"[1, 2]", &tight);
    reader.next().unwrap();
    reader.next().unwrap();
    assert_eq!(reader.peek().unwrap_err().kind, ErrorKind::ValueLimit);
    let mut reader = PullReader::with_limits(b"[[]]", &tight);
    reader.next().unwrap();
    assert_eq!(reader.peek().unwrap(), Some(EventKind::BeginArray));
    assert_eq!(reader.next().unwrap_err().kind, ErrorKind::DepthLimit);
    let small = Limits { max_input_bytes: 2, ..Limits::default() };
    let mut reader = PullReader::with_limits(b"[1]", &small);
    assert_eq!(reader.peek().unwrap_err().kind, ErrorKind::InputTooLarge);
    let short = Limits { max_string_bytes: 2, ..Limits::default() };
    let mut reader = PullReader::with_limits(br#"["ab", "a\nb"]"#, &short);
    reader.next().unwrap();
    reader.next().unwrap();
    assert_eq!(reader.skip_value().unwrap_err().kind, ErrorKind::StringTooLong);
    let mut reader = PullReader::with_limits(b"[0]", &Limits::UNBOUNDED);
    assert!(reader.skip_value().unwrap());
}

#[test]
fn deep_input_does_not_recurse() {
    let input = "[".repeat(200_000);
    let mut reader = PullReader::with_limits(input.as_bytes(), &Limits::UNBOUNDED);
    assert_eq!(reader.skip_value().unwrap_err().kind, ErrorKind::UnexpectedEnd);
    assert_eq!(reader.depth(), 200_000);
}
