use super::*;

fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|word| (*word).to_owned()).collect()
}

#[test]
fn tokens_percent_decode_once_split_and_lowercase() {
    assert_eq!(tokens(b"/etc/passwd"), words(&["etc", "passwd"]));
    assert_eq!(tokens(b"q=1%27%20UNION%20SELECT"), words(&["q", "1", "union", "select"]));
    // Decoded once: `%2541` is `%41`, which is not decoded again.
    assert_eq!(tokens(b"%2541"), words(&["41"]));
    assert_eq!(tokens(b"100%zz%4"), words(&["100", "zz", "4"]));
    assert_eq!(
        tokens("Caf\u{e9} \u{c9}LAN_x-y".as_bytes()),
        words(&["caf\u{e9}", "\u{e9}lan", "x", "y"])
    );
    // Invalid UTF-8 becomes U+FFFD, which separates tokens.
    assert_eq!(tokens(b"ab\xffcd"), words(&["ab", "cd"]));
    assert_eq!(tokens(b"%00admin%ff"), words(&["admin"]));
    assert!(tokens(b"--/..;'\"").is_empty());
    // Non-ASCII letters and digits are token characters; symbols are not.
    assert_eq!(
        tokens("\u{43c}\u{438}\u{440}\u{20ac}\u{661}".as_bytes()),
        words(&["\u{43c}\u{438}\u{440}", "\u{661}"])
    );
}

#[test]
fn long_tokens_split_at_character_boundaries() {
    let long = "a".repeat(130);
    assert_eq!(tokens(long.as_bytes()), words(&[&"a".repeat(64), &"a".repeat(64), "aa"]));
    // 40 two-byte letters are 80 bytes: 32 letters fit in 64 bytes.
    let wide = "\u{e9}".repeat(40);
    let pieces = tokens(wide.as_bytes());
    assert_eq!(pieces, words(&[&"\u{e9}".repeat(32), &"\u{e9}".repeat(8)]));
    let mixed = format!("{}\u{e9}", "a".repeat(63));
    assert_eq!(tokens(mixed.as_bytes()), words(&[&"a".repeat(63), "\u{e9}"]));
}

#[test]
fn the_index_keeps_128_tokens_per_field() {
    let field = "x ".repeat(200);
    assert_eq!(index_tokens(field.as_bytes()).len(), MAX_FIELD_TOKENS);
    assert_eq!(tokens(field.as_bytes()).len(), 200);
}

#[test]
fn tsvector_literals_weigh_path_and_payload() {
    let path = words(&["etc", "passwd"]);
    let payload = words(&["cat", "etc"]);
    assert_eq!(tsvector_literal(&path, &payload), "'cat':3B 'etc':1A,4B 'passwd':2A");
    assert_eq!(tsvector_literal(&[], &[]), "");
    assert_eq!(fts_text(&path), "etc passwd");
}

fn parse(text: &str) -> Query {
    Query::parse(text).expect("valid").expect("not empty")
}

fn problem(text: &str) -> (SearchProblem, usize) {
    let error = Query::parse(text).expect_err(text);
    (error.problem, error.offset)
}

#[test]
fn queries_parse_into_groups_of_terms() {
    assert_eq!(Query::parse("").unwrap(), None);
    assert_eq!(Query::parse("   ").unwrap(), None);
    let query = parse("union select OR path:/etc/passwd payload:\"<script>alert\"");
    assert_eq!(query.groups.len(), 2);
    assert_eq!(
        query.groups[0],
        [
            Term { field: None, tokens: words(&["union"]) },
            Term { field: None, tokens: words(&["select"]) },
        ]
    );
    assert_eq!(
        query.groups[1],
        [
            Term { field: Some(Field::Path), tokens: words(&["etc", "passwd"]) },
            Term { field: Some(Field::Payload), tokens: words(&["script", "alert"]) },
        ]
    );
    // `or` in lower case and a quoted `OR` are words.
    assert_eq!(parse("a or b").groups.len(), 1);
    assert_eq!(parse("\"OR\"").groups[0][0].tokens, words(&["or"]));
    // A prefix with nothing after it is an ordinary word; an unknown prefix too.
    assert_eq!(parse("path:").groups[0][0], Term { field: None, tokens: words(&["path"]) });
    assert_eq!(parse("host:x").groups[0][0].tokens, words(&["host", "x"]));
    assert_eq!(parse("payload:path:x").groups[0][0].field, Some(Field::Payload));
    assert_eq!(parse("  a   OR   b  ").groups.len(), 2);
    assert_eq!(parse("ORx").groups[0][0].tokens, words(&["orx"]));
}

#[test]
fn invalid_queries_name_the_offset() {
    assert_eq!(problem("a -- b"), (SearchProblem::NoSearchableCharacters, 2));
    assert_eq!(problem("path:--"), (SearchProblem::NoSearchableCharacters, 5));
    assert_eq!(problem("OR a"), (SearchProblem::MisplacedOr, 0));
    assert_eq!(problem("a OR"), (SearchProblem::MisplacedOr, 4));
    assert_eq!(problem("a OR OR b"), (SearchProblem::MisplacedOr, 5));
    assert_eq!(problem("a \"b c"), (SearchProblem::UnterminatedPhrase, 2));
    assert_eq!(problem("\"\""), (SearchProblem::EmptyPhrase, 0));
    assert_eq!(problem("ab\"c"), (SearchProblem::QuoteInWord, 2));
    assert_eq!(problem("\"a\"b"), (SearchProblem::NoSpaceAfterPhrase, 3));
    assert_eq!(problem(&"a ".repeat(17)), (SearchProblem::TooManyTerms, 32));
    assert_eq!(
        problem("a OR ".repeat(9).trim_end_matches(" OR ")).0,
        SearchProblem::TooManyGroups
    );
    assert_eq!(problem("a-b-c-d-e-f-g-h-i").0, SearchProblem::TooManyTokens);
    assert_eq!(problem(&"a".repeat(257)), (SearchProblem::TooLong, 256));
    // The bounds themselves are allowed.
    assert_eq!(parse(&"a ".repeat(16)).groups[0].len(), 16);
    assert_eq!(parse("a-b-c-d-e-f-g-h").groups[0][0].tokens.len(), 8);
    assert_eq!(parse("a OR ".repeat(8).trim_end_matches(" OR ")).groups.len(), 8);
    assert!(Query::parse(&"a".repeat(256)).is_ok());
}

#[test]
fn diagnostics_are_elm_style() {
    let error = Query::parse("path:-- foo").unwrap_err();
    let text = error.to_string();
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines[0].starts_with("-- INVALID SEARCH --") && lines[0].ends_with(" search:1:6"));
    assert_eq!(lines[0].len(), 88);
    assert_eq!(lines[2], "This term has no searchable characters.");
    assert_eq!(lines[4], "1| path:-- foo");
    assert_eq!(lines[5], "        ^^");
    assert_eq!(lines[6], "Hint: Add letters or digits, or remove the term.");
    let error = Query::parse("\u{e9}\u{e9} \"x").unwrap_err();
    assert_eq!(error.to_string().lines().nth(5), Some("      ^"));
}

#[test]
fn translations_follow_the_record() {
    let query = parse("etc OR /etc/passwd path:admin payload:\"union select\"");
    assert_eq!(
        query.to_fts5(),
        "(\"etc\") OR (\"etc passwd\" AND path : \"admin\" AND \
         offending_payload : \"union select\")"
    );
    assert_eq!(
        query.to_tsquery(),
        "('etc') | ((('etc':A <-> 'passwd':A) | ('etc':B <-> 'passwd':B)) & 'admin':A & \
         ('union':B <-> 'select':B))"
    );
    assert_eq!(query.expression(Dialect::Sqlite), query.to_fts5());
    assert_eq!(query.expression(Dialect::Postgres), query.to_tsquery());
}

/// A small xorshift generator, so the fuzz test is deterministic and dependency-free.
struct Xorshift(u64);

impl Xorshift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound.max(1)).unwrap()).unwrap()
    }
}

fn mutate(rng: &mut Xorshift, seeds: &[&str], out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(seeds[rng.below(seeds.len())].as_bytes());
    for _ in 0..rng.below(4) {
        match rng.below(6) {
            0 if !out.is_empty() => {
                let at = rng.below(out.len());
                out[at] ^= 1 << rng.below(8);
            }
            1 => out.truncate(rng.below(out.len() + 1)),
            2 => {
                let copy = out.clone();
                out.extend_from_slice(&copy);
            }
            3 => out.extend_from_slice(seeds[rng.below(seeds.len())].as_bytes()),
            4 => {
                let at = rng.below(out.len() + 1);
                let piece = b" \"%:OR"[rng.below(6)];
                out.insert(at, piece);
            }
            _ => out.extend((0..rng.below(40)).map(|_| rng.next() as u8)),
        }
    }
}

fn check_token(token: &str) {
    assert!(!token.is_empty() && token.len() <= MAX_TOKEN_BYTES, "{token:?}");
    assert!(
        token
            .bytes()
            .all(|byte| !byte.is_ascii() || byte.is_ascii_digit() || byte.is_ascii_lowercase()),
        "{token:?}"
    );
}

/// Every input either parses within the bounds or fails with an offset inside the query;
/// tokens are non-empty, short, and hold no ASCII punctuation, space or upper case, so they
/// can be quoted in both dialects.
#[test]
fn fuzz_tokens_and_queries() {
    let seeds = [
        "union select",
        "path:/etc/passwd OR payload:\"<script>\"",
        "a OR b c OR \"d e f\"",
        "UNION%20SELECT%27 %zz \u{c9}t\u{e9}",
        "\u{130}stanbul \u{212a}elvin",
        "\"unterminated",
        "",
    ];
    let mut rng = Xorshift(0x5eed_0013_5eac_0001);
    let mut buffer = Vec::new();
    for _ in 0..100_000 {
        mutate(&mut rng, &seeds, &mut buffer);
        for token in tokens(&buffer) {
            check_token(&token);
        }
        let text = String::from_utf8_lossy(&buffer);
        match Query::parse(&text) {
            Ok(None) => assert!(text.bytes().all(|byte| byte == b' ')),
            Ok(Some(query)) => {
                assert!((1..=MAX_GROUPS).contains(&query.groups.len()));
                let terms: usize = query.groups.iter().map(Vec::len).sum();
                assert!((1..=MAX_TERMS).contains(&terms));
                for term in query.groups.iter().flatten() {
                    assert!((1..=MAX_TERM_TOKENS).contains(&term.tokens.len()));
                    term.tokens.iter().for_each(|token| check_token(token));
                }
                assert!(!query.to_tsquery().contains('\\'));
            }
            Err(error) => {
                assert!(error.offset <= text.len() && error.length >= 1);
                assert!(!error.to_string().is_empty());
            }
        }
    }
}
