use super::*;

fn parse(args: &[&str]) -> Result<Config, ArgError> {
    Config::parse_args(args)
}

#[test]
fn config_defaults_and_arg_parsing() {
    let config = Config::default();
    assert_eq!(config.listen_port, 8080);
    assert_eq!(config.default_difficulty, 16);
    assert_eq!(config.algorithm, PowAlgorithm::Posw);
    assert!(!config.trusts_forwarded());

    let args = [
        "--port",
        "9090",
        "--upstream-port",
        "8000",
        "--difficulty",
        "18",
        "--mode",
        "forward_auth",
        "--policy-file",
        "/etc/sibuna/policy.json",
        "--algorithm",
        "hashcash",
        "--token-scheme",
        "ed25519",
        "--workers",
        "3",
        "--rate-limit",
        "20",
        "--idle-timeout",
        "7",
        "--max-connections",
        "500",
        "--rate-window",
        "5",
        "--challenge-rate-limit",
        "6",
        "--no-waf",
        "--secret-file",
        "/run/secret",
        "--data-dir",
        "/var/lib/sibuna",
        "--cluster-node",
        "2",
        "--verbose",
    ];
    let parsed = parse(&args).unwrap();
    assert_eq!(parsed.listen_port, 9090);
    assert_eq!(parsed.upstream_port, 8000);
    assert_eq!(parsed.default_difficulty, 18);
    assert_eq!(parsed.mode, Mode::ForwardAuth);
    assert!(parsed.trusts_forwarded());
    assert_eq!(parsed.policy_file.as_deref(), Some("/etc/sibuna/policy.json"));
    assert_eq!(parsed.algorithm, PowAlgorithm::Hashcash);
    assert_eq!(parsed.token_scheme, TokenScheme::Ed25519);
    assert_eq!(parsed.workers, 3);
    assert_eq!(parsed.rate_limit, 20);
    assert_eq!(parsed.idle_timeout_seconds, 7);
    assert_eq!(parsed.max_connections, 500);
    assert_eq!(parsed.rate_window_seconds, 5);
    assert_eq!(parsed.challenge_rate_limit, 6);
    assert!(!parsed.waf);
    assert_eq!(parsed.secret_file.as_deref(), Some("/run/secret"));
    assert_eq!(parsed.data_dir.as_deref(), Some("/var/lib/sibuna"));
    assert_eq!(parsed.cluster_node, Some(2));
    assert_eq!(parsed.node_id(), 2);
    assert_eq!(parsed.storage_backend(), StorageBackend::Sqlite);
    assert!(parsed.verbose);
}

#[test]
fn unknown_options_and_invalid_values_reject_the_command_line_and_name_the_fault() {
    use ArgErrorKind::*;
    // `at` indexes the argument the error must name.
    let cases: [(&[&str], ArgErrorKind, usize); 13] = [
        (&["--prot"], UnknownOption, 0),
        (&["--port"], MissingValue, 0),
        (&["--port", "70000"], InvalidValue, 0),
        (&["--port", "eighty"], InvalidValue, 0),
        (&["-d", "0"], InvalidValue, 0),
        (&["--algorithm", "md5"], InvalidValue, 0),
        (&["--workers", "65"], InvalidValue, 0),
        (&["--rate-limit", "0"], InvalidValue, 0),
        (&["--max-connections", "9000"], InvalidValue, 0),
        (&["--cookie-name", "a b"], InvalidValue, 0),
        (&["--verbose", "yes"], UnknownOption, 1),
        (&["--mode", "proxy", "-m", "auth"], DuplicateMode, 2),
        (&["--mode=proxy"], InvalidMode, 0),
    ];
    for (args, kind, at) in cases {
        let error = parse(args).unwrap_err();
        assert_eq!(error.kind, kind, "{args:?}");
        assert_eq!(error.option, args[at], "{args:?}");
    }
    let accepted = parse(&["--rate-limit", "100000000", "--workers", "0"]).unwrap();
    assert_eq!(accepted.rate_limit, 100_000_000);
}

#[test]
fn every_alias_and_flag_sets_its_field() {
    let parsed = parse(&[
        "-p",
        "1",
        "-h",
        "::1",
        "-u",
        "2",
        "-m",
        "auth",
        "-a",
        "SHA256",
        "-d",
        "64",
        "-s",
        "s",
        "-P",
        "p",
        "-D",
        "d",
        "-w",
        "64",
        "-v",
        "--gate",
        "--shield",
        "--secure-cookie",
        "--no-trust-forwarded",
        "--upstream-host",
        "origin",
        "--posw-challenges",
        "32",
        "--token-ttl",
        "31536000",
        "--challenge-ttl",
        "86400",
        "--cookie-name",
        "a!#$%&'*+-.^_`|~",
        "--websocket-idle-timeout",
        "0",
        "--ban-seconds",
        "0",
        "--storage-poll-ms",
        "60000",
    ])
    .unwrap();
    assert_eq!((parsed.listen_port, parsed.upstream_port), (1, 2));
    assert_eq!((parsed.listen_host.as_str(), parsed.upstream_host.as_str()), ("::1", "origin"));
    assert_eq!(parsed.mode, Mode::ForwardAuth);
    assert_eq!(parsed.algorithm, PowAlgorithm::Hashcash);
    assert_eq!(parsed.default_difficulty, 64);
    assert_eq!(parsed.secret_file.as_deref(), Some("s"));
    assert_eq!(parsed.policy_file.as_deref(), Some("p"));
    assert_eq!(parsed.data_dir.as_deref(), Some("d"));
    assert_eq!(parsed.workers, 64);
    assert!(parsed.verbose && parsed.waf && parsed.secure_cookie);
    assert_eq!(parsed.trust_forwarded, Some(false));
    assert!(!parsed.trusts_forwarded());
    assert_eq!(parsed.posw_challenges, 32);
    assert_eq!(parsed.token_ttl_seconds, 31_536_000);
    assert_eq!(parsed.challenge_ttl_seconds, 86_400);
    assert_eq!(parsed.cookie_name, "a!#$%&'*+-.^_`|~");
    assert_eq!(parsed.websocket_idle_timeout_seconds, 0);
    assert_eq!(parsed.ban_seconds, 0);
    assert_eq!(parsed.storage_poll_ms, 60_000);
    // Repeated options other than --mode keep the last value, as in Zig.
    assert_eq!(parse(&["-p", "1", "--port", "3"]).unwrap().listen_port, 3);
    assert_eq!(parse(&["--trust-forwarded"]).unwrap().trust_forwarded, Some(true));
}

#[test]
fn the_defaults_are_the_zig_defaults() {
    let config = Config::default();
    assert_eq!(
        (config.listen_host.as_str(), config.upstream_host.as_str()),
        ("0.0.0.0", "127.0.0.1")
    );
    assert_eq!((config.listen_port, config.upstream_port), (8080, 3000));
    assert_eq!(config.mode, Mode::ReverseProxy);
    assert_eq!((config.posw_challenges, config.token_scheme), (16, TokenScheme::Mac));
    assert_eq!((config.token_ttl_seconds, config.challenge_ttl_seconds), (86_400, 300));
    assert_eq!(config.cookie_name, "__sibuna_token");
    assert!(!config.secure_cookie && config.waf && !config.verbose);
    assert_eq!((config.workers, config.max_connections), (0, 1024));
    assert_eq!((config.idle_timeout_seconds, config.websocket_idle_timeout_seconds), (15, 300));
    assert_eq!((config.rate_limit, config.rate_window_seconds), (100, 10));
    assert_eq!((config.challenge_rate_limit, config.ban_seconds), (30, 3600));
    assert_eq!(config.console_query_steps, 4_000_000);
    assert!(!config.console_capture_heads && config.console_capture_headers.is_empty());
    assert_eq!(config.storage_poll_ms, 500);
    assert_eq!(config.cluster_node, None);
    assert_eq!(config.node_id(), 0);
    assert_eq!(config.storage_backend(), StorageBackend::InMemory);
    assert_eq!(parse(&[] as &[&str]).unwrap(), config);
}

#[test]
fn removed_cluster_options_fail_and_point_to_sid_0011() {
    for option in [
        "--cluster-listen",
        "--cluster-peer",
        "--cluster-secret-file",
        "--cluster-tls-cert",
        "--cluster-tls-key",
        "--cluster-tls-ca",
    ] {
        let error = parse(&["--cluster-node", "1", option, "x"]).unwrap_err();
        assert_eq!(error.kind, ArgErrorKind::RemovedOption);
        assert_eq!(error.option, option);
        assert!(error.kind.hint().contains("SID 0011"));
        assert!(error.kind.hint().contains("--database-url"));
        // Without a value too: the option itself is the fault.
        assert_eq!(parse(&[option]).unwrap_err().kind, ArgErrorKind::RemovedOption);
    }
}

#[test]
fn storage_options_follow_sid_0011() {
    let url = "postgres://sibuna:hunter2@db.example/sibuna";
    let cluster = parse(&["--database-url", url, "--cluster-node", "3"]).unwrap();
    assert_eq!(cluster.database_url.as_deref(), Some(url));
    assert_eq!(cluster.storage_backend(), StorageBackend::Postgres);
    let from_file = parse(&["--database-url-file", "/run/db", "--cluster-node", "2"]).unwrap();
    assert_eq!(from_file.database_url_file.as_deref(), Some("/run/db"));
    assert_eq!(from_file.storage_backend(), StorageBackend::Postgres);

    // Node 0 would share storage node 1; ids beyond the schema's bound are refused too.
    for id in ["0", "8388608"] {
        assert!(parse(&["--database-url", url, "--cluster-node", id]).is_err(), "{id}");
    }
    assert_eq!(parse(&["--cluster-node", "8388607"]).unwrap().node_id(), 8_388_607);
    let missing = parse(&["--database-url", url]).unwrap_err();
    assert_eq!(
        (missing.kind, missing.option.as_str()),
        (ArgErrorKind::MissingOption, "--database-url")
    );
    let missing = parse(&["--database-url-file", "/run/db"]).unwrap_err();
    assert_eq!(missing.option, "--database-url-file");
    let both = parse(&["--data-dir", "/d", "--database-url", url, "--cluster-node", "1"]);
    assert_eq!(both.unwrap_err().kind, ArgErrorKind::ConflictingOptions);
    let both = parse(&["--database-url", url, "--database-url-file", "/f", "--cluster-node", "1"]);
    let both = both.unwrap_err();
    assert_eq!(
        (both.kind, both.option.as_str()),
        (ArgErrorKind::ConflictingOptions, "--database-url-file")
    );
    // A single node may still name itself.
    assert_eq!(parse(&["-D", "/d", "--cluster-node", "9"]).unwrap().node_id(), 9);
}

#[test]
fn database_urls_never_appear_in_errors_debug_or_the_banner() {
    let secret = "postgres://sibuna:hunter2@db.example/sibuna";
    let rejected = parse(&["--database-url", "mysql://root:hunter2@db"]).unwrap_err();
    assert_eq!(rejected.kind, ArgErrorKind::InvalidValue);
    assert_eq!(rejected.value, "[redacted]");
    assert!(!rejected.to_string().contains("hunter2"));
    let config = Config {
        secret_seed: Some([7; 32]),
        ..parse(&["--database-url", secret, "--cluster-node", "1"]).unwrap()
    };
    let debug = format!("{config:?}");
    assert!(!debug.contains("hunter2") && !debug.contains("7, 7"));
    assert!(debug.contains("database_url: Some(\"[redacted]\")"));
    let mut banner = String::new();
    config.write_banner(&mut banner, "0.2.0").unwrap();
    assert!(!banner.contains("hunter2"));
}

#[test]
fn the_banner_shows_the_running_configuration() {
    let config = Config { secret_file: Some("env".to_owned()), ..Config::default() };
    let mut banner = String::new();
    config.write_banner(&mut banner, "0.2.0").unwrap();
    let rule = "-".repeat(80);
    let expected = format!(
        "{rule}\n  SIBUNA Web AI Firewall & Anti-Crawler Daemon v0.2.0\n  \
         \"Weighing incoming connections with silicon speed\"\n{rule}\n\
         Mode:        reverse_proxy\nListening:   0.0.0.0:8080\nUpstream:    127.0.0.1:3000\n\
         Proof:       posw at 16 work bits (mac tokens)\n\
         Surface:     shield (challenge + semantic WAF + limits)\nStorage:     in-memory only\n\
         Secret:      loaded from file\n{rule}\n"
    );
    assert_eq!(banner, expected);
}

#[test]
fn errors_render_the_invalid_command_line_report() {
    let error = parse(&["--port", "70000"]).unwrap_err();
    assert_eq!(
        error.to_string(),
        "-- INVALID COMMAND LINE ----------------------------------------------------\n\n\
         The daemon cannot start with this command line.\n\nOption:   --port\n\
         Value:    70000\nExpected: a port 1-65535\nError:    InvalidValue\n\n\n\
         Hint: Correct the value; see sibuna --help for each option's range.\n"
    );
    let removed = parse(&["--cluster-peer", "1@h:1"]).unwrap_err().to_string();
    assert!(removed.contains("Error:    RemovedOption\n"));
    assert!(
        removed.contains("Expected: --database-url <url> with --cluster-node <id> (SID 0011)")
    );
}

/// A deterministic xorshift64* generator, so every run fuzzes the same inputs.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}

const WORDS: [&str; 32] = [
    "--port",
    "-p",
    "--mode",
    "-m",
    "--mode=auth",
    "--verbose",
    "--gate",
    "--waf",
    "--cookie-name",
    "--database-url",
    "--database-url-file",
    "--data-dir",
    "--cluster-node",
    "--cluster-peer",
    "--max-connections",
    "--difficulty",
    "--algorithm",
    "--storage-poll-ms",
    "0",
    "1",
    "-0",
    "+8_080",
    "65535",
    "65536",
    "8192",
    "18446744073709551616",
    "posw",
    "auth",
    "postgres://db",
    "a b",
    "",
    "__sibuna_token",
];

/// Mutates a word: flips a bit of one byte (keeping it valid UTF-8 by staying ASCII),
/// truncates it, or doubles it.
fn mutate(rng: &mut Rng, word: &str) -> String {
    let mut bytes = word.as_bytes().to_vec();
    match rng.below(3) {
        0 if !bytes.is_empty() => {
            let at = rng.below(bytes.len());
            bytes[at] = (bytes[at] ^ (1 << rng.below(7))) & 0x7f;
        }
        1 if !bytes.is_empty() => bytes.truncate(rng.below(bytes.len())),
        _ => bytes.extend_from_slice(word.as_bytes()),
    }
    String::from_utf8(bytes).unwrap()
}

/// Every accepted configuration keeps every range check.
fn assert_in_range(config: &Config) {
    assert!(config.listen_port >= 1 && config.upstream_port >= 1);
    assert!((1..=64).contains(&config.default_difficulty));
    assert!((1..=32).contains(&config.posw_challenges));
    assert!(config.workers <= 64);
    assert!((1..=Config::MAX_CONNECTIONS_LIMIT).contains(&config.max_connections));
    assert!((1..=60_000).contains(&config.storage_poll_ms));
    assert!(!config.listen_host.is_empty() && config.listen_host.len() <= 4096);
    assert!((1..=64).contains(&config.cookie_name.len()));
    assert!(config.check_storage().is_ok());
}

#[test]
fn fuzz_command_lines_never_panic_and_name_a_given_option() {
    let mut rng = Rng(0x5eed_0003);
    for _ in 0..100_000 {
        let args: Vec<String> = (0..rng.below(8))
            .map(|_| {
                let word = WORDS[rng.below(WORDS.len())];
                if rng.below(4) == 0 { mutate(&mut rng, word) } else { word.to_owned() }
            })
            .collect();
        match Config::parse_args(&args) {
            Ok(config) => assert_in_range(&config),
            Err(error) => {
                let storage = error.option.starts_with("--database-url");
                assert!(args.contains(&error.option) || storage, "{args:?} {error:?}");
                assert!(error.to_string().starts_with("-- INVALID COMMAND LINE "));
            }
        }
    }
}
