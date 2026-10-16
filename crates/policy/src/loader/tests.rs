use super::*;
use crate::RequestView;
use crate::limits::Limits;

#[test]
fn loader_parses_json_policy_into_engine_rules() {
    let json = br#"{
      "default_action": "ALLOW",
      "rules": [
        { "name": "block-bad-worker", "headers": { "CF-Worker": ".*" }, "action": "DENY" },
        {
          "name": "protect-checkout",
          "path": "/api/checkout/*",
          "action": "CHALLENGE",
          "challenge": { "difficulty": 8, "algorithm": "sha256" }
        },
        { "name": "suspicious", "user_agent": "Headless", "action": "WEIGH", "weight": 12 }
      ],
      "waf": false,
      "thresholds": { "deny_at": 30 },
      "ip_rules": { "2001:db8::/32": "DENY" }
    }"#;
    let engine = Engine::load_json(json, 4).unwrap();
    let rules = engine.rules();
    assert_eq!(rules.len(), 3);
    assert_eq!(rules[2].weight, 12);
    assert_eq!(engine.thresholds.deny_at, 30);
    assert!(!engine.waf_enabled);
    assert_eq!(engine.reputation(b"2001:db8::1"), Some(Action::Deny));
    assert_eq!(
        (rules[0].name.as_str(), rules[0].action, rules[0].headers.len()),
        ("block-bad-worker", Action::Deny, 1)
    );
    assert_eq!((rules[1].name.as_str(), rules[1].action), ("protect-checkout", Action::Challenge));
    assert_eq!((rules[1].difficulty, rules[1].algorithm), (Some(8), Some(Algorithm::Hashcash)));
}

#[test]
fn file_quotas_compile_stable_scopes_and_reject_nonterminal_or_incomplete_settings() {
    let input = b"{\"rules\":[{\"name\":\"Checkout\",\"path\":\"/checkout\",\"action\":\"CHALLENG\
        E\",\"limits\":{\"rate\":2,\"window_seconds\":60}}]}";
    let first = Engine::load_json(input, 8).unwrap();
    let second = Engine::load_json(input, 8).unwrap();
    assert_eq!(first.rules()[0].limit_scope, second.rules()[0].limit_scope);
    let decision = first.evaluate(&RequestView::new(b"/checkout", b"8.8.8.8", b""));
    assert_eq!(decision.limits.map(|l| l.rate), Some(2));
    assert_eq!(decision.limit_scope, first.rules()[0].limit_scope);
    let weigh = b"{\"rules\":[{\"name\":\"Weight\",\"action\":\"WEIGH\",\"weight\":1,\"limits\":\
        {\"rate\":2,\"window_seconds\":60}}]}";
    assert_eq!(Engine::load_json(weigh, 8).unwrap_err(), LoadError::InvalidRuleLimit);
    let partial = br#"{"rules":[{"name":"Partial","action":"ALLOW","limits":{"rate":2}}]}"#;
    assert_eq!(Engine::load_json(partial, 8).unwrap_err().name(), "MissingField");
}

/// A rejected file leaves nothing behind: the engine a caller discards was never
/// published, and the diagnostic names the rule and field so the operator can repair it.
#[test]
fn invalid_values_reject_the_file_instead_of_widening_or_defaulting_a_rule() {
    let cases: [(&[u8], &str, &str); 12] = [
        (b"{\"rules\":[{\"name\":\"office\",\"action\":\"ALLOW\",\"cidrs\":[\"10.0.0.0/8\",\"not-\
            a-network\"]}]}", "InvalidCidr", "cidrs"),
        (br#"{"rules":[{"name":"block","action":"DNEY","path":"/"}]}"#, "InvalidAction", "action"),
        (br#"{"rules":[{"name":"block","path":"/"}]}"#, "MissingAction", "action"),
        (br#"{"rules":[{"name":"typo","actoin":"DENY","path":"/"}]}"#, "UnknownField", ""),
        (br#"{"default_action":"WEIGH"}"#, "InvalidAction", "default_action"),
        (br#"{"ip_rules":{"10.0.0.0/33":"DENY"}}"#, "InvalidIpRule", "ip_rules"),
        (br#"{"thresholds":{"challenge_at":50,"deny_at":10}}"#, "InvalidThreshold", "thresholds"),
        (b"{\"rules\":[{\"name\":\"c\",\"action\":\"CHALLENGE\",\"challenge\":{\"difficulty\":99}\
            }]}", "InvalidChallenge", "challenge.difficulty"),
        (b"{\"rules\":[{\"name\":\"c\",\"action\":\"DENY\",\"challenge\":{\"algorithm\":\"posw\"}\
            }]}", "InvalidChallenge", "challenge"),
        (br#"{"rules":[{"name":"w","action":"WEIGH"}]}"#, "InvalidWeight", "weight"),
        (b"{\"rules\":[{\"name\":\"h\",\"action\":\"DENY\",\"headers\":{\"CF-Worker\":1}}]}", "In\
            validHeader", "headers"),
        (b"[]", "UnexpectedToken", ""),
    ];
    for (text, error, field) in cases {
        let mut engine = Engine::new(8);
        let mut diagnostic = Diagnostic::default();
        let result = engine.apply_json(text, &mut diagnostic);
        assert_eq!(result.unwrap_err().name(), error, "{}", String::from_utf8_lossy(text));
        assert_eq!(diagnostic.field, field);
        assert!(!result.unwrap_err().explain().title.is_empty());
    }
    // The same rule with a readable address list admits only that network.
    let file = b"{\"rules\":[{\"name\":\"office\",\"action\":\"ALLOW\",\"cidrs\":[\"10.0.0.0/8\"]\
        }],\"default_action\":\"DENY\"}";
    let engine = Engine::load_json(file, 8).unwrap();
    assert_eq!(
        engine.evaluate(&RequestView::new(b"/", b"10.1.2.3", b"curl")).action,
        Action::Allow
    );
    assert_eq!(engine.evaluate(&RequestView::new(b"/", b"8.8.8.8", b"curl")).action, Action::Deny);
}

#[test]
fn diagnostics_name_rule_field_and_value() {
    let mut engine = Engine::new(8);
    let mut diagnostic = Diagnostic::default();
    let text = br#"{"rules":[{"name":"r1","action":"ALLOW","path":""}]}"#;
    assert_eq!(engine.apply_json(text, &mut diagnostic), Err(LoadError::InvalidPattern));
    assert_eq!(
        (diagnostic.rule.as_str(), diagnostic.field, diagnostic.value.as_str()),
        ("r1", "path", "")
    );
    let text = br#"{"ip_rules":{"10.0.0.0/8":"WEIGH"}}"#;
    assert_eq!(engine.apply_json(text, &mut diagnostic), Err(LoadError::InvalidIpRule));
    assert_eq!((diagnostic.field, diagnostic.value.as_str()), ("ip_rules", "10.0.0.0/8"));
    let text =
        br#"{"rules":[{"name":"x","action":"CHALLENGE","challenge":{"algorithm":"argon"}}]}"#;
    assert_eq!(engine.apply_json(text, &mut diagnostic), Err(LoadError::InvalidChallenge));
    assert_eq!((diagnostic.field, diagnostic.value.as_str()), ("challenge.algorithm", "argon"));
    let text = br#"{"waf": true, "rules": [ {"name": "x", "action": 5} ]}"#;
    let error = engine.apply_json(text, &mut diagnostic).unwrap_err();
    assert_eq!((error.name(), diagnostic.offset.is_some()), ("UnexpectedToken", true));
    assert_eq!(engine.apply_json(b"{}", &mut diagnostic), Ok(()));
    assert_eq!(diagnostic, Diagnostic::default());
}

#[test]
fn first_error_in_document_order_decides_the_explanation() {
    let unknown_then_broken = br#"{"bogus": 1, "rules": [ }"#;
    let error = Engine::load_json(unknown_then_broken, 8).unwrap_err();
    assert_eq!(error.explain().title, "UNKNOWN POLICY FIELD");
    let broken_then_unknown = br#"{"waf": tru, "bogus": 1}"#;
    let error = Engine::load_json(broken_then_unknown, 8).unwrap_err();
    assert_eq!((error.name(), error.explain().title), ("SyntaxError", "INVALID POLICY FILE"));
}

#[test]
fn zig_typed_parse_quirks_are_kept() {
    let strings_as_numbers = b"{\"thresholds\":{\"deny_at\":\"30\",\"challenge_at\":1e1},\"inspec\
        tion\":{\"sqli\":1,\"xss\":\"disabled\"}}";
    let engine = Engine::load_json(strings_as_numbers, 8).unwrap();
    assert_eq!((engine.thresholds.deny_at, engine.thresholds.challenge_at), (30, 10));
    assert_eq!(engine.inspection_modes.sqli, crate::inspection::Mode::Audit);
    let bytes_as_array = br#"{"rules":[{"name":[104,105],"action":"allow"}]}"#;
    assert_eq!(Engine::load_json(bytes_as_array, 8).unwrap().rules()[0].name, "hi");
    let duplicate_ip = br#"{"ip_rules":{"10.0.0.0/8":"DENY","10.0.0.0/8":"ALLOW"}}"#;
    assert_eq!(Engine::load_json(duplicate_ip, 8).unwrap_err().name(), "DuplicateField");
    let both_cidr_spellings =
        br#"{"rules":[{"name":"x","action":"allow","cidrs":[],"remote_addresses":["1.2.3.4"]}]}"#;
    assert_eq!(Engine::load_json(both_cidr_spellings, 8).unwrap_err(), LoadError::InvalidCidr);
    let null_headers =
        br#"{"rules":[{"name":"x","action":"allow","headers":null,"headers_regex":{"A":"b"}}]}"#;
    assert_eq!(Engine::load_json(null_headers, 8).unwrap().rules()[0].headers.len(), 1);
    let trailing = br#"{} {}"#;
    assert_eq!(Engine::load_json(trailing, 8).unwrap_err().name(), "SyntaxError");
    let empty_rules = br#"{"rules":[]}"#;
    assert_eq!(Engine::load_json(empty_rules, 8).unwrap().rule_count(), 0);
    let limits = b"{\"rules\":[{\"name\":\"x\",\"action\":\"deny\",\"limits\":{\"rate\":1,\"windo\
        w_seconds\":1,\"ban_seconds\":86400}}]}";
    let expected = Limits { rate: 1, window_seconds: 1, ban_seconds: 86_400 };
    assert_eq!(Engine::load_json(limits, 8).unwrap().rules()[0].limits, Some(expected));
}

#[test]
fn every_error_has_an_explanation() {
    let errors = [
        LoadError::InvalidAction,
        LoadError::MissingAction,
        LoadError::InvalidRuleName,
        LoadError::InvalidPattern,
        LoadError::InvalidHeader,
        LoadError::TooManyHeaders,
        LoadError::InvalidCidr,
        LoadError::TooManyCidrs,
        LoadError::InvalidChallenge,
        LoadError::InvalidWeight,
        LoadError::InvalidThreshold,
        LoadError::InvalidIpRule,
        LoadError::InvalidRuleLimit,
        LoadError::TooManyRules,
        LoadError::TrieFull,
        LoadError::InvalidJa4,
    ];
    for error in errors {
        assert_ne!(explain(error), GENERIC, "{error}");
    }
    let syntax = LoadError::Json(JsonError { kind: ErrorKind::SyntaxError, offset: 0 });
    assert_eq!(explain(syntax), GENERIC);
}

/// A `ja4` criterion (SID 0014) is a fingerprint or a prefix and `*`; a pattern no
/// fingerprint could match rejects the file and names the rule, the field and the value.
#[test]
fn ja4_patterns_compile_or_reject_the_file() {
    let json = br#"{"rules":[
        {"name":"old-tls","ja4":"t12*","action":"DENY"},
        {"name":"one","ja4":"t13d1516h2_8daaf6152771_02713d6af862","action":"ALLOW"}
    ]}"#;
    let engine = Engine::load_json(json, 8).unwrap();
    let rules = engine.rules();
    assert_eq!(rules[0].ja4.as_ref().map(ToString::to_string).as_deref(), Some("t12*"));
    let old = crate::ja4::Fingerprint::parse(b"t12d1207h1_c866b44c5a26_b5b8b9a1b1e2");
    let view = RequestView { ja4: old, ..RequestView::new(b"/", b"192.0.2.1", b"") };
    assert_eq!(engine.evaluate(&view).rule_name, "old-tls");
    let mut diagnostic = Diagnostic::default();
    let bad = br#"{"rules":[{"name":"typo","ja4":"T13D*","action":"DENY"}]}"#;
    let error = Engine::new(8).apply_json(bad, &mut diagnostic).unwrap_err();
    assert_eq!(error, LoadError::InvalidJa4);
    assert_eq!((diagnostic.rule.as_str(), diagnostic.field), ("typo", "ja4"));
    assert_eq!(diagnostic.value, "T13D*");
}
