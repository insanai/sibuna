use super::*;
use crate::waf::AttackCategory;

fn view<'a>(path: &'a [u8], ip: &'a [u8], ua: &'a [u8]) -> RequestView<'a> {
    RequestView::new(path, ip, ua)
}

#[test]
fn engine_evaluates_declarative_rules_bypass_ip_and_bot_user_agents() {
    let mut engine = Engine::new(16);
    let d1 = engine.evaluate(&view(b"/robots.txt", b"1.2.3.4", b"GPTBot"));
    assert_eq!(d1.action, Action::Allow);
    let d_amz = engine.evaluate(&view(b"/index.html", b"1.2.3.4", b"Mozilla/5.0 Amazonbot/0.1"));
    assert_eq!((d_amz.action, d_amz.rule_name), (Action::Deny, "amazonbot"));
    let headers = [Header { name: b"CF-Worker", value: b"worker-1" }];
    let request = RequestView { headers: &headers, ..view(b"/api/data", b"1.2.3.4", b"curl") };
    let d_cf = engine.evaluate(&request);
    assert_eq!((d_cf.action, d_cf.rule_name), (Action::Deny, "cloudflare-workers"));
    let d2 = engine.evaluate(&view(b"/api/data", b"1.2.3.4", b"Python-Requests/2.28"));
    assert_eq!(
        (d2.action, d2.rule_name, d2.difficulty),
        (Action::Challenge, "python-requests", 16)
    );
    // Browsers and unknown clients both pay the default challenge; only explicit rules,
    // bypass paths, or reputation entries admit for free.
    let ua = b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    let d3 = engine.evaluate(&view(b"/index.html", b"192.168.1.1", ua));
    assert_eq!((d3.action, d3.rule_name), (Action::Challenge, "generic-browser"));
    let d4 = engine.evaluate(&view(b"/index.html", b"192.168.1.1", b""));
    assert_eq!((d4.action, d4.rule_name), (Action::Challenge, "default/challenge"));
    engine.insert_reputation(b"192.168.0.0/16", Action::Allow).unwrap();
    assert_eq!(engine.evaluate(&view(b"/index.html", b"192.168.1.1", b"")).action, Action::Allow);
    engine.insert_reputation(b"2001:db8::/32", Action::Deny).unwrap();
    let d6 = engine.evaluate(&view(b"/index.html", b"2001:db8::7", ua));
    assert_eq!((d6.action, d6.rule_name), (Action::Deny, "ip/cidr-trie"));
}

#[test]
fn weigh_rules_accumulate_into_allow_challenge_with_extra_bits_or_deny() {
    let mut engine = Engine::new(16);
    engine.clear_rules();
    let weigh = |name: &str, weight, ua: Option<&str>, path: Option<&str>| PolicyRule {
        weight,
        ua_pattern: ua.map(str::to_owned),
        path_pattern: path.map(str::to_owned),
        ..PolicyRule::new(name, Action::Weigh)
    };
    engine.add_rule(weigh("no-accept-language", 10, Some("Mozilla"), None)).unwrap();
    engine.add_rule(weigh("old-chrome", 15, Some("Chrome/7"), None)).unwrap();
    engine.add_rule(weigh("known-good", -20, None, Some("/trusted/*"))).unwrap();
    engine.add_rule(weigh("very-bad", 30, Some("Headless"), None)).unwrap();
    let mild = engine.evaluate(&view(b"/", b"1.1.1.1", b"Mozilla/5.0"));
    assert_eq!((mild.action, mild.difficulty, mild.score), (Action::Challenge, 16, 10));
    let harder = engine.evaluate(&view(b"/", b"1.1.1.1", b"Mozilla/5.0 Chrome/79"));
    assert_eq!((harder.action, harder.difficulty), (Action::Challenge, 19));
    let vouched = engine.evaluate(&view(b"/trusted/x", b"1.1.1.1", b"Mozilla/5.0"));
    assert_eq!((vouched.action, vouched.score), (Action::Allow, -10));
    let denied = engine.evaluate(&view(b"/", b"1.1.1.1", b"Mozilla/5.0 HeadlessChrome/79"));
    assert_eq!((denied.action, denied.score), (Action::Deny, 55));
}

#[test]
fn hot_path_policy_classification_loop() {
    let engine = Engine::new(16);
    let uas: [&[u8]; 5] = [
        b"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        b"GPTBot/1.2 (+https://openai.com/gptbot)",
        b"ClaudeBot/1.0",
        b"Python-Requests/2.28.1",
        b"curl/7.88.1",
    ];
    let mut challenged = 0;
    for i in 0..100_000 {
        let decision =
            engine.evaluate(&view(b"/api/v1/resource", b"192.168.1.50", uas[i % uas.len()]));
        challenged += usize::from(decision.action == Action::Challenge);
    }
    assert_eq!(challenged, 100_000);
}

#[test]
fn engine_blocks_safeline_waf_attack_vectors_and_can_disable_the_waf() {
    let mut engine = Engine::new(16);
    let request = RequestView {
        query: b"id=1%20union%20select%20null",
        ..view(b"/api/users", b"1.2.3.4", b"curl")
    };
    let d_sqli = engine.evaluate(&request);
    assert_eq!((d_sqli.action, d_sqli.rule_name), (Action::Deny, "waf:sqli"));
    let d_lfi = engine.evaluate(&view(b"/static/../../etc/passwd", b"1.2.3.4", b"Mozilla"));
    assert_eq!((d_lfi.action, d_lfi.rule_name), (Action::Deny, "waf:path-traversal"));
    let headers = [Header { name: b"X-Query", value: b"<script>alert(1)</script>" }];
    let request = RequestView { headers: &headers, ..view(b"/search", b"1.2.3.4", b"Mozilla") };
    assert_eq!(engine.evaluate(&request).rule_name, "waf:xss");
    let request =
        RequestView { body: b"cmd=test; /bin/sh", ..view(b"/submit", b"1.2.3.4", b"Mozilla") };
    let d_rce = engine.evaluate(&request);
    assert_eq!((d_rce.action, d_rce.rule_name), (Action::Deny, "waf:rce"));
    engine.waf_enabled = false;
    let gate_only = engine.evaluate(&view(b"/static/../../etc/passwd", b"1.2.3.4", b"Mozilla"));
    assert_eq!(gate_only.action, Action::Challenge);
}

#[test]
fn observed_evaluation_records_weigh_and_terminal_matches_without_changing_decisions() {
    let mut engine = Engine::new(16);
    engine.clear_rules();
    engine.add_rule(PolicyRule { weight: 7, ..PolicyRule::new("score", Action::Weigh) }).unwrap();
    engine
        .add_rule(PolicyRule {
            path_pattern: Some("/public".into()),
            ..PolicyRule::new("allow", Action::Allow)
        })
        .unwrap();
    engine.add_rule(PolicyRule::new("deny", Action::Deny)).unwrap();
    engine
        .add_rule(PolicyRule { weight: 99, ..PolicyRule::new("unreached", Action::Weigh) })
        .unwrap();
    let mut matches = RuleMatches::new();
    for index in 0..MAX_RULES {
        matches.set(index);
    }
    for (index, path) in [&b"/public"[..], b"/private"].into_iter().enumerate() {
        let request = view(path, b"8.8.8.8", b"");
        let decision = engine.evaluate_with_matches(&request, &mut matches);
        assert_eq!(engine.evaluate(&request), decision);
        assert_eq!(matches.count(), 2);
        assert!(matches.is_set(0) && matches.is_set(index + 1));
    }
    engine.insert_reputation(b"8.8.8.8/32", Action::Deny).unwrap();
    let early = view(b"/public", b"8.8.8.8", b"");
    assert_eq!(engine.evaluate(&early), engine.evaluate_with_matches(&early, &mut matches));
    assert_eq!(matches.count(), 0);
    let attack =
        RequestView { query: b"q=<script>alert(1)</script>", ..view(b"/public", b"1.1.1.1", b"") };
    assert_eq!(engine.evaluate(&attack), engine.evaluate_with_matches(&attack, &mut matches));
    assert_eq!(matches.count(), 0);
}

#[test]
fn rules_are_validated_and_scoped_when_added() {
    let mut engine = Engine::new(16);
    engine.clear_rules();
    assert_eq!(
        engine.add_rule(PolicyRule::new("", Action::Allow)),
        Err(RuleError::InvalidRuleName)
    );
    assert_eq!(
        engine.add_rule(PolicyRule::new("a\nb", Action::Allow)),
        Err(RuleError::InvalidRuleName)
    );
    assert_eq!(
        engine.add_rule(PolicyRule::new(&"x".repeat(129), Action::Allow)),
        Err(RuleError::InvalidRuleName)
    );
    let quota = Limits { rate: 2, window_seconds: 60, ban_seconds: 0 };
    let limits = Some(quota);
    let weigh = PolicyRule { limits, ..PolicyRule::new("w", Action::Weigh) };
    assert_eq!(engine.add_rule(weigh), Err(RuleError::InvalidRuleLimit));
    engine
        .add_rule(PolicyRule { limits, ..PolicyRule::new("Checkout", Action::Challenge) })
        .unwrap();
    let expected = quota.scope(file_identity(b"Checkout", 0));
    assert_eq!(engine.rules()[0].limit_scope, expected);
    for index in 1..MAX_RULES {
        engine.add_rule(PolicyRule::new(&format!("r{index}"), Action::Deny)).unwrap();
    }
    assert_eq!(
        engine.add_rule(PolicyRule::new("full", Action::Deny)),
        Err(RuleError::TooManyRules)
    );
    let decision = engine.evaluate(&view(b"/", b"8.8.8.8", b""));
    assert_eq!((decision.limits, decision.limit_scope), (limits, expected));
}

#[test]
fn mixed_modes_report_audited_bits_on_admitted_requests() {
    let mut engine = Engine::new(16);
    engine.inspection_modes.sqli = inspection::Mode::Audit;
    engine.inspection_modes.xss = inspection::Mode::Disabled;
    let request =
        RequestView { query: b"union select <script>", ..view(b"/robots.txt", b"8.8.8.8", b"") };
    let decision = engine.evaluate(&request);
    assert_eq!(decision.action, Action::Allow);
    assert_eq!(decision.audited, inspection::bit(AttackCategory::Sqli));
}

#[test]
fn extreme_weights_and_difficulties_saturate() {
    let mut engine = Engine::new(u32::MAX - 1);
    engine.clear_rules();
    engine.thresholds = WeighThresholds {
        challenge_at: -1000,
        deny_at: i32::MAX,
        bits_step: 1,
        max_extra_bits: 6,
    };
    for name in ["a", "b"] {
        engine
            .add_rule(PolicyRule { weight: i32::MAX, ..PolicyRule::new(name, Action::Weigh) })
            .unwrap();
    }
    let decision = engine.evaluate(&view(b"/", b"1.1.1.1", b""));
    assert_eq!((decision.action, decision.score), (Action::Deny, i32::MAX));
    engine.thresholds.deny_at = i32::MAX;
    engine.rules.clear();
    engine.compiled.clear();
    engine
        .add_rule(PolicyRule { weight: i32::MAX - 1, ..PolicyRule::new("c", Action::Weigh) })
        .unwrap();
    let decision = engine.evaluate(&view(b"/", b"1.1.1.1", b""));
    assert_eq!((decision.action, decision.difficulty), (Action::Challenge, u32::MAX));
}

#[test]
fn default_deny_keeps_the_zig_rule_name() {
    let mut engine = Engine::new(16);
    engine.clear_rules();
    engine.default_action = Action::Deny;
    let decision = engine.evaluate(&view(b"/", b"1.1.1.1", b"x"));
    assert_eq!(
        (decision.action, decision.rule_name, decision.difficulty),
        (Action::Deny, "default/challenge", 0)
    );
    engine.default_action = Action::Allow;
    assert_eq!(engine.evaluate(&view(b"/", b"1.1.1.1", b"x")).rule_name, "default/allow");
}

#[test]
fn compiled_rules_agree_with_direct_rule_matching() {
    let engine = Engine::new(16);
    let headers = [Header { name: b"cf-worker", value: b"" }];
    let samples = [
        view(b"/.well-known/x", b"1.1.1.1", b""),
        view(b"/favicon.ico", b"::1", b"Amazonbot"),
        RequestView { headers: &headers, ..view(b"/x", b"bogus", b"mozilla") },
        view(b"/__sibuna/a", b"", b"MOZILLA"),
    ];
    for request in samples {
        let address = sibuna_cidr::parse_ip(request.client_ip).ok();
        for (rule, compiled) in engine.rules.iter().zip(&engine.compiled) {
            let direct =
                rule.matches(request.path, request.client_ip, request.user_agent, request.headers);
            assert_eq!(compiled.matches(&request, address), direct, "{}", rule.name);
        }
    }
}

/// The parsed address decides reputation and CIDR rules: every spelling of one address
/// gets one decision, and a view that carries the address is not re-read from its text.
#[test]
fn the_parsed_client_address_decides_reputation_and_cidr_rules() {
    let mut engine = Engine::new(16);
    engine.clear_rules();
    let cidr = sibuna_cidr::parse_cidr(b"1.2.3.0/24").unwrap();
    engine
        .add_rule(PolicyRule { cidrs: vec![cidr], ..PolicyRule::new("net", Action::Deny) })
        .unwrap();
    engine.insert_reputation(b"5.6.7.8/32", Action::Deny).unwrap();
    for spelling in [&b"1.2.3.4"[..], b"::ffff:1.2.3.4", b"001.2.3.4", b"::FFFF:1.2.3.4"] {
        let decision = engine.evaluate(&view(b"/", spelling, b"x"));
        assert_eq!((decision.action, decision.rule_name), (Action::Deny, "net"), "{spelling:?}");
    }
    for spelling in [&b"5.6.7.8"[..], b"::ffff:5.6.7.8"] {
        assert_eq!(engine.evaluate(&view(b"/", spelling, b"x")).rule_name, "ip/cidr-trie");
    }
    // The carried address wins over the text, which then serves only logs.
    let carried = RequestView {
        client_address: Some([1, 2, 3, 9].into()),
        ..view(b"/", b"203.0.113.1", b"x")
    };
    assert_eq!(engine.evaluate(&carried).rule_name, "net");
    // A view built field by field without the address is judged by its text.
    let fields = RequestView { path: b"/", client_ip: b"1.2.3.4", ..RequestView::default() };
    assert_eq!(fields.address(), Some([1, 2, 3, 4].into()));
    assert_eq!(engine.evaluate(&fields).rule_name, "net");
    let unparsed = view(b"/", b"not an address", b"x");
    assert_eq!(unparsed.address(), None);
    assert_ne!(engine.evaluate(&unparsed).action, Action::Deny);
}

#[test]
fn reputation_node_count_covers_every_entry() {
    let mut engine = Engine::new(16);
    let empty = engine.reputation_node_count();
    // The root and the IPv4-mapped path exist before any entry.
    assert!(empty > 1);
    engine.insert_reputation(b"192.0.2.0/24", Action::Deny).unwrap();
    let one = engine.reputation_node_count();
    assert_eq!(one, empty + 24);
    // A replaced entry adds no node; a sibling prefix adds only its own branch.
    engine.insert_reputation(b"192.0.2.0/24", Action::Allow).unwrap();
    assert_eq!(engine.reputation_node_count(), one);
    engine.insert_reputation(b"192.0.3.0/24", Action::Deny).unwrap();
    assert_eq!(engine.reputation_node_count(), one + 1);
    engine.clear_reputation();
    assert_eq!(engine.reputation_node_count(), empty);
}
