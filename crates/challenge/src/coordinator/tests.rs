//! The Zig coordinator tests, ported, and tests of properties Rust makes checkable.

use sibuna_pow::posw::{self, Params, Workspace};

use super::*;
use crate::spec::{Requirement, required_work};
use crate::token::mac;

fn coordinator(spec: ChallengeSpec, token_scheme: TokenScheme) -> Coordinator {
    let options = Options {
        default_spec: spec,
        challenge_ttl: 600,
        token_ttl: 3600,
        token_scheme,
        ..Default::default()
    };
    Coordinator::new(&Seed::new([9; 32]), options)
}

fn hashcash(difficulty: u32) -> ChallengeSpec {
    ChallengeSpec { algorithm: Algorithm::Hashcash, difficulty, ..Default::default() }
}

#[test]
fn hashcash_challenge_issue_solve_verify_mint_replay_binding() {
    let coord = coordinator(hashcash(10), TokenScheme::Mac);
    let now = 1_700_000_000;
    let (ip, ua) = (&b"127.0.0.1"[..], &b"SibunaTestAgent/1.0"[..]);

    let ch = coord.create_challenge_with_spec(ip, ua, now, coord.default_spec(), 7);
    assert_eq!(ch.algorithm, Algorithm::Hashcash);
    assert_eq!(ch.difficulty, 10);
    assert_eq!(ch.challenges, 0);
    assert_eq!(ch.expires_at, now + 600);
    let id = ch.id.as_bytes();
    let nonce = hashcash::solve_bits(id, 10, 10_000_000).unwrap();

    // A neighbouring nonce may or may not meet the difficulty, but it must not panic, and if
    // it is refused it is refused for the difficulty.
    if let Err(error) = coord.verify_and_mint(id, Solution::Nonce(nonce + 1), ip, ua, now + 5) {
        assert_eq!(error, VerifyError::DifficultyNotMet);
    }
    assert_eq!(
        coord.verify_and_mint(id, Solution::Nonce(nonce), b"10.0.0.9", ua, now + 5),
        Err(VerifyError::FingerprintMismatch)
    );
    assert_eq!(
        coord.verify_and_mint(id, Solution::Proof(b""), ip, ua, now + 5),
        Err(VerifyError::WrongSolutionType)
    );
    let result = coord.verify_and_mint(id, Solution::Nonce(nonce), ip, ua, now + 5).unwrap();
    assert_eq!(result.token.as_str().len(), mac::TOKEN_LEN);
    assert_eq!(result.token.scheme(), TokenScheme::Mac);
    assert_eq!(
        (result.algorithm, result.difficulty, result.challenges),
        (Algorithm::Hashcash, 10, 0)
    );
    assert_eq!(result.ttl_seconds, 3600);
    let token = coord.verify_cookie(result.token.as_str().as_bytes(), ip, ua, now + 10).unwrap();
    assert_eq!(token.rule_hash, 7);
    assert_eq!(token.work, WorkLevel { algorithm: 0, bits: 10 });
    assert!(token.work.satisfies(required_work(Algorithm::Hashcash, 10)));
    assert!(!token.work.satisfies(required_work(Algorithm::Hashcash, 11)));
    assert!(!token.work.satisfies(required_work(Algorithm::Posw, 10)));
    assert_eq!(
        coord.verify_cookie(result.token.as_str().as_bytes(), b"1.2.3.4", ua, now + 10),
        Err(TokenError::TokenBoundAddressMismatch)
    );
    assert_eq!(
        coord.verify_and_mint(id, Solution::Nonce(nonce), ip, ua, now + 15),
        Err(VerifyError::DoubleSpendAttempt)
    );
    assert_eq!(
        coord.verify_and_mint(id, Solution::Nonce(nonce), ip, ua, now + 601),
        Err(VerifyError::ChallengeExpired)
    );

    let mut forged = *id;
    forged[5] = if forged[5] == b'A' { b'B' } else { b'A' };
    let forged_result = coord.verify_and_mint(&forged, Solution::Nonce(nonce), ip, ua, now + 5);
    assert!(matches!(
        forged_result,
        Err(VerifyError::InvalidChallengeTag | VerifyError::MalformedChallenge)
    ));
}

#[test]
fn requirement_tickets_carry_a_decision_to_its_client_only_within_the_lifetime() {
    let coord = coordinator(hashcash(8), TokenScheme::Mac);
    let now = 1_700_000_000;
    let (ip, ua) = (&b"203.0.113.9"[..], &b"Mozilla/5.0"[..]);
    let requirement = Requirement {
        spec: ChallengeSpec { algorithm: Algorithm::Posw, difficulty: 19, posw_challenges: 12 },
        rule_hash: 0xfeed,
    };
    let ticket = coord.requirement_ticket(requirement, ip, ua, now);
    assert_eq!(ticket.as_str().len(), 59);
    assert_eq!(coord.open_ticket(ticket.as_bytes(), ip, ua, now + 10), Some(requirement));
    // Another client, an expired ticket and a forged byte are all refused, never trusted.
    assert_eq!(coord.open_ticket(ticket.as_bytes(), b"203.0.113.10", ua, now), None);
    assert_eq!(coord.open_ticket(ticket.as_bytes(), ip, ua, now + 601), None);
    let mut forged = *ticket.as_bytes();
    forged[7] = if forged[7] == b'A' { b'B' } else { b'A' };
    assert_eq!(coord.open_ticket(&forged, ip, ua, now), None);
    assert_eq!(coord.open_ticket(&ticket.as_bytes()[..20], ip, ua, now), None);
}

#[test]
fn posw_challenge_round_trip_and_ed25519_token_scheme() {
    let spec = ChallengeSpec { algorithm: Algorithm::Posw, difficulty: 11, posw_challenges: 6 };
    let coord = coordinator(spec, TokenScheme::Ed25519);
    let now = 1_700_000_000;
    let (ip, ua) = (&b"203.0.113.5"[..], &b"Mozilla/5.0"[..]);

    let ch = coord.create_challenge_with_spec(ip, ua, now, coord.default_spec(), 1);
    assert_eq!(ch.algorithm, Algorithm::Posw);
    assert_eq!(ch.difficulty, 8);
    assert_eq!(ch.challenges, 6);

    let mut ws = Box::new(Workspace::new());
    let params = Params { depth: ch.difficulty, challenges: ch.challenges };
    let id = ch.id.as_bytes();
    let proof = posw::solve(id, params, &mut ws).unwrap();

    assert_eq!(
        coord.verify_and_mint(id, Solution::Nonce(1), ip, ua, now),
        Err(VerifyError::WrongSolutionType)
    );
    assert_eq!(
        coord.verify_and_mint(id, Solution::Proof(&proof[..proof.len() - 1]), ip, ua, now),
        Err(VerifyError::InvalidProof)
    );
    let result = coord.verify_and_mint(id, Solution::Proof(proof), ip, ua, now + 1).unwrap();
    assert_eq!(result.token.as_str().len(), ed25519::TOKEN_LEN);
    assert_eq!(result.token.scheme(), TokenScheme::Ed25519);
    let token = coord.verify_cookie(result.token.as_str().as_bytes(), ip, ua, now + 2).unwrap();
    assert_eq!(token.rule_hash, 1);
    // Depth 8 plus the offset: the level a route asking for 11 work bits requires.
    assert_eq!(token.work, WorkLevel { algorithm: 1, bits: 11 });
    assert!(token.work.satisfies(required_work(Algorithm::Posw, 11)));
    assert!(!token.work.satisfies(required_work(Algorithm::Posw, 12)));
    assert_eq!(
        coord.verify_and_mint(id, Solution::Proof(proof), ip, ua, now + 3),
        Err(VerifyError::DoubleSpendAttempt)
    );
}

#[test]
fn cheap_checks_run_in_order_before_the_proof() {
    let coord = coordinator(hashcash(20), TokenScheme::Mac);
    let now = 1_000_000;
    let (ip, ua) = (&b"198.51.100.1"[..], &b"agent"[..]);
    let id = coord.create_challenge(ip, ua, now).id;
    let id = id.as_bytes();
    // Expired and from another client: expiry is reported first.
    assert_eq!(
        coord.verify_and_mint(id, Solution::Nonce(0), b"other", ua, now + 601),
        Err(VerifyError::ChallengeExpired)
    );
    // Issued more than a minute in the future (a clock running ahead).
    assert_eq!(
        coord.verify_and_mint(id, Solution::Nonce(0), ip, ua, now - 61),
        Err(VerifyError::ChallengeExpired)
    );
    // Sixty seconds of skew are tolerated, and the last second of the lifetime counts.
    for at in [now - 60, now + 600] {
        let refused = coord.verify_and_mint(id, Solution::Proof(b""), ip, ua, at);
        assert_eq!(refused, Err(VerifyError::WrongSolutionType));
    }
    assert_eq!(
        coord.verify_and_mint(b"short", Solution::Nonce(0), ip, ua, now),
        Err(VerifyError::MalformedChallenge)
    );
    // A wrong proof does not consume the challenge: the right one is still accepted later.
    let nonce = (0..).find(|&n| !hashcash::verify_bits(id, n, 20)).unwrap();
    assert_eq!(
        coord.verify_and_mint(id, Solution::Nonce(nonce), ip, ua, now),
        Err(VerifyError::DifficultyNotMet)
    );
}

#[test]
fn identifiers_from_another_node_or_seed_are_refused() {
    let seed = Seed::new([0x42; 32]);
    let node = |id| Options { node: NonZeroU32::new(id), ..Default::default() };
    let one = Coordinator::new(&seed, node(1));
    let two = Coordinator::new(&seed, node(2));
    let unbound = Coordinator::new(&seed, Options::default());
    let other_seed = Coordinator::new(&Seed::new([0x43; 32]), node(1));
    let (ip, ua, now) = (&b"192.0.2.1"[..], &b"ua"[..], 5_000);
    let ch = one.create_challenge(ip, ua, now);
    for verifier in [&two, &unbound, &other_seed] {
        assert_eq!(
            verifier.verify_and_mint(ch.id.as_bytes(), Solution::Nonce(0), ip, ua, now),
            Err(VerifyError::InvalidChallengeTag)
        );
    }
    // Tickets and tokens are not node-bound: any member sharing the seed honours them.
    let requirement = Requirement { spec: hashcash(12), rule_hash: 3 };
    let ticket = one.requirement_ticket(requirement, ip, ua, now);
    assert_eq!(two.open_ticket(ticket.as_bytes(), ip, ua, now), Some(requirement));
    assert_eq!(other_seed.open_ticket(ticket.as_bytes(), ip, ua, now), None);
    let nonce = hashcash::solve_bits(ch.id.as_bytes(), 16, 1 << 32).unwrap();
    let minted = one.verify_and_mint(ch.id.as_bytes(), Solution::Nonce(nonce), ip, ua, now);
    let cookie = minted.unwrap().token;
    assert!(two.verify_cookie(cookie.as_str().as_bytes(), ip, ua, now).is_ok());
    assert!(other_seed.verify_cookie(cookie.as_str().as_bytes(), ip, ua, now).is_err());
}

#[test]
fn tickets_refuse_out_of_range_fields_and_saturate_difficulty() {
    let coord = coordinator(hashcash(8), TokenScheme::Mac);
    let (ip, ua, now) = (&b"192.0.2.7"[..], &b"ua"[..], 10_000);
    let big = Requirement { spec: hashcash(300), rule_hash: 1 };
    let opened =
        coord.open_ticket(coord.requirement_ticket(big, ip, ua, now).as_bytes(), ip, ua, now);
    assert_eq!(opened.map(|r| r.spec.difficulty), Some(255));
    for posw_challenges in [0, 33] {
        let spec = ChallengeSpec { posw_challenges, ..hashcash(8) };
        let ticket = coord.requirement_ticket(Requirement { spec, rule_hash: 1 }, ip, ua, now);
        assert_eq!(coord.open_ticket(ticket.as_bytes(), ip, ua, now), None);
    }
    // Skew: up to a minute ahead is accepted, more is not.
    let ticket =
        coord.requirement_ticket(Requirement { spec: hashcash(8), rule_hash: 1 }, ip, ua, now);
    assert!(coord.open_ticket(ticket.as_bytes(), ip, ua, now - 60).is_some());
    assert_eq!(coord.open_ticket(ticket.as_bytes(), ip, ua, now - 61), None);
    assert!(coord.open_ticket(ticket.as_bytes(), ip, ua, now + 600).is_some());
}

#[test]
fn concurrent_submissions_of_one_solution_mint_exactly_once() {
    let coord = coordinator(hashcash(8), TokenScheme::Mac);
    let (ip, ua, now) = (&b"192.0.2.9"[..], &b"ua"[..], 20_000);
    let ch = coord.create_challenge(ip, ua, now);
    let nonce = hashcash::solve_bits(ch.id.as_bytes(), 8, 1 << 32).unwrap();
    let results: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    coord.verify_and_mint(ch.id.as_bytes(), Solution::Nonce(nonce), ip, ua, now)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(
        results.iter().filter(|r| r.is_err()).all(|r| *r == Err(VerifyError::DoubleSpendAttempt))
    );
}

#[test]
fn identifiers_are_unique_and_debug_hides_secrets() {
    let coord = coordinator(hashcash(8), TokenScheme::Mac);
    let a = coord.create_challenge(b"ip", b"ua", 1);
    let b = coord.create_challenge(b"ip", b"ua", 1);
    assert_ne!(a.id, b.id);
    let text = format!("{coord:?}");
    assert!(text.starts_with("Coordinator {"));
    assert!(!text.contains("keys"));
    let nonce = hashcash::solve_bits(a.id.as_bytes(), 8, 1 << 32).unwrap();
    let token = coord
        .verify_and_mint(a.id.as_bytes(), Solution::Nonce(nonce), b"ip", b"ua", 1)
        .unwrap()
        .token;
    assert_eq!(format!("{token:?}"), "SessionToken(Mac, <75 characters>)");
}

#[test]
fn verify_errors_map_to_explanations_name_for_name() {
    let all = [
        VerifyError::MalformedChallenge,
        VerifyError::InvalidChallengeTag,
        VerifyError::ChallengeExpired,
        VerifyError::FingerprintMismatch,
        VerifyError::DifficultyNotMet,
        VerifyError::InvalidProof,
        VerifyError::WrongSolutionType,
        VerifyError::DoubleSpendAttempt,
        VerifyError::StoreFull,
    ];
    for error in all {
        let kind = ErrorKind::from(error);
        assert_eq!(kind.name(), format!("{error:?}"));
        assert_ne!(kind, ErrorKind::Unexpected);
    }
}

#[test]
fn the_adaptive_bump_raises_issued_difficulty() {
    let options = Options {
        default_spec: hashcash(10),
        adaptive: AdaptiveConfig { baseline_per_second: 10, max_bump: 3, alpha_256: 256 },
        ..Default::default()
    };
    let coord = Coordinator::new(&Seed::new([1; 32]), options);
    for _ in 0..100 {
        assert_eq!(coord.create_challenge(b"ip", b"ua", 50).difficulty, 10);
    }
    // 100/s over a 10/s baseline: ceil(log2(11)) = 4 bits, capped at 3.
    assert_eq!(coord.create_challenge(b"ip", b"ua", 51).difficulty, 13);
    assert_eq!(coord.adaptive().bump(), 3);
    // The route's requirement ignores the bump, so the stronger token still satisfies it.
    assert!(
        WorkLevel { algorithm: 0, bits: 13 }.satisfies(required_work(Algorithm::Hashcash, 10))
    );
}
