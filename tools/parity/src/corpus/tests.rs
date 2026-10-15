use std::collections::HashSet;

use super::*;
use crate::configs;

fn corpus(seed: u64, requests: usize) -> Vec<Case> {
    generate(seed, requests, &configs::all())
}

#[test]
fn a_seed_names_one_corpus() {
    let first = corpus(11, 2000);
    let second = corpus(11, 2000);
    let other = corpus(12, 2000);
    let bytes = |cases: &[Case]| -> Vec<Vec<Vec<Vec<u8>>>> {
        cases.iter().map(|case| case.connections.clone()).collect()
    };
    assert_eq!(bytes(&first), bytes(&second));
    assert_ne!(bytes(&first), bytes(&other));
}

#[test]
fn the_corpus_reaches_its_size_and_covers_everything() {
    let configs = configs::all();
    let cases = generate(3, 6000, &configs);
    let total: usize = cases.iter().map(Case::request_count).sum();
    assert!(total >= 6000);
    // The last scenario is the one that crossed the size.
    assert!(total - cases.last().unwrap().request_count() < 6000);
    let categories: HashSet<Category> = cases.iter().map(|case| case.category).collect();
    assert_eq!(categories.len(), Category::WEIGHTS.len());
    let used: HashSet<usize> = cases.iter().map(|case| case.config).collect();
    assert_eq!(used.len(), configs.len());
    assert!(cases.iter().all(|case| case.connections.iter().all(|c| !c.is_empty())));
    assert!(cases.iter().enumerate().all(|(index, case)| case.id == index));
}

#[test]
fn every_scenario_has_its_own_addresses() {
    let mut sources = HashSet::new();
    for index in 0..200_000 {
        let address = source_address(index);
        let octets = address.octets();
        assert_eq!(octets[0], 127);
        assert_ne!(octets[1], 0, "{address}");
        assert!(octets[3] != 0 && octets[3] != 255, "{address}");
        assert!(sources.insert(address), "{address} repeats");
    }
    let fragments = Fragments::load();
    let config = &configs::all()[0];
    let mut rng = Rng::new(1);
    let mut clients = HashSet::new();
    for index in 0..100_000 {
        let scene = Scene { rng: &mut rng, fragments: &fragments, config, index };
        assert!(clients.insert((scene.client(), scene.other_client(), scene.client_v6())));
    }
}

#[test]
fn placeholders_occur_only_in_challenge_scenarios() {
    for case in corpus(5, 8000) {
        let templated = case.connections.iter().flatten().any(|request| has_placeholder(request));
        if templated {
            assert_eq!(case.category, Category::Challenge, "{}", case.label);
        }
    }
}

#[test]
fn requests_start_with_a_request_line_or_a_deliberate_fault() {
    for case in corpus(9, 4000) {
        for request in case.connections.iter().flatten() {
            let line_end = request.windows(2).position(|w| w == b"\r\n").unwrap_or(request.len());
            let line = &request[..line_end];
            let well_formed = line.ends_with(b" HTTP/1.1") || line.ends_with(b" HTTP/1.0");
            assert!(
                well_formed || matches!(case.category, Category::Method),
                "{}: {:?}",
                case.label,
                String::from_utf8_lossy(line)
            );
        }
    }
}

#[test]
fn forward_authorization_moves_the_target_into_metadata() {
    let configs = configs::all();
    let auth = configs.iter().find(|config| config.mode == Mode::ForwardAuth).unwrap();
    let fragments = Fragments::load();
    let mut rng = Rng::new(4);
    let mut described = 0;
    for index in 0..200 {
        let mut scene = Scene { rng: &mut rng, fragments: &fragments, config: auth, index };
        let request =
            scene.adapt(Request::new("POST", "/orig?x=1").body(Body::Length(b"x".to_vec())));
        if request.target != b"/orig?x=1" {
            described += 1;
            assert_eq!(request.method, "GET");
            assert_eq!(request.body, Body::Empty);
            assert!(request.headers.iter().any(|(_, value)| value == b"/orig?x=1"));
        }
    }
    assert!(described > 100 && described < 200, "{described}");
}
