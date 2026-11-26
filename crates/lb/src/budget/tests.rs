//! SID 0015 measures the cost and limits of admission separately from socket storage.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::pool::{Loads, Pool};
use crate::{Regime, config::MAX_FLOWS};

#[test]
#[ignore = "ten million simultaneous admission reservations, requires about 600 MiB"]
fn ten_million_live_reservations() {
    let mut nodes = Vec::new();
    let start = Instant::now();
    let vip = "127.0.0.1:8080".parse().unwrap();
    let document = br#"{"global":{"max_flows":1000000},"backends":{"app":{"mode":"tcp",
        "servers":["127.0.0.1:9000"]}},"frontends":{"web":{"proto":"tcp",
        "binds":["127.0.0.1:8080"],"default_backend":"app"}}}"#;
    for _ in 0..10 {
        let mut config = Config::parse(document).unwrap();
        let budget = FlowBudget::new(&config);
        let pool = Pool::new(config.pools.remove("app").unwrap(), &mut Loads::default());
        let mut live = Vec::with_capacity(MAX_FLOWS);
        for _ in 0..MAX_FLOWS {
            live.push((
                budget.reserve().unwrap(),
                pool.reserve(start, vip, vip, Regime::Standalone).unwrap(),
            ));
        }
        nodes.push((budget, pool, live));
    }
    assert_eq!(nodes.iter().map(|(budget, _, _)| budget.active()).sum::<usize>(), 10_000_000);
    for (budget, pool, _) in &nodes {
        let mut servers = Vec::new();
        pool.statuses("app", &mut servers);
        assert_eq!(servers[0].flows, MAX_FLOWS);
        assert!(budget.reserve().is_none());
        assert!(pool.reserve(start, vip, vip, Regime::Standalone).is_none());
    }
    eprintln!("held ten million node permits and backend tickets in {:?}", start.elapsed());
    for (budget, pool, live) in nodes {
        drop(live);
        assert_eq!(budget.active(), 0);
        let mut servers = Vec::new();
        pool.statuses("app", &mut servers);
        assert_eq!(servers[0].flows, 0);
        assert!(budget.reserve().is_some());
        assert!(pool.reserve(start, vip, vip, Regime::Standalone).is_some());
    }
}

#[test]
fn disabling_active_pressure_publishes_the_off_transition() {
    let document = br#"{"global":{"max_flows":1},"backends":{"app":{"mode":"tcp",
        "servers":["127.0.0.1:9000"]}},"frontends":{"web":{"proto":"tcp",
        "binds":["127.0.0.1:8080"],"default_backend":"app"}}}"#;
    let mut config = Config::parse(document).unwrap();
    let budget = FlowBudget::new(&config);
    let _live = budget.reserve().unwrap();
    assert_eq!(budget.update_pressure(), Some(true));
    config.pressure = None;
    budget.configure(&config);
    assert_eq!(budget.update_pressure(), Some(false));
    assert!(!budget.is_pressed());
    assert_eq!(budget.update_pressure(), None);
}
