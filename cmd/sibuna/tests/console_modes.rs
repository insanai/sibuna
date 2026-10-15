//! The console in both data-plane modes (the Zig e2e script `console_modes_test.py`): the
//! query-step option is refused outside its bounds with `CONSOLE002`; in reverse-proxy and
//! forward-auth mode the statistics report the mode, the admitted requests and the origin
//! failures the mode can observe, a restart begins a new boot, and the `stats` topic
//! carries the mode.
#![cfg(feature = "console")]
#![allow(clippy::unwrap_used)]

mod support;

use std::process::Command;

use sibuna_console_protocol::subscriptions::Topic;
use sibuna_core::{Config, Mode};
use support::console::{
    Node, PASSWORD, Stream, console_config, data_plane, field, field_of, init_admin, number,
    scratch,
};
use support::{BROWSER_UA, get};

/// An explicit policy that admits everything, so the origin's answers reach the counters.
const POLICY: &str = "{\"default_action\":\"ALLOW\",\"waf\":true,\"rules\":[]}";

#[test]
fn query_steps_outside_their_bounds_are_refused() {
    let invalid: [&[&str]; 6] = [
        &["99999"],
        &["50000001"],
        &["4M"],
        &["-1"],
        &[],
        &["100000", "--console-query-steps", "200000"],
    ];
    for options in invalid {
        let output = Command::new(env!("CARGO_BIN_EXE_sibuna"))
            .args(["--console", "127.0.0.1:9443", "--console-query-steps"])
            .args(options)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{options:?}: {stderr}");
        assert!(stderr.contains("CONSOLE002") && stderr.contains("Hint:"), "{stderr}");
    }
}

#[test]
fn both_modes_report_their_origin_coverage() {
    let dir = scratch("modes");
    let base = data_plane(&dir);
    let temporary = init_admin(&base);
    let steps = sibuna_console::Config { query_steps: 8_000_000, ..console_config() };
    let mut previous_boot = String::new();
    let mut temporary = Some(temporary);
    for mode in [Mode::ReverseProxy, Mode::ForwardAuth] {
        let config = Config { mode, ..base.clone() };
        let mut node = Node::start(config, steps.clone(), Some(POLICY));
        let console = node.console();
        let session = match temporary.take() {
            Some(temporary) => console.change_password(&temporary),
            None => console.login("admin", PASSWORD),
        };
        let port = node.port();
        let failed = get(port, "/origin-error", "203.0.113.40", BROWSER_UA, "");
        let reverse = mode == Mode::ReverseProxy;
        assert_eq!(failed.status(), if reverse { 500 } else { 200 }, "{}", failed.text());
        if !reverse {
            let extra = "X-Original-URI: /__sibuna/health\r\n";
            let allowed = get(port, "/auth", "203.0.113.41", BROWSER_UA, extra);
            assert_eq!(allowed.status(), 200);
            assert_eq!(allowed.body_text(), "OK");
        }
        let name = if reverse { "reverse_proxy" } else { "forward_auth" };
        let stats = console.stats(&session);
        assert_eq!(field(&stats, "proxy_mode"), name);
        assert_eq!(number(&stats, "admitted"), if reverse { 1 } else { 2 });
        assert_eq!(number(&stats, "origin_5xx"), u64::from(reverse));
        assert_ne!(field(&stats, "boot"), previous_boot);
        previous_boot = field(&stats, "boot");
        let mut stream = Stream::open(&console, &session);
        stream.subscribe("stats", "{}");
        let view = stream.until(Topic::Stats, 10, |_| true);
        assert_eq!(field_of(view.as_bytes(), "proxy_mode"), name);
        node.stop();
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
