//! The daemon configurations a run compares: every combination of mode (reverse proxy or
//! forward authorization), surface (gate or shield), policy (none or the sample policy)
//! and forwarded-header trust, plus one configuration for a documented deliberate change.

use std::path::Path;

/// The sample policy of the policy crate's differential test: IP rules, header, path and
/// User-Agent rules, quotas, weights and per-rule challenges.
pub const SAMPLE_POLICY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/policy/tests/data/differential/policy.json"
));

/// A policy whose only rule is `0.0.0.0/0`: the Rust trie matches it, the Zig trie ignored
/// it (SID 0003, revision of 2026-10-15). It shows that the allow-list works.
pub const ANY_IPV4_POLICY: &str = r#"{"ip_rules":{"0.0.0.0/0":"DENY"}}"#;

/// How the daemon answers admitted requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Streams admitted requests to the origin.
    ReverseProxy,
    /// Answers an ingress's authorization subrequests.
    ForwardAuth,
}

/// Which protections run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Surface {
    /// Bot challenge only (`--gate`).
    Gate,
    /// Bot challenge and the semantic WAF (`--shield`).
    Shield,
}

/// The policy file the daemons load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// No policy file: the built-in defaults.
    None,
    /// [`SAMPLE_POLICY`].
    Sample,
    /// [`ANY_IPV4_POLICY`].
    AnyIpv4,
}

/// The default proof of work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Work {
    /// Hashcash at 8 bits.
    Hashcash,
    /// PoSW at depth 9 with 4 openings.
    Posw,
}

/// One configuration both daemons run with.
#[derive(Clone, Debug)]
pub struct Config {
    /// A short unique name, used in reports and allow-list entries.
    pub name: String,
    /// The `--mode`.
    pub mode: Mode,
    /// `--gate` or `--shield`.
    pub surface: Surface,
    /// The `--policy-file`, if any.
    pub policy: Policy,
    /// Whether `--trust-forwarded` is given (`trust` in the name, else `direct`). Forward
    /// authorization trusts forwarded headers without the flag, so there `direct` only
    /// means that the flag is absent; the client sockets are still bound per scenario.
    pub trust: bool,
    /// The default proof of work.
    pub work: Work,
    /// Relative share of the corpus this configuration receives.
    pub weight: u32,
}

/// Requests per window per client (`--rate-limit`).
pub const RATE_LIMIT: usize = 40;
/// Challenge issues and verifications per window per client (`--challenge-rate-limit`).
pub const CHALLENGE_BUDGET: usize = 30;
/// The session cookie name (the default).
pub const COOKIE_NAME: &str = "__sibuna_token";

/// Returns the configurations of a run, in a fixed order.
pub fn all() -> Vec<Config> {
    let mut configs = Vec::new();
    for mode in [Mode::ReverseProxy, Mode::ForwardAuth] {
        for surface in [Surface::Shield, Surface::Gate] {
            for policy in [Policy::None, Policy::Sample] {
                for trust in [true, false] {
                    let work = if configs.len() % 2 == 0 { Work::Hashcash } else { Work::Posw };
                    configs.push(Config {
                        name: String::new(),
                        mode,
                        surface,
                        policy,
                        trust,
                        work,
                        weight: 6,
                    });
                }
            }
        }
    }
    configs.push(Config {
        name: String::new(),
        mode: Mode::ReverseProxy,
        surface: Surface::Shield,
        policy: Policy::AnyIpv4,
        trust: false,
        work: Work::Hashcash,
        weight: 1,
    });
    for config in &mut configs {
        config.name = config.describe();
    }
    configs
}

impl Config {
    /// The name that lists the configuration's choices, such as
    /// `proxy-shield-sample-trust-hashcash`.
    fn describe(&self) -> String {
        let mode = match self.mode {
            Mode::ReverseProxy => "proxy",
            Mode::ForwardAuth => "auth",
        };
        let surface = match self.surface {
            Surface::Gate => "gate",
            Surface::Shield => "shield",
        };
        let policy = match self.policy {
            Policy::None => "default",
            Policy::Sample => "sample",
            Policy::AnyIpv4 => "any-ipv4",
        };
        let trust = if self.trust { "trust" } else { "direct" };
        let work = match self.work {
            Work::Hashcash => "hashcash",
            Work::Posw => "posw",
        };
        format!("{mode}-{surface}-{policy}-{trust}-{work}")
    }

    /// The policy text this configuration loads, if any.
    pub fn policy_text(&self) -> Option<&'static str> {
        match self.policy {
            Policy::None => None,
            Policy::Sample => Some(SAMPLE_POLICY),
            Policy::AnyIpv4 => Some(ANY_IPV4_POLICY),
        }
    }

    /// The command-line arguments of a daemon listening on `port` in front of the origin
    /// at `origin_port`, with the master seed in `secret` and the policy at `policy`.
    pub fn arguments(
        &self,
        port: u16,
        origin_port: u16,
        secret: &Path,
        policy: Option<&Path>,
    ) -> Vec<String> {
        let mut args: Vec<String> = [
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--upstream-port",
            &origin_port.to_string(),
            "--workers",
            "2",
            "--rate-limit",
            &RATE_LIMIT.to_string(),
            "--rate-window",
            "10",
            "--challenge-rate-limit",
            &CHALLENGE_BUDGET.to_string(),
            "--ban-seconds",
            "60",
        ]
        .iter()
        .map(|text| (*text).to_owned())
        .collect();
        args.push("--secret-file".into());
        args.push(secret.display().to_string());
        let mode = match self.mode {
            Mode::ReverseProxy => "reverse_proxy",
            Mode::ForwardAuth => "forward_auth",
        };
        args.extend(["--mode".to_owned(), mode.to_owned()]);
        args.push(match self.surface {
            Surface::Gate => "--gate".into(),
            Surface::Shield => "--shield".into(),
        });
        if self.trust {
            args.push("--trust-forwarded".into());
        }
        match self.work {
            Work::Hashcash => args.extend(["-a", "hashcash", "-d", "8"].map(String::from)),
            Work::Posw => {
                args.extend(["-a", "posw", "-d", "9", "--posw-challenges", "4"].map(String::from))
            }
        }
        if !self.trust {
            // Signed tokens on the untrusted half, MAC tokens on the other.
            args.extend(["--token-scheme", "ed25519"].map(String::from));
        }
        if self.policy == Policy::Sample {
            args.push("--secure-cookie".into());
        }
        if let Some(policy) = policy {
            args.push("--policy-file".into());
            args.push(policy.display().to_string());
        }
        args
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configurations_cover_the_grid_once() {
        let configs = all();
        assert_eq!(configs.len(), 17);
        let mut names: Vec<&str> = configs.iter().map(|config| config.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 17);
        assert!(configs.iter().any(|c| c.mode == Mode::ForwardAuth && !c.trust));
        assert!(configs.iter().any(|c| c.work == Work::Posw && c.policy == Policy::Sample));
    }

    #[test]
    fn arguments_carry_the_choices() {
        let config = &all()[0];
        let args = config.arguments(1, 2, Path::new("/s"), None);
        let text = args.join(" ");
        assert!(text.contains("--mode reverse_proxy --shield --trust-forwarded"), "{text}");
        assert!(text.contains("-a hashcash -d 8"));
        assert!(!text.contains("--policy-file"));
        assert_eq!(config.name, "proxy-shield-default-trust-hashcash");
    }

    #[test]
    fn the_sample_policy_is_embedded() {
        assert!(SAMPLE_POLICY.contains("protect-checkout"));
    }
}
