//! The descriptor limit against what a topology can use (SID 0020).
//!
//! A flow uses two descriptors: one to the client and one to the server. At startup we
//! raise the soft limit towards the need when the hard limit allows it, and warn when the
//! process still cannot open what the topology asks for.

use std::fmt::Write as _;

use sibuna_reactor::DescriptorLimit;

/// Descriptors beside the flows. The reserve holds what has a fixed bound: at most 128
/// listeners, the idle server connections of the thread-per-connection path, the one
/// socket of the mesh, and the files and pollers of the threads.
const RESERVE: u64 = 512;

// The fixed bounds must fit, with room for the files and pollers.
const _: () = assert!(sibuna_net::Pool::CAPACITY as u64 + 128 + 1 + 64 <= RESERVE);

/// The sizes of a topology that decide its descriptor use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Demand {
    /// `global.max_flows`.
    pub max_flows: u64,
    /// `http.max_connections`, or `None` without an HTTP frontend.
    pub http_connections: Option<u64>,
}

impl Demand {
    /// The demand of `config`.
    pub fn of(config: &sibuna_lb::Config) -> Self {
        Self {
            max_flows: config.max_flows() as u64,
            http_connections: config.http().map(|http| u64::from(http.max_connections)),
        }
    }

    /// The descriptors the topology can use at once.
    pub fn need(&self) -> u64 {
        2 * self.max_flows + 2 * self.http_connections.unwrap_or(0) + RESERVE
    }
}

/// What the check decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Plan {
    /// The soft limit covers the need.
    Enough,
    /// Raise the soft limit to this value, which covers the need.
    Raise(u64),
    /// Raise the soft limit to the hard limit, which does not cover the need.
    RaiseAndWarn(u64),
    /// The limit cannot rise and does not cover the need.
    Warn,
}

/// Decides what to do about `limit` for a topology that needs `need` descriptors.
pub(super) fn plan(limit: DescriptorLimit, need: u64) -> Plan {
    if limit.soft >= need {
        Plan::Enough
    } else if limit.hard >= need {
        Plan::Raise(need)
    } else if limit.hard > limit.soft {
        Plan::RaiseAndWarn(limit.hard)
    } else {
        Plan::Warn
    }
}

/// Checks the descriptor limit for `demand`, raises the soft limit when that helps, and
/// prints a warning on standard error when the topology can still exceed it. `path`
/// names the topology file in the warning. Startup continues either way.
pub(super) fn check(path: &str, demand: Demand) {
    let Ok(limit) = sibuna_reactor::descriptor_limit() else { return };
    let need = demand.need();
    let raised = match plan(limit, need) {
        Plan::Enough => return,
        Plan::Raise(soft) | Plan::RaiseAndWarn(soft) => {
            sibuna_reactor::set_descriptor_limit(soft).is_ok()
        }
        Plan::Warn => false,
    };
    let now = sibuna_reactor::descriptor_limit().map_or(limit.soft, |limit| limit.soft);
    if raised && now >= need {
        super::note(format_args!(
            "Sibuna edge raised the descriptor limit from {} to {now}",
            limit.soft
        ));
        return;
    }
    super::note(format_args!("{}", warning(path, demand, now).trim_end_matches('\n')));
}

/// The warning for a process that may open `available` descriptors.
pub(super) fn warning(path: &str, demand: Demand, available: u64) -> String {
    let need = demand.need();
    let title = "-- DESCRIPTOR LIMIT TOO LOW ";
    let rule = "-".repeat(80usize.saturating_sub(title.len() + path.len() + 1));
    let mut text = format!("{title}{rule} {path}\n\n");
    let _ = writeln!(
        text,
        "This topology can use {need} file descriptors, but the process may open {available}.\n"
    );
    let flows = demand.max_flows;
    match demand.http_connections {
        Some(http) => {
            let _ = writeln!(
                text,
                "global.max_flows = {flows}, http.max_connections = {http}\n\
                 need = 2 * {flows} + 2 * {http} + {RESERVE} = {need}\n"
            );
        }
        None => {
            let _ = writeln!(
                text,
                "global.max_flows = {flows}\nneed = 2 * {flows} + {RESERVE} = {need}\n"
            );
        }
    }
    let _ = writeln!(
        text,
        "Hint: Raise the limit (`LimitNOFILE={need}` in the systemd unit, \
         or `ulimit -n {need}`),\n\
         or lower `global.max_flows` and `http.max_connections`."
    );
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEMAND: Demand = Demand { max_flows: 8192, http_connections: Some(1024) };

    #[test]
    fn the_need_counts_two_descriptors_per_flow_and_a_reserve() {
        assert_eq!(DEMAND.need(), 18_944);
        assert_eq!(Demand { max_flows: 100, http_connections: None }.need(), 712);
    }

    #[test]
    fn the_plan_raises_only_as_far_as_needed_and_warns_when_that_is_not_enough() {
        let limit = |soft, hard| DescriptorLimit { soft, hard };
        assert_eq!(plan(limit(20_000, 20_000), 18_944), Plan::Enough);
        assert_eq!(plan(limit(1024, 524_288), 18_944), Plan::Raise(18_944));
        assert_eq!(plan(limit(1024, u64::MAX), 18_944), Plan::Raise(18_944));
        assert_eq!(plan(limit(1024, 4096), 18_944), Plan::RaiseAndWarn(4096));
        assert_eq!(plan(limit(4096, 4096), 18_944), Plan::Warn);
    }

    #[test]
    fn the_warning_has_a_title_the_numbers_and_a_hint() {
        let text = warning("edge.jlv", DEMAND, 4096);
        let first = text.lines().next().unwrap_or_default();
        assert!(first.starts_with("-- DESCRIPTOR LIMIT TOO LOW ---"), "{text}");
        assert!(first.ends_with(" edge.jlv") && first.len() == 80, "{first}");
        assert!(text.contains("can use 18944 file descriptors, but the process may open 4096."));
        assert!(text.contains("need = 2 * 8192 + 2 * 1024 + 512 = 18944"), "{text}");
        assert!(text.contains("Hint: Raise the limit (`LimitNOFILE=18944`"), "{text}");
        let tcp = warning("edge.json", Demand { max_flows: 100, http_connections: None }, 64);
        assert!(tcp.contains("need = 2 * 100 + 512 = 712"), "{tcp}");
    }
}
