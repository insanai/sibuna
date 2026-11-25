//! What the daemon says about learned source affinity and its disk tier (SID 0027): one
//! line at start, and the lines of `show info`.

use std::fmt::Write as _;

use sibuna_lb::SpillStatus;
use sibuna_spill::Outcome;

/// What opening the file found, in the words of an operator.
fn found(status: &SpillStatus) -> String {
    match status.outcome {
        None => "in use by another process, hints are kept in memory only".to_owned(),
        Some(Outcome::Created) => "created".to_owned(),
        Some(Outcome::Reused) => "reused".to_owned(),
        Some(Outcome::Discarded(reason)) => format!("discarded because {reason}, created anew"),
    }
}

/// The memory of the process that the hints hold: the table, the sketches and the queue.
fn memory_bytes(status: &SpillStatus) -> u64 {
    status.table_bytes + status.budget.memory_bytes()
}

/// The line that the daemon notes at start, with the code `EDGE013`. It says whether
/// the hints of the last run are in use, and what the tiers cost.
pub(super) fn start_line(status: &SpillStatus) -> String {
    let mut line = format!("EDGE013: spill cache {}: {}", status.path.display(), found(status));
    if status.outcome.is_some() {
        let _ = write!(
            line,
            ", {} slots in {} bytes on disk, {} bytes of memory",
            status.slots,
            status.budget.file_bytes,
            memory_bytes(status)
        );
        if !status.persistent {
            line.push_str(", not kept over a restart on this platform");
        }
    }
    line
}

/// Appends the lines of `show info` for the hints: the file, the cost and the counters.
pub(super) fn write_info(text: &mut String, status: &SpillStatus) {
    let disk = &status.disk.cache;
    let written = disk.stored + disk.updated + disk.replaced;
    let _ = write!(
        text,
        "spill: {}\nspill_state: {}\nspill_slots: {}\nspill_file_bytes: {}\n\
         spill_memory_bytes: {}\nspill_table_entries: {}\nspill_hits: {}\nspill_misses: {}\n\
         spill_promoted: {}\nspill_disk_lookups: {}\nspill_disk_hits: {}\n\
         spill_disk_written: {written}\nspill_disk_rejected: {}\nspill_disk_corrupt: {}\n\
         spill_disk_shed: {}\n",
        status.path.display(),
        found(status),
        status.slots,
        status.budget.file_bytes,
        memory_bytes(status),
        status.entries,
        status.hits,
        status.misses,
        status.promoted,
        disk.lookups,
        disk.hits,
        disk.rejected,
        disk.corrupt,
        status.disk.shed,
    );
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use sibuna_spill::{Budget, Reason, ServiceCounters};

    use super::*;

    fn status(outcome: Option<Outcome>) -> SpillStatus {
        let budget = Budget {
            file_bytes: 1_040_384,
            slot_bytes: 1_032_192,
            index_bytes: 8_192,
            sketch_bytes: 32_768,
            scratch_bytes: 1_000,
            queue_bytes: 262_144,
        };
        SpillStatus {
            path: PathBuf::from("/var/lib/sibuna/hints.spill"),
            outcome,
            persistent: true,
            slots: 16_128,
            entries: 4_096,
            budget,
            table_bytes: 65_536,
            disk: ServiceCounters::default(),
            hits: 7,
            misses: 3,
            promoted: 2,
        }
    }

    #[test]
    fn the_line_at_start_says_what_was_found_and_what_it_costs() {
        let reused = start_line(&status(Some(Outcome::Reused)));
        assert_eq!(
            reused,
            "EDGE013: spill cache /var/lib/sibuna/hints.spill: reused, 16128 slots in \
             1040384 bytes on disk, 361448 bytes of memory"
        );
        let discarded = Outcome::Discarded(Reason::Version(2));
        let line = start_line(&status(Some(discarded)));
        assert!(line.contains("discarded because it has format version 2, created anew"));
        let busy = start_line(&status(None));
        assert!(busy.ends_with("in use by another process, hints are kept in memory only"));
        let mut memory = status(Some(Outcome::Created));
        memory.persistent = false;
        assert!(start_line(&memory).ends_with("not kept over a restart on this platform"));
    }

    #[test]
    fn show_info_names_the_file_the_cost_and_the_counters() {
        let mut text = String::new();
        write_info(&mut text, &status(Some(Outcome::Created)));
        assert!(text.starts_with("spill: /var/lib/sibuna/hints.spill\nspill_state: created\n"));
        for line in ["spill_slots: 16128\n", "spill_hits: 7\n", "spill_promoted: 2\n"] {
            assert!(text.contains(line), "{text}");
        }
        assert!(text.ends_with("spill_disk_shed: 0\n"));
        assert_eq!(text.lines().count(), 15);
    }
}
